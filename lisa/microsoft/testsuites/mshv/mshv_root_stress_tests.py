# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.
import base64
import re
import secrets
import time
from dataclasses import dataclass
from functools import partial
from pathlib import Path, PurePath
from typing import Any, Dict, List, Optional, Tuple

import yaml
from assertpy import assert_that
from microsoft.testsuites.mshv.cloud_hypervisor_tool import CloudHypervisor

from lisa import Logger, Node, TestCaseMetadata, TestSuite, TestSuiteMetadata
from lisa.messages import TestStatus, send_sub_test_result_message
from lisa.operating_system import CpuArchitecture
from lisa.testsuite import TestResult
from lisa.tools import (
    Chown,
    Cp,
    Free,
    Ls,
    Lsblk,
    Lscpu,
    Mount,
    QemuImg,
    Rm,
    Ssh,
    Usermod,
    Wget,
    Whoami,
)
from lisa.tools.lsblk import DiskInfo
from lisa.tools.mkfs import FileSystem
from lisa.util import SkippedException
from lisa.util.parallel import Task, TaskManager
from lisa.util.process import Process


@dataclass(frozen=True)
class _VmWorkloadInfo:
    serial_log_path: PurePath
    start_token: str
    done_token: str


@TestSuiteMetadata(
    area="mshv",
    category="stress",
    description="""
    This test suite contains tests that are meant to be run on the
    Microsoft Hypervisor (MSHV) root partition.
    """,
)
class MshvHostStressTestSuite(TestSuite):
    IGVM_PATH_VARIABLE = "igvm_path"
    CONFIG_VARIABLE = "mshv_vm_create_stress_configs"
    DEFAULT_ITERS = 15
    DEFAULT_CPUS_PER_VM = 1
    DEFAULT_MEM_PER_VM_MB = 1024
    DEFAULT_GUEST_VM_TYPE = "NON-CVM"

    DISK_IMG_NAME = "vm_disk_img.raw"

    # cloud-hypervisor EDK2 firmware. Preferred location is the preinstalled
    # copy under /usr/share/cloud-hypervisor; if that is missing we fall back
    # to the pinned GitHub release below. Filename is arch-specific.
    CLOUDHV_FIRMWARE_SYSTEM_DIR = "/usr/share/cloud-hypervisor"
    CLOUDHV_FIRMWARE_RELEASE_URL = "https://github.com/cloud-hypervisor/edk2/releases/download/ch-1e1b96f126"  # noqa: E501
    _CLOUDHV_FW_FILENAME: Dict[CpuArchitecture, str] = {
        CpuArchitecture.X64: "CLOUDHV.fd",
        CpuArchitecture.ARM64: "CLOUDHV_EFI.fd",
    }

    # Launcher script written into each guest by cloud-init via the per-VM
    # seed ISO. Args: $1=time_secs, $2=start_token, $3=done_token.
    # The background loop emits a heartbeat ("${start_token}_HB") every 2 s
    # while openssl runs, so the host can confirm the workload is actively
    # scheduled (not hung) by sampling the count twice.
    _LAUNCHER_SCRIPT_PATH = "/usr/local/bin/lisa_cpu_workload.sh"
    _LAUNCHER_SCRIPT_CONTENT = (
        "#!/bin/sh\n"
        "exec > /dev/console 2>&1\n"
        'echo "$2"\n'
        '(while :; do echo "${2}_HB"; sleep 2; done) &\n'
        "HB=$!\n"
        'openssl speed -multi "$(nproc)" -seconds "$1" -evp sha256\n'
        'kill "$HB" 2>/dev/null\n'
        'echo "$3"\n'
    )

    # Workload runs for 1 hour; the test never waits for it to finish.
    _CPU_WORKLOAD_RUN_SECS = 3600
    # Fixed wait after the last VM is launched, to let cloud-init boot and
    # start the workload before we verify it is in progress.
    _POST_LAUNCH_WAIT_SECS = 180
    # Window between two heartbeat samples; must exceed the launcher's
    # 2 s heartbeat interval so a live workload produces a new heartbeat.
    _HEARTBEAT_WAIT_SECS = 5

    _WORKLOAD_START_PREFIX = "LISA_CPU_WORKLOAD_START_"
    _WORKLOAD_DONE_PREFIX = "LISA_CPU_WORKLOAD_DONE_"
    _HEARTBEAT_SUFFIX = "_HB"

    # Recovers the VM index from a serial-log filename, e.g.
    # ".../CH_VM7_serial.log" -> 7. Used to attribute grep matches back to
    # the VM that produced them.
    _SERIAL_LOG_VM_INDEX_RE = re.compile(r"CH_VM(\d+)_serial\.log$")

    # Each stress VM gets its own /24 to avoid host-side IP/route collisions.
    # skipping 0 and 255 out of paranoia for legacy software
    _MAX_VMS_PER_BATCH = 254

    # Bounded worker pool for per-VM prep+launch. Sized so peak SSH-session
    # use stays under `MaxSessions` (200); bumping it requires re-checking
    # that headroom AND remote disk-I/O headroom for concurrent `cp`s.
    _VM_LAUNCH_PARALLELISM = 8

    # Packages required on the remote node to build the per-VM NoCloud seed
    # image: mkfs.fat (dosfstools), mcopy (mtools), and iconv data used by
    # mcopy at runtime on minimal distros (glibc-iconv on Azure Linux).
    _SEED_BUILD_PACKAGES = ["dosfstools", "mtools", "glibc-iconv"]

    def before_case(self, log: Logger, **kwargs: Any) -> None:
        node = kwargs["node"]
        if not node.tools[Ls].path_exists("/dev/mshv", sudo=True):
            raise SkippedException("This suite is for MSHV root partition only")

        # add user to mshv group for access to /dev/mshv
        node.tools[Usermod].add_user_to_group("mshv", sudo=True)

        node.os.install_packages(self._SEED_BUILD_PACKAGES)

        working_path = node.get_working_path()

        # Resolve the cloud-hypervisor firmware path. If the preinstalled
        # firmware under CLOUDHV_FIRMWARE_SYSTEM_DIR is present we use it as-is;
        # otherwise download the matching CLOUDHV*.fd from the pinned GitHub
        # release into the working path.
        remote_arch = node.tools[Lscpu].get_architecture()
        firmware_filename = self._get_fw_filename(remote_arch)
        firmware_path = self._get_fw_path(node, log)
        if not firmware_path.startswith(self.CLOUDHV_FIRMWARE_SYSTEM_DIR):
            firmware_url = f"{self.CLOUDHV_FIRMWARE_RELEASE_URL}/{firmware_filename}"
            log.info(
                f"Preinstalled cloud-hypervisor firmware not found; "
                f"downloading {firmware_url} -> {firmware_path}"
            )
            node.tools[Wget].get(
                firmware_url,
                file_path=str(working_path),
                filename=firmware_filename,
            )

        guest_image_url = self._get_ubuntu_cloud_image_url(
            remote_arch,
        )
        qcow2_name = f"{self.DISK_IMG_NAME}.img"
        qcow2_path = working_path / qcow2_name
        raw_path = working_path / self.DISK_IMG_NAME

        node.tools[Wget].get(
            guest_image_url,
            file_path=str(working_path),
            filename=qcow2_name,
            timeout=1200,
        )

        node.tools[QemuImg].convert(
            "qcow2",
            str(qcow2_path),
            "raw",
            str(raw_path),
        )

        # qcow2 is no longer needed after the convert; reclaim disk space
        # on the remote host.
        try:
            node.tools[Rm].remove_file(str(qcow2_path), sudo=True)
        except Exception as e:
            log.debug(
                f"Failed to delete remote qcow2 {qcow2_path}: {e}"
            )

    def _get_ubuntu_cloud_image_url(
        self, arch: CpuArchitecture
    ) -> str:
        if arch == CpuArchitecture.X64:
            suffix = "amd64"
        elif arch == CpuArchitecture.ARM64:
            suffix = "arm64"
        else:
            raise SkippedException(
                f"Unsupported remote host architecture [{arch}] for MSHV "
                f"stress VM create. Supported architectures: "
                f"[{CpuArchitecture.X64.value}, {CpuArchitecture.ARM64.value}]."
            )

        url = (
            f"https://cloud-images.ubuntu.com/jammy/current/"
            f"jammy-server-cloudimg-{suffix}.img"
        )

        return url

    def _get_fw_filename(self, arch: CpuArchitecture) -> str:
        filename = self._CLOUDHV_FW_FILENAME.get(arch)
        if filename is None:
            raise SkippedException(
                f"Unsupported remote host architecture [{arch}] for MSHV "
                f"stress VM create. Supported architectures: "
                f"{sorted(a.value for a in self._CLOUDHV_FW_FILENAME)}."
            )
        return filename

    def _get_fw_path(self, node: Node, log: Logger) -> str:
        # Prefer the preinstalled firmware shipped under
        # /usr/share/cloud-hypervisor; fall back to the working-path location
        # where before_case downloads it from the pinned GitHub release.
        arch = node.tools[Lscpu].get_architecture()
        filename = self._get_fw_filename(arch)
        system_path = f"{self.CLOUDHV_FIRMWARE_SYSTEM_DIR}/{filename}"
        if node.tools[Ls].path_exists(system_path, sudo=True):
            log.info(f"Using preinstalled cloud-hypervisor firmware {system_path}")
            return system_path
        return str(node.get_working_path() / filename)

    @TestCaseMetadata(
        description="""
        Stress the MSHV virt stack by repeatedly creating and destroying
        multiple VMs in parallel. By default creates VMs with 1 vCPU and
        1 GiB of RAM each. Number of VMs createdis equal to the number of
        CPUs available on the host. By default, the test is repeated 25
        times. All of these can be configured via the variable
        "mshv_vm_create_stress_configs" in the runbook.
        """,
        priority=4,
        timeout=10800,  # 3 hours
    )
    def stress_mshv_vm_create(
        self,
        log: Logger,
        node: Node,
        variables: Dict[str, Any],
        log_path: Path,
        result: TestResult,
    ) -> None:
        configs = variables.get(self.CONFIG_VARIABLE, [{}])
        igvm_path = variables.get(self.IGVM_PATH_VARIABLE, "")
        guest_vm_type = variables.get("clh_guest_vm_type", self.DEFAULT_GUEST_VM_TYPE)

        # This test can end up creating and a lot of ssh sessions and these kept active
        # at the same time.
        # In Ubuntu, the default limit is easily exceeded. So change the MaxSessions
        # property in sshd_config to a high number that is unlikely to be exceeded.
        node.tools[Ssh].set_max_session()

        failures = 0
        for config in configs:
            times = config.get("iterations", self.DEFAULT_ITERS)
            cpus_per_vm = config.get("cpus_per_vm", self.DEFAULT_CPUS_PER_VM)
            mem_per_vm_mb = config.get("mem_per_vm_mb", self.DEFAULT_MEM_PER_VM_MB)
            test_name = f"mshv_stress_vm_create_{times}times_{cpus_per_vm}cpu_{mem_per_vm_mb}MB"  # noqa: E501
            try:
                vm_failures = self._mshv_stress_vm_create(
                    times=times,
                    cpus_per_vm=cpus_per_vm,
                    mem_per_vm_mb=mem_per_vm_mb,
                    log=log,
                    node=node,
                    log_path=log_path,
                    guest_vm_type=guest_vm_type,
                    igvm_path=igvm_path,
                )
                if vm_failures == 0:
                    send_sub_test_result_message(
                        test_result=result,
                        test_case_name=test_name,
                        test_status=TestStatus.PASSED,
                    )
                else:
                    failures += vm_failures
                    fail_msg = (
                        f"{vm_failures} VM(s) failed workload checks "
                        f"across {times} iteration(s)"
                    )
                    log.error(f"{test_name} FAILED: {fail_msg}")
                    send_sub_test_result_message(
                        test_result=result,
                        test_case_name=test_name,
                        test_status=TestStatus.FAILED,
                        test_message=fail_msg,
                    )
            except Exception as e:
                failures += 1
                log.error(f"{test_name} FAILED: {e}")
                send_sub_test_result_message(
                    test_result=result,
                    test_case_name=test_name,
                    test_status=TestStatus.FAILED,
                    test_message=repr(e),
                )
        ch_tool: CloudHypervisor = node.tools[CloudHypervisor]
        # ch_tool.save_dmesg_logs(node, log_path)
        assert_that(failures).described_as(
            "Total VM workload failures across all configs and iterations"
        ).is_equal_to(0)
        return

    def _mshv_stress_vm_create(
        self,
        times: int,
        cpus_per_vm: int,
        mem_per_vm_mb: int,
        log: Logger,
        node: Node,
        log_path: Path,
        guest_vm_type: str = "NON-CVM",
        igvm_path: str = "",
    ) -> int:
        log.info(
            f"MSHV stress VM create: times={times}, cpus_per_vm={cpus_per_vm}, mem_per_vm_mb={mem_per_vm_mb}"  # noqa: E501
        )
        kernel_path = self._get_fw_path(node, log)
        disk_img_path = node.get_working_path() / self.DISK_IMG_NAME
        disk_img_copy_path = self._get_disk_img_copy_path(node, log)
        threads = node.tools[Lscpu].get_thread_count()
        vm_count = int(threads / cpus_per_vm)
        if vm_count > self._MAX_VMS_PER_BATCH:
            raise SkippedException(
                f"vm_count [{vm_count}] exceeds the per-batch limit "
                f"[{self._MAX_VMS_PER_BATCH}] imposed by the per-VM /24 "
                f"networking scheme."
            )
        inject_cpu_workload = guest_vm_type != "CVM"

        # Pre-touch the lazy tool cache on the main thread so that the
        # parallel workers only ever do dict reads. Constructing a tool
        # on first access is not guaranteed to be thread-safe.
        for _tool_cls in (Cp, CloudHypervisor, Free, Whoami):
            _ = node.tools[_tool_cls]

        failures = 0
        for test_iter in range(times):
            log.info(f"Test iteration {test_iter + 1} of {times}")
            node.tools[Free].log_memory_stats_mb()

            procs, vm_workload_info = self._launch_vms_parallel(
                vm_count=vm_count,
                cpus_per_vm=cpus_per_vm,
                mem_per_vm_mb=mem_per_vm_mb,
                disk_img_path=disk_img_path,
                disk_img_copy_path=disk_img_copy_path,
                kernel_path=kernel_path,
                guest_vm_type=guest_vm_type,
                igvm_path=igvm_path,
                inject_cpu_workload=inject_cpu_workload,
                node=node,
                log=log,
                log_path=log_path,
            )

            if inject_cpu_workload:
                log.info(
                    f"Waiting {self._POST_LAUNCH_WAIT_SECS}s for guests to boot,"
                    f" start the CPU workload and have it running for a while"
                )
                time.sleep(self._POST_LAUNCH_WAIT_SECS)
                failures += self._verify_cpu_workload_in_progress(
                    node=node,
                    procs=procs,
                    vm_workload_info=vm_workload_info,
                    serial_log_dir=disk_img_copy_path,
                    log_path=log_path,
                    log=log,
                )
                for i in range(len(procs)):
                    p = procs[i]
                    if p.is_running():
                        log.info(f"Killing VM {i}")
                        p.kill()
            else:
                # CVM path keeps the original blind-sleep semantics.
                # 20 seconds per VM (with default 1024M) is what CVM boot
                # needs in practice.
                sleep_time = 20 * vm_count
                time.sleep(sleep_time)

                for i in range(len(procs)):
                    p = procs[i]
                    if not p.is_running():
                        log.info(f"VM {i} was not running")
                        failures += 1
                        vm_log_file_path = (
                            disk_img_copy_path / f"CH_VM{i}.log"
                        )
                        vm_log_file_copy_back_path = (
                            log_path / f"CH_VM{i}.log"
                        )
                        node.shell.copy_back(
                            vm_log_file_path,
                            vm_log_file_copy_back_path,
                        )
                        log.info(
                            f"Failed VM logs copied to "
                            f"{vm_log_file_copy_back_path}"
                        )
                        continue
                    log.info(f"Killing VM {i}")
                    p.kill()

                # CVM guest killing takes sometime
                time.sleep(20)

            node.tools[Free].log_memory_stats_mb()

        return failures

    def _launch_vms_parallel(
        self,
        vm_count: int,
        cpus_per_vm: int,
        mem_per_vm_mb: int,
        disk_img_path: PurePath,
        disk_img_copy_path: PurePath,
        kernel_path: str,
        guest_vm_type: str,
        igvm_path: str,
        inject_cpu_workload: bool,
        node: Node,
        log: Logger,
        log_path: Path,
    ) -> Tuple[List[Process], List[_VmWorkloadInfo]]:
        # Run the per-VM prep+launch pipeline (seed build, seed upload,
        # disk-image copy, cloud-hypervisor start) concurrently across a
        # bounded worker pool. Results are returned in VM-index order so
        # the caller's downstream logic (which is index-addressed) is
        # unchanged.
        #
        # We use TaskManager directly rather than `run_in_parallel(...)`
        # because the latter sizes the pool to len(tasks) -- at vm_count
        # = 128 that would defeat the bound we need to keep SSH-session
        # usage safe.
        max_workers = min(vm_count, self._VM_LAUNCH_PARALLELISM)
        task_manager: TaskManager[
            Tuple[Process, Optional[_VmWorkloadInfo]]
        ] = TaskManager(max_workers=max_workers, callback=lambda _: None)
        wrapped_tasks: List[Task[Tuple[Process, Optional[_VmWorkloadInfo]]]] = []
        for i in range(vm_count):
            task_callable = partial(
                self._prepare_and_start_vm,
                vm_index=i,
                cpus_per_vm=cpus_per_vm,
                mem_per_vm_mb=mem_per_vm_mb,
                disk_img_path=disk_img_path,
                disk_img_copy_path=disk_img_copy_path,
                kernel_path=kernel_path,
                guest_vm_type=guest_vm_type,
                igvm_path=igvm_path,
                inject_cpu_workload=inject_cpu_workload,
                node=node,
                log=log,
                log_path=log_path,
            )
            wrapped = Task(task_id=i, task=task_callable, parent_logger=log)
            wrapped_tasks.append(wrapped)
            task_manager.submit_task(wrapped)

        log.info(f"Launching {vm_count} VMs in parallel with {max_workers} workers")
        try:
            task_manager.wait_for_all_workers()
        except Exception:
            # One or more per-VM tasks raised. Reap whatever did manage
            # to launch this iteration so we don't leak cloud-hypervisor
            # processes (and their persistent SSH channels) into the
            # next iteration, then re-raise.
            for wrapped in wrapped_tasks:
                result = wrapped.result
                if result is None:
                    continue
                proc, _ = result
                try:
                    if proc.is_running():
                        proc.kill()
                except Exception as kill_err:
                    log.debug(
                        f"Failed to kill VM {wrapped.id} during partial-"
                        f"launch cleanup: {kill_err}"
                    )
            raise

        procs: List[Process] = []
        # inject_cpu_workload is per-batch, not per-VM, so _prepare_and_start_vm
        # returns either None for every VM or an info for every VM. Skip the
        # None case so callers see an empty list when injection is off and a
        # length-vm_count list otherwise -- never a heterogeneous mix.
        vm_workload_info: List[_VmWorkloadInfo] = []
        for wrapped in wrapped_tasks:
            assert wrapped.result is not None
            proc, info = wrapped.result
            procs.append(proc)
            if info is not None:
                vm_workload_info.append(info)
        assert not vm_workload_info or len(vm_workload_info) == vm_count, (
            f"vm_workload_info length {len(vm_workload_info)} must be 0 or "
            f"vm_count {vm_count}; inject_cpu_workload is per-batch"
        )
        return procs, vm_workload_info

    def _prepare_and_start_vm(
        self,
        vm_index: int,
        cpus_per_vm: int,
        mem_per_vm_mb: int,
        disk_img_path: PurePath,
        disk_img_copy_path: PurePath,
        kernel_path: str,
        guest_vm_type: str,
        igvm_path: str,
        inject_cpu_workload: bool,
        node: Node,
        log: Logger,
        log_path: Path,
    ) -> Tuple[Process, Optional[_VmWorkloadInfo]]:
        i = vm_index
        vm_disk_img_path = disk_img_copy_path / f"VM{i}_{self.DISK_IMG_NAME}"
        vm_log_file_path = disk_img_copy_path / f"CH_VM{i}.log"
        vm_seed_img_path = disk_img_copy_path / f"VM{i}_seed.img"
        vm_serial_log_path = disk_img_copy_path / f"CH_VM{i}_serial.log"

        node.tools[Cp].copy(
            disk_img_path,
            vm_disk_img_path,
            sudo=True,
            timeout=1200,
        )
        # `cp` writes through the page cache and returns before the data is
        # durably on storage.  Flush this disk before starting the VM.
        node.execute(
            f'sync {node.get_str_path(vm_disk_img_path)}',
            shell=True,
            sudo=True,
            expected_exit_code=0,
            expected_exit_code_failure_message=(
                f"Failed to sync root disk image for VM {i} at "
                f"{vm_disk_img_path}."
            ),
        )

        extra_disks: Optional[List[str]] = None
        serial_file = ""
        mac = ""
        # Per-VM /24 applies to both NON-CVM and CVM paths -- the
        # underlying cloud-hypervisor TAP collision is the same.
        host_ip, guest_ip, netmask, gateway, prefix_len = self._vm_subnet(i)
        workload_info: Optional[_VmWorkloadInfo] = None
        if inject_cpu_workload:
            # Per-VM unique tokens; suffix preserves human-readable
            # context in failure logs.
            start_token = (
                f"{self._WORKLOAD_START_PREFIX}"
                f"{i}_{secrets.token_hex(4)}"
            )
            done_token = (
                f"{self._WORKLOAD_DONE_PREFIX}"
                f"{i}_{secrets.token_hex(4)}"
            )
            mac = self._generate_mac()
            log.info(
                f"VM {i} network assignment: mac={mac} "
                f"host_ip={host_ip} guest_ip={guest_ip} "
                f"gateway={gateway} netmask={netmask}"
            )
            self._build_upload_cloud_init_seed(
                node=node,
                vm_index=i,
                time_secs=self._CPU_WORKLOAD_RUN_SECS,
                start_token=start_token,
                done_token=done_token,
                remote_seed_path=vm_seed_img_path,
                mac=mac,
                guest_ip=guest_ip,
                prefix_len=prefix_len,
                gateway=gateway,
                log=log,
            )
            extra_disks = [str(vm_seed_img_path)]
            serial_file = str(vm_serial_log_path)
            workload_info = _VmWorkloadInfo(
                serial_log_path=vm_serial_log_path,
                start_token=start_token,
                done_token=done_token,
            )

        log.info(f"Starting VM {i}")
        ch_tool: CloudHypervisor = node.tools[CloudHypervisor]
        p = ch_tool.start_vm_async(
            # kernel=kernel_path,
            kernel="/home/cloud/Image-arm64",
            cpus=cpus_per_vm,
            memory_mb=mem_per_vm_mb,
            disk_path=str(vm_disk_img_path),
            sudo=True,
            guest_vm_type=guest_vm_type,
            igvm_path=igvm_path,
            log_file=str(vm_log_file_path),
            extra_disks=extra_disks,
            serial_file=serial_file,
            mac=mac,
            host_ip=host_ip,
            host_mask=netmask,
            cmdline="console=ttyAMA0 root=/dev/vda1 rw loglevel=8",
        )
        time.sleep(10)  # Let the VM start and fail fast if it's going to
        if not p:
            node.shell.copy_back(
                vm_log_file_path,
                log_path / vm_log_file_path,
            )
        assert_that(p).described_as(f"Failed to create VM {i}").is_not_none()
        assert_that(p.is_running()).described_as(f"VM {i} failed to start").is_true()
        return p, workload_info

    def _build_upload_cloud_init_seed(
        self,
        node: Node,
        vm_index: int,
        time_secs: int,
        start_token: str,
        done_token: str,
        remote_seed_path: PurePath,
        mac: str,
        guest_ip: str,
        prefix_len: int,
        gateway: str,
        log: Logger,
    ) -> None:
        # Build a NoCloud seed image (FAT, volume label CIDATA) on the
        # remote node that:
        #   1. drops the CPU-workload launcher script into the guest at
        #      _LAUNCHER_SCRIPT_PATH (via cloud-init's write_files),
        #   2. invokes that launcher with the per-VM workload parameters
        #      (via cloud-init's runcmd), and
        #   3. binds the NIC with the given MAC to a static IPv4 on this
        #      VM's per-VM /24 (via cloud-init's network-config v2).
        #
        # The image is constructed entirely on the remote node so the LISA
        # controller does not need dosfstools / mtools installed. The three
        # rendered yaml payloads are shipped in a single SSH invocation as
        # inline base64 blobs, decoded into a per-VM temp dir, packed into a
        # fresh FAT image with mkfs.fat + mcopy, then atomically moved into
        # remote_seed_path (typically root-owned, e.g. /mnt/resource). The
        # whole script runs under sudo so the final mv succeeds without
        # juggling per-step privileges.

        user_data: Dict[str, Any] = {
            "hostname": f"mshv-stress-vm-{vm_index}",
            # write_files runs before runcmd, so the launcher exists and
            # is executable by the time runcmd invokes it.
            "write_files": [
                {
                    "path": self._LAUNCHER_SCRIPT_PATH,
                    "permissions": "0755",
                    "content": self._LAUNCHER_SCRIPT_CONTENT,
                }
            ],
            "runcmd": [
                [
                    "sh",
                    "-c",
                    f"{self._LAUNCHER_SCRIPT_PATH} "
                    f"{time_secs} '{start_token}' '{done_token}'",
                ]
            ],
        }
        meta_data: Dict[str, Any] = {
            "instance-id": f"mshv-stress-vm-{vm_index}",
            "local-hostname": f"mshv-stress-vm-{vm_index}",
        }
        # network-config v2: match by MAC (independent of udev naming) and
        # assign this VM's static IPv4 on its own /24.
        network_data: Dict[str, Any] = {
            "version": 2,
            "ethernets": {
                "guest0": {
                    "match": {"macaddress": mac},
                    "set-name": "eth0",
                    "addresses": [f"{guest_ip}/{prefix_len}"],
                    "gateway4": gateway,
                }
            },
        }

        user_data_string = "#cloud-config\n" + yaml.safe_dump(user_data)
        meta_data_string = yaml.safe_dump(meta_data)
        network_data_string = yaml.safe_dump(network_data)

        # base64-encode each rendered yaml so the entire payload is a single
        # SSH-safe ASCII blob (no shell-quoting concerns for newlines or
        # quotes) inside the remote bash script below.
        user_data_b64 = base64.b64encode(user_data_string.encode()).decode()
        meta_data_b64 = base64.b64encode(meta_data_string.encode()).decode()
        network_data_b64 = base64.b64encode(network_data_string.encode()).decode()

        # Stage the three yaml files and build the FAT seed image in a
        # per-VM temp dir under the user-writable working path, then mv the
        # finished image into `remote_seed_path`. `set -euo pipefail` makes
        # any internal failure surface as a non-zero exit so node.execute()'s
        # expected_exit_code check fires with our message.
        working_path = node.get_working_path()
        install_hint = (
            f"Verify '{', '.join(self._SEED_BUILD_PACKAGES)}' are installed "
            f"on the remote node (installed by before_case)."
        )
        seed_build_script = (
            "set -euo pipefail\n"
            f"src_dir=$(mktemp -d {working_path}/VM{vm_index}_seed_src_XXXXXX)\n"
            'trap "rm -rf \\"$src_dir\\"" EXIT\n'
            f'printf "%s" "{user_data_b64}" | base64 -d > "$src_dir/user-data"\n'
            f'printf "%s" "{meta_data_b64}" | base64 -d > "$src_dir/meta-data"\n'
            f'printf "%s" "{network_data_b64}" '
            '| base64 -d > "$src_dir/network-config"\n'
            'seed_img="$src_dir/seed.img"\n'
            'mkfs.fat -n CIDATA -C "$seed_img" 8192\n'
            'mcopy -oi "$seed_img" -s "$src_dir/user-data" ::\n'
            'mcopy -oi "$seed_img" -s "$src_dir/meta-data" ::\n'
            'mcopy -oi "$seed_img" -s "$src_dir/network-config" ::\n'
            f'mv "$seed_img" {remote_seed_path}\n'
            # Flush the seed image so cloud-hypervisor doesn't open it before
            # the blocks are durably on storage (same writeback race as the
            # root disk under the parallel launch).
            f'sync {remote_seed_path}\n'
        )

        log.debug(
            f"Building CPU-workload seed image for VM {vm_index} on remote "
            f"node at {remote_seed_path}"
        )
        node.execute(
            seed_build_script,
            shell=True,
            sudo=True,
            expected_exit_code=0,
            expected_exit_code_failure_message=(
                f"Failed to build NoCloud seed image for VM {vm_index} at "
                f"{remote_seed_path}. {install_hint}"
            ),
        )

    def _verify_cpu_workload_in_progress(
        self,
        node: Node,
        procs: List[Any],
        vm_workload_info: List[_VmWorkloadInfo],
        serial_log_dir: PurePath,
        log_path: Path,
        log: Logger,
    ) -> int:
        failures = 0

        # Phase 1: per-VM static checks + snapshot heartbeat count.
        # hb_baseline[i] is the pre-wait heartbeat count for VM i, or
        # None if VM i already failed (skip its heartbeat check entirely).
        markers = self._collect_workload_markers(node, serial_log_dir)
        hb_baseline: List[Optional[int]] = [None] * len(vm_workload_info)
        for i, info in enumerate(vm_workload_info):
            p = procs[i]
            vm_marker = markers.get(
                i, {"started": False, "done": False, "hb_baseline": 0}
            )
            reason: Optional[str] = None
            if not p.is_running():
                reason = "cloud-hypervisor process is not running"
            elif not vm_marker["started"]:
                reason = (
                    f"start-token {info.start_token} not found in serial log; "
                    f"workload did not start"
                )
            elif vm_marker["done"]:
                reason = (
                    f"done-token {info.done_token} unexpectedly present; "
                    f"workload finished before kill"
                )

            if reason is not None:
                failures += 1
                log.error(f"VM {i} workload-in-progress check failed: {reason}")
                self._copy_back_vm_failure_logs(
                    node=node,
                    vm_index=i,
                    serial_log_path=info.serial_log_path,
                    log_path=log_path,
                    log=log,
                )
                continue
            hb_baseline[i] = int(vm_marker["hb_baseline"])

        # Single global wait, then re-sample heartbeats for surviving VMs.
        log.info(
            f"Sleeping {self._HEARTBEAT_WAIT_SECS}s to observe new "
            f"workload heartbeats"
        )
        time.sleep(self._HEARTBEAT_WAIT_SECS)

        # Phase 2: confirm heartbeat count grew (workload actively scheduled).
        hb_current = self._collect_heartbeat_counts(node, serial_log_dir)
        for i, info in enumerate(vm_workload_info):
            baseline = hb_baseline[i]
            if baseline is None:
                continue
            current = hb_current.get(i, 0)
            if current <= baseline:
                failures += 1
                log.error(
                    f"VM {i} workload heartbeat did not advance "
                    f"({baseline} -> {current}) over "
                    f"{self._HEARTBEAT_WAIT_SECS}s; workload appears hung"
                )
                self._copy_back_vm_failure_logs(
                    node=node,
                    vm_index=i,
                    serial_log_path=info.serial_log_path,
                    log_path=log_path,
                    log=log,
                )
                continue
            log.info(
                f"VM {i} CPU workload is in progress "
                f"(heartbeats {baseline} -> {current})"
            )
        return failures

    def _collect_workload_markers(
        self,
        node: Node,
        serial_log_dir: PurePath,
    ) -> Dict[int, Dict[str, Any]]:
        # One grep across every CH_VM*_serial.log under serial_log_dir,
        # matching both the start and done prefixes. Output format from
        # `grep -H` is `<path>:<matched line>` per match.
        pattern = (
            f"{self._WORKLOAD_START_PREFIX}|{self._WORKLOAD_DONE_PREFIX}"
        )
        log_glob = f"{serial_log_dir}/CH_VM*_serial.log"
        result = node.execute(
            f"grep -H -E -- '{pattern}' {log_glob} 2>/dev/null || true",
            shell=True,
            sudo=True,
            no_debug_log=True,
            no_info_log=True,
            no_error_log=True,
        )

        markers: Dict[int, Dict[str, Any]] = {}
        for line in result.stdout.splitlines():
            # `grep -H` output: "<path>:<matched line>". Matched lines may
            # themselves contain ':' so split only on the first one.
            path, _, matched = line.partition(":")
            if not matched:
                continue
            m = self._SERIAL_LOG_VM_INDEX_RE.search(path)
            if not m:
                continue
            vm_index = int(m.group(1))
            entry = markers.setdefault(
                vm_index,
                {"started": False, "done": False, "hb_baseline": 0},
            )
            if self._WORKLOAD_DONE_PREFIX in matched:
                entry["done"] = True
            elif self._WORKLOAD_START_PREFIX in matched:
                # Heartbeat lines end with _HB; the singular start
                # announcement does not. Counting heartbeats here gives
                # Phase 2 its baseline without a second grep.
                if matched.rstrip().endswith(self._HEARTBEAT_SUFFIX):
                    entry["hb_baseline"] = int(entry["hb_baseline"]) + 1
                else:
                    entry["started"] = True
        return markers

    def _collect_heartbeat_counts(
        self,
        node: Node,
        serial_log_dir: PurePath,
    ) -> Dict[int, int]:
        # Single directory-wide grep that returns the current heartbeat
        # count per serial log. We match the START prefix (fixed string)
        # and filter heartbeat lines in Python rather than counting `_HB`
        # alone, to avoid accidentally counting unrelated kernel log lines
        # that happen to contain the suffix.
        log_glob = f"{serial_log_dir}/CH_VM*_serial.log"
        result = node.execute(
            f"grep -H -F -- '{self._WORKLOAD_START_PREFIX}' "
            f"{log_glob} 2>/dev/null || true",
            shell=True,
            sudo=True,
            no_debug_log=True,
            no_info_log=True,
            no_error_log=True,
        )

        counts: Dict[int, int] = {}
        for line in result.stdout.splitlines():
            path, _, matched = line.partition(":")
            if not matched:
                continue
            if not matched.rstrip().endswith(self._HEARTBEAT_SUFFIX):
                continue
            m = self._SERIAL_LOG_VM_INDEX_RE.search(path)
            if not m:
                continue
            vm_index = int(m.group(1))
            counts[vm_index] = counts.get(vm_index, 0) + 1
        return counts

    @staticmethod
    def _generate_mac() -> str:
        # Locally-administered unicast MAC: first octet 0x02 (bit1=1 LAA,
        # bit0=0 unicast); remaining 5 octets from a CSPRNG.
        suffix = secrets.token_bytes(5)
        return "02:" + ":".join(f"{b:02x}" for b in suffix)

    def _vm_subnet(self, vm_index: int) -> Tuple[str, str, str, str, int]:
        # Returns (host_ip, guest_ip, netmask, gateway, prefix_len) for VM
        # vm_index. Each VM gets its own non-overlapping 192.168.<1+i>.0/24
        third_octet = 1 + vm_index
        host_ip = f"192.168.{third_octet}.1"
        guest_ip = f"192.168.{third_octet}.2"
        netmask = "255.255.255.0"
        prefix_len = 24
        return host_ip, guest_ip, netmask, host_ip, prefix_len

    def _copy_back_vm_failure_logs(
        self,
        node: Node,
        vm_index: int,
        serial_log_path: PurePath,
        log_path: Path,
        log: Logger,
    ) -> None:
        ch_log_remote = serial_log_path.parent / f"CH_VM{vm_index}.log"
        ch_log_local = log_path / f"CH_VM{vm_index}.log"
        serial_log_local = log_path / f"CH_VM{vm_index}_serial.log"
        # cloud-hypervisor is started with sudo, so both files are
        # root-owned. The SSH user used by copy_back cannot read them as-is,
        # so chown each file to the SSH user first.
        current_user = node.tools[Whoami].get_username()
        for remote, local in (
            (ch_log_remote, ch_log_local),
            (serial_log_path, serial_log_local),
        ):
            try:
                node.tools[Chown].change_owner(
                    remote, user=current_user, group=current_user
                )
                node.shell.copy_back(remote, local)
                log.info(f"Copied {remote} -> {local}")
            except Exception as e:
                log.debug(f"Failed to copy back {remote}: {e}")

    def _get_disk_img_copy_path(self, node: Node, log: Logger) -> PurePath:
        # The guest disk image is copied once per concurrent VM, so we need
        # a directory backed by a large disk. Prefer an existing resource
        # disk mount; otherwise try to mount an unused nvme*n1 disk at
        # /mnt/resource.
        mount_point = "/mnt/resource"
        fallback_mount = "/mnt"

        disks = node.tools[Lsblk].get_disks(force_run=True)

        if self._is_mountpoint_in_use(disks, mount_point):
            return PurePath(mount_point)
        if self._is_mountpoint_in_use(disks, fallback_mount):
            return PurePath(fallback_mount)

        candidate = self._find_unused_nvme_disk(disks)
        if candidate is None:
            log.info(
                "No mounted resource disk and no unused nvme*n1 disk found; "
                "falling back to working path. The test may run out of disk "
                "space."
            )
            return node.working_path

        try:
            node.execute(f"mkdir -p {mount_point}", shell=True, sudo=True)
            node.tools[Mount].mount(
                name=candidate,
                point=mount_point,
                fs_type=FileSystem.ext4,
                format_=True,
            )
        except Exception as e:
            log.info(
                f"Failed to mount {candidate} at {mount_point}: {e}; "
                "falling back to working path."
            )
            return node.working_path

        log.info(f"Mounted {candidate} at {mount_point} for VM disk copies")
        return PurePath(mount_point)

    @staticmethod
    def _is_mountpoint_in_use(disks: List[DiskInfo], mountpoint: str) -> bool:
        for disk in disks:
            if disk.mountpoint == mountpoint:
                return True
            for partition in disk.partitions:
                if partition.mountpoint == mountpoint:
                    return True
        return False

    def _find_unused_nvme_disk(self, disks: List[DiskInfo]) -> Optional[str]:
        nvme_pattern = re.compile(r"^nvme\d+n1$")
        for disk in disks:
            if disk.is_os_disk:
                continue
            if not nvme_pattern.match(disk.name):
                continue
            if disk.partitions:
                continue
            if disk.is_mounted:
                continue
            return f"/dev/{disk.name}"
        return None
