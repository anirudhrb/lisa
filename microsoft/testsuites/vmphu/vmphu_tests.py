# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path, PurePath, PurePosixPath
from time import sleep
from typing import Any, Dict, List, Optional, Type

from assertpy import assert_that, fail
from dataclasses_json import dataclass_json
from func_timeout import FunctionTimedOut, func_set_timeout  # type: ignore

from lisa import Environment, notifier, schema
from lisa.base_tools import Cat, Sed, Service, Wget
from lisa.executable import Tool
from lisa.features import SerialConsole
from lisa.messages import SubTestMessage, TestStatus, create_test_result_message
from lisa.node import Node, quick_connect
from lisa.operating_system import CBLMariner
from lisa.testsuite import TestCaseMetadata, TestResult, TestSuite, TestSuiteMetadata
from lisa.tools import Chown, Git, Ls, QemuImg, Rm, SystemdAnalyze, Tee, Who, Whoami
from lisa.transformer import Transformer
from lisa.util import field_metadata
from lisa.util.logger import Logger
from lisa.util.perf_timer import create_timer


@func_set_timeout(30)  # type: ignore
def _who_last(who: Who) -> datetime:
    return who.last_boot()


@dataclass_json()
@dataclass
class VmOrcInstallerTansformerSchema(schema.Transformer):
    connection: Optional[schema.RemoteNode] = field(
        default=None, metadata=field_metadata(required=True)
    )
    ado_auth_token: str = field(default="")


class VmOrcInstallerTransformer(Transformer):
    repo = "https://microsoft.visualstudio.com/LSG/_git/vm-orc"

    @classmethod
    def type_name(cls) -> str:
        return "vm_orc_installer"

    @classmethod
    def type_schema(cls) -> Type[schema.TypedSchema]:
        return VmOrcInstallerTansformerSchema

    @property
    def _output_names(self) -> List[str]:
        return []

    def _internal_run(self) -> Dict[str, Any]:
        runbook: VmOrcInstallerTansformerSchema = self.runbook

        node = quick_connect(runbook.connection, "vm-orc-installer-node")

        if node.tools[Service].is_service_running("vm-orc"):
            return {}

        tool_path = node.working_path / "vm-orc-installer"

        git = node.tools[Git]
        git.clone(
            self.repo,
            tool_path,
            fail_on_exists=False,
            auth_token=runbook.ado_auth_token,
        )

        repo_root = tool_path / "vm-orc"
        cmd_path = repo_root / "install.sh"

        node.execute(f"sh {cmd_path}", cwd=repo_root, sudo=True)

        return {}


class ChRemote(Tool):
    @property
    def command(self) -> str:
        return "ch-remote"

    @property
    def can_install(self) -> bool:
        return False

    def info(self, api_socket: str) -> Dict[str, Any]:
        output = self.run(
            f"--api-socket {api_socket} info", force_run=True, shell=True, sudo=True
        ).stdout

        self._log.info(output)

        response: Dict[str, Any] = json.loads(output)

        return response


@TestSuiteMetadata(
    area="vmphu",
    category="functional",
    description="",
)
class VmphuTests(TestSuite):
    VM_ORC_BASE_PATH = PurePosixPath("/etc/vm-orc")
    VM_ORC_PIPE_PATH = VM_ORC_BASE_PATH / "vm-orc.pipe"
    VMPHU_STATS_FILE = VM_ORC_BASE_PATH / "vmphu_stats.json"
    NUM_GUESTS_VARIABLE = "vmphu_test_num_guests"

    @TestCaseMetadata(
        description="""
            This test case starts guest VMs, performs a VMPHU (VM preserving host
            update), tests whether the VMs are restored correctly and records the
            time taken by the various stages of VMPHU.
        """,
        priority=3,
    )
    def verify_vmphu(
        self,
        log: Logger,
        node: Node,
        environment: Environment,
        result: TestResult,
        log_path: PurePath,
        variables: Dict[str, Any],
    ) -> None:
        vmphu_wait_timeout = 60
        num_vms = 4

        if self.NUM_GUESTS_VARIABLE in variables:
            num_vms = int(variables[self.NUM_GUESTS_VARIABLE])

        log.info(f"VMPHU test with {num_vms} guests")

        who = node.tools[Who]

        if not node.provision_time:
            node.provision_time = 1

        self._setup_node(node)

        for i in range(num_vms):
            vm_name = f"vm{i}"
            log.info(f"Starting VM {vm_name}...")
            self._create_guest(node, vm_name, 2, 2)

        self._verify_guests_alive(node, log, num_vms)

        self._vm_orc_cmd(node, "vmphu")

        host_alive = False
        timer = create_timer()
        while not host_alive and timer.elapsed(False) < vmphu_wait_timeout:
            try:
                node.close()
                sleep(5)
                _who_last(who)
                host_alive = True
            except FunctionTimedOut:
                log.info("Timed out while connecting to node. Retry.")
            except Exception as e:
                log.info(f"Unable to connect to node {e}. Will try again...")

        assert_that(host_alive).is_true()

        timer = create_timer()
        stats_file_exists = False
        while not stats_file_exists and timer.elapsed(False) < 30:
            stats_file_exists = node.tools[Ls].path_exists(
                str(self.VMPHU_STATS_FILE), sudo=True
            )
            if not stats_file_exists:
                sleep(1)

        assert_that(stats_file_exists).is_true()

        self._verify_guests_alive(node, log, num_vms)

        stats = json.loads(
            node.tools[Cat].read(str(self.VMPHU_STATS_FILE), force_run=True, sudo=True)
        )

        boot_time = node.tools[SystemdAnalyze].get_boot_time()
        kernel_boot_time = boot_time.kernel_boot_time
        lines = node.execute(
            "cat /proc/uptime && date +%s%3N", shell=True
        ).stdout.splitlines()
        uptime = float(lines[0].split(" ")[0])
        cur_time = float(lines[1]) / 1000.00

        kexec_start: float = stats["kexec"]["start"]
        kexec_shutdown_time = cur_time - kexec_start - uptime
        kexec_kernel_boot_time = kernel_boot_time / 1000.00
        kexec_service_alive_time = (
            stats["kexec"]["total"] - kexec_shutdown_time - kexec_kernel_boot_time
        )

        stats["kexec"]["shutdown"] = kexec_shutdown_time
        stats["kexec"]["kernel"] = kexec_kernel_boot_time
        stats["kexec"]["service_alive"] = kexec_service_alive_time

        final_stats: Dict[str, Any] = {
            "pause_snapshot_kill": stats["snap"],
            "pre_kexec_umount": stats["pre_kexec_umount"],
            "kexec": {
                "shutdown": kexec_shutdown_time,
                "kernel_boot": kexec_kernel_boot_time,
                "service_alive": kexec_service_alive_time,
            },
            "post_kexec_mount": stats["post_kexec_mount"],
            "restore_and_resume": stats["restore"],
            "total": stats["total"],
        }

        final_stats_json = json.dumps(final_stats)
        self._send_subtest_msg(
            result, environment, "vmphu_stats", TestStatus.PASSED, final_stats_json
        )

        log.info(f"{final_stats}")

    def after_case(self, log: Logger, **kwargs: Any) -> None:
        node: Node = kwargs["node"]
        log_path: Path = kwargs["log_path"]
        result: TestResult = kwargs["result"]

        if node.features.is_supported(SerialConsole):
            serial_console = node.features[SerialConsole]
            serial_console.get_console_log(log_path, force_run=True)

        vm_orc_log_save_path = log_path / "vm-orc.log"
        node.shell.copy_back(
            PurePosixPath("/etc/vm-orc/vm-orc.log"), vm_orc_log_save_path
        )

        if result.status != TestStatus.PASSED:
            return

        systemd_plot_remote_path = node.working_path / "systemd_analyze_plot.svg"
        node.tools[SystemdAnalyze].plot(systemd_plot_remote_path)
        systemd_plot_path = log_path / "systemd_analyze_plot.svg"
        node.shell.copy_back(systemd_plot_remote_path, systemd_plot_path)

    def _create_guest(self, node: Node, name: str, cpus: int, memory_gib: int) -> None:
        self._vm_orc_cmd(node, f"create_vm {name} {cpus} {memory_gib} kernel_boot")

    def _vm_orc_cmd(self, node: Node, cmd: str) -> None:
        node.tools[Tee].write_to_file(cmd, self.VM_ORC_PIPE_PATH, sudo=True)

    def _ready_vm_mem(self, node: Node) -> None:
        self._vm_orc_cmd(node, "ready_vm_mem")

    def _get_vm_dir(self, vm_name: str) -> PurePosixPath:
        return self.VM_ORC_BASE_PATH / f"vm-{vm_name}"

    def _get_ch_sock_path(self, vm_name: str) -> PurePosixPath:
        return self._get_vm_dir(vm_name) / "ch.sock"

    def _verify_guests_alive(
        self,
        node: Node,
        log: Logger,
        num_vms: int,
        guest_alive_timeout: int = 600,
        ch_sock_wait_timeout: int = 300,
    ) -> None:
        for i in range(num_vms):
            vm_name = f"vm{i}"
            ch_sock_path = str(self._get_ch_sock_path(vm_name))

            timer = create_timer()
            ch_sock_exists = node.tools[Ls].path_exists(ch_sock_path, sudo=True)
            while not ch_sock_exists and timer.elapsed(False) < ch_sock_wait_timeout:
                sleep(5)
                ch_sock_exists = node.tools[Ls].path_exists(ch_sock_path, sudo=True)

            timer = create_timer()
            vm_info = node.tools[ChRemote].info(ch_sock_path)
            while vm_info["state"] != "Running" and timer.elapsed(False) < 300:
                sleep(5)
                vm_info = node.tools[ChRemote].info(ch_sock_path)

            assert_that(vm_info["state"]).is_equal_to("Running")

            ip_addr = vm_info["config"]["net"][0]["ip"]
            ip_addr_parts = ip_addr.split(".")
            ip_addr_parts[3] = "55"
            ip_addr = ".".join(ip_addr_parts)

            guest_alive = False
            timer = create_timer()
            while not guest_alive and timer.elapsed(False) < guest_alive_timeout:
                try:
                    node.execute(f"ping -c 1 {ip_addr}", expected_exit_code=0)
                    guest_alive = True
                except Exception as e:
                    log.info(f"Unable to ping guest, will retry. Exception: {e}")
                    sleep(5)

            assert_that(guest_alive).is_true()
            log.info(f"Guest {vm_name} is alive")

    def _setup_node(self, node: Node) -> None:
        reboot_needed = False
        if isinstance(node.os, CBLMariner):
            node.os.install_packages(
                [
                    "qemu-img",
                    "kexec-tools",
                    "dosfstools",
                    "mtools",
                ],
                signed=False,
            )
        else:
            fail(f"Unsupported OS {node.os}")

        user = node.tools[Whoami].get_username()
        node.tools[Chown].change_owner(self.VM_ORC_BASE_PATH, user)

        hypervisor_fw_name = "hypervisor-fw"
        if not node.tools[Ls].path_exists(
            str(self.VM_ORC_BASE_PATH / hypervisor_fw_name), sudo=True
        ):
            node.tools[Wget].get(
                "https://github.com/cloud-hypervisor/rust-hypervisor-firmware/releases/download/0.4.2/hypervisor-fw",  # noqa: E501
                file_path=str(self.VM_ORC_BASE_PATH),
                filename="hypervisor-fw",
                sudo=True,
            )

        focal_image_name = "focal-server-cloudimg-amd64.img"
        focal_image_name_raw = "focal-server-cloudimg-amd64.raw"
        if not node.tools[Ls].path_exists(
            str(self.VM_ORC_BASE_PATH / focal_image_name)
        ):
            node.tools[Wget].get(
                "https://cloud-images.ubuntu.com/focal/current/focal-server-cloudimg-amd64.img",  # noqa: E501
                file_path=str(self.VM_ORC_BASE_PATH),
                filename=focal_image_name,
                sudo=True,
            )

            node.tools[QemuImg].convert(
                "qcow2",
                str(self.VM_ORC_BASE_PATH / focal_image_name),
                "raw",
                str(self.VM_ORC_BASE_PATH / focal_image_name_raw),
                sudo=True,
            )

        vmlinux_name = "vmlinux.bin"
        if not node.tools[Ls].path_exists(str(self.VM_ORC_BASE_PATH / vmlinux_name)):
            node.tools[Wget].get(
                "https://anrayabhstorage.blob.core.windows.net/chkernel/vmlinux.bin",
                file_path=str(self.VM_ORC_BASE_PATH),
                filename=vmlinux_name,
                sudo=True,
            )

        boot_cfg = "/boot/mariner-mshv.cfg"
        old_cmdline = node.tools[Cat].read_with_filter(
            boot_cfg, "mariner_cmdline_mshv=", force_run=True, sudo=True
        )
        old_cmdline = old_cmdline[old_cmdline.find("=") + 1 :]

        if "memmap" not in old_cmdline:
            new_cmdline = old_cmdline + " memmap=40G!6G memmap=32G!68G"
            node.tools[Sed].substitute(
                "mariner_cmdline_mshv=.*",
                f"mariner_cmdline_mshv={new_cmdline}".replace("/", "\\/"),
                boot_cfg,
                sudo=True,
            )
            reboot_needed = True

        old_initrd = node.tools[Cat].read_with_filter(
            boot_cfg, "mariner_initrd_mshv", force_run=True, sudo=True
        )
        old_initrd = old_initrd[old_initrd.find("=") + 1 :]

        if old_initrd != "none":
            node.tools[Sed].substitute(
                "mariner_initrd_mshv=.*",
                "mariner_initrd_mshv=none",
                boot_cfg,
                sudo=True,
            )
            reboot_needed = True

        if reboot_needed:
            node.reboot()

        self._ready_vm_mem(node)

        node.tools[Rm].remove_directory("/etc/vm-orc/vm-vm*", sudo=True)
        node.tools[Rm].remove_directory("/etc/vm-orc/vm_mem/*.mem", sudo=True)

    def _send_subtest_msg(
        self,
        test_result: TestResult,
        environment: Environment,
        test_name: str,
        test_status: TestStatus,
        test_message: str,
    ) -> None:
        subtest_msg = create_test_result_message(
            SubTestMessage,
            test_result,
            environment,
            test_name,
            test_status,
            test_message=test_message,
        )

        notifier.notify(subtest_msg)
