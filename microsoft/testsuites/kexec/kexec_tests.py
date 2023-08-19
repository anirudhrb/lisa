from time import sleep
from typing import Any, Dict, Optional

from assertpy import assert_that
from func_timeout import FunctionTimedOut, func_set_timeout  # type: ignore

from lisa.base_tools.uname import Uname
from lisa.messages import ProvisionBootTimeMessage
from lisa.node import Node
from lisa.testsuite import TestCaseMetadata, TestSuite, TestSuiteMetadata
from lisa.tools.kdump import Kexec
from lisa.tools.systemd_analyze import SystemdAnalyze
from lisa.util.logger import Logger
from lisa.util.perf_timer import create_timer


@func_set_timeout(30)
def _boot_time(systemd_analyze: SystemdAnalyze) -> ProvisionBootTimeMessage:
    return systemd_analyze.get_boot_time()


@TestSuiteMetadata(
    area="kexec",
    category="functional",
    description="""
    This test suite verifies kexec functionality.
    """,
)
class KexecTests(TestSuite):
    @TestCaseMetadata(
        description="Verifies whether kexec is functional.",
        priority=3,
    )
    def verify_kexec(self, log: Logger, node: Node, variables: Dict[str, Any]) -> None:
        time_out = 60
        iters = 15
        times = []
        node.provision_time = 1

        times = self._do_kexec(node, log, iters, time_out)

        log.info(f"Kernel kexec times: {times}")

    def _do_kexec(
        self, node: Node, log: Logger, num_times: int, time_out: int
    ) -> [ProvisionBootTimeMessage]:
        boot_times: [ProvisionBootTimeMessage] = []
        kexec = node.tools[Kexec]
        version = node.tools[Uname].get_linux_information().kernel_version_raw

        while num_times > 0:
            num_times -= 1
            boot_time: Optional[ProvisionBootTimeMessage] = None
            timestamp_file = "/home/anirudh/kts"
            shutdown_timer = create_timer()
            kexec.do_kexec(
                version,
                use_initrd=False,
                append_cmdline="foo=bar",
                timestamp_file="/home/anirudh/kts",
            )
            log.info(f"shutdown_timer {shutdown_timer.elapsed(False)}")
            timer = create_timer()
            log.info(f"timer created {timer.elapsed(False)}")

            # Sleep for a while before checking if the node is up after kexec.
            # This gives some time for the kexec reboot to finish. There is no
            # point checking immediately because kexec won't be finished anyway.
            sleep(2)
            while timer.elapsed(False) < time_out:
                try:
                    node.close()
                    boot_time = _boot_time(node.tools[SystemdAnalyze])
                    break
                except FunctionTimedOut as identifier:
                    log.info("retry...")
                except Exception as identifier:
                    log.info("ignorable ssh exception...")

            assert_that(boot_time).is_not_none()

            result = node.execute(
                f"cat {timestamp_file} && cat /proc/uptime && date +%s%3N", shell=True
            )
            lines = result.stdout.splitlines()
            log.info(f"{lines}")
            kexec_trigger_time = float(lines[0])
            uptime = float(lines[1].split(" ")[0]) * 1000.00
            cur_time = float(lines[2])
            kexec_shutdown_time = cur_time - kexec_trigger_time - uptime

            kexec_kernel_time = boot_time.kernel_boot_time
            log.info(
                f"Kexec (kernel) took {kexec_kernel_time} ms. Shutdown took {kexec_shutdown_time} ms"
            )
            boot_times.append(boot_time)
