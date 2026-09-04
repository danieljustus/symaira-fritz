//go:build !windows

package portcontract

import (
	"os/exec"
	"syscall"
)

func configureProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func killProcessGroup(cmd *exec.Cmd) error {
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}
