//go:build windows

package portcontract

import (
	"fmt"
	"os/exec"
	"strconv"
	"syscall"
)

const createNewProcessGroup = 0x00000200

func configureProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNewProcessGroup}
}

func killProcessGroup(cmd *exec.Cmd) error {
	killer := exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(cmd.Process.Pid))
	if output, err := killer.CombinedOutput(); err != nil {
		return fmt.Errorf("taskkill: %w: %s", err, output)
	}
	return nil
}
