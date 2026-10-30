//go:build !windows

package main

import (
	"os"
	"os/exec"
	"syscall"
)

// runAsDaemon 在类 Unix（Linux / macOS）上以 setsid 重新拉起自身：
// 子进程成为新会话首进程、脱离控制终端，父进程退出后仍常驻，SSH 断开不受影响。
// 返回后台实例的 PID。
func runAsDaemon() (int, error) {
	exe, err := os.Executable()
	if err != nil {
		return 0, err
	}
	dev, err := nullDevice()
	if err != nil {
		return 0, err
	}
	defer dev.Close()

	cmd := exec.Command(exe, daemonArgs(os.Args)...)
	cmd.Env = daemonEnvList()
	cmd.Stdin, cmd.Stdout, cmd.Stderr = dev, dev, dev
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	pid := cmd.Process.Pid
	// Release：不等子进程，交还由 init 收养（失败只影响本进程的进程表项，后台实例已在跑）
	_ = cmd.Process.Release()
	return pid, nil
}
