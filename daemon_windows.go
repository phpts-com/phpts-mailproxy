//go:build windows

package main

import (
	"os"
	"os/exec"
	"syscall"
)

const (
	// DETACHED_PROCESS：子进程不继承父进程控制台（关掉 PowerShell / 会话不影响服务）
	daemonDetachedProcess = 0x00000008
	// CREATE_NEW_PROCESS_GROUP：独立进程组，父进程收到的 CTRL_C_EVENT 不会广播到子进程
	daemonNewProcessGroup = 0x00000200
)

// runAsDaemon 在 Windows 上以分离进程重新拉起自身（无控制台窗口、独立进程组），
// 父进程打印 PID 后立即退出。返回后台实例的 PID。
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
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: daemonDetachedProcess | daemonNewProcessGroup}
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	pid := cmd.Process.Pid
	// Release：不等子进程，父进程退出后由系统回收句柄
	_ = cmd.Process.Release()
	return pid, nil
}
