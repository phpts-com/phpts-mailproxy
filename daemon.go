// 后台守护运行（-d）的平台无关辅助。
//
// 实现口径（借鉴 ddns-go）：Go 没有 fork，所以「daemon 化」= 用当前参数（去掉 -d）
// 重新拉起一个自己，子进程脱离父进程的控制终端/控制台，父进程打印 PID 后立即退出，
// 命令行马上归还 shell。子进程带 PHPTS_MAILPROXY_DAEMON=1 环境变量，据此判定
// 「已是后台实例」，绝不会再二次 daemon。
//
// 后台实例的 stdin/stdout/stderr 一律重定向到系统空设备：要看日志必须用 -log 指定文件
// （由子进程自己打开写）。用 systemd 常驻的场景**不要**加 -d——systemd 会把提前退出的父
// 进程当成主进程已死，进而反复重启。
package main

import (
	"os"
	"strings"
)

// daemonEnv 标记「当前进程是由 -d 派生的后台实例」。
const daemonEnv = "PHPTS_MAILPROXY_DAEMON"

// isDaemonized 报告本进程是否为 -d 派生的后台实例。
func isDaemonized() bool { return os.Getenv(daemonEnv) == "1" }

// daemonArgs 生成后台子进程的参数：丢掉 -d 的等价写法，其余原样保留（顺序不变）。
func daemonArgs(argv []string) []string {
	out := make([]string, 0, len(argv))
	for _, a := range argv[1:] {
		switch a {
		case "-d", "--d", "-d=true", "--d=true":
			continue
		}
		out = append(out, a)
	}
	return out
}

// daemonEnvList 生成子进程的环境变量：先剔除同名旧值再打上后台标记，
// 避免环境块里出现两份 PHPTS_MAILPROXY_DAEMON（Windows 按先出现的取值，会误判）。
func daemonEnvList() []string {
	env := os.Environ()
	out := make([]string, 0, len(env)+1)
	for _, kv := range env {
		if strings.HasPrefix(kv, daemonEnv+"=") {
			continue
		}
		out = append(out, kv)
	}
	return append(out, daemonEnv+"=1")
}

// nullDevice 打开系统空设备（Linux /dev/null、Windows NUL）供后台进程三路标准流使用。
func nullDevice() (*os.File, error) {
	return os.OpenFile(os.DevNull, os.O_RDWR, 0)
}
