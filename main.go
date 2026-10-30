// phpts-mailproxy —— PHPTS 电子邮局公网代理服务器（Go）。
// 零配置文件：全部运行参数经命令行指定。部署到公网 VPS 后，把 PHPTS 电子邮局各端口
// 映射到本机公网，并为内网 PHPTS 提供出站投递通道（token 认证 + AES-256-GCM 加密隧道）。
//
// 示例：
//   phpts-mailproxy-linux-x64 -token <token>              （控制端口默认 3325）
//   phpts-mailproxy-win64.exe -token <token>
//   phpts-mailproxy-linux-x64 -listen [::] -port 3325 -token <token>
//   phpts-mailproxy-win64.exe -listen [::] -port 3325 -token <token>
//   phpts-mailproxy-linux-x64 -d -token <token> -log /var/log/mailproxy.log   （后台守护方式运行）
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
)

func main() {
	listen := flag.String("listen", "[::]", "监听 IP（支持 IPv6）：0.0.0.0 / [::] / 具体 IPv4 或 IPv6 地址")
	port := flag.Int("port", 3325, "控制端口（PHPTS 侧隧道拨号此端口，默认 3325）")
	token := flag.String("token", "", "共享 token（必填，与 PHPTS「公网代理」设置一致）")
	smtp := flag.Int("smtp", 25, "SMTP 入站映射端口（0=不映射）")
	submit := flag.Int("submit", 2525, "客户端提交发信映射端口（0=不映射）")
	submission := flag.Int("submission", 587, "STARTTLS 提交映射端口（0=不映射）")
	smtps := flag.Int("smtps", 465, "隐式 TLS 提交映射端口（0=不映射）")
	imap := flag.Int("imap", 143, "IMAP 映射端口（0=不映射）")
	imaps := flag.Int("imaps", 993, "IMAPS 映射端口（0=不映射）")
	pop3 := flag.Int("pop3", 110, "POP3 映射端口（0=不映射）")
	pop3s := flag.Int("pop3s", 995, "POP3S 映射端口（0=不映射）")
	publicIP := flag.String("public-ip", "", "握手上报的公网 IP（空=启动时自动探测）")
	outPorts := flag.String("out-ports", "25", "允许出站的目标端口白名单（逗号分隔）")
	withPeer := flag.String("with-peer", "auto", "入站是否把真实来源地址透传给 PHPTS（Received 头记真 IP）：auto=自动探测（对端邮局过旧则退回旧格式）、on=始终带、off=不带")
	logFile := flag.String("log", "", "日志文件路径（空=仅输出到控制台；-d 后台运行时必须指定才留得住日志）")
	daemon := flag.Bool("d", false, "以后台 daemon 方式运行：分离进程常驻，父进程打印 PID 后立即退出（用 systemd 常驻时不要加）")
	flag.Parse()

	// -d：重新拉起一个脱离控制台的自己，父进程退出、命令行归还 shell。
	// 已在后台实例里（环境变量标记）则跳过，避免递归 daemon。
	if *daemon && !isDaemonized() {
		if *token == "" {
			fmt.Fprintln(os.Stderr, "错误：-token 为必填参数（与 PHPTS 侧「公网代理」设置相同的 token）")
			os.Exit(1)
		}
		pid, err := runAsDaemon()
		if err != nil {
			fmt.Fprintf(os.Stderr, "后台启动失败: %v\n", err)
			os.Exit(1)
		}
		if *logFile == "" {
			fmt.Printf("phpts-mailproxy 已转入后台运行（PID %d）；未指定 -log，日志将被丢弃\n", pid)
		} else {
			fmt.Printf("phpts-mailproxy 已转入后台运行（PID %d），日志：%s\n", pid, *logFile)
		}
		return
	}

	if *logFile != "" {
		f, err := os.OpenFile(*logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "打开日志文件失败: %v\n", err)
			os.Exit(1)
		}
		log.SetOutput(io.MultiWriter(os.Stdout, f))
	}
	if *token == "" {
		fmt.Fprintln(os.Stderr, "错误：-token 为必填参数（与 PHPTS 侧「公网代理」设置相同的 token）")
		os.Exit(1)
	}
	if len(*token) < 16 {
		log.Printf("警告：token 长度不足 16，建议使用更长的随机 token")
	}
	switch *withPeer {
	case "auto", "on", "off":
	default:
		fmt.Fprintf(os.Stderr, "错误：-with-peer 只能是 auto / on / off（当前 %q）\n", *withPeer)
		os.Exit(1)
	}

	ports := map[string]int{
		"smtp":       *smtp,
		"submit":     *submit,
		"submission": *submission,
		"smtps":      *smtps,
		"imap":       *imap,
		"imaps":      *imaps,
		"pop3":       *pop3,
		"pop3s":      *pop3s,
	}
	used := map[int]string{*port: "控制端口"}
	for name, p := range ports {
		if p <= 0 {
			continue
		}
		if p > 65535 {
			fmt.Fprintf(os.Stderr, "错误：%s 端口 %d 超出范围\n", name, p)
			os.Exit(1)
		}
		if prev, dup := used[p]; dup {
			fmt.Fprintf(os.Stderr, "错误：端口 %d 与%s冲突（%s）\n", p, prev, name)
			os.Exit(1)
		}
		used[p] = name
	}

	out := map[int]bool{}
	for _, s := range strings.Split(*outPorts, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		v, err := strconv.Atoi(s)
		if err != nil || v <= 0 || v > 65535 {
			fmt.Fprintf(os.Stderr, "错误：-out-ports 含非法端口 %q\n", s)
			os.Exit(1)
		}
		out[v] = true
	}

	srv := &Server{
		listenIP:    *listen,
		controlPort: *port,
		token:       *token,
		publicIP:    strings.TrimSpace(*publicIP),
		ports:       ports,
		outPorts:    out,
		withPeer:    *withPeer,
	}
	if err := srv.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "启动失败: %v\n", err)
		os.Exit(1)
	}
	log.Printf("phpts-mailproxy 就绪：PID %d，控制端口 %d，映射端口 %d 个，出站放行端口 %v", os.Getpid(), *port, countMapped(ports), keysOf(out))

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	log.Println("收到退出信号，停止服务")
}

func countMapped(m map[string]int) int {
	n := 0
	for _, p := range m {
		if p > 0 {
			n++
		}
	}
	return n
}

func keysOf(m map[int]bool) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
