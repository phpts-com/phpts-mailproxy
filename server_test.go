package main

import (
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------- 测试基础设施 ----------

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return p
}

// startEcho 起一个逐字节回显服务，返回端口。
func startEcho(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						if _, werr := c.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// tclient 极简测试客户端：握手后按帧处理 OPEN_IN / DATA / OPEN 应答（与 Rust proxy.rs 同协议）。
type tclient struct {
	sc       *secureConn
	onOpenIn func(name string) (net.Conn, error)

	mu    sync.Mutex
	data  map[uint32]chan frame
	opens map[uint32]chan frame
}

func newTClient(t *testing.T, token string, onOpenIn func(string) (net.Conn, error)) (*tclient, string) {
	t.Helper()
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(tclientCtlPort)))
	if err != nil {
		t.Fatalf("拨控制端口失败: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	sc, pi, err := clientHandshake(conn, token)
	if err != nil {
		t.Fatalf("客户端握手失败: %v", err)
	}
	c := &tclient{sc: sc, onOpenIn: onOpenIn, data: map[uint32]chan frame{}, opens: map[uint32]chan frame{}}
	go c.run()
	return c, pi
}

var tclientCtlPort int // 由各测试在 newTClient 前设置（测试串行执行）

func (c *tclient) run() {
	for {
		rec, err := c.sc.readRecord()
		if err != nil {
			return
		}
		f, err := decodeFrame(rec)
		if err != nil {
			return
		}
		switch f.typ {
		case framePing:
			_ = c.send(frame{typ: framePong})
		case frameOpenIn:
			go c.handleOpenIn(f)
		case frameData:
			c.mu.Lock()
			ch := c.data[f.streamID]
			c.mu.Unlock()
			if ch != nil {
				ch <- f
			}
		case frameOpenOK, frameOpenFail:
			c.mu.Lock()
			ch := c.opens[f.streamID]
			c.mu.Unlock()
			if ch != nil {
				ch <- f
			}
		}
	}
}

func (c *tclient) handleOpenIn(f frame) {
	conn, err := c.onOpenIn(string(f.payload))
	if err != nil {
		_ = c.send(frame{typ: frameOpenFail, streamID: f.streamID, payload: []byte(err.Error())})
		return
	}
	defer conn.Close()
	if err := c.send(frame{typ: frameOpenOK, streamID: f.streamID}); err != nil {
		return
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				p := append([]byte{}, buf[:n]...)
				if c.send(frame{typ: frameData, streamID: f.streamID, payload: p}) != nil {
					return
				}
			}
			if err != nil {
				_ = c.send(frame{typ: frameClose, streamID: f.streamID})
				return
			}
		}
	}()
	c.mu.Lock()
	ch := make(chan frame, 64)
	c.data[f.streamID] = ch
	c.mu.Unlock()
	for {
		select {
		case df := <-ch:
			if _, err := conn.Write(df.payload); err != nil {
				return
			}
		case <-done:
			return
		}
	}
}

func (c *tclient) send(f frame) error {
	return c.sc.writeRecord(encodeFrame(f))
}

// ---------- 端到端 ----------

// 入站：外部 → 代理映射端口 → 隧道 → 本地回显（模拟电子邮局端口）。
func TestE2EInbound(t *testing.T) {
	echoPort := startEcho(t)
	ctlPort := freePort(t)
	mapPort := freePort(t)
	tclientCtlPort = ctlPort

	srv := &Server{
		listenIP:    "127.0.0.1",
		controlPort: ctlPort,
		token:       "e2e-token-0123456789",
		publicIP:    "203.0.113.9",
		ports:       map[string]int{"smtp": mapPort},
		outPorts:    map[int]bool{25: true},
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}

	var seen []string
	c, pi := newTClient(t, "e2e-token-0123456789", func(name string) (net.Conn, error) {
		seen = append(seen, name)
		base, _, _ := strings.Cut(name, "|")
		if base != "smtp" {
			t.Errorf("逻辑名不符: %s", name)
		}
		return net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(echoPort)))
	})
	_ = c
	if pi != "203.0.113.9" {
		t.Fatalf("握手上报公网 IP 不符: %q", pi)
	}
	time.Sleep(200 * time.Millisecond) // 等映射端口 accept 循环就绪

	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(mapPort)))
	if err != nil {
		t.Fatalf("连映射端口失败: %v", err)
	}
	defer conn.Close()
	msg := []byte("hello-mail-proxy")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, len(msg))
	if _, err := readFull(conn, buf); err != nil {
		t.Fatalf("读回显失败: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("回显内容不符: %q", buf)
	}
	// 载荷必须带上来源地址（`smtp|源地址|映射地址`），PHPTS 侧靠它还原 Received 头的来访 IP
	if len(seen) != 1 || !strings.HasPrefix(seen[0], "smtp|") || strings.Count(seen[0], "|") != 2 {
		t.Fatalf("OPEN_IN 载荷格式不符（应带两段地址）: %#v", seen)
	}
}

// 入站来源地址透传的兼容路径：对端是旧版 PHPTS（不认识带地址的逻辑名，回「未知逻辑名」）时，
// auto 模式必须自动退回只带逻辑名的旧载荷重发一次，且此后本隧道不再带地址 —— 保证先升级哪一端都不中断收信。
func TestE2EInboundLegacyPeerFallback(t *testing.T) {
	echoPort := startEcho(t)
	ctlPort := freePort(t)
	mapPort := freePort(t)
	tclientCtlPort = ctlPort

	srv := &Server{
		listenIP:    "127.0.0.1",
		controlPort: ctlPort,
		token:       "e2e-token-0123456789",
		publicIP:    "203.0.113.9",
		ports:       map[string]int{"smtp": mapPort},
		outPorts:    map[int]bool{25: true},
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var seen []string
	c, _ := newTClient(t, "e2e-token-0123456789", func(name string) (net.Conn, error) {
		mu.Lock()
		seen = append(seen, name)
		n := len(seen)
		mu.Unlock()
		if n == 1 && strings.Contains(name, "|") {
			// 模拟旧版 PHPTS：带 `|` 的逻辑名认不出来
			return nil, errors.New("未知逻辑名 " + name)
		}
		return net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(echoPort)))
	})
	_ = c
	time.Sleep(250 * time.Millisecond)

	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(mapPort)))
	if err != nil {
		t.Fatalf("连映射端口失败: %v", err)
	}
	defer conn.Close()
	msg := []byte("fallback-ok")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, len(msg))
	if _, err := readFull(conn, buf); err != nil {
		t.Fatalf("退回旧格式后回显失败: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("回显内容不符: %q", buf)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seen) < 2 {
		t.Fatalf("未观察到退回旧格式的重发，看到的载荷: %#v", seen)
	}
	if !strings.Contains(seen[0], "|") {
		t.Fatalf("首帧应带来源地址: %#v", seen)
	}
	for _, s := range seen[1:] {
		if s != "smtp" {
			t.Fatalf("本隧道回退后仍带了来源地址: %#v", seen)
		}
	}
}

// 出站：客户端 OPEN_OUT → 代理拨号白名单端口 → 数据双向。
func TestE2EOutbound(t *testing.T) {
	echoPort := startEcho(t)
	ctlPort := freePort(t)
	tclientCtlPort = ctlPort

	srv := &Server{
		listenIP:    "127.0.0.1",
		controlPort: ctlPort,
		token:       "e2e-token-0123456789",
		publicIP:    "",
		ports:       map[string]int{},
		outPorts:    map[int]bool{echoPort: true},
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	c, _ := newTClient(t, "e2e-token-0123456789", nil)

	const sid = 2
	okCh := make(chan frame, 1)
	dataCh := make(chan frame, 8)
	c.mu.Lock()
	c.opens[sid] = okCh
	c.data[sid] = dataCh
	c.mu.Unlock()

	if err := c.send(frame{typ: frameOpenOut, streamID: sid, payload: encodeOpenOut("127.0.0.1", uint16(echoPort))}); err != nil {
		t.Fatal(err)
	}
	select {
	case f := <-okCh:
		if f.typ != frameOpenOK {
			t.Fatalf("OPEN_OUT 被拒: %s", f.payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("等待 OPEN_OK 超时")
	}

	body := []byte("outbound-body")
	if err := c.send(frame{typ: frameData, streamID: sid, payload: body}); err != nil {
		t.Fatal(err)
	}
	select {
	case f := <-dataCh:
		if string(f.payload) != string(body) {
			t.Fatalf("出站回显不符: %q", f.payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("等待出站数据超时")
	}
}

// 出站端口不在白名单必须 OPEN_FAIL。
func TestE2EOutboundPortDenied(t *testing.T) {
	echoPort := startEcho(t)
	ctlPort := freePort(t)
	tclientCtlPort = ctlPort

	srv := &Server{
		listenIP:    "127.0.0.1",
		controlPort: ctlPort,
		token:       "e2e-token-0123456789",
		ports:       map[string]int{},
		outPorts:    map[int]bool{25: true}, // 白名单只有 25，echo 端口必拒
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	c, _ := newTClient(t, "e2e-token-0123456789", nil)

	const sid = 2
	okCh := make(chan frame, 1)
	c.mu.Lock()
	c.opens[sid] = okCh
	c.mu.Unlock()
	if err := c.send(frame{typ: frameOpenOut, streamID: sid, payload: encodeOpenOut("127.0.0.1", uint16(echoPort))}); err != nil {
		t.Fatal(err)
	}
	select {
	case f := <-okCh:
		if f.typ != frameOpenFail {
			t.Fatalf("非白名单端口竟放行: %d", f.typ)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("等待 OPEN_FAIL 超时")
	}
}

// 坏 token 的客户端无法建立隧道。
func TestE2EBadTokenRejected(t *testing.T) {
	ctlPort := freePort(t)
	tclientCtlPort = ctlPort
	srv := &Server{
		listenIP:    "127.0.0.1",
		controlPort: ctlPort,
		token:       "right-token-0123456789",
		ports:       map[string]int{},
		outPorts:    map[int]bool{25: true},
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(ctlPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, _, err := clientHandshake(conn, "wrong-token-0123456789"); err == nil {
		t.Fatal("坏 token 竟建立隧道")
	}
}

// 多隧道：两个客户端会话并存（多域名各一条 TCP 通道），各自出站互不影响。
func TestE2EMultiSession(t *testing.T) {
	echoPort := startEcho(t)
	ctlPort := freePort(t)
	tclientCtlPort = ctlPort

	srv := &Server{
		listenIP:    "127.0.0.1",
		controlPort: ctlPort,
		token:       "e2e-token-0123456789",
		publicIP:    "",
		ports:       map[string]int{},
		outPorts:    map[int]bool{echoPort: true},
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	c1, _ := newTClient(t, "e2e-token-0123456789", nil)
	c2, _ := newTClient(t, "e2e-token-0123456789", nil)

	// 两条会话同时出站（不同流 id 空间）
	for n, c := range []*tclient{c1, c2} {
		sid := uint32(2 * (n + 1))
		okCh := make(chan frame, 1)
		dataCh := make(chan frame, 8)
		c.mu.Lock()
		c.opens[sid] = okCh
		c.data[sid] = dataCh
		c.mu.Unlock()
		if err := c.send(frame{typ: frameOpenOut, streamID: sid, payload: encodeOpenOut("127.0.0.1", uint16(echoPort))}); err != nil {
			t.Fatal(err)
		}
		select {
		case f := <-okCh:
			if f.typ != frameOpenOK {
				t.Fatalf("会话 %d OPEN_OUT 被拒: %s", n, f.payload)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("会话 %d 等待 OPEN_OK 超时", n)
		}
		body := []byte("multi-session")
		if err := c.send(frame{typ: frameData, streamID: sid, payload: body}); err != nil {
			t.Fatal(err)
		}
		select {
		case f := <-dataCh:
			if string(f.payload) != string(body) {
				t.Fatalf("会话 %d 回显不符: %q", n, f.payload)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("会话 %d 等待出站数据超时", n)
		}
	}
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
