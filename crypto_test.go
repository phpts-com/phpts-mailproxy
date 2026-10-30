package main

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// 握手 + 记录层往返（正确 token）。
func TestHandshakeAndRecordRoundtrip(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	type res struct {
		sc *secureConn
		pi string
		err error
	}
	ch := make(chan res, 1)
	go func() {
		sc, pi, err := clientHandshake(c1, "0123456789abcdef")
		ch <- res{sc, pi, err}
	}()
	srv, err := serverHandshake(c2, "0123456789abcdef", "203.0.113.9")
	if err != nil {
		t.Fatalf("服务端握手失败: %v", err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatalf("客户端握手失败: %v", r.err)
	}
	if r.pi != "203.0.113.9" {
		t.Fatalf("公网 IP 未回传: %q", r.pi)
	}

	// 双向记录往返
	msg := []byte("hello PHPTS mail proxy")
	go func() {
		if err := r.sc.writeRecord(msg); err != nil {
			t.Errorf("客户端写记录失败: %v", err)
		}
	}()
	got, err := srv.readRecord()
	if err != nil {
		t.Fatalf("服务端读记录失败: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("记录内容不一致: %q", got)
	}
	go func() {
		if err := srv.writeRecord([]byte("pong")); err != nil {
			t.Errorf("服务端写记录失败: %v", err)
		}
	}()
	got2, err := r.sc.readRecord()
	if err != nil {
		t.Fatalf("客户端读记录失败: %v", err)
	}
	if string(got2) != "pong" {
		t.Fatalf("记录内容不一致: %q", got2)
	}
}

// 坏 token 必须被拒绝。
func TestHandshakeBadToken(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	errCh := make(chan error, 1)
	go func() {
		_, _, err := clientHandshake(c1, "wrong-token-wrong-token")
		errCh <- err
	}()
	_, err := serverHandshake(c2, "0123456789abcdef", "")
	if err == nil {
		t.Fatal("坏 token 竟握手成功")
	}
	if ce := <-errCh; ce == nil {
		t.Fatal("客户端对坏 token 未报错")
	}
}

// 服务端在 token 不符时应快速断开（不挂死）。
func TestHandshakeTimeoutGuard(t *testing.T) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()
		go func() { _, _, _ = clientHandshake(c1, "another-token-xxxx") }()
		_, _ = serverHandshake(c2, "0123456789abcdef", "")
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("握手未在限时内结束")
	}
}

// 密钥派生确定性：同输入同输出（与 Rust proxy.rs 测试向量对齐的基础）。
func TestDeriveKeysDeterministic(t *testing.T) {
	cr := bytes.Repeat([]byte{0x11}, 16)
	sr := bytes.Repeat([]byte{0x22}, 16)
	k1, n1, err := deriveKeys("tok", cr, sr)
	if err != nil {
		t.Fatal(err)
	}
	k2, n2, err := deriveKeys("tok", cr, sr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1, k2) || !bytes.Equal(n1, n2) {
		t.Fatal("派生结果不确定")
	}
	if len(k1) != 32 || len(n1) != 4 {
		t.Fatalf("派生长度异常: key=%d prefix=%d", len(k1), len(n1))
	}
	k3, _, _ := deriveKeys("other", cr, sr)
	if bytes.Equal(k1, k3) {
		t.Fatal("不同 token 派生出了相同密钥")
	}
}
