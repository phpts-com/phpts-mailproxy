// 代理服务器核心：控制连接管理（token 认证 + 加密隧道，单活跃客户端）、
// 公网映射端口监听（入站 OPEN_IN 转发到 PHPTS 电子邮局）、出站 CONNECT（仅放行白名单端口）。
package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	openTimeout   = 10 * time.Second // 等待 OPEN_OK/FAIL
	dialTimeout   = 15 * time.Second // 出站拨号超时
	pingInterval  = 30 * time.Second
	idleTimeout   = 90 * time.Second // 无任何帧判死
	probeURL      = "https://ipv4.phpts.com/software/v2/myip"
	chunkSize     = 32 * 1024
)

// Server 一个代理服务实例（对应一次命令行启动）。
type Server struct {
	listenIP   string
	controlPort int
	token      string
	publicIP   string
	ports      map[string]int // 逻辑名 → 公网映射端口（>0 才监听）
	outPorts   map[int]bool   // 允许出站的目标端口白名单
	// withPeer 入站是否把真实来源地址透传给 PHPTS（-with-peer=auto|on|off，见 openInPayload）
	withPeer string

	mu       sync.Mutex
	sessions []*session
	rr       int // 入站分发轮询游标（多域名各自一条隧道时轮询取用）
}

// session 一条已认证的隧道（与 PHPTS 侧 phpts-mailserver 的 proxy.rs 对应）。
// 一个 PHPTS 可为多个邮箱域名各建一条隧道，服务端允许多会话并存，入站轮询分发。
type session struct {
	sc  *secureConn
	srv *Server

	wmu sync.Mutex // 串行写帧（多协程共用一条加密连接）

	smu     sync.Mutex
	streams map[uint32]*streamCtl
	nextID  uint32 // 服务端发起流 id（奇数递增）

	lastActive atomic.Int64
	closed     chan struct{}
	closeOnce  sync.Once

	// peerMode 入站 OPEN_IN 是否携带真实来源地址（PROXY protocol 透传，见 openInPayload）：
	// peerAuto 首次带地址发，若对端是旧版 PHPTS（不认带 `|` 的逻辑名）自动退回 peerLegacy。
	peerMode atomic.Int32
}

// OPEN_IN 载荷的来源地址透传状态
const (
	peerAuto   = 0 // 默认：带着来源地址发，失败自动退回旧格式
	peerOn     = 1 // -with-peer=on：始终带（对端必须是新版 PHPTS）
	peerLegacy = 2 // -with-peer=off：始终用旧格式（只有逻辑名）
)

// unknownNameMark PHPTS 侧 handle_open_in_ports 拒绝未知逻辑名的应答前缀，
// 用于识别「对端是不认识新载荷的旧版 PHPTS」。
const unknownNameMark = "未知逻辑名"

// streamCtl 一条转发流：公网/出站连接 ↔ 隧道流。
type streamCtl struct {
	side   *streamSide
	conn   net.Conn
	opened chan error // OPEN_OK(nil) / OPEN_FAIL(原因)
}

func (s *Server) Start() error {
	if s.token == "" {
		return errors.New("token 不能为空")
	}
	if s.publicIP == "" {
		s.publicIP = probePublicIP()
		if s.publicIP != "" {
			log.Printf("探测到公网 IP: %s", s.publicIP)
		}
	}
	ctlAddr := net.JoinHostPort(normalizeIP(s.listenIP), strconv.Itoa(s.controlPort))
	ctl, err := net.Listen("tcp", ctlAddr)
	if err != nil {
		return fmt.Errorf("监听控制端口 %s 失败: %w", ctlAddr, err)
	}
	log.Printf("控制端口监听 %s（token 认证隧道）", ctlAddr)
	go s.serveControl(ctl)

	for name, port := range s.ports {
		if port <= 0 {
			continue
		}
		addr := net.JoinHostPort(normalizeIP(s.listenIP), strconv.Itoa(port))
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("监听映射端口 %s（%s）失败: %w", addr, name, err)
		}
		log.Printf("映射端口 %s → 逻辑名 %s", addr, name)
		go s.servePublic(name, ln)
	}
	return nil
}

// normalizeIP 兼容 "[::]" / "::" / "0.0.0.0" / 具体 IPv4、IPv6 写法（供 JoinHostPort 加括号）。
func normalizeIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if strings.HasPrefix(ip, "[") && strings.HasSuffix(ip, "]") {
		ip = ip[1 : len(ip)-1]
	}
	return ip
}

func (s *Server) serveControl(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("控制端口 accept 失败: %v", err)
			return
		}
		go s.handleControl(conn)
	}
}

func (s *Server) handleControl(conn net.Conn) {
	sc, err := serverHandshake(conn, s.token, s.publicIP)
	if err != nil {
		log.Printf("隧道握手失败 %s: %v", conn.RemoteAddr(), err)
		_ = conn.Close()
		return
	}
	sess := newSession(sc, s)
	log.Printf("隧道已建立 %s", conn.RemoteAddr())
	s.addSession(sess) // 多域名多隧道：会话并存，入站轮询分发
	sess.run()
	log.Printf("隧道已断开 %s", conn.RemoteAddr())
}

func newSession(sc *secureConn, srv *Server) *session {
	s := &session{
		sc:      sc,
		srv:     srv,
		streams: map[uint32]*streamCtl{},
		nextID:  1,
		closed:  make(chan struct{}),
	}
	// -with-peer：auto 探测（默认）、on 强制带来源地址、off 始终用旧格式
	switch srv.withPeer {
	case "on":
		s.peerMode.Store(peerOn)
	case "off":
		s.peerMode.Store(peerLegacy)
	default:
		s.peerMode.Store(peerAuto)
	}
	return s
}

func (s *Server) addSession(sess *session) {
	s.mu.Lock()
	s.sessions = append(s.sessions, sess)
	s.mu.Unlock()
}

func (s *Server) removeSession(sess *session) {
	s.mu.Lock()
	for i, x := range s.sessions {
		if x == sess {
			s.sessions = append(s.sessions[:i], s.sessions[i+1:]...)
			break
		}
	}
	s.mu.Unlock()
}

// pickSession 轮询取一条活跃隧道（入站分发）；无可用会话返回 nil。
func (s *Server) pickSession() *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.sessions)
	for i := 0; i < n; i++ {
		sess := s.sessions[s.rr%n]
		s.rr++
		select {
		case <-sess.closed:
			continue
		default:
			return sess
		}
	}
	return nil
}

func (sess *session) run() {
	defer func() {
		sess.shutdown()
		sess.srv.removeSession(sess)
	}()
	sess.touch()

	// 心跳 + 空闲看门狗
	go func() {
		pt := time.NewTicker(pingInterval)
		defer pt.Stop()
		wt := time.NewTicker(10 * time.Second)
		defer wt.Stop()
		for {
			select {
			case <-sess.closed:
				return
			case <-pt.C:
				_ = sess.sendFrame(frame{typ: framePing})
			case <-wt.C:
				if time.Since(time.Unix(sess.lastActive.Load(), 0)) > idleTimeout {
					log.Printf("隧道空闲超时，断开")
					_ = sess.sc.conn.Close()
					return
				}
			}
		}
	}()

	for {
		rec, err := sess.sc.readRecord()
		if err != nil {
			return
		}
		sess.touch()
		f, err := decodeFrame(rec)
		if err != nil {
			log.Printf("帧解析失败: %v", err)
			return
		}
		sess.dispatch(f)
	}
}

func (sess *session) touch() {
	sess.lastActive.Store(time.Now().Unix())
}

func (sess *session) sendFrame(f frame) error {
	sess.wmu.Lock()
	defer sess.wmu.Unlock()
	select {
	case <-sess.closed:
		return errors.New("隧道已关闭")
	default:
	}
	return sess.sc.writeRecord(encodeFrame(f))
}

func (sess *session) dispatch(f frame) {
	switch f.typ {
	case framePing:
		_ = sess.sendFrame(frame{typ: framePong})
	case framePong: // 仅刷新活跃时间（touch 已做）
	case frameOpenOK, frameOpenFail:
		sess.smu.Lock()
		ctl := sess.streams[f.streamID]
		sess.smu.Unlock()
		if ctl != nil {
			var err error
			if f.typ == frameOpenFail {
				err = errors.New(string(f.payload))
			}
			select {
			case ctl.opened <- err:
			default:
			}
		}
	case frameData:
		sess.smu.Lock()
		ctl := sess.streams[f.streamID]
		sess.smu.Unlock()
		if ctl != nil {
			ctl.side.push(f.payload)
		}
	case frameClose:
		sess.closeStream(f.streamID)
	case frameOpenOut:
		go sess.handleOpenOut(f)
	default:
		log.Printf("未知帧类型 0x%02x", f.typ)
	}
}

// openInbound 入站：公网连接进来 → 隧道 OPEN_IN(逻辑名[|真实来源|映射地址]) → PHPTS 侧连本机端口后双向转发。
//
// 载荷默认带上真实来源地址，让 PHPTS 能在 Received 头里记下来访服务器的真 IP
// （否则它只看到本机回环 127.0.0.1，来源全丢、也无法按 IP 过滤）。
// 对端是旧版 PHPTS 时不认识带 `|` 的逻辑名，会回「未知逻辑名 smtp|…」——
// auto 模式据此自动退回旧格式并用旧载荷重发一次（本条隧道此后不再带地址），
// 所以「先升级哪一端」都不会中断收信。
func (sess *session) openInbound(name string, conn net.Conn) error {
	payload := sess.openInPayload(name, conn)
	// 首帧失败先不掐公网连接：可能要换旧格式立刻重试一次
	err := sess.openInOnce(name, conn, payload, false)
	if err != nil &&
		sess.peerMode.Load() == peerAuto &&
		strings.Contains(string(payload), "|") &&
		strings.Contains(err.Error(), unknownNameMark) {
		sess.peerMode.Store(peerLegacy)
		log.Printf("本机邮局不支持来源地址透传（版本过旧），本隧道入站已退回旧格式；升级 PHPTS 电子邮局后可恢复真实发件 IP")
		return sess.openInOnce(name, conn, []byte(name), true)
	}
	if err != nil {
		_ = conn.Close()
	}
	return err
}

// openInPayload 组装 OPEN_IN 载荷：不带地址时就是逻辑名本身；带地址时
// `smtp|203.0.113.5:52443|198.51.100.7:25`（逻辑名 | 公网侧真实来源 | 本代理的映射地址）。
// Go 的 Addr.String() 本就是 `ip:port`（IPv6 带中括号），原样传过去由 PHPTS 侧解析；
// 地址不成样子（空、通配、无端口）就退回旧格式，宁缺勿错。
func (sess *session) openInPayload(name string, conn net.Conn) []byte {
	if sess.peerMode.Load() == peerLegacy {
		return []byte(name)
	}
	src := conn.RemoteAddr().String()
	dst := conn.LocalAddr().String()
	if src == "" || dst == "" || !strings.Contains(src, ":") || strings.Contains(src, "[::]") || strings.Contains(src, "0.0.0.0") {
		return []byte(name)
	}
	return []byte(encodeOpenIn(name, src, dst))
}

// openInOnce 发一帧 OPEN_IN 并等应答；成功后起双向泵。closeConnOnFail=false 只摘流不掐
// 公网连接（入站首帧失败后还要换旧格式重试同一连接）。
func (sess *session) openInOnce(name string, conn net.Conn, payload []byte, closeConnOnFail bool) error {
	sess.smu.Lock()
	id := sess.nextID
	sess.nextID += 2 // 奇数
	ctl := &streamCtl{side: newStreamSide(id), conn: conn, opened: make(chan error, 1)}
	sess.streams[id] = ctl
	sess.smu.Unlock()

	if err := sess.sendFrame(frame{typ: frameOpenIn, streamID: id, payload: payload}); err != nil {
		sess.dropStream(id, closeConnOnFail)
		return err
	}
	select {
	case err := <-ctl.opened:
		if err != nil {
			sess.dropStream(id, closeConnOnFail)
			return err
		}
	case <-time.After(openTimeout):
		sess.dropStream(id, closeConnOnFail)
		return errors.New("等待隧道应答超时")
	case <-sess.closed:
		sess.dropStream(id, closeConnOnFail)
		return errors.New("隧道已关闭")
	}
	sess.startPumps(ctl)
	return nil
}

// encodeOpenIn 载荷编码（与 PHPTS 侧 proxy.rs::decode_open_in 一一对应）。
func encodeOpenIn(name, src, dst string) string {
	return name + "|" + src + "|" + dst
}

// handleOpenOut 出站：PHPTS 投递外域邮件 → 隧道 OPEN_OUT(host, port) → 本机拨号对方并转发。
func (sess *session) handleOpenOut(f frame) {
	host, port, err := decodeOpenOut(f.payload)
	if err != nil {
		_ = sess.sendFrame(frame{typ: frameOpenFail, streamID: f.streamID, payload: []byte("载荷非法")})
		return
	}
	if !sess.srv.outPorts[int(port)] {
		log.Printf("拒绝出站 %s:%d（端口不在白名单）", host, port)
		_ = sess.sendFrame(frame{typ: frameOpenFail, streamID: f.streamID, payload: []byte("出站端口未放行")})
		return
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))
	conn, err := net.DialTimeout("tcp", target, dialTimeout)
	if err != nil {
		_ = sess.sendFrame(frame{typ: frameOpenFail, streamID: f.streamID, payload: []byte(err.Error())})
		return
	}
	log.Printf("出站 %s", target)
	ctl := &streamCtl{side: newStreamSide(f.streamID), conn: conn, opened: make(chan error, 1)}
	sess.smu.Lock()
	sess.streams[f.streamID] = ctl
	sess.smu.Unlock()
	if err := sess.sendFrame(frame{typ: frameOpenOK, streamID: f.streamID}); err != nil {
		sess.closeStream(f.streamID)
		return
	}
	sess.startPumps(ctl)
}

// startPumps 双向泵：连接读 → DATA 帧；帧字节 → 连接写；任一端 EOF/错 → CLOSE 帧 + 拆流。
func (sess *session) startPumps(ctl *streamCtl) {
	go func() {
		buf := make([]byte, chunkSize)
		for {
			n, err := ctl.conn.Read(buf)
			if n > 0 {
				p := make([]byte, n)
				copy(p, buf[:n])
				if err := sess.sendFrame(frame{typ: frameData, streamID: ctl.side.id, payload: p}); err != nil {
					break
				}
			}
			if err != nil {
				_ = sess.sendFrame(frame{typ: frameClose, streamID: ctl.side.id})
				sess.closeStream(ctl.side.id)
				return
			}
		}
	}()
	go func() {
		for {
			select {
			case <-ctl.side.closed:
				_ = ctl.conn.Close()
				return
			case b := <-ctl.side.out:
				if _, err := ctl.conn.Write(b); err != nil {
					_ = sess.sendFrame(frame{typ: frameClose, streamID: ctl.side.id})
					sess.closeStream(ctl.side.id)
					return
				}
			}
		}
	}()
}

func (sess *session) closeStream(id uint32) {
	sess.dropStream(id, true)
}

// dropStream 摘掉一条流；closeConn=false 时不掐它持有的连接——
// 入站首帧失败后还要用同一条公网连接换旧格式重发，掐了就变成客户连接被无故重置。
func (sess *session) dropStream(id uint32, closeConn bool) {
	sess.smu.Lock()
	ctl := sess.streams[id]
	delete(sess.streams, id)
	sess.smu.Unlock()
	if ctl != nil {
		ctl.side.close()
		if closeConn {
			_ = ctl.conn.Close()
		}
	}
}

func (sess *session) shutdown() {
	sess.closeOnce.Do(func() {
		close(sess.closed)
		_ = sess.sc.conn.Close()
		sess.smu.Lock()
		ids := make([]uint32, 0, len(sess.streams))
		for id := range sess.streams {
			ids = append(ids, id)
		}
		sess.smu.Unlock()
		for _, id := range ids {
			sess.closeStream(id)
		}
	})
}

// servePublic 公网映射端口 accept 循环。
func (s *Server) servePublic(name string, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("映射端口 %s accept 失败: %v", name, err)
			return
		}
		go func() {
			sess := s.pickSession()
			if sess == nil {
				log.Printf("入站 %s 被拒：PHPTS 隧道未连接", name)
				_ = conn.Close()
				return
			}
			if err := sess.openInbound(name, conn); err != nil {
				log.Printf("入站 %s 转发失败: %v", name, err)
				_ = conn.Close()
			}
		}()
	}
}

// probePublicIP 启动时探测本机出口公网 IP（官方接口优先，失败返回空串，仅影响 DNS 引导展示）。
func probePublicIP() string {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(probeURL)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
