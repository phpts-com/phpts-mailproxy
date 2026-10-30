// 多路复用帧层：明文帧 [type:u8][stream_id:u32][len:u32][payload]，经加密记录层传输。
// 服务端发起的流用奇数 id，客户端发起的流用偶数 id，双方各自计数避免冲突。
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
)

const (
	frameOpenIn   = 0x01 // 服务端→客户端：入站新连接，payload=逻辑名（smtp/imap/...）
	frameOpenOut  = 0x02 // 客户端→服务端：出站拨号请求，payload=[hostLen:u16][host][port:u16]
	frameOpenOK   = 0x03 // 流建立成功
	frameOpenFail = 0x04 // 流建立失败，payload=原因
	frameData     = 0x05 // 流数据
	frameClose    = 0x06 // 流关闭
	framePing     = 0x07 // 心跳
	framePong     = 0x08 // 心跳应答

	maxFramePayload = 64 * 1024
)

type frame struct {
	typ      byte
	streamID uint32
	payload  []byte
}

func encodeFrame(f frame) []byte {
	b := make([]byte, 9+len(f.payload))
	b[0] = f.typ
	binary.BigEndian.PutUint32(b[1:5], f.streamID)
	binary.BigEndian.PutUint32(b[5:9], uint32(len(f.payload)))
	copy(b[9:], f.payload)
	return b
}

func decodeFrame(raw []byte) (frame, error) {
	if len(raw) < 9 {
		return frame{}, errors.New("帧过短")
	}
	n := binary.BigEndian.Uint32(raw[5:9])
	if int(n) != len(raw)-9 {
		return frame{}, fmt.Errorf("帧长度不符: 声明 %d 实际 %d", n, len(raw)-9)
	}
	if n > maxFramePayload {
		return frame{}, fmt.Errorf("帧超限: %d", n)
	}
	return frame{typ: raw[0], streamID: binary.BigEndian.Uint32(raw[1:5]), payload: raw[9:]}, nil
}

// encodeOpenOut 编码出站拨号请求 payload。
func encodeOpenOut(host string, port uint16) []byte {
	b := make([]byte, 2+len(host)+2)
	binary.BigEndian.PutUint16(b[:2], uint16(len(host)))
	copy(b[2:], host)
	binary.BigEndian.PutUint16(b[2+len(host):], port)
	return b
}

// decodeOpenOut 解码出站拨号请求 payload。
func decodeOpenOut(p []byte) (string, uint16, error) {
	if len(p) < 4 {
		return "", 0, errors.New("OPEN_OUT 载荷过短")
	}
	hl := int(binary.BigEndian.Uint16(p[:2]))
	if len(p) != 2+hl+2 {
		return "", 0, errors.New("OPEN_OUT 载荷长度不符")
	}
	return string(p[2 : 2+hl]), binary.BigEndian.Uint16(p[2+hl:]), nil
}

// streamSide 单条流的一端：向隧道发帧的出口 + 对端字节的入口。
type streamSide struct {
	id     uint32
	out    chan []byte // 待写入对端连接的字节（读循环投递）
	closed chan struct{} // 关闭信号（只关一次）
	once   sync.Once
}

func newStreamSide(id uint32) *streamSide {
	return &streamSide{
		id:     id,
		out:    make(chan []byte, 64),
		closed: make(chan struct{}),
	}
}

// push 把对端字节投递给连接写出协程；流关闭后丢弃。
func (s *streamSide) push(b []byte) {
	select {
	case <-s.closed:
	case s.out <- b:
	}
}

// close 幂等关闭。
func (s *streamSide) close() {
	s.once.Do(func() { close(s.closed) })
}
