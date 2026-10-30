package main

import (
	"bytes"
	"testing"
)

func TestFrameRoundtrip(t *testing.T) {
	f := frame{typ: frameData, streamID: 7, payload: []byte("mail-body")}
	got, err := decodeFrame(encodeFrame(f))
	if err != nil {
		t.Fatal(err)
	}
	if got.typ != f.typ || got.streamID != f.streamID || !bytes.Equal(got.payload, f.payload) {
		t.Fatalf("帧往返不一致: %+v", got)
	}
}

func TestFrameEmptyPayload(t *testing.T) {
	f := frame{typ: framePing, streamID: 0, payload: nil}
	got, err := decodeFrame(encodeFrame(f))
	if err != nil {
		t.Fatal(err)
	}
	if got.typ != framePing || len(got.payload) != 0 {
		t.Fatalf("空载荷帧异常: %+v", got)
	}
}

func TestFrameBadDecode(t *testing.T) {
	if _, err := decodeFrame([]byte{1, 2, 3}); err == nil {
		t.Fatal("过短帧未报错")
	}
	raw := encodeFrame(frame{typ: frameData, streamID: 1, payload: []byte("x")})
	raw[5] = 0xff // 篡改长度
	if _, err := decodeFrame(raw); err == nil {
		t.Fatal("长度不符未报错")
	}
}

func TestOpenOutPayload(t *testing.T) {
	p := encodeOpenOut("mx.example.com", 25)
	host, port, err := decodeOpenOut(p)
	if err != nil {
		t.Fatal(err)
	}
	if host != "mx.example.com" || port != 25 {
		t.Fatalf("OPEN_OUT 载荷不一致: %s %d", host, port)
	}
	if _, _, err := decodeOpenOut([]byte{0, 1}); err == nil {
		t.Fatal("非法载荷未报错")
	}
}
