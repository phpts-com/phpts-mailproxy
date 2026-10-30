// 握手与加密记录层：token 挑战-应答认证 + HKDF 派生会话密钥 + AES-256-GCM 记录加密。
// 与 phpts-mailserver/src/proxy.rs 的 Rust 实现逐字节对齐（phpts-mailproxy-v1）。
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	challengeLen = 16 // 服务端随机挑战长度
	randomLen    = 16 // 双端随机数长度
	macLen       = 32 // HMAC-SHA256 输出长度
	hkdfInfo     = "phpts-mailproxy-v1"
	// 单条加密记录上限：64KB 明文帧 + GCM 标签 + nonce
	maxRecord = 64*1024 + 64
	handshakeTO = 10 * time.Second
)

// hmacToken 用 token 作 HMAC 密钥对挑战签名（证明持有 token，token 本身不上线）。
func hmacToken(token string, challenge []byte) []byte {
	m := hmac.New(sha256.New, []byte(token))
	m.Write(challenge)
	return m.Sum(nil)
}

// deriveKeys 派生会话密钥：HKDF-SHA256(ikm=token, salt=clientRandom||serverRandom) → 32B AES key + 4B nonce 前缀。
func deriveKeys(token string, clientRandom, serverRandom []byte) (key, noncePrefix []byte, err error) {
	salt := make([]byte, 0, randomLen*2)
	salt = append(salt, clientRandom...)
	salt = append(salt, serverRandom...)
	okm, err := hkdf.Key(sha256.New, []byte(token), salt, hkdfInfo, 36)
	if err != nil {
		return nil, nil, err
	}
	return okm[:32], okm[32:36], nil
}

// secureConn：加密记录层。记录格式 [rec_len:u32][nonce:12B][ciphertext]，rec_len = 12+len(ciphertext)。
// nonce = 4B 前缀 + 8B 递增计数器，发送方计数、接收方取记录内 nonce 校验。
type secureConn struct {
	conn        net.Conn
	aead        cipher.AEAD
	noncePrefix []byte
	sendCounter uint64
}

func newSecureConn(conn net.Conn, key, noncePrefix []byte) (*secureConn, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &secureConn{conn: conn, aead: aead, noncePrefix: noncePrefix}, nil
}

func (s *secureConn) writeRecord(plain []byte) error {
	nonce := make([]byte, 12)
	copy(nonce[:4], s.noncePrefix)
	binary.BigEndian.PutUint64(nonce[4:], s.sendCounter)
	s.sendCounter++
	ct := s.aead.Seal(nil, nonce, plain, nil)
	rec := make([]byte, 4+12+len(ct))
	binary.BigEndian.PutUint32(rec[:4], uint32(12+len(ct)))
	copy(rec[4:16], nonce)
	copy(rec[16:], ct)
	_, err := s.conn.Write(rec)
	return err
}

func (s *secureConn) readRecord() ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(s.conn, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n < 12+16 || n > maxRecord {
		return nil, fmt.Errorf("非法记录长度 %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(s.conn, buf); err != nil {
		return nil, err
	}
	return s.aead.Open(nil, buf[:12], buf[12:], nil)
}

// serverHandshake 服务端握手：下发挑战 → 校验客户端 HMAC → 回 server_random + 公网 IP。
func serverHandshake(conn net.Conn, token, publicIP string) (*secureConn, error) {
	_ = conn.SetDeadline(time.Now().Add(handshakeTO))
	defer conn.SetDeadline(time.Time{})

	challenge := make([]byte, challengeLen)
	if _, err := rand.Read(challenge); err != nil {
		return nil, err
	}
	if _, err := conn.Write(challenge); err != nil {
		return nil, err
	}
	buf := make([]byte, macLen+randomLen)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	clientRandom := buf[macLen:]
	expect := hmacToken(token, challenge)
	if !hmac.Equal(expect, buf[:macLen]) {
		return nil, errors.New("token 校验失败")
	}
	serverRandom := make([]byte, randomLen)
	if _, err := rand.Read(serverRandom); err != nil {
		return nil, err
	}
	pi := []byte(publicIP)
	out := make([]byte, 0, randomLen+4+len(pi))
	out = append(out, serverRandom...)
	out = append(out, byte(len(pi)>>8), byte(len(pi)))
	out = append(out, pi...)
	if _, err := conn.Write(out); err != nil {
		return nil, err
	}
	key, np, err := deriveKeys(token, clientRandom, serverRandom)
	if err != nil {
		return nil, err
	}
	return newSecureConn(conn, key, np)
}

// clientHandshake 客户端握手（phpts-mailserver 的 proxy.rs 与本函数同口径）。
func clientHandshake(conn net.Conn, token string) (*secureConn, string, error) {
	_ = conn.SetDeadline(time.Now().Add(handshakeTO))
	defer conn.SetDeadline(time.Time{})

	challenge := make([]byte, challengeLen)
	if _, err := io.ReadFull(conn, challenge); err != nil {
		return nil, "", err
	}
	clientRandom := make([]byte, randomLen)
	if _, err := rand.Read(clientRandom); err != nil {
		return nil, "", err
	}
	out := append(hmacToken(token, challenge), clientRandom...)
	if _, err := conn.Write(out); err != nil {
		return nil, "", err
	}
	head := make([]byte, randomLen+2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return nil, "", err
	}
	piLen := int(binary.BigEndian.Uint16(head[randomLen:]))
	if piLen > 256 {
		return nil, "", errors.New("非法公网 IP 长度")
	}
	pi := make([]byte, piLen)
	if piLen > 0 {
		if _, err := io.ReadFull(conn, pi); err != nil {
			return nil, "", err
		}
	}
	key, np, err := deriveKeys(token, clientRandom, head[:randomLen])
	if err != nil {
		return nil, "", err
	}
	sc, err := newSecureConn(conn, key, np)
	return sc, string(pi), err
}
