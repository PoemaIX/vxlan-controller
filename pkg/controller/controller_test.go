package controller

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"vxlan-controller/pkg/crypto"
)

type packetRead struct {
	data []byte
	addr net.Addr
	err  error
}

type scriptedPacketConn struct {
	reads     chan packetRead
	delivered chan struct{}
	closed    chan struct{}
	readOnce  sync.Once
	closeOnce sync.Once
}

func newScriptedPacketConn(reads ...packetRead) *scriptedPacketConn {
	pc := &scriptedPacketConn{
		reads:     make(chan packetRead, len(reads)),
		delivered: make(chan struct{}),
		closed:    make(chan struct{}),
	}
	for _, read := range reads {
		pc.reads <- read
	}
	return pc
}

func (pc *scriptedPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case read := <-pc.reads:
		copy(b, read.data)
		pc.readOnce.Do(func() {
			close(pc.delivered)
		})
		return len(read.data), read.addr, read.err
	case <-pc.closed:
		return 0, nil, net.ErrClosed
	}
}

func (pc *scriptedPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return len(b), nil
}

func (pc *scriptedPacketConn) Close() error {
	pc.closeOnce.Do(func() {
		close(pc.closed)
	})
	return nil
}

func (pc *scriptedPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 6789}
}

func (pc *scriptedPacketConn) SetDeadline(time.Time) error {
	return nil
}

func (pc *scriptedPacketConn) SetReadDeadline(time.Time) error {
	return nil
}

func (pc *scriptedPacketConn) SetWriteDeadline(time.Time) error {
	return nil
}

func TestUDPReadLoopIgnoresEmptyDatagram(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pc := newScriptedPacketConn(packetRead{
		addr: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 12345},
	})
	defer pc.Close()

	c := &Controller{ctx: ctx, cancel: cancel}
	al := &AFListener{
		AF:          "v4",
		Channel:     "test",
		UDPConn:     pc,
		UDPSessions: crypto.NewSessionManager(),
	}

	panicCh := make(chan any, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if recovered := recover(); recovered != nil {
				panicCh <- recovered
			}
		}()
		c.udpReadLoop(al)
	}()

	select {
	case <-pc.delivered:
	case <-time.After(time.Second):
		t.Fatal("udpReadLoop did not read the empty datagram")
	}

	select {
	case recovered := <-panicCh:
		t.Fatalf("udpReadLoop panicked on empty datagram: %v", recovered)
	case <-time.After(100 * time.Millisecond):
	}

	cancel()
	if err := pc.Close(); err != nil {
		t.Fatalf("close packet conn: %v", err)
	}

	select {
	case recovered := <-panicCh:
		t.Fatalf("udpReadLoop panicked while stopping: %v", recovered)
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("udpReadLoop did not stop")
	}
}
