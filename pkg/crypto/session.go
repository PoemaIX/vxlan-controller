package crypto

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

var (
	ErrDecryptFailed = errors.New("decryption failed")
	ErrReplayDetected = errors.New("replay detected")
)

// Session holds the session keys established after a Noise IK handshake.
type Session struct {
	LocalIndex  uint32
	RemoteIndex uint32
	SendKey     [32]byte
	RecvKey     [32]byte
	SendCounter NonceCounter
	// For TCP: strict increment check
	RecvTCPCounter TCPCounter
	// For UDP: sliding window
	RecvWindow SlidingWindow
	PeerID     [32]byte
	IsUDP      bool // determines which recv counter to use
	CreatedAt  time.Time
	LastRecv   time.Time
}

// Encrypt encrypts plaintext using ChaCha20-Poly1305 with counter-based nonce.
func (s *Session) Encrypt(plaintext []byte) (ciphertext []byte, counter uint64, err error) {
	nonce, err := s.SendCounter.Next()
	if err != nil {
		return nil, 0, err
	}
	counter = s.SendCounter.Current() - 1

	aead, err := chacha20poly1305.New(s.SendKey[:])
	if err != nil {
		return nil, 0, err
	}

	ciphertext = aead.Seal(nil, nonce[:], plaintext, nil)
	return ciphertext, counter, nil
}

// Decrypt decrypts ciphertext using ChaCha20-Poly1305 with the given counter.
func (s *Session) Decrypt(ciphertext []byte, counter uint64) ([]byte, error) {
	if counter >= REJECT_AFTER_MESSAGES {
		return nil, ErrCounterExhausted
	}

	// Check replay
	if s.IsUDP {
		if !s.RecvWindow.Check(counter) {
			return nil, ErrReplayDetected
		}
	} else {
		if !s.RecvTCPCounter.Check(counter) {
			return nil, ErrReplayDetected
		}
	}

	nonce := MakeNonce(counter)
	aead, err := chacha20poly1305.New(s.RecvKey[:])
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce[:], ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptFailed
	}

	s.LastRecv = time.Now()
	return plaintext, nil
}

// SessionManager manages sessions indexed by local index.
type SessionManager struct {
	mu       sync.RWMutex
	sessions map[uint32]*Session
	byPeer   map[[32]byte]*Session
	indexGen atomic.Uint32
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[uint32]*Session),
		byPeer:   make(map[[32]byte]*Session),
	}
}

// AllocateIndex generates a random session index.
func (sm *SessionManager) AllocateIndex() uint32 {
	var buf [4]byte
	rand.Read(buf[:])
	return binary.LittleEndian.Uint32(buf[:])
}

// AddSession registers a session.
func (sm *SessionManager) AddSession(s *Session) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Remove old session for same peer
	if old, ok := sm.byPeer[s.PeerID]; ok {
		delete(sm.sessions, old.LocalIndex)
	}

	now := time.Now()
	s.CreatedAt = now
	s.LastRecv = now

	sm.sessions[s.LocalIndex] = s
	sm.byPeer[s.PeerID] = s
}

// FindByIndex looks up a session by receiver_index.
func (sm *SessionManager) FindByIndex(index uint32) *Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.sessions[index]
}

// FindByPeer looks up a session by peer ID.
func (sm *SessionManager) FindByPeer(peerID [32]byte) *Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.byPeer[peerID]
}

// ExpireByPeer removes a session if LastRecv is older than maxAge.
// Returns true if the session was expired (or didn't exist).
func (sm *SessionManager) ExpireByPeer(peerID [32]byte, maxAge time.Duration) bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	s, ok := sm.byPeer[peerID]
	if !ok {
		return true
	}
	if time.Since(s.LastRecv) <= maxAge {
		return false
	}
	delete(sm.sessions, s.LocalIndex)
	delete(sm.byPeer, peerID)
	return true
}

// RemoveByPeer removes a session by peer ID.
func (sm *SessionManager) RemoveByPeer(peerID [32]byte) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if s, ok := sm.byPeer[peerID]; ok {
		delete(sm.sessions, s.LocalIndex)
		delete(sm.byPeer, peerID)
	}
}
