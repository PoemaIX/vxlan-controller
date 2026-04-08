package apisock

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"vxlan-controller/pkg/vlog"
)

// Request is a JSON request sent over the Unix socket.
type Request struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

// Response is a JSON response sent over the Unix socket.
type Response struct {
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// Handler processes a method call and returns a result or error.
type Handler func(method string, params json.RawMessage) (interface{}, error)

// Call connects to a Unix socket, sends a request, and returns the response.
func Call(sockPath, method string, params interface{}) (json.RawMessage, error) {
	conn, err := net.DialTimeout("unix", sockPath, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect %s: %w", sockPath, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	req := Request{Method: method}
	if params != nil {
		raw, err := json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("marshal params: %w", err)
		}
		req.Params = raw
	}

	enc := json.NewEncoder(conn)
	if err := enc.Encode(&req); err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}

	var resp Response
	dec := json.NewDecoder(conn)
	if err := dec.Decode(&resp); err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.Error != "" {
		return nil, fmt.Errorf("%s", resp.Error)
	}
	return resp.Result, nil
}

// ListenAndServe starts a Unix socket listener and dispatches connections to the handler.
func ListenAndServe(ctx context.Context, sockPath string, handler Handler) error {
	os.Remove(sockPath)

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		return fmt.Errorf("listen %s: %w", sockPath, err)
	}
	defer listener.Close()
	defer os.Remove(sockPath)

	// Make socket accessible
	os.Chmod(sockPath, 0660)

	vlog.Debugf("[APISock] listening on %s", sockPath)

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				continue
			}
		}
		go serveConn(conn, handler)
	}
}

func serveConn(conn net.Conn, handler Handler) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	var req Request
	dec := json.NewDecoder(conn)
	if err := dec.Decode(&req); err != nil {
		writeError(conn, "invalid request")
		return
	}

	result, err := handler(req.Method, req.Params)
	if err != nil {
		writeError(conn, err.Error())
		return
	}

	var resp Response
	if result != nil {
		raw, err := json.Marshal(result)
		if err != nil {
			writeError(conn, fmt.Sprintf("marshal result: %v", err))
			return
		}
		resp.Result = raw
	}

	enc := json.NewEncoder(conn)
	enc.Encode(&resp)
}

func writeError(conn net.Conn, msg string) {
	enc := json.NewEncoder(conn)
	enc.Encode(&Response{Error: msg})
}
