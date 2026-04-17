package webui

import (
	"context"
	"embed"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"vxlan-controller/pkg/config"
	"vxlan-controller/pkg/vlog"
)

//go:embed index.html
var staticFS embed.FS

// StateProvider is called by the server to get current state JSON.
type StateProvider func() *StateSnapshot

// StateSnapshot is the JSON structure pushed to clients.
type StateSnapshot struct {
	Clients       []ClientJSON             `json:"clients"`
	RouteTable    []RouteEntryJSON         `json:"route_table"`
	LatencyMatrix []LatencyRowJSON         `json:"latency_matrix"`
	RouteMatrix   []RouteMatrixJSON        `json:"route_matrix"`
	McastStats    map[string][]MACStatsJSON `json:"mcast_stats"` // key: client name
	Config        UIConfigJSON             `json:"config"`
}

type ClientJSON struct {
	ID         string           `json:"id"`
	Name       string           `json:"name"`
	Online     bool             `json:"online"`
	LastSeen   int64            `json:"last_seen"`
	Routes     []ClientRouteJSON `json:"routes"`
	Endpoints  map[string]EndpointJSON `json:"endpoints"`
}

type ClientRouteJSON struct {
	MAC string `json:"mac"`
	IP  string `json:"ip"`
}

type EndpointJSON struct {
	IP string `json:"ip"`
}

type RouteEntryJSON struct {
	MAC    string            `json:"mac"`
	IP     string            `json:"ip"`
	Owners map[string]int64  `json:"owners"` // client_name -> expire_ts
}

type LatencyRowJSON struct {
	Src     string             `json:"src"`
	Entries []LatencyCellJSON  `json:"entries"`
}

type LatencyCellJSON struct {
	Dst     string  `json:"dst"`
	Latency float64 `json:"latency"`
	AF      string  `json:"af"`
}

type RouteMatrixJSON struct {
	Src     string                `json:"src"`
	Entries []RouteMatrixCellJSON `json:"entries"`
}

type RouteMatrixCellJSON struct {
	Dst     string `json:"dst"`
	NextHop string `json:"next_hop"`
	AF      string `json:"af"`
}

type MACStatsJSON struct {
	MAC           string             `json:"mac"`
	TxAccepted    uint64             `json:"tx_accepted"`
	TxRejected    uint64             `json:"tx_rejected"`
	RxAccepted    uint64             `json:"rx_accepted"`
	RxRejected    uint64             `json:"rx_rejected"`
	RejectReasons []RejectReasonJSON `json:"reject_reasons,omitempty"`
}

type RejectReasonJSON struct {
	Direction string             `json:"direction"`
	Reason    string             `json:"reason"`
	Count     uint64             `json:"count"`
	Details   []RejectDetailJSON `json:"details,omitempty"`
}

type RejectDetailJSON struct {
	Detail string `json:"detail"`
	Count  uint64 `json:"count"`
}

type UIConfigJSON struct {
	Title      string                 `json:"title"`
	URL        string                 `json:"url,omitempty"`
	MacAliases map[string]string      `json:"mac_aliases"`
	Nodes      map[string]UINodeJSON  `json:"nodes"`
}

type UINodeJSON struct {
	Label string     `json:"label"`
	Pos   [2]float64 `json:"pos"`
}

// Server serves the web UI and pushes state over WebSocket.
type Server struct {
	cfg      *config.WebUIConfig
	provider StateProvider
	hub      *wsHub
	srv      *http.Server
}

// New creates a new WebUI server.
func New(cfg *config.WebUIConfig, provider StateProvider) *Server {
	s := &Server{
		cfg:      cfg,
		provider: provider,
		hub:      newHub(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", s.handleWS)
	mux.HandleFunc("/api/state", s.handleAPIState)
	// Serve index.html for all other paths (SPA)
	mux.HandleFunc("/", s.handleIndex)

	s.srv = &http.Server{
		Addr:    cfg.BindAddr,
		Handler: mux,
	}

	return s
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	data, err := staticFS.ReadFile("index.html")
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

func (s *Server) handleAPIState(w http.ResponseWriter, r *http.Request) {
	state := s.provider()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(state)
}

// Run starts the HTTP server and the push loop. Blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) {
	go s.hub.run(ctx)
	go s.pushLoop(ctx)

	go func() {
		<-ctx.Done()
		s.srv.Close()
	}()

	vlog.Infof("[WebUI] listening on %s", s.cfg.BindAddr)
	if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		vlog.Errorf("[WebUI] server error: %v", err)
	}
}

func (s *Server) pushLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			state := s.provider()
			data, err := json.Marshal(state)
			if err != nil {
				continue
			}
			s.hub.broadcast(data)
		case <-ctx.Done():
			return
		}
	}
}

// --- WebSocket hub (gorilla-free, uses net/http hijack) ---

type wsHub struct {
	mu      sync.Mutex
	clients map[*wsConn]struct{}
}

func newHub() *wsHub {
	return &wsHub{
		clients: make(map[*wsConn]struct{}),
	}
}

func (h *wsHub) register(c *wsConn) {
	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()
}

func (h *wsHub) unregister(c *wsConn) {
	h.mu.Lock()
	delete(h.clients, c)
	h.mu.Unlock()
}

func (h *wsHub) broadcast(msg []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for c := range h.clients {
		select {
		case c.send <- msg:
		default:
			// slow client, drop
		}
	}
}

func (h *wsHub) run(ctx context.Context) {
	<-ctx.Done()
	h.mu.Lock()
	for c := range h.clients {
		c.close()
	}
	h.mu.Unlock()
}
