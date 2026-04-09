# ARCHITECTURE.md — VXLAN Controller (Go)

本文件基於 DESIGN.md，整理出 Go 語言實作的架構細節，包含模組劃分、核心結構體、goroutine 設計、IPC/通訊流程。

---

## 目錄結構（預計）

```
vxlan-controller/
├── cmd/
│   ├── controller/main.go      # Controller 入口
│   ├── client/main.go          # Client 入口
│   └── keygen/main.go          # 金鑰生成工具
├── proto/
│   └── messages.proto          # Protobuf 定義
├── pkg/
│   ├── config/                 # YAML 配置解析
│   │   ├── client.go
│   │   ├── controller.go
│   │   └── defaults.go         # 預設值定義
│   ├── crypto/                 # Noise IK handshake, ChaCha20-Poly1305, X25519
│   │   ├── noise.go
│   │   ├── session.go
│   │   └── nonce.go
│   ├── protocol/               # TCP framing, UDP packet, msg_type 定義
│   │   ├── framing.go
│   │   ├── msgtype.go
│   │   └── udp.go
│   ├── controller/             # Controller 核心邏輯
│   │   ├── controller.go
│   │   ├── state.go
│   │   ├── routing.go          # Floyd-Warshall, AdditionalCost 加權, RouteMatrix
│   │   ├── sync.go             # 全量/增量推送
│   │   ├── addrwatch.go        # autoip_interface: 動態 IP 監聽 (Controller 端)
│   │   ├── stats.go            # multicast 統計彙整
│   │   └── webui.go            # WebUI 狀態推送橋接
│   ├── client/                 # Client 核心邏輯
│   │   ├── client.go
│   │   ├── authority.go        # 權威 Controller 選擇
│   │   ├── fdb.go              # FDB 寫入 (master+self split)
│   │   ├── probe.go            # Probe 執行
│   │   ├── neighbor.go         # 鄰居表監聽
│   │   ├── tap.go              # TAP device 讀寫
│   │   ├── netlink.go          # bridge/vxlan device 管理
│   │   ├── firewall.go         # nftables VXLAN 注入防護
│   │   ├── addrwatch.go        # autoip_interface: 動態 IP 監聽 (Client 端)
│   │   └── mcast_stats.go      # multicast 封包統計追蹤
│   ├── filter/                 # Lua 過濾系統
│   │   ├── engine.go           # gopher-lua 執行引擎，四個 hook
│   │   ├── config.go           # 過濾配置解析
│   │   ├── rate.go             # per-MAC / per-client 頻率限制
│   │   ├── defaults.go         # 預設 Lua 腳本
│   │   └── addrselect.go       # autoip_interface 地址選擇 Lua 引擎
│   ├── vlog/                   # 分級日誌系統
│   │   └── vlog.go             # error/warn/info/debug/verbose 五級
│   ├── webui/                  # WebUI 即時管理介面
│   │   ├── server.go           # HTTP + WebSocket server
│   │   ├── ws.go               # WebSocket 連線管理
│   │   └── index.html          # 內嵌 SPA 前端頁面
│   ├── ntp/                    # NTP 校時
│   │   └── ntp.go
│   └── types/                  # 共用型別
│       └── types.go
├── tests/                      # 整合測試（需 root，使用 network namespace）
│   ├── run_all.sh
│   ├── helpers.sh              # 共用測試工具（namespace/veth/netem 設定）
│   ├── test_connectivity.sh
│   ├── test_neigh_suppress.sh
│   ├── test_controller_failover.sh
│   ├── test_transit_failure.sh
│   ├── test_broadcast_relay.sh
│   ├── test_dual_stack.sh
│   ├── test_ip_change.sh
│   ├── test_no_flood.sh
│   ├── test_firewall.sh
│   └── compare_static_vs_controller.sh
├── go.mod
├── go.sum
├── DESIGN.md
├── ARCHITECTURE.md
└── README.md
```

---

## 1. 共用型別 (`pkg/types`)

```go
// ClientID 是 X25519 public key，32 bytes
type ClientID [32]byte

// ControllerID 同上
type ControllerID [32]byte

// AFName 代表一個 address family，例如 "v4", "v6", "asia_v4"
type AFName string

// Endpoint 代表某個 AF 下的連線端點
type Endpoint struct {
    IP         netip.Addr
    ProbePort  uint16
    VxlanDstPort uint16
}

// PerClientConfig 是 Controller 配置中每個 Client 的設定
type PerClientConfig struct {
    ClientID       ClientID
    ClientName     string          // 標記用，會下發給所有 Client 用於 log 和 WebUI 顯示
    Filters        *FilterConfig   // 可選，per-client Lua 過濾設定
}

// ClientInfo 是 Controller 維護的單一 Client 資訊
type ClientInfo struct {
    ClientID       ClientID
    ClientName     string                // 來自 PerClientConfig，debug 用
    Endpoints      map[AFName]*Endpoint  // 每個 AF 的端點
    LastSeen       time.Time
    Routes         []Type2Route          // Client 上報的 MAC/IP
    AdditionalCost float64               // 來自 PerClientConfig
}

// Type2Route 模仿 EVPN Type-2
type Type2Route struct {
    MAC net.HardwareAddr
    IP  netip.Addr
}

// LatencyEntry 用於 LatencyMatrix
type LatencyEntry struct {
    LatencyMean    float64
    LatencyStd     float64
    PacketLoss     float64
    Priority       int
    AdditionalCost float64  // per-AF AdditionalCost，來自 Client 配置
}

// RouteEntry 用於 RouteMatrix
type RouteEntry struct {
    NextHop ClientID
    AF      AFName
}

// RouteTableEntry 用於 RouteTable
type RouteTableEntry struct {
    MAC     net.HardwareAddr
    IP      netip.Addr
    Owners  map[ClientID]time.Time  // client_id -> ExpireTime
}
```

---

## 2. Controller 架構

### 2.0 Controller 配置

```go
type ControllerConfig struct {
    PrivateKey              [32]byte
    AFSettings              map[AFName]*ControllerAFConfig
    ClientOfflineTimeout    time.Duration          // 預設 300s
    SyncNewClientDebounce   time.Duration          // 預設 5s
    SyncNewClientDebounceMax time.Duration          // 預設 10s
    TopologyUpdateDebounce  time.Duration
    TopologyUpdateDebounceMax time.Duration
    Probing                 ProbingConfig
    AllowedClients          []PerClientConfig
    LogLevel                string                 // "error"/"warn"/"info"/"debug"/"verbose"
    WebUI                   *WebUIConfig           // nil = 不啟用
}

type ControllerAFConfig struct {
    Name              AFName
    Enable            bool
    BindAddr          netip.Addr                // 與 AutoIPInterface 二擇一
    AutoIPInterface   string                    // 網卡名稱，動態 IP 綁定
    AddrSelectScript  string                    // Lua 地址選擇腳本（內嵌或 @file）
    CommunicationPort uint16                    // 同一 port 同時 listen TCP + UDP
    VxlanVNI          uint32
    VxlanDstPort      uint16
    VxlanSrcPortStart uint16
    VxlanSrcPortEnd   uint16
}

type ProbingConfig struct {
    ProbeIntervalS     int   // 預設 60
    ProbeTimes         int   // 預設 5
    InProbeIntervalMs  int   // 預設 200
    ProbeTimeoutMs     int   // 預設 1000
}

type WebUIConfig struct {
    BindAddr    string                        // 監聽地址 (e.g. ":8080")
    MACaliases  map[string]string             // MAC → 友善名稱
    Nodes       map[string]*NodeConfig        // node_name → 顯示配置
}

type NodeConfig struct {
    Label string
    Pos   [2]float64                          // [x, y] 座標
}
```

### 2.1 核心結構體

```go
type Controller struct {
    // === 配置 ===
    Config          *ControllerConfig
    PrivateKey      [32]byte
    ControllerID    ControllerID        // = PublicKey(PrivateKey)

    // === 全域狀態（受 mu 保護）===
    mu              sync.Mutex
    State           *ControllerState

    // === Per-AF Listener ===
    AFListeners     map[AFName]*AFListener

    // === Per-Client 連線管理 ===
    clients         map[ClientID]*ClientConn

    // === Per-Client 統計 ===
    mcastStats      map[ClientID]*McastStats  // multicast 統計（由 Client 上報）

    // === Debounce timers ===
    newClientTimer  *time.Timer         // sync_new_client_debounce
    topoTimer       *time.Timer         // topology_update_debounce
    offlineTicker   *time.Ticker        // 定期檢查 ClientOfflineTimeout

    // === WebUI ===
    webUI           *webui.Server       // nil if not configured
}

type ControllerState struct {
    Clients         map[ClientID]*ClientInfo
    LatencyMatrix   map[ClientID]map[ClientID]*SelectedLatency  // [src][dst]
    RouteMatrix     map[ClientID]map[ClientID]*RouteEntry       // [src][dst]
    RouteTable      []*RouteTableEntry
    LastClientChange time.Time
}

type SelectedLatency struct {
    Latency float64
    AF      AFName
}

// AFListener 管理某個 AF 上的 TCP + UDP 監聽
type AFListener struct {
    AF          AFName
    BindAddr    netip.Addr
    Port        uint16
    TCPListener net.Listener
    UDPConn     net.PacketConn
}

// QueueItem 是發送佇列的元素，同時也是訊息結構
type QueueItem struct {
    State   []byte  // 狀態更新（全量或增量），nil 表示無
    Message []byte  // 非狀態訊息（probe request 等），nil 表示無
}

// ClientConn 代表 Controller 與單一 Client 的連線狀態（controller_com）
type ClientConn struct {
    ClientID    ClientID
    AFConns     map[AFName]*AFConn     // 每個 AF 一條 TCP
    ActiveAF    AFName                 // 當前 active 的 AF（Controller 選擇最早連線的 AF）
    Synced      bool                   // 已發送全量給 Client，後續可發增量
    SendQueue   chan QueueItem         // buffered channel 作為發送佇列
}

type AFConn struct {
    AF          AFName
    TCPConn     net.Conn
    Session     *crypto.Session        // handshake 後的 session key
    ConnectedAt time.Time
    Done        chan struct{}           // closed 時通知 goroutine 停止
    Cleaned     chan struct{}           // handleDisconnect 完成清理後 close
    doneOnce    sync.Once              // 防止 Done 被重複 close
}
```

### 2.2 Controller Goroutines

```
Controller 啟動後的 goroutine 拓撲:

main goroutine
 │
 ├─ [per-AF] tcpAcceptLoop(af)          // 接受 TCP 連線
 │   └─ [per-conn] handleTCPConn(conn)  // 握手 → 讀取訊息迴圈
 │
 ├─ [per-AF] udpReadLoop(af)            // 讀取 UDP broadcast 封包
 │
 ├─ [per-client] clientSendLoop(client) // 從 SendQueue 取訊息，透過 active AF 的 TCP 發送
 │
 ├─ offlineChecker()                    // 定期掃描 LastSeen，超時則移除 Client
 │
 ├─ [per-AF, optional] addrWatchLoop(af)  // autoip_interface: 監聽網卡地址變更
 │
 ├─ [optional] webUI.Run()              // WebUI HTTP + WebSocket server
 │
 └─ signalHandler()                     // 處理 SIGTERM/SIGINT 優雅關閉
```

| Goroutine | 數量 | 職責 |
|-----------|------|------|
| `tcpAcceptLoop` | N (每個 AF 一個) | `net.Listener.Accept()` 迴圈，每個新連線 spawn `handleTCPConn` |
| `handleTCPConn` | M (每條 TCP 連線) | 執行 Noise IK handshake → 識別 ClientID → 進入訊息讀取迴圈，處理 ClientRegister / MAC 上報 / ProbeResults / McastStats 等 |
| `udpReadLoop` | N (每個 AF 一個) | 讀取 UDP 封包，解密後分發 MulticastForward（轉發給其他 Client） |
| `clientSendLoop` | K (每個已連線 Client 一個) | 從 `SendQueue` channel 取出訊息 → 透過 active AF 的 TCP 連線加密發送。當 `Synced=false` 時觸發重新全量同步 |
| `offlineChecker` | 1 | 每隔 N 秒掃描所有 Client 的 `LastSeen`，超過 `ClientOfflineTimeout` 且無 active TCP 連線的才移除並重算路由。有 active 連線時刷新 `LastSeen` |
| `addrWatchLoop` | 0-N (每個使用 autoip_interface 的 AF) | netlink 監聽網卡地址/連結事件 → 1s debounce → 執行 Lua select() → 重新綁定 listener（IPv6 DAD 指數退避） |
| `webUI.Run` | 0-1 | HTTP server 提供 `/`（SPA）、`/ws`（WebSocket 每秒推送狀態）、`/api/state`（JSON） |

### 2.3 Controller 關鍵流程

#### 收到 ClientRegister

```
handleTCPConn:
  1. Noise IK handshake → 得到 session key + ClientID
  2. 讀取 ClientRegister 訊息
  3. mu.Lock()
  4. 更新/建立 ClientInfo（Endpoints, LastSeen）
     - 若已存在 Client 且 Endpoint IP 變更 → 標記 ipChanged
  5. 建立新 AFConn
  6. 替換舊 AFConn（單一清理路徑，統一由 handleDisconnect 處理）:
     - 若同 AF 已有舊連線:
       a. old.CloseDone()  // 通知舊 goroutine 停止（sync.Once 防重複 close）
       b. mu.Unlock()
       c. old.TCPConn.Close()  // 舊 goroutine 的 read 跳出
       d. <-old.Cleaned  // 等待舊 goroutine 的 handleDisconnect 完成清理
       e. mu.Lock()
  7. 設定新 AFConn, 判斷 ActiveAF（最早連線的 AF）
     - trySyncClient: 若有連線但未同步 → 發全量
  8. 新 Client: 更新 LastClientChange, 重設 newClientTimer, pushDelta(ClientJoined)
     已有 Client: pushDelta(ClientInfoUpdate)
     - 若 ipChanged → 同時觸發 resetNewClientDebounce() 重新 probe + 拓撲更新
  9. mu.Unlock()
  10. 進入訊息讀取迴圈（tcpRecvLoop）
  11. tcpRecvLoop 結束後 → handleDisconnect(cc, af, afc)
```

#### handleDisconnect（唯一的清理路徑）

所有清理邏輯集中在 handleDisconnect，替換和正常斷線共用同一路徑：

```
handleDisconnect(cc, af, afc):
  defer close(afc.Cleaned)  // 通知等待者清理完成
  mu.Lock()
  if cc.AFConns[af] != afc: return  // 已被替換，no-op（防禦性檢查）
  delete(cc.AFConns, af)             // 清空該 AF handle
  if af == cc.ActiveAF:
      cc.ActiveAF = ""               // activeAF = nil
      cc.Synced = false              // 需要重新全量同步
      drain(cc.SendQueue)
  // 非 activeAF 斷線：無事發生（僅清除 handle）
  mu.Unlock()
```

- **非 activeAF 斷線**: 只清除 handle，不影響 synced 和 sendqueue
- **activeAF 斷線**: `activeAF=nil` + `synced=false` + drain queue
- 新連線進來時，controller 選新的 activeAF → sendloop 檢查 `synced==false` → 發全量

clientSendLoop 的寫入錯誤不再做清理，統一由 handleDisconnect 處理。

#### State Mutation（增量推送）

```
handleTCPConn 收到 MAC 上報 / ProbeResults:
  1. mu.Lock()
  2. 修改 ControllerState（更新 RouteTable / LatencyMatrix）
  3. 序列化 delta 訊息
  4. for each client where Synced==true:
       select {
       case client.SendQueue <- QueueItem{State: delta}:
       default:
           client.Synced = false        // 佇列滿，sendloop 下次出隊時會覆寫為全量
       }
  5. mu.Unlock()
```

#### 全量推送

```
觸發: 新 Client 連入 / TCP 重連 / Active AF 斷線

不再由入隊方產生全量快照。流程：
  1. synced = false（由 handleDisconnect 或新連線邏輯設定）
  2. trySyncClient: 推入空 QueueItem 觸發 sendloop
  3. sendloop 出隊時檢查 synced=false → 覆寫 item.State = getFullState()
  4. 成功發送後 synced = true
```

#### Topology Update（收到 ProbeResults 後）

```
handleProbeResults:
  1. mu.Lock()
  2. 更新 LatencyMatrix[src][dst]（選擇 priority 低 → latency_mean 低的 AF）
  3. 重設 topoTimer (topology_update_debounce)
  4. mu.Unlock()

topoTimer 到期:
  1. mu.Lock()
  2. 對 LatencyMatrix 套用 AdditionalCost 加權:
     cost[src][dst] = latency[src][dst] + AdditionalCost[dst]
  3. FloydWarshall(加權後的 cost matrix) → RouteMatrix
  4. delta = diff(oldRouteMatrix, newRouteMatrix)
  5. 推送 delta 給所有 Synced Client
  6. mu.Unlock()
```

---

## 3. Client 架構

### 3.0 Client 配置

```go
type ClientConfig struct {
    PrivateKey          [32]byte
    BridgeName          string
    ClampMSSToMTU       bool
    ClampMSSTable       string            // nftables table 名稱（預設 "vxlan_mss"）
    NeighSuppress       bool              // 是否在 vxlan device 和 tap-inject 上啟用 neigh_suppress
    VxlanFirewall       bool              // 是否啟用 nftables VXLAN 注入防護
    VxlanFirewallTable  string            // nftables table 名稱（預設 "vxlan_fw"）
    StatsIntervalS      int               // multicast 統計上報間隔（預設 5s）
    AFSettings          map[AFName]*ClientAFConfig
    InitTimeout         time.Duration     // 預設 10s
    NTPServers          []string
    NTPPeriodH          int               // NTP 校時週期（小時）
    LogLevel            string            // "error"/"warn"/"info"/"debug"/"verbose"
    Filters             *FilterConfig     // Lua 過濾系統配置
}

type ClientAFConfig struct {
    Name              AFName
    Enable            bool
    BindAddr          netip.Addr          // 與 AutoIPInterface 二擇一
    AutoIPInterface   string              // 網卡名稱，動態 IP 綁定
    AddrSelectScript  string              // Lua 地址選擇腳本（內嵌或 @file）
    ProbePort         uint16
    CommunicationPort uint16
    VxlanName         string
    VxlanVNI          uint32
    VxlanMTU          int
    VxlanDstPort      uint16
    VxlanSrcPortStart uint16
    VxlanSrcPortEnd   uint16
    Priority          int                 // 給 Controller 計算路由時參考
    AdditionalCost    float64             // per-AF 繞路懲罰成本（預設 20）
    Controllers       []ControllerEndpoint
}

type ControllerEndpoint struct {
    PubKey [32]byte
    Addr   netip.AddrPort
}

// FilterConfig Lua 過濾系統配置
type FilterConfig struct {
    InputMcast   string    // Lua 腳本: 過濾收到的 broadcast 封包
    OutputMcast  string    // Lua 腳本: 過濾上傳的 broadcast 封包
    InputRoute   string    // Lua 腳本: 過濾收到的路由更新
    OutputRoute  string    // Lua 腳本: 過濾上報的 MAC/neighbor
    RateLimit    RateLimitConfig
}

type RateLimitConfig struct {
    PerMAC    int  // 每個 source MAC 的封包速率上限（預設 64 pps）
    PerClient int  // 每個 Client 的封包速率上限（預設 1000 pps）
}
```

### 3.1 核心結構體

```go
type Client struct {
    // === 配置 ===
    Config        *ClientConfig
    PrivateKey    [32]byte
    ClientID      ClientID              // = PublicKey(PrivateKey)

    // === Per-Controller 狀態 ===
    mu            sync.Mutex
    Controllers   map[ControllerID]*ControllerConn
    AuthorityCtrl *ControllerID         // 當前權威 Controller（nil = 未選定）

    // === 網路設備 ===
    Bridge        string                // bridge name
    VxlanDevs     map[AFName]*VxlanDev  // 每個 AF 的 vxlan device
    TapFD         *os.File              // tap-inject 的 fd

    // === 本地狀態（macMu RWMutex 保護，獨立於 c.mu）===
    macMu         sync.RWMutex          // Write: netlink event, Read: sendloop full push
    LocalMACs     []Type2Route          // 本地 FDB MAC 表

    // === FDB 狀態 ===
    CurrentFDB    map[fdbKey]fdbEntry   // 目前已寫入 kernel 的 FDB

    // === Probe ===
    probeSessions    *SessionManager       // probe channel 的 session 管理
    probeConns       map[AFName]*net.UDPConn // 每個 AF 的 probe UDP socket
    probeResponseChs map[uint64]chan probeResponseData // probe_id → response 收集器
    probeResultsMu   sync.Mutex

    // === NTP ===
    TimeOffset    time.Duration         // 本地時鐘與 NTP 的偏差

    // === Lua 過濾 ===
    filterEngine  *filter.Engine        // Lua 過濾引擎（input/output mcast/route）

    // === Multicast 統計 ===
    mcastStats    *McastStatsTracker    // per-MAC 封包統計追蹤

    // === VXLAN 防火牆 ===
    firewall      *FirewallManager      // nftables 注入防護（nil if disabled）
}

// ControllerConn 代表 Client 與單一 Controller 的連線狀態（client_com）
type ControllerConn struct {
    ControllerID  ControllerID
    AFConns       map[AFName]*ClientAFConn
    ActiveAF      AFName               // 收到 Controller 全量更新的 AF（Controller 決定，Client 跟隨）
    State         *ControllerView      // 該 Controller 推送的狀態（client_side_controller_state）
    Synced        bool                 // 是否已發送本地全量給 Controller（進入增量模式）
    mu            sync.Mutex           // 保護 ActiveAF, Synced, AFConns 等內部狀態
}

type ControllerView struct {
    ClientCount          int
    LastClientChange     time.Time
    Clients              map[ClientID]*ClientInfo
    RouteMatrix          map[ClientID]map[ClientID]*RouteEntry
    RouteTable           []*RouteTableEntry
}

type ClientAFConn struct {
    AF          AFName
    TCPConn     net.Conn
    Session     *crypto.Session
    UDPConn     net.PacketConn        // probe channel (per-AF)
    Cancel      context.CancelFunc
    Connected   bool
}

type VxlanDev struct {
    AF       AFName
    Name     string                   // e.g. "vxlan-v4"
    VNI      uint32
    MTU      int
    BindAddr netip.Addr
}
```

### 3.2 Client Goroutines

```
Client 啟動後的 goroutine 拓撲:

main goroutine
 │
 ├─ ntpSyncLoop()                              // 定期 NTP 校時
 │
 ├─ initDevices()                              // 建立 bridge, vxlan, tap-inject (一次性)
 │
 ├─ [per-controller, per-AF] tcpConnLoop(ctrl, af)   // TCP 連線 + 重連迴圈
 │   └─ tcpRecvLoop(ctrl, af)                        // 讀取 Controller 推送的訊息
 │
 ├─ [per-AF] probeListenLoop(af)               // 監聯 probe channel UDP，回覆 ProbeResponse
 │
 ├─ neighborInit()                             // 同步：subscribe + initLocalMACs（在 TCP 連線前完成）
 ├─ neighborEventLoop()                       // goroutine：處理 netlink 事件
 │
 ├─ tapReadLoop()                              // 從 tap-inject fd 讀取 broadcast 封包 → 過濾 → 上傳 Controller
 │
 ├─ tapWriteLoop()                             // 從 channel 取封包 → 過濾 → 寫入 tap-inject fd
 │
 ├─ fdbReconcileLoop()                         // RouteMatrix/RouteTable 變更時重算 FDB 並寫入 kernel
 │
 ├─ authoritySelectLoop()                      // init_timeout 後選擇權威 Controller，後續持續監控切換
 │
 ├─ mcastStatsLoop()                           // 定期快照 multicast 統計並上報 Controller
 │
 ├─ [per-AF, optional] addrWatchLoop(af)       // autoip_interface: 監聽網卡地址變更
 │
 ├─ [optional] firewallManager()               // vxlan_firewall: 管理 nftables 規則和 IP set
 │
 └─ apiServer()                                // 暴露 API (讀寫 bind_addr 等)
```

| Goroutine | 數量 | 職責 |
|-----------|------|------|
| `ntpSyncLoop` | 1 | 定期向 `ntp_servers` 校時，更新 `TimeOffset` |
| `tcpConnLoop` | C*A (每個 Controller 的每個 AF) | 建立 TCP → Noise IK handshake → 發送 ClientRegister → 啟動 `tcpRecvLoop`。斷線後指數退避重連（1s→2s→...→30s），連線存活超過 10s 時重設退避 |
| `tcpRecvLoop` | C*A | 讀取 TCP 訊息（ControllerState / ControllerStateUpdate），更新 `ControllerView`。收到全量更新時切換 `ActiveAF` |
| `probeListenLoop` | A (每個 AF) | 監聽 probe UDP port，收到 ProbeRequest 解析 payload 取出 probe_id + src_timestamp，回覆 ProbeResponse{probe_id, dst_timestamp, src_timestamp}。收到 ProbeResponse 按 probe_id 路由到對應批次收集器 |
| `neighborInit` + `neighborEventLoop` | 1 | `neighborInit`（同步）：subscribe netlink + `initLocalMACs`（讀 FDB 寫入 LocalMACs），在 TCP 連線前完成。`neighborEventLoop`（goroutine）：處理 `RTM_NEWNEIGH` / `RTM_DELNEIGH`，macMu.WLock → 更新 LocalMACs → 推 incremental 到所有 sendqueue → macMu.WUnlock。上報前套用 output_route Lua filter |
| `tapReadLoop` | 1 | 從 `TapFD` 讀取 broadcast 封包 → output_mcast Lua filter → rate limit → 統計 → 透過 active AF 的 UDP 上傳 Controller (MulticastForward) |
| `tapWriteLoop` | 1 | 從 channel 取出 Controller relay 來的 broadcast 封包 → input_mcast Lua filter → 統計 → 寫入 `TapFD` 注入 bridge |
| `fdbReconcileLoop` | 1 | 監聽 `RouteMatrix` 或 `RouteTable` 變更通知 (channel) → 重新計算 FDB → diff 寫入 kernel (`netlink`)。FDB 使用 master+self split：master entry (NUD_NOARP) 告訴 bridge 轉發到 vxlan port，self entry (NUD_PERMANENT) 告訴 vxlan device 封裝目標 IP |
| `authoritySelectLoop` | 1 | `init_timeout` 後選擇權威 Controller；之後當 Controller Synced 狀態變化時重新評估。權威切換時觸發 firewall 規則更新 |
| `mcastStatsLoop` | 1 | 每 `stats_interval_s` 快照 multicast 統計（per-MAC TxAccepted/TxRejected/RxAccepted/RxRejected + reject reasons）→ 透過 protobuf `MACMcastStats` 上報所有 Controller |
| `addrWatchLoop` | 0-A (每個使用 autoip_interface 的 AF) | netlink 監聽網卡地址/連結事件 → 1s debounce → 執行 Lua select() → 更新 bind_addr → ip link set 更新 vxlan local → 關閉 TCP/UDP 強制重連 → 重建 firewall 規則 |
| `firewallManager` | 0-1 (啟用 vxlan_firewall 時) | 建立 nftables table + INPUT chain + per-AF IP set → 根據 authority controller 的 peer 列表更新 set elements → bind_addr 變更時重建規則 |
| `apiServer` | 1 | Unix socket API (`/tmp/vxlan-client-<id>.sock`)，支援 `GET_BIND_ADDR <af>` 和 `UPDATE_BIND_ADDR <af> <ip>` 指令。更新時：修改 config → `ip link set` 更新 VXLAN local → 關閉 TCP/UDP 連線強制重連 → 重啟 probe listener |

### 3.3 Client 關鍵流程

#### 啟動序列

```
1. 載入配置 (YAML)
2. 初始化 Lua 過濾引擎（載入 filter scripts，建立沙盒 VM）
3. ntpSyncLoop() 啟動，首次校時
4. initDevices():
   a. 建立/確認 bridge
   b. 每個 AF: 建立 vxlan device, attach to bridge, hairpin on, learning off, neigh_suppress 視配置決定
   c. 建立 tap-inject, attach to bridge, learning off, neigh_suppress 視配置決定
   d. 若 clamp_mss_to_mtu: 寫入 nftables 規則（table 名稱由 clamp_mss_table 配置）
   e. 開啟 tap-inject fd (IFF_TAP | IFF_NO_PI)
   f. 若 vxlan_firewall: 建立 nftables 防火牆規則（table 名稱由 vxlan_firewall_table 配置）
5. neighborInit()：subscribe netlink + initLocalMACs（同步完成，確保 LocalMACs 有資料）
6. 啟動 sendloop (per-controller)
7. 啟動所有 per-controller, per-AF tcpConnLoop
8. 啟動 probeListenLoop (per-AF)
9. 啟動 neighborEventLoop（處理 netlink 事件）
10. 啟動 tapReadLoop, tapWriteLoop
11. 啟動 fdbReconcileLoop
12. 啟動 mcastStatsLoop（multicast 統計上報）
13. 若有 autoip_interface: 啟動 addrWatchLoop (per-AF)
14. authoritySelectLoop: 等待 init_timeout → 選擇權威 Controller → 開始寫入 FDB → 更新 firewall peer set
```

#### 權威 Controller 選擇

```
selectAuthority():
  candidates = [ctrl for ctrl in Controllers if ctrl.Synced == true]
  if len(candidates) == 0: return nil

  sort candidates by:
    1. ClientCount DESC
    2. LastClientChange ASC (越早越穩定)
    3. ControllerID ASC (bytes 比較)

  return candidates[0]
```

#### Probe 執行（收到 ControllerProbeRequest）

```
tcpRecvLoop 收到 ControllerProbeRequest:
  1. 檢查是否來自權威 Controller → 否則忽略
  2. spawn probeExecGoroutine(request):
     responseChs[probe_id] = make(chan)   // 按 probe_id 路由 response
     sent = map[peer,af] → 0             // 計數：已發送
     for i := 0; i < probe_times; i++:
       srcTimestamp = ntp.Now()
       for each peer in knownClients:
         for each AF where self.enabled && peer.enabled:
           send ProbeRequest{probe_id, src_timestamp} via probe channel UDP
           sent[peer,af]++
       sleep(in_probe_interval_ms)
     wait(probe_timeout_ms), collect from responseChs[probe_id]:
       latency = resp.dst_timestamp - resp.src_timestamp  // 單向 local→peer
       latencies[peer,af].append(latency)
     delete(responseChs[probe_id])
     for each (peer,af):
       packet_loss = 1.0 - len(latencies[peer,af]) / sent[peer,af]
       latency_mean = mean(latencies[peer,af])
       latency_std  = std(latencies[peer,af])
     send ProbeResults to ALL Controllers (via active AF TCP)

  probeListenLoop 收到 ProbeRequest:
    解析 payload → req{probe_id, src_timestamp}
    回覆 ProbeResponse{probe_id, dst_timestamp=ntp.Now(), src_timestamp=req.src_timestamp}

  probeListenLoop 收到 ProbeResponse:
    根據 resp.probe_id 路由到 responseChs[probe_id]（忽略無對應 channel 的 late response）
```

#### FDB 寫入

```
fdbReconcileLoop (觸發: RouteMatrix 或 RouteTable 有更新):
  1. 若 AuthorityCtrl == nil → skip
  2. view = Controllers[AuthorityCtrl].State
  3. desiredFDB = {}
  4. for each route in view.RouteTable:
       ownerClient = selectOwner(route.Owners, view.LatencyMatrix)  // 延遲最小的
       entry = view.RouteMatrix[myClientID][ownerClient]
       if entry == nil: continue  // 不可達
       desiredFDB[route.MAC] = {dev: vxlanDevs[entry.AF], dst: peer.Endpoints[entry.AF].IP}
  5. diff(CurrentFDB, desiredFDB):
       - 新增: netlink bridge fdb append
       - 刪除: netlink bridge fdb del
       - 變更: del + append
  6. CurrentFDB = desiredFDB
```

---

## 4. Crypto 模組 (`pkg/crypto`)

### 4.1 Session

```go
type Session struct {
    LocalIndex   uint32
    RemoteIndex  uint32
    SendKey      [32]byte
    RecvKey      [32]byte
    SendCounter  atomic.Uint64    // nonce counter (發送方向)
    RecvCounter  uint64           // 上次驗證的 counter (TCP: 嚴格遞增)
    RecvWindow   *SlidingWindow   // UDP only: 2048-bit sliding window 防 replay
    PeerID       ClientID         // 握手後關聯的對端 ID
    CreatedAt    time.Time
}

type SlidingWindow struct {
    bitmap  [256]byte  // 2048 bits
    top     uint64     // 窗口最高 counter
}
```

### 4.2 Noise IK Handshake

```go
// Initiator 端
func HandshakeInitiate(
    localStatic  [32]byte,  // private key
    remoteStatic [32]byte,  // peer public key
) (initMsg []byte, state *HandshakeState, err error)

// Responder 端
func HandshakeRespond(
    localStatic [32]byte,
    initMsg     []byte,
    allowedKeys []ClientID,  // Controller: Allowed_Clients; Client: controller pubkeys
) (respMsg []byte, session *Session, err error)

// Initiator 完成
func HandshakeFinalize(
    state   *HandshakeState,
    respMsg []byte,
) (session *Session, err error)
```

---

## 5. Protocol 模組 (`pkg/protocol`)

### 5.1 TCP Framing

```go
// TCP 訊息格式: [4B length][1B msg_type][NB encrypted_payload]
// length = 1 + N

func WriteTCPMessage(conn net.Conn, session *Session, msgType MsgType, payload []byte) error
func ReadTCPMessage(conn net.Conn, session *Session) (msgType MsgType, payload []byte, err error)
```

### 5.2 UDP Packet

```go
// UDP 封包格式: [1B msg_type][4B receiver_index][8B counter][NB encrypted_payload]

func WriteUDPPacket(conn net.PacketConn, addr net.Addr, session *Session, msgType MsgType, payload []byte) error
func ReadUDPPacket(data []byte, findSession func(uint32) *Session) (msgType MsgType, payload []byte, peerID ClientID, err error)
```

### 5.3 MsgType 定義

```go
type MsgType byte

const (
    // Handshake
    MsgHandshakeInit MsgType = 0x01
    MsgHandshakeResp MsgType = 0x02

    // Client → Controller (TCP)
    MsgClientRegister    MsgType = 0x10
    MsgMACUpdate         MsgType = 0x11
    MsgProbeResults      MsgType = 0x12
    MsgMcastStats        MsgType = 0x13  // multicast 統計上報

    // Controller → Client (TCP)
    MsgControllerState       MsgType = 0x20  // 全量
    MsgControllerStateUpdate MsgType = 0x21  // 增量
    MsgControllerProbeRequest MsgType = 0x22

    // Broadcast relay (UDP, communication channel)
    MsgMulticastForward  MsgType = 0x30  // Client → Controller
    MsgMulticastDeliver  MsgType = 0x31  // Controller → Client

    // Probe (UDP, probe channel)
    MsgProbeRequest      MsgType = 0x40
    MsgProbeResponse     MsgType = 0x41
)
```

---

## 6. IPC / 通訊流程總覽

### 6.1 Client ↔ Controller (TCP Communication Channel)

```
Client                                    Controller
  │                                           │
  │──── TCP connect ─────────────────────────>│  tcpAcceptLoop
  │                                           │
  │──── HandshakeInit ───────────────────────>│
  │<─── HandshakeResp ───────────────────────│  → session key established, ClientID known
  │                                           │
  │──── ClientRegister ──────────────────────>│  → Controller 更新 ClientInfo
  │<─── ControllerState (全量) ──────────────│  → Client 標記 Synced=true
  │                                           │
  │──── MACUpdate ───────────────────────────>│  (持續, debounced)
  │<─── ControllerStateUpdate (增量) ────────│  (持續)
  │                                           │
  │<─── ControllerProbeRequest ──────────────│  (觸發 probe)
  │──── ProbeResults ────────────────────────>│  (probe 完成後)
  │                                           │
```

### 6.2 Client ↔ Client (UDP Probe Channel)

```
Client A                                  Client B
  │                                           │
  │  (若無 session key，先 handshake)          │
  │──── HandshakeInit ───────────────────────>│
  │<─── HandshakeResp ───────────────────────│
  │                                           │
  │──── ProbeRequest {probe_id, src_ts} ─────>│
  │<─── ProbeResponse {probe_id, src_ts,     ─│
  │                     dst_ts}                │
  │                                           │
  │  按 probe_id 路由到對應批次收集器
  │  單向延遲 = dst_ts - src_ts (local→peer)
  │  丟包率 = 1 - received / sent
```

### 6.3 Broadcast Relay (UDP Communication Channel)

```
Client A          Controller           Client B, C, D...
  │                   │                      │
  │ (tap-inject read) │                      │
  │── MulticastFwd ──>│                      │
  │                   │── MulticastDeliver ─>│ (寫入 tap-inject)
  │                   │── MulticastDeliver ─>│
  │                   │  (skip Client A)     │
```

---

## 7. Debounce 機制

### 7.1 Client: FDB 變更（無 debounce，即時增量）

```
neighborInit()（同步，在 TCP 連線前完成）:
  1. subscribe netlink 事件
  2. initLocalMACs(): 讀 FDB 全量 → macMu.WLock → 寫入 LocalMACs → macMu.WUnlock

neighborEventLoop()（goroutine）:
  3. 每個 RTM_NEWNEIGH/RTM_DELNEIGH:
     - 判斷 add 或 delete（RTM_DELNEIGH 或 NUD 狀態不可用 → delete）
     - macMu.WLock → 更新 LocalMACs → encode incremental → 推入所有 controller sendqueue → macMu.WUnlock
     - queue 滿 → 只斷該 controller 的 activeAF（CloseDone）
  不使用 debounce：單條增量成本極低，TCP Nagle 自然合併
```

### 7.2 Controller: 新 Client (sync_new_client_debounce)

```go
// 收到新 Client 連線:
// 重設 newClientTimer (sync_new_client_debounce)
//
// newClientTimer 到期:
//   對所有 Client 發送 ControllerProbeRequest
```

### 7.3 Controller: Topology Update (topology_update_debounce)

```go
// 收到 ProbeResults:
// 更新 LatencyMatrix
// 重設 topoTimer (topology_update_debounce)
//
// topoTimer 到期:
//   FloydWarshall → RouteMatrix
//   推送 ControllerStateUpdate
```

---

## 8. 多 AF 連線管理

### Controller 側（controller_com）

- 同一 `ClientID` 可能有多條 AF 連線（如 v4 + v6）
- `ClientConn.ActiveAF` = 最早建立連線的 AF（**Controller 決定**）
- **非 activeAF 斷線** → 清空該 AF handle，無其他影響
- **activeAF 斷線** → `activeAF = nil` + `synced = false` + drain queue
- 新連線進來（通過驗證）：
    - 對應 AF handle 為 nil → 直接設定
    - 對應 AF handle 不為 nil → 關閉舊連線 → 等 handleDisconnect 清理完 → 替換
- 新連線設定後，sendloop 若 activeAF==nil 則直接選存活 AF 寫入 activeAF，檢查 synced=false → 發全量
- `activeAF`、`synced`、`AFConns` 受 Controller.mu 保護

### Client 側（client_com）

- 對每個 Controller 維護多條 AF 連線
- 收到某 AF 的 Controller 全量更新 → 將該 AF 設為 `ActiveAF`（**跟隨 Controller 決策**）→ 推 empty trigger 到 sendqueue
- `synced` 在 sendloop getFullState() 之後、send 之前設為 true
- sendloop 流程：dequeue → `activeAF == ""` 則 discard → `!synced` 則 getFullState(RLock) → synced=true → send full → discard item → `synced` 則 send incremental
- 某 AF 斷線 → 自動重連（指數退避），不影響其他 AF。若斷的是 activeAF → `activeAF=""` + `synced=false`
- `activeAF`、`synced`、`AFConns` 受 `c.mu` 保護

### activeAF 語義統一

| | Controller 端 | Client 端 |
|---|---|---|
| 誰設定 | Controller 自己選（最早連線的 AF） | 收到 Controller 全量更新時設定 |
| 含義 | 透過此 AF 發送訊息給 Client | 透過此 AF 接收 Controller 訊息 |
| 何時 nil | active AF 斷線且無其他 AF | active AF 斷線 |
| sendloop 行為 | activeAF==nil 時直接選存活 AF 並寫入 activeAF | activeAF==nil 時丟棄，等 controller 選好 |

---

## 9. 關鍵 Channel 設計

```go
// Controller: Per-Client 發送佇列
SendQueue chan QueueItem  // buffered, 容量可配置 (e.g. 256)

// Client: broadcast 注入佇列
tapInjectCh chan []byte  // tapWriteLoop 從此 channel 讀取並寫入 tap fd

// Client: FDB 重算通知
fdbNotifyCh chan struct{}  // RouteMatrix 或 RouteTable 變更時發送通知

// Client: 權威變更通知
authorityChangeCh chan struct{}  // Synced 狀態變化時觸發重新評估
```

---

## 10. 並發與鎖設計

### 鎖清單

| 鎖 | 保護範圍 | 持有者 |
|---|---|---|
| `Controller.mu` | ControllerState, clients map, AFConns, ActiveAF, Synced, debounce timers | handleTCPConn, handleDisconnect, tcpRecvLoop, offlineChecker, triggerSyncNewClient, triggerTopologyUpdate |
| `c.mu` (Client 端) | Controllers map, ActiveAF, MACsSynced, AFConns（per-controller 通訊狀態）| tcpConnLoop, tcpRecvLoop, sendloop, neighborEventLoop |
| `macMu` (Client 端 RWMutex) | LocalMACs（本地 FDB MAC 表）| neighborEventLoop(W), sendloop(R via getFullState) |
| `client_side_controller_state RWLock` | Controller 推送的狀態視圖 | tcpRecvLoop(W), fdbReconcileLoop(R) |

### 死鎖預防

Client 端有兩把鎖：`macMu`（RWMutex，保護 LocalMACs）和 `c.mu`（Mutex，保護 per-controller 狀態）。

**鎖順序**：允許巢狀 `macMu → c.mu`，禁止反向。

```
handleNeighEvent (write):  macMu.WLock → c.mu.Lock → c.mu.Unlock → macMu.WUnlock（巢狀）
sendloop (read):           c.mu.Lock → c.mu.Unlock → macMu.RLock → macMu.RUnlock → c.mu.Lock → c.mu.Unlock（序列，不同時持有）
```

不存在 A→B / B→A 的死鎖條件。

Queue push 使用 `select { default: }`（非阻塞），queue 滿時斷線而非阻塞，避免 WLock 持有者被 queue 阻塞。

### client_side_controller_state 寫入觸發 FDB

```go
func (cs *ControllerState) Write(update) {
    cs.WLock()
    套用 update
    cs.WUnlock()

    if 是權威控制器 {
        notifyFDB()  // non-blocking channel push
        // fdbReconcileLoop 異步執行：RLock 讀 controller state → 計算 FDB → netlink 寫入 kernel
    }
}
```

`notifyFDB()` 在鎖外調用，避免嵌套鎖。FDB reconcile goroutine 用 RLock 讀取狀態，不與 Write 的 WLock 衝突。

### handleDisconnect 的 Cleaned 信號

AFConn 持有 `Cleaned chan struct{}`，`handleDisconnect` 執行 `defer close(afc.Cleaned)` 通知等待者清理完成：

- **替換場景**: handleTCPConn close 舊連線 → 等 `<-oldAfc.Cleaned` → 繼續設新連線
- **正常斷線**: handleDisconnect 完成後 close Cleaned（無人等待，自然 GC）
- **Done 用 sync.Once 保護**: 防止多個 goroutine 同時 close（例如第三條連線幾乎同時到達）

---

## 11. 外部依賴

| 依賴 | 用途 |
|------|------|
| `golang.org/x/crypto` | X25519, ChaCha20-Poly1305 |
| `google.golang.org/protobuf` | Protobuf 序列化 |
| `github.com/vishvananda/netlink` | Netlink: bridge fdb, 鄰居表監聽, vxlan/bridge device 管理 |
| `gopkg.in/yaml.v3` | YAML 配置解析 |
| `github.com/beevik/ntp` | NTP 校時 |
| `github.com/yuin/gopher-lua` | Lua VM：過濾系統 + 地址選擇腳本 |
| `github.com/gorilla/websocket` | WebUI WebSocket 推送 |

---

## 12. Graceful Shutdown

```
收到 SIGTERM/SIGINT:
  1. 停止接受新 TCP 連線
  2. 關閉所有 debounce timer
  3. Controller: 關閉所有 Client SendQueue → clientSendLoop 結束 → 關閉 TCP → 關閉 WebUI server
  4. Client: 關閉 tap fd, 清理 FDB entries, 移除 nftables 規則（MSS clamping + VXLAN firewall）
  5. 關閉 vxlan devices (可選，留給 OS 清理)
  6. 退出
```
