# VXLAN Controller:

一個 vxlan 控制器,分成 Controller 和 Client 兩個角色

目的: 讓所有 client 使用 vxlan 組成 L2 大內網,類似 EVPN 。
由 Client 蒐集本地的 mac address 和 local IP(用來做 ARP/NA 代答) 發給 Controller , Controller 計算 L2路由分發 給 Client ,寫入 linux kernel fdb

類似 VXLAN-EVPN ，但 frr 遲遲不支援 ipv6 ，所以想自己搓一個

### Configuration

Client 配置(client.conf）:
* private_key：私鑰，兼任 id (client_id=公鑰) 和加密。
    * 使用者可以用 wg genkey 和 wg pubkey 生成該值填入 config
    * 內部表示為 fixed byte array ([u8; 32])，設定檔中以 base64 編碼儲存（WireGuard 風格）
    * 加密方案仿照 **WireGuard Noise IK pattern**：
        * X25519 ECDH（static + ephemeral）推導 session key pair
        * ChaCha20-Poly1305 對稱加密，counter-based nonce
    * 所有節點間通訊使用 session key 加密
    * probe channel: 類似 WireGuard，如果本地沒有該 peer 的 session key 就發起 handshake，任何一方都可以發起，完成後拿到 session key 進行通訊
    * 收到 handshake，如果成功就建立 session key；如果本地已有 key 就替換（應對對端重啟）。若攻擊者無 privkey 則握手失敗，不影響現有通訊
    * 每次 communication channel（TCP）連線時握手，建立 session key，同時關聯對應的 client_id
    * broadcast channel（UDP）復用同一 port 上 TCP 握手建立的 session key，透過 receiver_index 識別 session
* bridge_name: 要監控 FDB 變更的 Linux 橋接器名稱(例如「br-vxlan」)僅處理此橋接器及其從屬連接埠上的 FDB 事件
* clamp_mss_to_mtu: true / false
* clamp_mss_table: nftables table 名稱（預設 "vxlan_mss"），用於 MSS clamping 規則
* neigh_suppress: true / false: 是否在 VXLAN device 和 tap-inject 上啟用 `neigh_suppress`
    * 具體行為：bridge flood ARP/NS 到某個 port 時，若該 port 啟用了 `neigh_suppress` 且本地鄰居表有答案，bridge 不將 ARP/NS 送往該 port，改為直接生成 reply 回給發問者
    * 啟用時需要同時對 VXLAN device 和 tap-inject 都設定：
        * VXLAN device：阻止 ARP/NS 經由 vxlan data plane 轉發出去
        * tap-inject：阻止 ARP/NS 被 Client 讀走後上傳 Controller relay 給所有人
        * 兩者都設才能確保 ARP/NS 完全不外送
    * 鄰居表內容完全由 Controller 下發（步驟 14-16），不依賴 bridge 自學習
    * **啟用（on）**:
        * 優點：大幅減少 broadcast 流量。ARP/ND 是最常見的 broadcast，啟用後在本地直接代答，不需經過 Controller relay，降低延遲和頻寬開銷
        * 缺點：依賴 Controller 鄰居表的完整性。若遠端新裝置剛上線、尚未產生任何封包，Controller 還沒有它的鄰居資訊，此時 ARP/NS 會被 suppress 但無法代答，導致查詢失敗，直到 Controller 下發該裝置的鄰居資訊後才能解析
    * **關閉（off）**:
        * 優點：ARP/NS 照常廣播到所有節點，遠端新裝置即使靜默上線、尚未被 Controller 收錄，也能透過廣播讓對方收到 ARP/NS 後回應，立刻建立連線。對 Controller 鄰居表的時效性要求較低，容錯性更好
        * 缺點：所有 ARP/ND 請求都走 tap-inject → UDP 上傳 Controller → relay 給所有 Client 的完整路徑，broadcast 流量大，延遲高，尤其在節點數多的情況下開銷顯著
* vxlan_firewall: true / false: 是否啟用 nftables VXLAN 注入防護
    * 啟用時，會在 nftables 中建立 INPUT chain，只允許已知 peer endpoint IP 的 UDP 封包進入 VXLAN port
    * 每個 AF 建立一個 IP set（例如 `af_v4`、`af_v6`），包含該 AF 下所有已知 peer 的 endpoint IP
    * peer 加入/離開時自動更新 set，不需重建整個 table
    * bind_addr 變更時重建規則（因為需要偵測地址族）
* vxlan_firewall_table: nftables table 名稱（預設 "vxlan_fw"），用於 VXLAN 防火牆規則
* stats_interval_s: multicast 統計上報間隔（預設 5 秒）
    * Client 追蹤每個 source MAC 的 multicast 封包統計：TxAccepted、TxRejected、RxAccepted、RxRejected
    * 每隔此間隔快照並重置統計，透過 protobuf `MACMcastStats` 訊息上報給所有 Controller
    * 同時記錄每個方向的 reject 原因（如 "rate_limited"、"denied"、自定義 Lua 原因）
* log_level: 日誌級別（預設 "info"）
    * 可選值："error"、"warn"、"info"、"debug"、"verbose"
    * error(0): 僅顯示錯誤
    * warn(1): 顯示警告及以上
    * info(2): 顯示一般資訊及以上（預設）
    * debug(3): 顯示除錯資訊及以上
    * verbose(4): 顯示所有資訊
* filters: Lua 過濾系統配置
    * 使用 gopher-lua 執行使用者自定義 Lua 腳本，安全沙盒（僅載入 Base、String、Math、Table 標準庫）
    * 支援四個 hook:
        * input_mcast: 過濾從 Controller relay 收到的 broadcast/multicast 封包
        * output_mcast: 過濾從 tap-inject 讀取準備上傳的 broadcast/multicast 封包
        * input_route: 過濾從 Controller 收到的路由更新
        * output_route: 過濾準備上報給 Controller 的 MAC/neighbor 更新
    * 每個 hook 定義一個 Lua `filter(pkt)` 函數：
        * 回傳 `true`: 接受
        * 回傳 `false/nil`: 拒絕，原因為 "denied"
        * 回傳字串: 拒絕，原因為該字串
    * multicast filter 的 pkt 欄位: src_mac, dst_mac, ethertype, size, ipv6_next_header, icmpv6_type
    * route filter 的 pkt 欄位: mac, ip, is_delete
    * 腳本可以用 YAML 內嵌字串或 "@" 前綴指定檔案路徑
    * rate_limit: 頻率限制設定
        * per_mac: 每個 source MAC 的封包速率上限（預設 64 pps）
        * per_client: 每個 Client 的封包速率上限（預設 1000 pps）
* AddressFamilySpecficSettings: map<af_name, per_af_conf>
    * v4:
        * name: v4
        * enable:true/false
        * local bind addr（與 autoip_interface 二擇一）
        * autoip_interface: 網卡名稱（與 bind_addr 二擇一），啟用動態 IP 綁定
            * 設定後，系統透過 netlink 監聽該網卡的地址/連結事件（1 秒 debounce）
            * 執行 Lua `select(info)` 函數選擇最佳地址
            * 變更時自動更新 bind_addr 並重建防火牆規則
        * addr_select: 內嵌 Lua 腳本，定義 `select(info)` 函數選擇地址
        * addr_select_file: Lua 腳本檔案路徑（與 addr_select 二擇一）
        * 預設地址選擇邏輯:
            * v4: 優先公網 IP > 上一次使用的 IP > 私網 IP，過濾 deprecated 和 link-local
            * v6: 優先公網 IP（接近 /64）> 上一次使用的 IP > ULA，過濾 deprecated 和 link-local
        * probe port
        * communication port
        * vxlan_name
        * vxlan vni
        * vxlan mtu
        * priority
          * 給 controller 計算路由時參考
        * additional_cost: 每個 AF 的 AdditionalCost（預設 20）
            * 允許對不同 AF 設定不同的繞路懲罰成本
            * 例如 v4 的 additional_cost=10，v6 的 additional_cost=30，則更傾向走 v4 路徑
        * controllers (pubkey,addr:port)[](可以有多個 controller)
    * v6:
        * name: v6
        * enable:true/false
        * local bind addr（與 autoip_interface 二擇一）
        * autoip_interface: 同 v4
        * addr_select / addr_select_file: 同 v4
        * probe port
        * communication port
        * vxlan_name
        * vxlan vni
        * vxlan mtu
        * priority
            * 給 controller 計算路由時參考
        * additional_cost: 同 v4
        * v6 controllers (pubkey,addr:port)[](可以有多個 controller)
            * 若有多個( 例如 v4+v6 雙線上網)使用相同 pubkey ，視為同一個 controller。
            * 此時會建立 v4+v6 兩條通訊連結，目的是讓 controller 得知 client 的 v4+v6 地址。(或更多 af)
            * **多 AF 通訊連結選擇機制**:
                * 每個 controller 的每條 AF 連線各自維護一個 `active` 狀態
                * **Controller 視角**: 同一 client_id 的多條 AF 連線中，使用**最早建立連線**的一條作為 active communication channel
                    * tcp 建立 → 握手加密（同時得知 client_id）→ 發送全量更新
                    * 若 active 連線斷線，Controller 切換到剩餘連線中**最早連線**的 AF，對其發送全量更新（及後續增量更新）
                * **Client 視角**: 每當某個 AF 收到該 Controller 的全量更新，就自動將該 Controller 的 active communication channel 切換到這個 AF
                    * Client 上報訊息（MAC/鄰居/ProbeResults 等）時，使用當前 active AF 的 communication channel
                    * 某條 AF 的 TCP 斷線後自動嘗試重連，不影響其他 AF 的連線
                    * 重連成功後走正常流程（握手 → Controller 判斷是否設為 active → 若是則發送全量更新 → Client 收到後切換 active）
    * asia_v4:
        * 目前假設只有 v4+v6 兩個 af ，但使用 map 或 dict，可以允許更多 af
        * 設計原則是
          1. client 有多個 af
          2. controller 知道每個 client 有哪些 af
        * 所有**相同 af 內的 client 會 full mesh 互連**
        * 所以搭配多 af 設計，可以組合出更多變的用法。
          * 最基本的用法就只有 v4 +v6 ，部分節點 v4 only 部分節點 v6 only ，靠 v4+v6 雙線節點中轉
          * 還可以分出這些 af:
              * asia_v4
              * europe_v4
              * america_v4
              * 以及一個 backbone_v4 連接所有區域
          * 這樣子 asia_v4 節點就不會和 europe_v4 互聯，必須經過擁有 backbone_v4 屬性的節點
* 其中 local bind addr 允許動態變換(對應浮動IP的情況)
    * 暴露 API 讀寫。搭配一個 syncer ，讀取網卡 IP 變化，對比，更新到 client 裡面
    * 有人呼叫更新時，新建 socket 綁定新 IP,通訊切過去,釋放舊 socket
* init_timeout：初始化模式下等待的時間（以秒為單位），之後才會選擇權威控制器，並編寫 FDB 條目（預設值：10）。這允許所有控制器穩定運行client_count，last_client_change_timestamp 之後客戶端才會提交權威選擇。
* ntp_servers[]: NTP server 列表，校準本機時間的誤差
* ntp_period_h: NTP 校時週期（小時）
* ntp_rtt_threshold_ms: NTP RTT 門檻（預設 50ms），超過此門檻的 NTP server 回應會被忽略，避免高延遲 server 污染時間偏差
* api_socket: Unix socket 路徑，用於 CLI 工具和外部程式與 Client 互動


Controller 配置:

* private_key：私鑰，兼任 ID 和加密。
    * 格式同 Client：內部 [u8; 32]，設定檔 base64 編碼
    * 加密方式同 Client：X25519 ECDH + ChaCha20-Poly1305
* log_level: 日誌級別（預設 "info"），同 Client
* web_ui: WebUI 配置（可選，不設定則不啟用）
    * bind_addr: 監聽地址（例如 ":8080"、"0.0.0.0:8080"）
    * 提供即時 Web 管理介面，透過 WebSocket 每秒推送狀態快照
    * 顯示內容:
        * 所有 Client 列表及狀態
        * RouteTable（MAC/IP 路由表）
        * LatencyMatrix（延遲矩陣）
        * RouteMatrix（路由矩陣）
        * 每個 Client 的 multicast 統計（per-MAC 封包計數、reject 原因）
    * 端點:
        * `/`: 內嵌 SPA 頁面
        * `/ws`: WebSocket 即時推送
        * `/api/state`: 一次性 JSON 狀態查詢
    * mac_aliases: MAC 地址別名 map（顯示友善名稱）
    * nodes: 節點顯示配置 map（node_name → {label, pos:[x,y]}）
* AddressFamilySpecficSettings: map<af_name, per_af_conf>
    * v4:
        * name: v4
        * enable:true/false
        * local bind addr（與 autoip_interface 二擇一）
        * autoip_interface: 網卡名稱，啟用動態 IP 綁定（同 Client，但 Controller 端會在地址變更時重新綁定 listener，IPv6 DAD 使用指數退避）
        * addr_select / addr_select_file: 同 Client
        * communication port: 同一 port 同時 listen TCP（控制面）和 UDP（broadcast relay）。Controller 透過 Client TCP 連線的 remote IP 得知該 AF 下的 Client IP
        * vxlan vni
        * vxlan dstport
        * vxlan srcport-start, srcport-end
    * v6:
        * name: v6
        * enable:true/false
        * local bind addr（與 autoip_interface 二擇一）
        * autoip_interface / addr_select / addr_select_file: 同 v4
        * communication port: 同一 port 同時 listen TCP（控制面）和 UDP（broadcast relay）。Controller 透過 Client TCP 連線的 remote IP 得知該 AF 下的 Client IP
        * vxlan vni
        * vxlan dstport
        * vxlan srcport-start, srcport-end
            * id, dstport, srcports 在 controller 和所有 client 中必須完全相同
            * 因為 linux 不允許兩兩節點用各自的 port 通訊，要統一
            * 但未來專案可以擴展到非 vxlan 的場景，所以保留各自的 port 設定，戰未來
* ClientOfflineTimeout: Client 離線超過這麼久視為斷線,從路由表計算中移除。然後刪除其 Type-2 Route 條目並重新計算路由的持續時間（以秒為單位）（預設值：300）
* sync_new_client_debounce: 新客戶端連線後觸發 ControllerProbeRequest 事件前等待的秒數（預設值：2）
  * 如果在此期間有其他用戶端連接，計時器將重設
  * 必須滿足：sync_new_client_debounce > probe_times * in_probe_interval_ms + probe_timeout_ms + probe_request_timeout
* sync_new_client_debounce_max: sync_new_client_debounce 的最大等待時間（預設值：10）。從第一次新客戶端連線算起，即使持續有新客戶端加入，超過此時間也會強制觸發 ControllerProbeRequest，避免被無限推遲
    * 目的: 每當新客戶端連線進來， controller 要發送 ControllerProbeRequest ， client 收到以後發送 Probe 測量延遲，讓 controller 重新計算路由表
    * 但剛啟動時，短時間有大量 client 同時加入，導致大量重複的 Probe
    * 所以要加一個延遲，確認一段時間都沒有新人加入，才發送 ControllerProbeRequest
* topology_update_debounce: 收到 ProbeResults 後等待的靜默期，期間無新 ProbeResults 才觸發 topology_update（預設值：1）
* topology_update_debounce_max: topology_update_debounce 的最大等待時間（預設值：5）。從第一次收到 ProbeResults 算起，即使持續有新結果進來，超過此時間也會強制執行 topology_update，避免被無限推遲
* probing:
    * probe_interval_s: 60
    * probe_times: 5
    * in_probe_interval_ms: 200
    * probe_timeout_ms: 1000
    * 限制:
        * Client 收到以後，需要按照 in_probe_interval_ms 間隔，總共發出 probe_times 個 probe ，每個 probe 最多等待 probe_timeout_ms
        * 所以總時間花費 = probe_times * in_probe_interval_ms + probe_timeout_ms
        * 必須保證單一 probe 的總時間花費不能超過 probe_interval_s 多留一秒當緩衝，所以有以下限制
        * probe_times * in_probe_interval_ms + probe_timeout_ms < (probe_interval_s - 1) * 1000.
* Allowed_Clients: [PerClientConfig]
    * PerClientConfig:
        * client_id: 公鑰，用來識別 Client
        * client_name: 標記用，會包含在 ControllerState 中下發給所有 Client，用於 debug log 顯示可讀名稱
            * client_name 傳播流程: Controller 配置 → ClientInfo.ClientName → ControllerState 下發 → Client 在 log 和 FDB 中使用友善名稱
        * filters: 每個 Client 的 Lua 過濾設定（可選），格式同 Client 端的 filters
        * af_settings: per-AF 設定（可選）
            * endpoint_override: DDNS 域名或 IP，覆蓋 TCP remote IP 作為該 AF 的 endpoint。適用於 NAT 後面的 Client，Controller 從 TCP 連線看到的是 NAT IP，但實際 VXLAN 封包需要送到不同的地址（例如 DDNS 域名）。Controller 會快取 DNS 解析結果
        * AdditionalCost: （已移至 per-AF，此處不再使用）
        * 注意: AdditionalCost 現在是 per-AF 設定，在 Client 配置的 address_families.*.additional_cost 中指定（預設值：20）
            * 用途：在 LatencyMatrix 上加權後再計算 Floyd-Warshall，避免為了微小延遲差而繞路
            * **Per-AF AdditionalCost**: 每個 AF 可以獨立設定 additional_cost，允許對不同網路路徑設定不同的繞路懲罰
                * 例如：v4 additional_cost=10，v6 additional_cost=30 → 更傾向走 v4
                * Probe 結果中每個 AF 的 cost = latency_mean + additional_cost[af]
                * `LatencyInfo.BestPath()` 選擇 cost 最低的 AF
            * 範例：

              假設三個節點 A、B、C，所有節點 `AdditionalCost=10`：

              | Path    | Latency | AdditionalCost | Cost | Win |
              |---------|---------|----------------|------|-----|
              | A→B→C   | 3ms     | 20             | 23   |     |
              | A→C     | 4ms     | 10             | 14   | O   |

              A→C 直連勝出。`AdditionalCost=10` 意味著：必須能省下 10ms，繞路才值得
            * 其他用法：
                * 流量昂貴的節點設定 `AdditionalCost=10000`，其他節點就不會經過它中轉，除非別條路線全部不可達
                * 全部節點都設定 `AdditionalCost=10000`，效果為無視延遲、全節點盡量直連，只有直連失敗才繞路
* cost_mode: "probe"（預設）或 "static"
    * "probe": 使用 Probe 探測的延遲作為 Floyd-Warshall 的 cost（預設行為）
    * "static": 使用 static_costs 中預定義的 cost，但仍檢查 Probe 可達性（PacketLoss < 1.0 才視為可達）
    * 可透過 CLI 工具 `vxscli cost setmode` 在運行時切換
* static_costs: map[src_name][dst_name][af_name] → cost
    * 預定義的靜態 cost 矩陣，僅在 cost_mode="static" 時使用
    * key 使用 client_name（非 client_id），方便人類閱讀和編輯
    * 可透過 CLI 工具 `vxscli cost store` 將當前 Probe 結果持久化為 static_costs 寫回配置檔
* api_socket: Unix socket 路徑，用於 CLI 工具（vxscli）和外部程式與 Controller 互動

## 運作過程:

分成3個通道

1. data channel(udp via vxlan port): 實際的資料傳輸通道,明文傳輸
2. probe channel(udp via probe port): Client 之間發送 Latency Probe ,計算延遲。使用 X25519 ECDH shared secret + ChaCha20-Poly1305 加密
3. communication channel(communication port): Client - Controller 之間通訊，同一個 port 上同時使用 TCP 和 UDP
    * 使用 X25519 ECDH shared secret + ChaCha20-Poly1305 加密
    * TCP: 控制面訊息（可靠、有序）
        * ClientRegister（上報 client_id、各 AF 的 probe port / vxlan dstport）
        * 上報 local mac / neighbor
        * 下載 L2 路由
        * ControllerState / ControllerStateUpdate
        * ControllerProbeRequest / ProbeResults
    * UDP: 廣播封包轉發（盡力傳輸、低延遲）
        * 上傳廣播封包（MulticastForward，有 rate limit）
        * 下載廣播封包（MulticastDeliver）



## 實作細節:

0. 初始化時 Client 會使用 ntp_servers 校時，得知系統時間偏差。接下來所有時間計算都會套用修正。後續定時重新校正
1. 首先 Client 會使用 tcp(local bind addr:communication port --> controller addr:port ) 建立到**所有 Controller 的連線**，並選擇一個 Controller 作為權威控制器
    * Client 對所有 Controller 執行相同操作，並為所有控制器維護一個狀態，但只使用權威控制器的結果
    * 權威 Controller 選擇策略:
        * 候選池：只有 Synced = true 的控制器才有資格被選擇。Synced = false 的控制器排除
        * 主要標準：客戶端數量最高（連線的客戶端最多）
        * 平手決勝規則 1：最早的 last_client_change_timestamp（獎勵穩定的控制器-客戶連線；時間戳越小，穩定性越長）
        * 平手決勝規則 2：最低的 controller_id（以公鑰位元組比較確定性地打破平手）
2. Client 對所有 Controller 發送 ClientRegister，包含：
    * client_id (pubkey)
    * 每個啟用 AF 的資訊：probe port、vxlan dstport
    * （IP 不需要帶，Controller 從 TCP remote IP 得知）
3. Controller 返回 ControllerState ，自此 Client 和該 Controller 狀態同步
    * Client 此時拿到了其他所有 Client 的 pubkey 和 EndpointV4, EndpointV6
    * Client 標記該 Controller 為 Synced = true
4. Client 等待 init_timeout
    * 目的：讓所有 Controller 的 ControllerState 都穩定下來（client_count、last_client_change_timestamp）
    * init_timeout 到期後，從 Synced = true 的 Controller 中選擇權威 Controller
    * 選完權威後，才開始：寫入 FDB、回應 ControllerProbeRequest
5. Controller 會維護所有 client 的 tcp 連線地址作為 ClientIP,作為 Client info 的一部份
  * Client Info 有以下資訊:
    * ClientID(=PubKey)
    * EndpointV4
        * IP
        * probe port
        * vxlan dstport
    * EndpointV6
        * IP
        * probe port
        * vxlan dstport
    * LastSeen
    * Routes: client 上報的 mac address
      * Type: 模仿 EVPN Routes 。目前只實作 Type 2
      * IP
      * MAC
6. Client 建立 bridge、vxlan devices、tap-inject 後，開始監聽本地鄰居表變更，上報 mac+ip 給所有 Controller（與 probe 流程並行）
7. 接著 Controller 會等待 sync_new_client_debounce ，這期間沒有新客戶加入的話，執行 sync_new_client
8. Controller 執行 sync_new_client
    * 對所有 Client 發送 ControllerProbeRequest
      * 訊息包含
      * probe_id
      * probe_timeout_ms
      * probe_times
      * in_probe_interval_ms
    * 客戶端收到以後，**如果是自己的權威控制器發來的 ControllerProbeRequest ，執行 Probe**
9. Client 執行 Probe
    * Client 需要按照 in_probe_interval_ms 間隔，總共發出 probe_times 個 probe
    * 透過 probe channel ，對所有的其他 Client 發送 ProbeRequest
      * ProbeRequest 包含 probe_id 和 src_timestamp（NTP 校準後的本地時間戳）
      * 如果自己的 v4+v6 enable ，且對面也是，v4+v6 兩個 probe channel 都會發送
      * 每輪 probe 共發 probe_times 個 ProbeRequest 給每個 peer 的每個 AF，以 in_probe_interval_ms 為間隔
    * 收到 ProbeRequest 以後，原路返回 ProbeResponse
      * ProbeResponse 包含 probe_id（原封回傳，用於路由到正確的 probe 批次，避免跨批次的 late response 污染）、dst_timestamp（接收端 NTP 時間戳）、src_timestamp（原封回傳發送端的時間戳）
    * 收到 ProbeResponse 以後，根據 probe_id 路由到對應的 probe 批次收集器，計算單向延遲 = dst_timestamp - src_timestamp（local→peer 方向，依賴 NTP 校準）
    * 丟包率計算：每個 (peer, AF) 組合記錄 sent 計數（= probe_times）和 received 計數（在 probe_timeout 內收到的 response 數），PacketLoss = 1.0 - received / sent
    * 當 probe_timeout 到期後，整合 ProbeResults 上傳給**所有 Controller**
        * 為什麼是**所有 Controller**呢?
        * 因為前面的設計「只處理權威控制器發來的 ControllerProbeRequest」
        * 如果所有控制器來的 ControllerProbeRequest 都處裡，會導致重複的 Probe 太多
        * 但是只回應給權威 Controller，非權威又拿不到結果。
        * 所以設計成 Client 只處理權威控制器發來的 ControllerProbeRequest
        * 但探測完的結果發給所有的 Controller ，讓全部 Controller 都有延遲資訊
        * 就算不是自己 issued ProbeRequest ，Controller 也會接受這個 ProbeResults
    * ProbeResults:
        * probe_id
        * source_client_id
        * probe_results: map< dst_client_id , ProbeResult>
        * ProbeResult< af_name, Result>:
            * v4:
                * latency_mean // INF_NUM if unreachable
                * latency_std
                * packet_loss
                * priority
            * v6:
                * latency_mean // INF_NUM if unreachable
                * latency_std
                * packet_loss
                * priority
            * 每個 af 的測量結果，包含 mean std loss priority ，目前只實作比較 priority 然後比較 mean
10. Controller 收到 ProbeResults 更新到 LatencyMatrix 裡面
    * 等待 topology_update_debounce 以後(如果等待期間有新的 ProbeResults 進來就重新等待，但最多等待 topology_update_debounce_max)，執行 topology_update
    * topology_update: 計算 RouteMatrix ，並發布 ControllerStateUpdate
    * LatencyMatrix:
        * [src_id][dst_id] = LatencyInfo { AFs: map[af_name]AFLatency, LastReachable }
        * 保存所有 AF 的完整探測資料（mean, std, packet_loss, priority, additional_cost）
        * 額外維護 BestPaths[src_id][dst_id] = BestPathEntry { AF, Cost, Raw }
        * BestPath 選擇邏輯：priority 數值低的優先；priority 相同時選 cost（= latency_mean + additional_cost）最低的
        * 支援兩種 cost mode：
            * probe mode（預設）：cost = latency_mean + additional_cost
            * static mode：cost 來自 static_costs 配置，但仍檢查 probe 可達性（packet_loss < 1.0）
    * **AdditionalCost 加權**: 在計算 Floyd-Warshall 之前，先對 LatencyMatrix 套用 AdditionalCost。對於每一條邊 `LatencyMatrix[src][dst]`，其 cost 為：
        * `cost = latency + AdditionalCost[dst]`
        * 即經過目標節點轉發時，需要額外支付該節點的 AdditionalCost
        * 加權後的 cost matrix 才送入 Floyd-Warshall 計算最短路徑
    * RouteMatrix:
        * [src_id][dst_id] = [ nexthop_id, af_name( v4 or v6) ] or null(如果客戶端不可達)
        * af_name 是指 **src → nexthop 這一跳**的 AF，不是端到端的 AF
            * 例如 A→C 最短路徑為 A→B→C，A→B 走 v4，B→C 走 v6
            * RouteMatrix[A][C] = { nexthop=B, af=v4 }（A 到 B 這段走 v4）
            * RouteMatrix[B][C] = { nexthop=C, af=v6 }（B 到 C 這段走 v6）
        * 使用 Floyd-Warshall 在 AdditionalCost 加權後的 cost matrix 上計算所有客戶端對的最短路徑。
        * 不包含延遲訊息,僅包含下一跳路由決策。
11. 發布 ControllerStateUpdate
12. Client 收到 ControllerStateUpdate ，更新到對應的Controller 狀態
    * Client 能設定多個 Controller ，每個 Controller 都有其狀態
    * 但只會選擇一個 Controller 作為權威 Controller ，使用他的狀態
    * 客戶端在更改其權威控制器選擇時不會通知控制器。權威 Controller 的選擇是本地決策。
    * 理想情況所有 Controller 會得到相同結果，所以選誰都會通
13. Client 和 linux bridge 開始互動
    * 多個 VXLAN devices (one per AF), attached to the same Linux bridge.
    * 另外建立一個 **TAP device (tap-inject)**，掛到 bridge 上
        * 用途：Client 透過 `open /dev/net/tun`（TUN/TAP）取得 tap-inject 的 fd，直接 read/write 進行 broadcast capture 與 inject
        * read: bridge flood 的 broadcast/multicast 封包會送到 tap-inject，Client 從 fd 讀取
        * write: Client 將 Controller relay 的 broadcast/multicast 封包寫入 fd，注入 bridge
    * **Learning 策略**: 所有 FDB entry 由 Controller 管理，bridge 上所有 port 關閉自學習
        * vxlan device: `learning off` — 防止自學習和 Controller 分發的 FDB 衝突，且 hairpin 下自學習可能學到中轉節點的 IP 而非源節點
        * tap-inject: `learning off` — 否則 bridge 從 relay broadcast 中學到 MAC 指向 tap-inject，導致 unicast 走錯 port
        * 普通 slave（VM 的 tap/veth、eth0 等）: 保持 `learning on` — bridge 需要從本地 port 學習 MAC，才能正確將 unicast 送到對的本地設備
    * **Device Configuration**: 使用這個指令創建 vxlan device:
      ```bash
      ip link add {vxlan_name} type vxlan id {vni} local {bind_addr} ttl 255 dstport {port} srcport {port} {port} nolearning udp6zerocsumrx
      ip link set {vxlan_name} master {bridge_name}
      ip link set {vxlan_name} type bridge_slave hairpin on learning off neigh_suppress on  # neigh_suppress 視配置決定
      ip link set {vxlan_name} up
      ```
    * **TAP device for broadcast injection**:
      ```bash
      ip tuntap add dev tap-inject mode tap
      ip link set tap-inject master {bridge_name}
      ip link set tap-inject type bridge_slave learning off neigh_suppress on  # neigh_suppress 視配置決定
      # 不需要啟用 hairpin（vxlan FDB 無 broadcast entry，broadcast 不會從 vxlan 轉發出去）
      ip link set tap-inject up
      ```
      Client 透過 `open /dev/net/tun`（flag: IFF_TAP | IFF_NO_PI）取得 tap-inject 的 fd 進行讀寫
    * **Hairpin Mode**: bridge 上對 VXLAN interface 必須啟用 hairpin mode
        * 允許從一個 VXLAN 隧道接收的封包透過另一個 VXLAN 隧道轉送出去
        * （多跳路由所必需，例如 A→B→C，其中 B 在兩個 VXLAN 隧道之間轉送流量）。
    * 當 Client 收到 bind_addr update 時，需要呼叫 ip link 更新隧道的 local {bind_addr}
    * 當 clamp_mss_to_mtu 設定為 true 時，會新增以下 nftables 規則(vxlan-v4替換成實際名稱，table 名稱由 clamp_mss_table 配置，預設 "vxlan_mss"):
        ```nft
        table bridge vxlan_mss {
            chain forward {
                type filter hook forward priority filter; policy accept;

                # Clamp MSS for IPv4 and IPv6 traffic traversing VXLAN devices
                # MSS calculation: config.vxlan.mtu - 40 (TCP 20 bytes + IP 20 bytes)
                # Using rt mtu for dynamic adjustment based on routing table

                oifname "vxlan-v4" ether type {ip, ip6} tcp flags syn tcp option maxseg size set rt mtu
                iifname "vxlan-v4" ether type {ip, ip6} tcp flags syn tcp option maxseg size set rt mtu
                oifname "vxlan-v6" ether type {ip, ip6} tcp flags syn tcp option maxseg size set rt mtu
                iifname "vxlan-v6" ether type {ip, ip6} tcp flags syn tcp option maxseg size set rt mtu
            }
        }
        ```
## Broadcast / Multicast 轉發機制

* **設計原則**: Broadcast/multicast 封包**完全不走 vxlan data plane**，一律由 Controller relay
    * FDB 中不寫入 broadcast/default entry（`00:00:00:00:00:00` 或 `ff:ff:ff:ff:ff:ff`），vxlan device 自然不會轉發 broadcast
    * 避免 hairpin + multi-AF 造成的 loop 問題
        * 例如 A(v4 only) → broadcast → B(v4 in, hairpin, v6 out) → C(v6 in, hairpin, v4 out) → B → loop
* **流程**:
    * tap-inject 掛在 bridge 上，bridge 的 broadcast/multicast 會自然 flood 到此 port
    * Client 透過 tap-inject 的 fd 進行讀寫，一個 TAP device 同時解決 capture 和 inject
    1. Client 從 tap-inject fd 讀取 broadcast/multicast 封包（bridge flood 過來的）
        * 套用 rate limit
    2. Client 透過 **UDP** communication channel 將封包上傳給 Controller（MulticastForward 訊息）
    3. Controller 透過 **UDP** 轉發給**除了來源以外**的所有 Client（MulticastDeliver 訊息）
    4. Client 收到後，將封包寫入 tap-inject fd，注入 bridge
        * bridge flood 到所有 port，但 vxlan device FDB 中沒有 broadcast/default entry，查無匹配直接丟棄，不會送出 → 不會 loop
* **Client + Controller 同節點**: 完全支援
    * Client 透過 localhost TCP/UDP 連線到同節點的 Controller
    * Controller relay 時根據 source_client_id 跳過來源 Client，不會自己收到自己的 broadcast

## 配置檔格式

使用 **YAML** 格式。支援巢狀結構（AF settings map）且可讀性高。

## FDB 寫入邏輯

* 當 RouteMatrix 計算出 A→C nexthop=B, af=v4 時:
    * 在 A 的 vxlan-v4 device 上寫入兩個 FDB entry:
        * **self entry** (NUD_PERMANENT): 告訴 vxlan device 封裝目標 IP
          `bridge fdb append <C_mac> dev vxlan-v4 dst <B_v4_addr> self permanent`
        * **master entry** (NUD_NOARP/static): 告訴 bridge 轉發到 vxlan port，避免 unknown unicast flooding
          `bridge fdb append <C_mac> dev vxlan-v4 master static`
    * 只寫入被選中 AF 的 vxlan device，不寫其他 AF
    * **重要**: master entry 必須使用 `NUD_NOARP`（即 `static`），不可使用 `NUD_PERMANENT`。在某些 kernel 上（如 Ubuntu 的 fan-map vxlan 擴展），`permanent` 的 master entry 會導致 bridge→vxlan TX 路徑靜默失效，封包被丟棄
* Broadcast/multicast MAC **不寫入** FDB（由 Controller relay 處理）

14. Client 透過 **netlink** 讀取並持續監聽本地的 FDB 資訊，上報給所有 Controller：
    * **FDB（forwarding database）**: 讀取 bridge 上本地 port 自學習到的 (mac, nil)（無 dst，代表本地 MAC），用於告知 Controller 哪些 MAC 在本 Client 上
    * 透過 netlink 實現：啟動時先 **subscribe** 變更事件，再 **init**（讀取 FDB 全量寫入 LocalMACs）。init 必須在 TCP 連線啟動前同步完成，確保 sendloop 讀不到空的 LocalMACs。之後持續處理事件（RTM_NEWNEIGH / RTM_DELNEIGH），每個事件即時發送增量更新
    * Local state（macMu RWMutex）生命週期：subscribe → init → 之後只有兩種操作：
        * **write**（netlink event）：macMu.WLock → 更新 LocalMACs → 推到所有 controller sendqueue → macMu.WUnlock
        * **read/dump**（sendloop full push）：macMu.RLock → encode snapshot → macMu.RUnlock
    * **增量更新格式**（仿 BGP UPDATE）：每條 `Type2Route` 自帶 `is_delete` 標記。`is_delete=false` 為宣告（add），`is_delete=true` 為撤回（withdraw）。一個 `MACUpdate` 可同時包含 add 和 delete
    * 不使用 debounce：單條 MAC 增量更新成本極低（幾十 bytes），TCP Nagle 會自然合併短時間內的多筆小訊息
15. Controller 收到更新，同步到 Controller 的 RouteTable
    * RouteTable: 由以下三元組構成
        * mac
        * ip
        * map<client_id, ExpireTime>
    * 當相同的 ip+mac 歸屬多個 client_id 時，走 **LatencyMatrix 中延遲最小**的 client
    * 相當於 anycast
16. Controller 推送新版路由表給全部的 Client
17. Client 收到以後，結合 RouteMatrix + RouteTable 寫入 bridge fdb
    * **FDB 寫入需要兩者都就緒**:
        * RouteTable 提供「mac=X 在 Client C 上」
        * RouteMatrix 提供「到 Client C 走 nexthop=B, af=v4」
        * 合併後寫入: `bridge fdb append <X> dev vxlan-v4 dst <B_v4_addr>`
    * RouteMatrix 或 RouteTable 任一方更新，都觸發重新計算 FDB

# 同步機制:

使用 Mutex + Per-Client 發送佇列，不引入 sequence number 或 per-client view state。

## 解偶架構

Controller 和 Client 各自的狀態管理與通訊通道完全解偶：

```
Client 端:
  client_state          ←→  client_com (per controller)  ←→ 網路 ←→  controller_com (per client)  ←→  controller_state
  (本地 MAC/neigh)           (多 AF TCP 連線管理)                      (多 AF TCP 連線管理)              (全域路由狀態)

Controller 端:
  controller_state      ←→  controller_com (per client)  ←→ 網路 ←→  client_com (per controller)  ←→  client_side_controller_state
  (全域路由狀態)              (多 AF TCP 連線管理)                      (多 AF TCP 連線管理)              (Controller 推送的狀態視圖)
```

### client_state（Client 端本地狀態）

* 保存本地 MAC（LocalMACs），由 `macMu`（sync.RWMutex）保護，獨立於 `c.mu`
* 生命週期：subscribe → init（同步完成，在 TCP 連線前）→ 之後只有 write 和 read
* `Write(inc_update)`: macMu.WLock → 同步增量到 LocalMACs → 推入所有 controller 的 client_com.sendqueue → macMu.WUnlock。queue 滿 → 只斷該 controller 的 activeAF（CloseDone），其他 AF 不動
* `GetFullState()`: macMu.RLock → encode snapshot 返回 → macMu.RUnlock（sendloop full push 時使用）

### client_com（Client 端通訊通道，per controller）

* 每個 controller 各有一個實例，內部管理多個 AF 連線
* 每個 AF 斷線後自動重連
* 內部變數（受 `c.mu` 保護）：
    * `activeAF`: 當前接收訊息使用的 AF。**由 controller 決定**：當某個 AF 收到 controller 的合法全量更新時，`activeAF` = 該 AF
    * `synced` (MACsSynced): 代表發送方向是否已進入增量模式。sendloop 發送全量後變為 true
* `activeAF` 和 `synced` 的語義差異：
    * `activeAF != nil`: 該 AF 已收到 controller 全量更新，可用於接收訊息
    * `synced == true`: 已發送本地全量狀態給 controller，後續可只發增量
* sendloop 流程：
    * dequeue → 讀 activeAF, synced（c.mu）
    * `activeAF == ""` → discard
    * `!synced` → GetFullState（macMu.RLock）→ synced=true → send full state → discard dequeued item
    * `synced` → send item as incremental
* 斷線處理：若斷線的 AF 是 activeAF → `activeAF = ""` + `synced = false`（只影響該 controller，不碰其他 AF 或 state）

### controller_com（Controller 端通訊通道，per client）

* 每個 client 各有一個實例，內部管理多個 AF 連線
* 內部變數同 client_com（`activeAF`、`synced`）
* 斷線處理：
    * 非 activeAF 斷線 → 清空該 AF handle，無其他影響
    * activeAF 斷線 → `synced = false` + `activeAF = nil`
* 新連線處理（通過驗證後）：
    * 對應 AF handle 為 nil → 直接設定
    * 對應 AF handle 不為 nil → 關閉舊連線觸發斷線清理，再替換

### client_side_controller_state（Client 端的 Controller 狀態視圖）

* 每個 controller 各一份，只使用權威控制器的結果
* 持有自己的 RWLock
* `Write()` 更新後，若是權威控制器 → 觸發 FDB reconcile（非阻塞 channel 通知，FDB reconcile goroutine 異步執行）

### controller_state（Controller 端全域狀態）

* 保存所有 client 的路由表、endpoint、RouteMatrix 等
* 持有一把 RWLock
* `Write(inc_update)`: WLock → 同步增量到狀態 → 推入所有 client 的 controller_com.sendqueue → WUnlock
* `GetFullState()`: RLock → 複製狀態返回 → RUnlock

## 增量更新策略

### 增量 vs 全量（仿 BGP 模型）

類似 BGP/EVPN 的增量同步模型：
* **Session 內**: TCP 保證順序和完整性，增量更新可靠傳遞
* **Session 重建時**: drain 佇列 + 重發全量（類似 BGP session reset 時的 full table dump）
* **所有操作必須冪等**: MAC add 重複無害，MAC delete 不存在 = no-op。這是增量同步正確性的基礎

### 全量後殘留增量

Session 重建時，drain 佇列後 sendloop 發全量。但全量發送與新增量入隊之間有時序窗口，可能導致少量增量重複發送：

```
T1: drain queue, synced=false
T2: write(inc1) → queue: [inc1], state 包含 inc1
T3: write(inc2) → queue: [inc1, inc2], state 包含 inc1+inc2
T4: sendloop dequeue inc1, synced=false → getFullState() 包含 inc1+inc2 → 發全量
T5: synced=true
T6: sendloop dequeue inc2, synced=true → 發 inc2（重複，已在全量中）
```

因為所有操作冪等，重複無害。這是 BGP 數十年運行驗證過的模型。

### Client 端增量上報

Client 監聽 netlink 事件，向所有 Controller 發送增量 MACUpdate：

* macMu.WLock → 更新 LocalMACs → encode incremental → **無條件**推入所有 controller sendqueue → macMu.WUnlock
* 不檢查 MACsSynced — write 不碰 per-controller 狀態，state 和 controller 完全獨立
* Queue 滿 → 只斷該 controller 的 activeAF（CloseDone），走正常斷線重連流程，reconnect 後 sendloop 自動 full resync

### sendloop 的 AF 選擇

Controller 端和 Client 端的 sendloop 在 `activeAF == nil` 時行為不同：

* **Controller 端 sendloop**：`activeAF == nil` 時，直接選擇存活最久的 AF 並寫入 `activeAF`。Controller 是決策方，選好就定：
    ```
    if activeAF == nil:
        activeAF = pickSurvivor()
        if activeAF == nil: discard; continue
    ```
* **Client 端 sendloop**：`activeAF == nil` 時，直接丟棄。Client 必須等 controller 選好 AF 並發來全量更新後，才知道該用哪個 AF

### activeAF 的決策權

* **Controller 決定 activeAF**: Controller 選擇最早建立連線的 AF 作為 active，對其發送全量更新
* **Client 跟隨**: Client 收到某 AF 的全量更新 → 將該 AF 設為自己的 activeAF
* 整體語義：activeAF 總是由 Controller 選擇，Client 只是確認

## 死鎖預防：鎖順序

Client 端有兩把鎖：`macMu`（RWMutex，保護 LocalMACs）和 `c.mu`（Mutex，保護 per-controller 狀態）。

**鎖順序規則**：允許巢狀 `macMu → c.mu`，禁止反向。

* **handleNeighEvent（write）**: `macMu.WLock` → `c.mu.Lock`（push queue）→ `c.mu.Unlock` → `macMu.WUnlock`（巢狀）
* **sendloop（read）**: `c.mu.Lock` → 讀 activeAF/synced → `c.mu.Unlock` → `macMu.RLock`（getFullState）→ `macMu.RUnlock` → `c.mu.Lock` → synced=true → `c.mu.Unlock`（全部序列，從不同時持有兩把鎖）

不存在 A→B / B→A 的死鎖條件。

**Queue 滿的處理**：write 持有 macMu.WLock 時 push queue 使用 `select { default: }`（非阻塞），queue 滿時不阻塞而是斷線。避免 WLock 持有者因 queue 滿而阻塞導致 sendloop（需要 RLock）也阻塞的死鎖。

## 資料結構

* **ControllerState / ClientState**: 各自的全域狀態，受 RWLock 保護
    * 任何時刻只有一個操作能持有 WLock：state mutation、全量推送準備、增量推送準備
* **Per-peer 發送佇列**: 每個對端持有一個帶 buffer 的發送佇列（send queue），元素為 QueueItem
* **QueueItem**: 佇列項目同時也是訊息結構，包含兩個欄位：
    ```
    QueueItem {
        State   []byte  // 狀態更新（全量或增量），nil 表示無
        Message []byte  // 非狀態訊息（probe request/result 等），nil 表示無
    }
    ```
    * 入隊時：增量狀態更新填入 `State`，probe request 填入 `Message`
    * sendloop 出隊時：若 `synced == false`，丟棄 dequeued item，改為 `getFullState()`（RLock）發送全量
    * 收端：若 `State` 和 `Message` 都有值，當成兩個訊息分別處理
    * **好處**: probe request/result 永遠不會因為狀態重同步而丟失
* **synced 旗標**: 標記是否已完成全量同步。`synced=true` 在 getFullState() 之後、send 之前設定。這確保 RLock 釋放後新的 write 能正常推到 queue 並被 sendloop 當 incremental 處理

## State Mutation（收到對端上報）

1. WLock
2. 修改 state
3. Mutation 本身就是 delta（例如「client X 加入」「RouteMatrix 更新」），不需要額外 diff 計算
4. WUnlock
5. 將 delta 包裝為 `QueueItem{State: delta}` 推入所有 synced=true 的對端的發送佇列（鎖外，避免死鎖）

## 全量推送（Client 端 sendloop）

觸發時機：
* 新 controller 連線建立（收到 controller 全量更新 → activeAF 設定 → 推 empty trigger 到 sendqueue）
* TCP 斷線重連（activeAF 斷線 → synced=false → 重連後同上）

流程：
1. synced=false（由 handleDisconnect 設定，或新連線初始狀態）
2. sendloop dequeue → 檢查 synced=false → getFullState()（macMu.RLock，blocks writes）→ synced=true → send full state → discard dequeued item
3. RLock 釋放後 write 可以繼續，新增量推到 queue → sendloop 下一輪 synced=true → 走 incremental
4. synced=true 在 send 之前設定，確保 RLock 釋放後新 write 的 incremental 能被正常處理

## 佇列滿的處理

* **Client → Controller**: queue 滿 → 只斷該 controller 的 activeAF（CloseDone），不碰其他 AF 或 state。斷線走正常斷線流程 → reconnect → sendloop 自動 full resync
* **Controller → Client**: queue 滿 → synced=false + drain queue → sendloop 下次出隊時發全量

## TCP 斷線重連

* TCP 斷線重連成功後，重新經歷全量推送流程（synced=false → sendloop 發全量 → synced=true）
* **TCP 斷線不影響 Client 的上線狀態和路由**：
    * Controller 維護的 ClientInfo、RouteMatrix、RouteTable 不因 TCP 斷線而立即清除
    * 由 ClientOfflineTimeout 控制：只有超過此 timeout 仍無法重連，才視為該 Client 離線，清除其相關路由並重新計算
    * 這避免了短暫網路波動導致路由震盪（flapping）
* TCP 斷線期間的增量更新會丟失，但重連後的全量推送會補齊

## TCP 斷線偵測

Controller 端完全依賴 TCP 本身偵測 Client 離線，不需要額外的應用層心跳或 disconnect 訊息：

* **Client 正常關閉**: kernel 發送 FIN，Controller 的 `conn.Read()` 收到 `io.EOF`，觸發斷線處理
* **Client 崩潰/斷網**: TCP keepalive 超時或收到 RST，`conn.Read()` 返回 error，觸發斷線處理
* **TCP Keepalive 設定**: 在 `net.TCPConn` 上啟用 keepalive 並設定合理的探測間隔（例如 30s），確保在 `ClientOfflineTimeout`（預設 300s）之前能偵測到無回應的 Client
    ```go
    conn.SetKeepAlive(true)
    conn.SetKeepAlivePeriod(30 * time.Second)
    ```
* 斷線後 Controller 不立即清除 ClientInfo/路由，而是由 `ClientOfflineTimeout` 控制：超過 timeout 仍未重連才視為離線並清除路由，避免短暫網路波動造成路由震盪

## 保證

* TCP 保證資料流的順序和完整性
* Mutex 保證 state mutation、全量推送準備、增量推送準備三者互斥，不會有競爭
* 不需要 sequence number 或 per-client view state。發送佇列的 FIFO 順序保證 Client 先收到全量、再依序收到增量，最終一致
* 鎖僅保護本地記憶體操作（修改 state + 推入佇列），不涉及網路 I/O，持鎖時間為微秒級


## 協議規格

### 訊息序列化

* **配置檔**: 使用 **YAML** 格式
* **網路訊息**: 使用 **Protocol Buffers (protobuf)** 序列化。所有訊息類型定義在 `.proto` 檔案中，透過 protoc 產生 Go 代碼

### TCP Framing

TCP 連線上使用 length-prefixed framing，格式如下：

```
[4 bytes: length (big-endian uint32)][1 byte: msg_type][8 bytes: counter][N bytes: ciphertext]
```

* `length` = `sizeof(msg_type) + sizeof(counter) + sizeof(ciphertext)` = `1 + 8 + N`
* `msg_type`: 訊息類型識別碼（例如 0x01=HandshakeInit, 0x02=HandshakeResp, 0x10=ClientRegister, ...）
* `counter`: nonce 的 counter 部分（8 bytes little-endian），用於解密及 replay 檢測
* `ciphertext`: 握手完成前為明文（僅 Handshake 訊息），握手完成後所有 payload 使用 ChaCha20-Poly1305 session key 加密

### Probe Channel Handshake

Probe channel（UDP）的 handshake 獨立於 TCP communication channel，仿照 **WireGuard Noise IK pattern**：

* 任何一方都可以發起 handshake（當本地沒有該 peer 的 session key 時）
* **HandshakeInit 訊息結構**（仿 WireGuard）：
    * `msg_type` (1B)
    * `sender_index` (4B): 發起方分配的 session index，用於後續封包中標識 session
    * `ephemeral_pubkey` (32B): 發起方的 ephemeral X25519 公鑰（明文）
    * `encrypted_static` (32B + 16B tag): 發起方的 static pubkey，用 ephemeral ECDH 結果加密
    * `encrypted_timestamp` (12B + 16B tag): TAI64N 時間戳，用於防止 replay
    * `mac` (16B): 整個訊息的 MAC
* **HandshakeResp 訊息結構**：
    * `msg_type` (1B)
    * `sender_index` (4B): 回應方分配的 session index
    * `receiver_index` (4B): 對應 HandshakeInit 的 sender_index
    * `ephemeral_pubkey` (32B): 回應方的 ephemeral X25519 公鑰
    * `encrypted_nothing` (0B + 16B tag): 確認金鑰推導正確
    * `mac` (16B)
* 雙方從兩組 ephemeral + static ECDH 結果推導出 session key pair（發送/接收各一）
* **重傳機制**: 發起方在未收到 HandshakeResp 時，按指數退避重傳 HandshakeInit（例如 1s, 2s, 4s），最多重傳 N 次
* 收到成功的 HandshakeResp 後建立 session key；若本地已有 session key 則替換（應對對端重啟）
* 握手失敗（對端無 private key）不影響既有 session key

### Nonce 與加密策略

仿照 WireGuard 的 nonce 管理：

* **ChaCha20-Poly1305** 對稱加密，nonce 為 **counter-based**（8 bytes little-endian counter + 4 bytes zero padding = 12 bytes nonce）
* 每個方向（發送/接收）維護獨立的 counter，從 0 遞增
* **TCP**: counter 隨訊息順序遞增，接收方驗證 counter 嚴格遞增（TCP 保證有序）
* **UDP**（probe + multicast）: counter 遞增發送，接收方使用 **sliding window**（仿 WireGuard，窗口大小 2048）防止 replay，允許亂序接收
* Counter 達到 `REJECT_AFTER_MESSAGES`（2^60）時，必須重新握手建立新 session

### UDP 封包格式（Probe 與 Multicast）

仿照 WireGuard transport data 格式：

```
[1 byte: msg_type][4 bytes: receiver_index][8 bytes: counter][N bytes: encrypted payload]
```

* `receiver_index`: 握手時對端分配的 session index，接收方用它查找對應的 session key
* `counter`: 即 nonce 的 counter 部分，用於解密及 replay 檢測
* `encrypted payload`: ChaCha20-Poly1305 加密的實際內容（protobuf 序列化的 ProbeRequest/ProbeResponse/MulticastForward/MulticastDeliver）

### TCP Communication Channel Handshake

TCP 連線建立後，同樣使用 WireGuard 風格的 Noise IK handshake（訊息結構同 Probe Channel Handshake），但透過 TCP framing 傳輸：

* 握手訊息使用 TCP framing（length-prefixed）包裝
* 握手完成後，雙方得到 session key pair + 關聯 client_id
* 後續所有 TCP payload 使用 session key + counter-based nonce 加密
* TCP 保證順序，所以接收方驗證 counter 嚴格遞增即可（不需 sliding window）


### Test
新增 tests 資料夾，在裡面新增各種測試
例如 test_xxx.sh
測試完要清理不用的 namespace 和 bridge 之類

測試腳本會用 network namespace + veth 模擬 6 個 client 節點
以及 br-lan_v4: 192.168.47.0/24 和 br-lab_v6: fd87:4789::/64
1,2,3,4,10 加入 lan_v4
3,4,10,5,6 加入 lan_v6
1 2 3 4 5 6 是 Client
4,10 是 Controller

模擬部分 v4 only: 1 2
部分 v6 only: 5 6
部分雙線: 3 4 10
的情境

同時有
同時兼任 Client + Controller: 4
獨立擔任 Controller: 10
的場景

所有的 client 節點用 tc 發包時增加延遲模擬現實的，非對稱的延遲
確認確實會轉發

每個 client node 用 veth 連接一個 leaf ，確認所有的 leaf 都可以互 ping
每個 client node 的預設 local bind ip 都是 192.168.47.{id} 和 fd87:4789::{id}

#### 測試項目

##### 1. 基本連通性測試（neigh_suppress = false）
* 所有 leaf 互 ping，應直接全通
* 因為 neigh_suppress 關閉，ARP/NS 會正常 flood，雙方都能學到對方的 MAC 和 IP

##### 2. neigh_suppress = true 的行為差異
* A ping B：A 發出 ARP/NS，但此時 B 的鄰居表尚未被上報到 A 所在節點，neigh_suppress 無法代答，ARP/NS 需透過 broadcast relay 到 B
* 此時 A 已上報自己的鄰居資訊，但 B 尚未上報，所以 A→B 的第一次 ping 可能失敗（B 端的 neigh_suppress 無法代答 A 的 ARP request）
* B ping A 後，B 的鄰居資訊也被上報，此時雙向的 neigh_suppress 都有足夠資訊代答，A↔B 互通
* 測試步驟：
    1. 啟動所有節點，等待路由收斂
    2. 從 leaf-A ping leaf-B，預期初次可能不通（取決於鄰居表是否已同步）
    3. 從 leaf-B ping leaf-A
    4. 再次從 leaf-A ping leaf-B，預期此時互通

##### 3. 單一 Controller 斷線與恢復
* 測試步驟：
    1. 正常運行，確認所有 leaf 互通
    2. 關閉 Controller-10，Client 應 fallback 到 Controller-4（權威切換）
    3. 確認所有 leaf 仍互通
    4. 恢復 Controller-10，等待其重新握手、同步狀態
    5. 確認所有 leaf 仍互通
    6. 關閉 Controller-4，Client 應切換回 Controller-10
    7. 確認所有 leaf 仍互通
    8. 恢復 Controller-4，確認恢復正常

##### 4. 途經轉發節點斷線（topology_update 驗證）
* 前置：透過 tc 設定延遲，使部分路徑的最短路必須經過中繼 Client（例如 1→3→5，其中 3 是轉發節點）
* 測試步驟：
    1. 正常運行，確認 leaf-1 可 ping leaf-5（路徑經過 Client-3 轉發）
    2. 關閉 Client-3
    3. Controller 偵測到 Client-3 離線，等待 topology_update_debounce 後重新計算 RouteMatrix
    4. 確認 topology_update 產生新路由，leaf-1 仍可 ping leaf-5（改走其他路徑）
    5. 恢復 Client-3，確認 Client-3 能重新握手、重建 session
    6. 等待 sync_new_client_debounce 後觸發新一輪 Probe，RouteMatrix 更新
    7. 確認所有 leaf 恢復互通，且路由可能恢復經過 Client-3 轉發（若仍為最短路）

##### 5. Broadcast / Multicast 轉發測試
* 測試步驟：
    1. 從 leaf-A 發送 broadcast（例如 arping -b），確認所有其他 leaf 收到
    2. 確認 broadcast 封包未經過 vxlan data plane（vxlan device 上無 broadcast FDB entry）
    3. 確認 Controller relay 的 broadcast 不會回送給來源 Client

##### 6. 雙棧路由測試
* 驗證 v4-only（1,2）↔ 雙棧（3,4）↔ v6-only（5,6）的路由正確性
* 測試步驟：
    1. leaf-1（v4-only）ping leaf-5（v6-only），確認經由雙棧節點轉發成功
    2. 確認 FDB 寫入正確的 vxlan device（v4 段寫 vxlan-v4，v6 段寫 vxlan-v6）

#### 7. IP 變動測試
* 驗證 IP 變動，可以順利
    1. 新的 local bind ip 同步到 vxlan 介面
    2. 使用新的 local IP 進行 tcp udp 通訊
    3. 控制器能更新 client ip 變化，推送給其他節點
    4. 其他節點能更新 state 和同步到 kernel

所以要驗證 1, 3, 5 連線成功後，介面卡移除舊 IP ，新增 100+ id 的 IP ，然後呼叫 API 更新
（現在也支援 autoip_interface 模式，透過 netlink 監聽網卡地址變更自動更新）

#### 8. VXLAN 防火牆測試（test_firewall.sh）
* 驗證 vxlan_firewall 功能正常
* 測試步驟：
    1. 啟用 vxlan_firewall，正常運行確認所有 leaf 互通
    2. 確認 nftables 規則已建立，per-AF set 包含正確的 peer IP
    3. 從未授權的 IP 發送 VXLAN 封包，確認被 drop
    4. peer 離開後確認其 IP 從 set 中移除

#### 9. No-flood 測試（test_no_flood.sh）
* 驗證未知 unicast 不會 flood
* 測試步驟：
    1. 確認 bridge 上所有 port learning 設定正確
    2. 確認未知 MAC 的 unicast 不會被 flood 到 vxlan data plane

#### 10. 靜態 vs 控制器比較（compare_static_vs_controller.sh）
* 基準測試：比較靜態 FDB 配置和 Controller 驅動的 FDB 效能差異


## VXLAN 防火牆規則

當 `vxlan_firewall: true` 時，建立以下 nftables 規則（table 名稱由 `vxlan_firewall_table` 配置，預設 "vxlan_fw"）：

```nft
table inet vxlan_fw {
    # 每個 AF 一個 set，包含該 AF 所有已知 peer 的 endpoint IP
    set af_v4 {
        type ipv4_addr
        elements = { 192.168.1.1, 192.168.1.2, ... }
    }
    set af_v6 {
        type ipv6_addr
        elements = { fd00::1, fd00::2, ... }
    }

    chain input {
        type filter hook input priority filter; policy accept;

        # 對每個 AF：目的地是本機 bind_addr 且目的 port 是 vxlan dstport 的 UDP 封包
        # 來源 IP 不在對應 set 中 → drop
        udp dport <vxlan_dstport> ip daddr <bind_addr_v4> ip saddr != @af_v4 counter drop
        udp dport <vxlan_dstport> ip6 daddr <bind_addr_v6> ip6 saddr != @af_v6 counter drop
    }
}
```

* peer 加入時：`nft add element inet vxlan_fw af_v4 { <peer_ip> }`
* peer 離開時：`nft delete element inet vxlan_fw af_v4 { <peer_ip> }`
* bind_addr 變更時：重建整個 table（需要更新 daddr 匹配）


## autoip_interface 動態 IP 綁定

取代手動設定 `bind_addr`，使用 `autoip_interface` 指定網卡名稱，系統自動選擇地址：

* **監聯機制**: 透過 netlink 監聽 `RTM_NEWADDR`/`RTM_DELADDR` 和 `RTM_NEWLINK`/`RTM_DELLINK` 事件，1 秒 debounce
* **地址選擇**: 執行 Lua `select(info)` 函數，`info` 包含:
    * `addrs`: 該網卡上所有有效地址列表（排除 deprecated、link-local）
    * `prev`: 上一次選擇的地址（用於穩定性偏好）
    * `af`: 當前的 address family（"v4" 或 "v6"）
* **預設選擇邏輯** (pkg/filter/defaults.go):
    * v4: 公網 IP > 上次使用的 IP > 私網 IP
    * v6: 公網 IP（接近 /64 prefix）> 上次使用的 IP > ULA
* **Controller 端特殊處理**: IPv6 DAD（Duplicate Address Detection）可能導致地址短暫不可用，Controller 使用指數退避重試綁定 listener


## Lua 過濾系統

### 架構

```
封包流向:
  tap-inject read → output_mcast filter → rate_limit → upload to Controller
  Controller relay → input_mcast filter → write to tap-inject
  neighbor update → output_route filter → upload to Controller
  Controller state → input_route filter → apply to local state
```

### 配置範例

```yaml
filters:
  output_mcast: |
    function filter(pkt)
      -- 只允許 ARP 和 IPv6 NS/NA
      if pkt.ethertype == 0x0806 then return true end
      if pkt.ethertype == 0x86dd and pkt.ipv6_next_header == 58 then
        if pkt.icmpv6_type == 135 or pkt.icmpv6_type == 136 then return true end
      end
      return "non-arp/nd"
    end
  rate_limit:
    per_mac: 64
    per_client: 1000
```

### Controller 端 per-client filter

Controller 可以在 `allowed_clients` 中為每個 Client 設定獨立的 filter，用於在 Controller 端過濾特定 Client 的流量。

### Lua 封包欄位（filter engine 萃取）

multicast filter 的 pkt table 除了基本欄位外，還包含深度解析的欄位：
* src_mac, dst_mac, ethertype, size
* ip_protocol, src_ip, dst_ip（IPv4/IPv6）
* src_port, dst_port（TCP/UDP）
* tcp_flags（SYN, ACK, FIN 等）
* icmp_type（ICMPv4/v6）
* arp_op（ARP operation）
* 引擎提供 `ip_in_cidr(ip, cidr)` 輔助函數
* `require()` 支援從磁碟或內建模組載入 Lua 模組


## CLI 工具

統一入口 `vxlan-controller`，透過子命令切換角色：

* `controller` / `server`: 作為 Controller 運行
* `client`: 作為 Client 運行
* `keygen`: 金鑰生成工具
    * `genkey`: 生成新的私鑰
    * `pubkey`: 從 stdin 讀取私鑰，輸出對應公鑰
* `autogen`: 從拓撲描述檔自動生成所有 controller 和 client 的配置檔
* `vxscli`: Controller CLI 工具，透過 Unix socket API 與 Controller 互動
    * `show client`: 顯示所有已連線的 Client
    * `show route`: 顯示路由表
    * `show route client <name>`: 顯示特定 Client 的路由
    * `cost get`: 取得當前 cost 矩陣
    * `cost getmode`: 取得當前 cost mode（probe/static）
    * `cost setmode <probe|static>`: 切換 cost mode
    * `cost store`: 將當前 Probe 結果持久化為 static_costs 寫回配置檔
* `vxccli`: Client CLI 工具，透過 Unix socket API 與 Client 互動

### Mock 模式

Controller 支援 `--mock` 模式，生成假資料（模擬多個 Client、延遲矩陣、路由表等），用於 WebUI 開發和測試，不需要實際的網路環境。

