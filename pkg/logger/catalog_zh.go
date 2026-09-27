package logger

// 中文對照表。用詞原則（用戶原話「記得也得弄成平民大白話」）：
// 講「誰做了什麼」，不講術語縮寫；`StickyIP` 這種功能名一律翻成「固定出口IP」，
// 因為他看的是「這行在講哪件事」，不是「這行對應哪個 Go 符號」。
//
// 表裡只放**這臺機器日誌真的刷出來過**的訊息（按出現次數排序取的），
// 沒見過的訊息一律留英文原樣——翻錯比不翻更糟，而且英文原字還在，不丟證據。
var messagesZh = map[string]string{
	"Connectivity Check Failed": "節點健康檢查沒過",
	// 延遲數字是 logrus 的欄位、不在訊息字串裡，所以這裡是「精確」而非前綴。
	"Connectivity Check":               "節點健康檢查",
	"Skip check due to no DNS record.": "這個節點目前沒有可用的解析結果，這次檢查先跳過",
	// alive_dialer_set.go 的實際訊息是 `Infof("[ALIVE --%v-> NOT ALIVE]")`，
	// 括號是訊息的一部分（prefixed formatter 之後才把它拆成前綴顯示），
	// 所以這裡要按「帶括號的原字串」比對，不然永遠命中不了。
	"[ALIVE --tcp4-> NOT ALIVE]":      "節點轉為不通（tcp4）",
	"[ALIVE --tcp6-> NOT ALIVE]":      "節點轉為不通（tcp6）",
	"[ALIVE --udp4-> NOT ALIVE]":      "節點轉為不通（udp4）",
	"[ALIVE --udp6-> NOT ALIVE]":      "節點轉為不通（udp6）",
	"[ALIVE --udp4(DNS)-> NOT ALIVE]": "節點查 DNS 轉為不通（udp4）",
	"[ALIVE --udp6(DNS)-> NOT ALIVE]": "節點查 DNS 轉為不通（udp6）",
	"[NOT ALIVE --tcp4-> ALIVE]":      "節點恢復可用（tcp4）",
	"[NOT ALIVE --tcp6-> ALIVE]":      "節點恢復可用（tcp6）",
	"[NOT ALIVE --udp4-> ALIVE]":      "節點恢復可用（udp4）",
	"[NOT ALIVE --udp6-> ALIVE]":      "節點恢復可用（udp6）",
	"[NOT ALIVE --udp4(DNS)-> ALIVE]": "節點查 DNS 恢復可用（udp4）",
	"[NOT ALIVE --udp6(DNS)-> ALIVE]": "節點查 DNS 恢復可用（udp6）",
	"TCP relay completed":             "TCP 中轉結束",
	"Group has no dialer alive":       "這個分組已經沒有可用節點",
	"The number of dialers is 0":      "一條節點都沒有",
	"dae is running":                  "dae 已啟動",
	"start process successfully":      "啟動完成",
}

// 前綴表：訊息後面掛了動態內容（延遲數字、節點名、域名）就用這條。
// 命中後「中文前綴 ＋ 英文剩下的部分」直接拼接，所以前綴要自己帶好分隔空格。
// 固定出口IP 那批訊息的**原字串帶方括號**（`[StickyIP] …`，來自 outbound 模組），
// 是 prefixed formatter 把方括號當成「前綴」顯示成 `StickyIP: …` 的。
// 比對要用原字串；翻成中文後不再帶方括號，就不會被再拆一次前綴。
var messagePrefixesZh = map[string]string{
	"[StickyIP] Check cycle incremented":                                         "固定出口IP：檢查週期遞進 ",
	"[StickyIP] No cache entry found":                                            "固定出口IP：沒有快取可查（第一次連這個地址） ",
	"[StickyIP] DialContext called":                                              "固定出口IP：要連線了 ",
	"[StickyIP] Trying proxy IP":                                                 "固定出口IP：改用記下來的那個地址 ",
	"[StickyIP] No valid cached IP - resolving proxy domain":                     "固定出口IP：快取的地址不能用，重新查域名 ",
	"[StickyIP] Resolved proxy domain to IPs":                                    "固定出口IP：域名查到了 ",
	"[StickyIP] Successfully connected to proxy IP":                              "固定出口IP：連線成功 ",
	"[StickyIP] All proxy IPs failed":                                            "固定出口IP：記下的地址全部連不上 ",
	"[StickyIP] Failed to connect to proxy IP (will try next)":                   "固定出口IP：這個地址連不上，換下一個 ",
	"[StickyIP] Cached IP failed - invalidating and re-resolving":                "固定出口IP：記下的地址壞了，作廢重查 ",
	"[StickyIP] Cache entry expired":                                             "固定出口IP：快取過期 ",
	"[StickyIP] Cache is nil":                                                    "固定出口IP：還沒有快取 ",
	"[StickyIP] Cycle mismatch - cache not from current cycle":                   "固定出口IP：快取是上個週期的，作廢 ",
	"[StickyIP] Cache hit - returning cached IP":                                 "固定出口IP：快取命中，直接沿用 ",
	"[StickyIP] Cache hit - using cached proxy IP":                               "固定出口IP：沿用記下來的地址 ",
	"[StickyIP] Cached proxy IP":                                                 "固定出口IP：已記下地址 ",
	"[StickyIP] No cached IP for this network type and IP version":               "固定出口IP：這個網路類型還沒有記下的地址 ",
	"[StickyIP] DNS resolution failed (will use original domain)":                "固定出口IP：域名查不到，改用原本的方式 ",
	"[StickyIP] Direct dial (already an IP)":                                     "固定出口IP：目標本身就是位址，不用查 ",
	"[StickyIP] Pass-through (not proxy address)":                                "固定出口IP：這不是代理地址，原樣放行 ",
	"[StickyIP] Invalidated cache for protocol+IP version":                       "固定出口IP：作廢該協議＋位址類型的快取 ",
	"[StickyIP] Protocol cache invalidated due to connection failure":            "固定出口IP：連線失敗，作廢該協議快取 ",
	"[StickyIP] Protocol+IP version cache invalidated due to connection failure": "固定出口IP：連線失敗，作廢該協議＋位址類型快取 ",
	"[StickyIP] NewStickyIpDialer created":                                       "固定出口IP：建立好包装器 ",
	"[DialerRegister] Checking if sticky IP caching is needed":                   "節點註冊：先看這條要不要固定出口IP ",
	"[DialerRegister] Creating sticky IP dialer wrapper for proxy domain":        "節點註冊：為這個域名建立固定出口IP包装 ",
	"[DialerRegister] Proxy is IP address - no sticky IP caching needed":         "節點註冊：代理本身就是位址，不需要固定出口IP ",
	"StickyIP: Check cycle incremented":                                          "固定出口IP：檢查週期遞進 ",
	"StickyIP: No cache entry found":                                             "固定出口IP：沒有快取可查（第一次連這個地址） ",
	"StickyIP: DialContext called":                                               "固定出口IP：要連線了 ",
	"StickyIP: Trying proxy IP":                                                  "固定出口IP：改用記下來的那個地址 ",
	"StickyIP: No valid cached IP - resolving proxy domain":                      "固定出口IP：快取的地址不能用，重新查域名 ",
	"StickyIP: Resolved proxy domain to IPs":                                     "固定出口IP：域名查到了 ",
	"StickyIP: Successfully connected to proxy IP":                               "固定出口IP：連線成功 ",
	"StickyIP: Cycle mismatch - cache not from current cycle":                    "固定出口IP：快取是上個週期的，作廢 ",
	"StickyIP: Cache hit - returning cached IP":                                  "固定出口IP：快取命中，直接沿用 ",
	"StickyIP: Cache hit - using cached proxy IP":                                "固定出口IP：沿用記下來的地址 ",
	"StickyIP: Cached proxy IP":                                                  "固定出口IP：已記下地址 ",
	"StickyIP: NewStickyIpDialer created":                                        "固定出口IP：建立好包装器 ",
	"DialerRegister: Checking if sticky IP caching is needed":                    "節點註冊：先看這條要不要固定出口IP ",
	"DialerRegister: Creating sticky IP dialer wrapper for proxy domain":         "節點註冊：為這個域名建立固定出口IP包装 ",
	"Suppressing dialer availability failure during reload handoff":              "重載交接中，這次的失敗先不算節點壞",
	"CRITICAL: the conn-state maps are rejecting flows continuously":             "嚴重：連線狀態表已經持續擋掉新連線 ",
	"datapath resource exhaustion or event loss in this interval":                "這區間有資源耗盡或事件遺失 ",
	"datapath counters with no per-event warning advanced in this interval":      "這區間有些資料徑計數器有增加（不會單獨告警的那種） ",
	"Group ": "分組 ",
	"Recovery confirmed: long-term stability detected":              "已確認節點穩定，重試退減檔位調低 ",
	"Recovery detection initialized":                                "已啟動「節點恢復偵測」",
	"cleanupRoutingHandoffMap: removed":                             "清掉重載交接表的過期條目：",
	"Skip TCP relay eBPF offload":                                   "跳過 TCP 中轉的 eBPF 卸載：",
	"Rewrite dial target":                                           "改寫連線目標",
	"Group selects dialer":                                          "分組選中節點",
	"Group re-selects dialer":                                       "分組換了節點",
	"Group's check option has been override.":                       "這個分組的健康檢查靶子已覆寫（各組獨立判定）",
	"dialer connectivity check is sleeping due":                     "節點檢查暫停中，原因：",
	"cleanupConnStateMap: removed":                                  "清掉過期連線記錄：",
	"NotifyLatencyChange: ignoring stale availability notification": "忽略一則過期的可用性通知",
	"Read geosite":                                                  "讀取域名清單",
	"Read geoip":                                                    "讀取位址清單",
	"cache hit":                                                     "DNS 快取命中",
	"Connectivity Check failed":                                     "節點健康檢查沒過",
	"Failed to connect to the dialer":                               "連不上這條節點",
	"failed to dial":                                                "撥號失敗：",
	"[Reload]":                                                      "〔重載〕",
}

var errsZh = map[string]string{
	"no applicable IP for this network type": "這個網路類型（v4／v6）沒有可用位址",
	"network is unreachable":                 "沒有路由可以到這個網路（通常是 v6 沒起來）",
	"connection refused":                     "對方直接拒絕連線",
	"no such host":                           "域名解析不到",
	"i/o timeout":                            "等回應等到逾時",
	"context deadline exceeded":              "等太久被取消",
	"context canceled":                       "連線被取消",
	"operation was canceled":                 "作業被取消",
	"tls: failed to verify certificate":      "憑證驗證不過",
	"tls: handshake failure":                 "TLS 握手失敗",
	"bad file descriptor":                    "檔案描述符已失效（程式正在收尾）",
	"permission denied":                      "權限不足",
	"address already in use":                 "通訊埠已被佔用",
}

// 前綴型錯誤（`Head "https://…": EOF`、`dial tcp 1.2.3.4:443: …`）：
// 把「做了什麼」留著、只換掉後面的原因，免得連是哪个靶子掛了都看不出來。
var errPrefixesZh = map[string]string{
	"Head \"":  "對 HEAD 請求沒回應：",
	"Get \"":   "對 GET 請求沒回應：",
	"dial tcp": "撥號失敗 ",
	"dial udp": "UDP 撥號失敗 ",
}
