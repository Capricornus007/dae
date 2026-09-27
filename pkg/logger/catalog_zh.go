package logger

// 中文對照表。用詞原則（用戶原話「記得也得弄成平民大白話」）：
// 講「誰做了什麼」，不講術語縮寫；`StickyIP` 這種功能名一律翻成「固定出口IP」，
// 因為他看的是「這行在講哪件事」，不是「這行對應哪個 Go 符號」。
//
// 表裡只放**這臺機器日誌真的刷出來過**的訊息（按出現次數排序取的），
// 沒見過的訊息一律留英文原樣——翻錯比不翻更糟，而且英文原字還在，不丟證據。
var messagesZh = map[string]string{
	"Connectivity Check Failed":        "節點健康檢查沒過",
	"Skip check due to no DNS record.": "這個節點目前沒有可用的解析結果，這次檢查先跳過",
	"ALIVE --tcp4-> NOT ALIVE:":        "節點轉為「不通」（tcp4）：",
	"ALIVE --tcp6-> NOT ALIVE:":        "節點轉為「不通」（tcp6）：",
	"NOT ALIVE --tcp4-> ALIVE:":        "節點恢復「可用」（tcp4）：",
	"NOT ALIVE --tcp6-> ALIVE:":        "節點恢復「可用」（tcp6）：",
	"ALIVE --udp4(DNS)-> NOT ALIVE:":   "節點轉為「不通」（udp4 查 DNS）：",
	"ALIVE --udp6(DNS)-> NOT ALIVE:":   "節點轉為「不通」（udp6 查 DNS）：",
	"NOT ALIVE --udp4(DNS)-> ALIVE:":   "節點恢復「可用」（udp4 查 DNS）：",
	"NOT ALIVE --udp6(DNS)-> ALIVE:":   "節點恢復「可用」（udp6 查 DNS）：",
	"ALIVE --tcp4-> ALIVE:":            "節點仍可用（tcp4）：",
	"TCP relay completed":              "TCP 中轉結束",
	"Group has no dialer alive":        "這個分組已經沒有可用節點",
	"The number of dialers is 0":       "一條節點都沒有",
	"dae is running":                   "dae 已啟動",
	"start process successfully":       "啟動完成",
}

// 前綴表：訊息後面掛了動態內容（延遲數字、節點名、域名）就用這條。
// 命中後「中文前綴 ＋ 英文剩下的部分」直接拼接，所以前綴要自己帶好分隔空格。
var messagePrefixesZh = map[string]string{
	"StickyIP: Check cycle incremented":                                  "固定出口IP：檢查週期遞進 ",
	"StickyIP: No cache entry found":                                     "固定出口IP：沒有快取可查（第一次連這個地址） ",
	"StickyIP: DialContext called":                                       "固定出口IP：要連線了 ",
	"StickyIP: Trying proxy IP":                                          "固定出口IP：改用記下來的那個地址 ",
	"StickyIP: No valid cached IP - resolving proxy domain":              "固定出口IP：快取的地址不能用，重新查域名 ",
	"StickyIP: Resolved proxy domain to IPs":                             "固定出口IP：域名查到了 ",
	"StickyIP: Successfully connected to proxy IP":                       "固定出口IP：連線成功 ",
	"StickyIP: Cycle mismatch - cache not from current cycle":            "固定出口IP：快取是上個週期的，作廢 ",
	"StickyIP: Cache hit - returning cached IP":                          "固定出口IP：快取命中，直接沿用 ",
	"StickyIP: Cache hit - using cached proxy IP":                        "固定出口IP：沿用記下來的地址 ",
	"StickyIP: Cached proxy IP":                                          "固定出口IP：已記下地址 ",
	"StickyIP: NewStickyIpDialer created":                                "固定出口IP：建立好包装器 ",
	"DialerRegister: Checking if sticky IP caching is needed":            "節點註冊：先看這條要不要固定出口IP ",
	"DialerRegister: Creating sticky IP dialer wrapper for proxy domain": "節點註冊：為這個域名建立固定出口IP包装 ",
	"Suppressing dialer availability failure during reload handoff":      "重載交接中，這次的失敗先不算節點壞",
	"Recovery detection initialized":                                     "已啟動「節點恢復偵測」",
	"Rewrite dial target":                                                "改寫連線目標",
	"Group selects dialer":                                               "分組選中節點",
	"Group re-selects dialer":                                            "分組換了節點",
	"Group's check option has been override.":                            "這個分組的健康檢查靶子已覆寫（各組獨立判定）",
	"dialer connectivity check is sleeping due":                          "節點檢查暫停中，原因：",
	"cleanupConnStateMap: removed":                                       "清掉過期連線記錄：",
	"NotifyLatencyChange: ignoring stale availability notification":      "忽略一則過期的可用性通知",
	"Read geosite":                    "讀取域名清單",
	"Read geoip":                      "讀取位址清單",
	"cache hit":                       "DNS 快取命中",
	"Connectivity Check avg":          "節點健康檢查 ",
	"Connectivity Check failed":       "節點健康檢查沒過",
	"Failed to connect to the dialer": "連不上這條節點",
	"failed to dial":                  "撥號失敗：",
	"[Reload]":                        "〔重載〕",
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
