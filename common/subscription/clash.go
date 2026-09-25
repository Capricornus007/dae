/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package subscription

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// Clash 系（Clash/Mihomo/Surge-Clash 混排）訂閱的相容層。市面上大量站點只發
// Clash 配置，而 dae 原本只認 SIP008 與 base64 的節點 URI 清單（見
// ResolveSubscription），這類源對 dae 等於不可用。這裡把它們翻成 dae 的
// link 寫法，讓 `subscription:` 直接吃。
//
// 欄位對照以本倉庫能實際解析的 link 為準（`node {}` 段的寫法），不是照抄某個
// Clash 分支：未知欄位一律忽略，不支援的協議丟棄並記一條 warn——靜默少節點比
// 靜默錯節點好。

type clashSubscription struct {
	Proxies []clashProxy `yaml:"proxies"`
}

type clashProxy struct {
	Name     string `yaml:"name"`
	Type     string `yaml:"type"`
	Server   string `yaml:"server"`
	Port     int    `yaml:"port"`
	Password string `yaml:"password"`
	UUID     string `yaml:"uuid"`
	Cipher   string `yaml:"cipher"`
	Method   string `yaml:"method"` // 部分配置把 ss 的加密寫成 method
	UDP      *bool  `yaml:"udp"`

	// TLS / SNI / 驗證
	TLS         bool     `yaml:"tls"`
	SNI         string   `yaml:"servername"`
	SkipVerify  bool     `yaml:"skip-cert-verify"`
	ALPN        []string `yaml:"alpn"`
	Fingerprint string   `yaml:"client-fingerprint"`

	// 傳輸層
	Network     string            `yaml:"network"`
	WsPath      string            `yaml:"ws-path"`
	WsHeaders   map[string]string `yaml:"ws-headers"`
	GrpcService string            `yaml:"grpc-service-name"`
	Host        string            `yaml:"host"`
	Path        string            `yaml:"path"`

	// Reality
	RealityOpts struct {
		PublicKey string `yaml:"public-key"`
		ShortID   string `yaml:"short-id"`
	} `yaml:"reality-opts"`

	// VLESS 流控
	Flow string `yaml:"flow"`

	// Hysteria2
	Obfs         string `yaml:"obfs"`
	ObfsPassword string `yaml:"obfs-password"`
	Up           string `yaml:"up"`
	Down         string `yaml:"down"`

	// TUIC
	CongestionControl string `yaml:"congestion-controller"`
	UdpRelayMode      string `yaml:"udp-relay-mode"`
	DisableSNI        bool   `yaml:"disable-sni"`

	// Shadowsocks 插件
	Plugin     string `yaml:"plugin"`
	PluginOpts string `yaml:"plugin-opts"`
}

// ResolveSubscriptionAsClash 把 Clash YAML 訂閱翻成 dae 的節點 URI 清單。
// 內容不是 Clash（沒有 proxies 段）時回 error，讓呼叫端續試下一種格式。
func ResolveSubscriptionAsClash(log *logrus.Logger, b []byte) (nodes []string, err error) {
	log.Debugln("Try to resolve as clash")
	var sub clashSubscription
	if err = yaml.Unmarshal(b, &sub); err != nil {
		return nil, fmt.Errorf("failed to unmarshal clash subscription: %w", err)
	}
	if len(sub.Proxies) == 0 {
		return nil, fmt.Errorf("does not seem like a clash subscription")
	}
	skipped := make(map[string]int)
	for i, p := range sub.Proxies {
		link, err := p.toDaeLink()
		if err != nil {
			// 不中斷：一個節點不支援不代表整份訂閱沒救
			key := strings.ToLower(p.Type)
			if err == errClashUnsupported {
				skipped[key]++
			} else {
				log.Warnf("clash proxy #%d (%q) 無法轉換：%v", i+1, p.Name, err)
			}
			continue
		}
		nodes = append(nodes, link)
	}
	for proto, n := range skipped {
		log.Warnf("clash 訂閱裡有 %d 個 %s 節點 dae 不支援，已跳過", n, proto)
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("clash subscription resolved to 0 usable nodes")
	}
	return nodes, nil
}

var errClashUnsupported = fmt.Errorf("unsupported protocol")

func (p *clashProxy) toDaeLink() (string, error) {
	if p.Server == "" || p.Port <= 0 {
		return "", fmt.Errorf("缺少 server/port")
	}
	switch strings.ToLower(p.Type) {
	case "ss", "shadowsocks":
		return p.ssLink()
	case "vmess":
		return p.vmessLink()
	case "vless":
		return p.vlessLink()
	case "trojan":
		return p.trojanLink()
	case "hysteria2", "hy2":
		return p.hysteria2Link()
	case "tuic":
		return p.tuicLink()
	default:
		// ssr / hysteria(v1) / snell / wireguard / shadow-tls / anytls /
		// naiveproxy / brook / juicity / trusttunnel：dae 沒有對應 dialer
		return "", errClashUnsupported
	}
}

func clashHostPort(server string, port int) string {
	// Clash 的 server 可能是 IPv6 字面量，必須加中括號，否則 URI 的 host:port 會歧義
	return net.JoinHostPort(server, strconv.Itoa(port))
}

func (p *clashProxy) fragment() string {
	name := p.Name
	if name == "" {
		name = fmt.Sprintf("%s:%d", p.Server, p.Port)
	}
	// URI 的 fragment 不允許裸空格/百分號，交給 url.URL 編碼而不是自己拼
	return name
}

// tlsQuery 組出各協議共用的 TLS 相關參數。
func (p *clashProxy) query() url.Values {
	q := make(url.Values)
	if p.SNI != "" {
		q.Set("sni", p.SNI)
	}
	if p.SkipVerify {
		q.Set("insecure", "1")
	}
	if len(p.ALPN) > 0 {
		q.Set("alpn", strings.Join(p.ALPN, ","))
	}
	if p.Fingerprint != "" {
		q.Set("fp", p.Fingerprint)
	}
	return q
}

// setTransport 把 network/ws/grpc 翻成 dae 的 type/path/host。
func (p *clashProxy) setTransport(q url.Values) {
	switch strings.ToLower(p.Network) {
	case "", "tcp", "raw":
		q.Set("type", "tcp")
	case "ws", "websocket":
		q.Set("type", "ws")
		if path := p.firstNonEmpty(p.WsPath, p.Path); path != "" {
			q.Set("path", path)
		}
		if host := p.wsHost(); host != "" {
			q.Set("host", host)
		}
	case "grpc", "grpc-multi":
		q.Set("type", "grpc")
		if p.GrpcService != "" {
			q.Set("serviceName", p.GrpcService)
		}
	case "http", "h2", "xhttp":
		// dae 的 link 沒有 xhttp 這一類，硬翻會變成連上行都錯的節點，寧可丟棄
		return
	default:
		q.Set("type", "tcp")
	}
}

func (p *clashProxy) wsHost() string {
	if p.Host != "" {
		return p.Host
	}
	for k, v := range p.WsHeaders {
		if strings.EqualFold(k, "host") && v != "" {
			return v
		}
	}
	return ""
}

func (p *clashProxy) firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// setReality 處理 VLESS/Trojan 的 REALITY 參數。public-key 缺了就不是 Reality
// 節點，此時寧可退回 tls（很多站的 reality-opts 是殘留欄位）。
func (p *clashProxy) setReality(q url.Values) bool {
	if p.RealityOpts.PublicKey == "" {
		return false
	}
	q.Set("security", "reality")
	q.Set("pbk", p.RealityOpts.PublicKey)
	if p.RealityOpts.ShortID != "" {
		q.Set("sid", p.RealityOpts.ShortID)
	}
	return true
}

func (p *clashProxy) ssLink() (string, error) {
	method := p.firstNonEmpty(p.Cipher, p.Method)
	if method == "" {
		return "", fmt.Errorf("ss 節點缺少 cipher")
	}
	userinfo := base64.RawURLEncoding.EncodeToString([]byte(method + ":" + p.Password))
	q := p.query()
	if p.Plugin != "" {
		plugin := p.Plugin
		if p.PluginOpts != "" {
			plugin += ";" + p.PluginOpts
		}
		q.Set("plugin", plugin)
	}
	u := url.URL{
		Scheme:   "ss",
		User:     url.User(userinfo),
		Host:     clashHostPort(p.Server, p.Port),
		RawQuery: q.Encode(),
		Fragment: p.fragment(),
	}
	return u.String(), nil
}

func (p *clashProxy) vmessLink() (string, error) {
	if p.UUID == "" {
		return "", fmt.Errorf("vmess 節點缺少 uuid")
	}
	security := p.firstNonEmpty(p.Cipher, "auto")
	if security == "none" {
		security = "auto"
	}
	m := map[string]any{
		"v":    "2",
		"ps":   p.fragment(),
		"add":  p.Server,
		"port": strconv.Itoa(p.Port),
		"id":   p.UUID,
		"aid":  "0",
		"type": security,
		"net":  p.normalizedNetwork(),
		"host": p.wsHost(),
		"path": p.firstNonEmpty(p.WsPath, p.Path),
		"tls":  "",
		"sni":  p.SNI,
		"alpn": strings.Join(p.ALPN, ","),
	}
	if p.TLS {
		m["tls"] = "tls"
	}
	if p.RealityOpts.PublicKey != "" {
		// vmess 沒有 reality，帶了會被誤解；保留 public-key 資訊在名稱裡由呼叫端判斷
		return "", fmt.Errorf("vmess 不支援 reality（pbk=%v…）", truncate(p.RealityOpts.PublicKey, 8))
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	// Opaque 要以「//」開頭才會被 url.URL 印成 `vmess://<base64>`；
	// 少了這兩個斜線就是 `vmess:xxx`，dae 的解析器直接報 missing link scheme。
	// 不附 `#名稱`：dae 的 ParseVmessURL 直接取 `vmess://` 之後的整段做 base64
	// 解碼，尾巴塞了 fragment 就解不動（實測報 unrecognized vmess address）。
	// 節點名由 JSON 裡的 ps 帶，dialer 的 Name 就是讀它。
	return "vmess://" + base64.StdEncoding.EncodeToString(b), nil
}

func (p *clashProxy) vlessLink() (string, error) {
	if p.UUID == "" {
		return "", fmt.Errorf("vless 節點缺少 uuid")
	}
	q := p.query()
	p.setTransport(q)
	q.Set("encryption", "none")
	if p.Flow != "" {
		q.Set("flow", p.Flow)
	}
	if !p.setReality(q) {
		if p.TLS {
			q.Set("security", "tls")
		}
	}
	u := url.URL{
		Scheme:   "vless",
		User:     url.User(p.UUID),
		Host:     clashHostPort(p.Server, p.Port),
		RawQuery: q.Encode(),
		Fragment: p.fragment(),
	}
	return u.String(), nil
}

func (p *clashProxy) trojanLink() (string, error) {
	if p.Password == "" {
		return "", fmt.Errorf("trojan 節點缺少 password")
	}
	q := p.query()
	p.setTransport(q)
	if !p.setReality(q) && p.TLS {
		q.Set("security", "tls")
	}
	u := url.URL{
		Scheme:   "trojan",
		User:     url.User(p.Password),
		Host:     clashHostPort(p.Server, p.Port),
		RawQuery: q.Encode(),
		Fragment: p.fragment(),
	}
	return u.String(), nil
}

func (p *clashProxy) hysteria2Link() (string, error) {
	if p.Password == "" {
		return "", fmt.Errorf("hysteria2 節點缺少 password")
	}
	q := p.query()
	if p.Obfs != "" {
		q.Set("obfs", p.Obfs)
		if p.ObfsPassword != "" {
			q.Set("obfs-password", p.ObfsPassword)
		}
	}
	if p.Up != "" {
		q.Set("up", p.Up)
	}
	if p.Down != "" {
		q.Set("down", p.Down)
	}
	u := url.URL{
		Scheme:   "hy2",
		User:     url.User(p.Password),
		Host:     clashHostPort(p.Server, p.Port),
		RawQuery: q.Encode(),
		Fragment: p.fragment(),
	}
	return u.String(), nil
}

func (p *clashProxy) tuicLink() (string, error) {
	if p.UUID == "" {
		return "", fmt.Errorf("tuic 節點缺少 uuid")
	}
	q := p.query()
	if p.CongestionControl != "" {
		q.Set("congestion_control", p.CongestionControl)
	}
	if p.UdpRelayMode != "" {
		q.Set("udp_relay_mode", p.UdpRelayMode)
	}
	u := url.URL{
		Scheme:   "tuic",
		User:     url.UserPassword(p.UUID, p.Password),
		Host:     clashHostPort(p.Server, p.Port),
		RawQuery: q.Encode(),
		Fragment: p.fragment(),
	}
	return u.String(), nil
}

func (p *clashProxy) normalizedNetwork() string {
	switch strings.ToLower(p.Network) {
	case "", "tcp", "raw":
		return "tcp"
	case "ws", "websocket":
		return "ws"
	case "grpc", "grpc-multi":
		return "grpc"
	default:
		return "tcp"
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
