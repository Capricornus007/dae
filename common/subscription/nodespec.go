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
	"regexp"
	"strconv"
	"strings"
)

// nodeSpec 是各家訂閱格式的共同中間表徵：Clash YAML、sing-box JSON、
// v2rayN(NG) JSON 都只負責把自已的欄位對映到這裡，URI 的產生邏輯只有一份。
// 欄位語意照 dae 能實際解析的 link（`node {}` 段），不是照抄某個客戶端。
type nodeSpec struct {
	Name     string
	Type     string // ss / vmess / vless / trojan / hysteria2 / tuic
	Server   string
	Port     int
	UUID     string
	Password string
	Cipher   string // ss 的 method；vmess 的 security

	UDP *bool

	TLS         bool
	SNI         string
	SkipVerify  bool
	ALPN        []string
	Fingerprint string

	Network string // tcp / ws / grpc / h2
	Path    string
	Host    string
	Service string // grpc 的 service_name

	RealityPBK string
	RealitySID string

	Flow string

	Obfs         string
	ObfsPassword string
	Up           string
	Down         string

	CongestionControl string
	UDPRelayMode      string

	Plugin     string // ss 的 v2ray-plugin / simple-obfs
	PluginOpts string

	// SSR 專用（dae 的 outbound 有註冊 shadowsocksr）
	Proto      string // origin / auth_sha256_v1 ...
	ProtoParam string
	SsrObfs    string // plain / http_simple ...
	ObfsParam  string

	// juicity / naiveproxy 的帳號（anytls 用 Password 當 auth）
	User        string
	PinnedCert  string
	NaiveScheme string // naive+https 或 naive+quic
}

var errUnsupportedProtocol = fmt.Errorf("unsupported protocol")

// toDaeLink 產生 dae 的 `node {}` 能直接吃的 link。
func (p *nodeSpec) toDaeLink() (string, error) {
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
	case "ssr", "shadowsocksr":
		return p.ssrLink()
	case "juicity":
		return p.juicityLink()
	case "anytls":
		return p.anytlsLink()
	case "naive", "naiveproxy":
		return p.naiveLink()
	case "socks", "socks4", "socks4a", "socks5", "http", "https":
		return p.plainProxyLink()
	default:
		// snell / hysteria(v1) / wireguard / ssh / brook / trusttunnel：
		// dae 的 outbound 沒註冊這些 dialer，翻不出來
		return "", errUnsupportedProtocol
	}
}

func (p *nodeSpec) hostPort() string {
	// IPv6 字面量一定要加中括號，否則 host:port 會歧義；net.JoinHostPort 已處理
	return net.JoinHostPort(p.Server, strconv.Itoa(p.Port))
}

// remark 放 URI 的 fragment（ss/vless/trojan/hy2/tuic 都是這個位置）。
func (p *nodeSpec) remark() string {
	if p.Name != "" {
		return p.Name
	}
	return fmt.Sprintf("%s:%d", p.Server, p.Port)
}

func (p *nodeSpec) query() url.Values {
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

// setTransport 把傳輸層翻成 dae 的 type/path/host。
func (p *nodeSpec) setTransport(q url.Values) {
	switch strings.ToLower(p.Network) {
	case "", "tcp", "raw", "system":
		q.Set("type", "tcp")
	case "ws", "websocket":
		q.Set("type", "ws")
		if p.Path != "" {
			q.Set("path", p.Path)
		}
		if p.Host != "" {
			q.Set("host", p.Host)
		}
	case "grpc", "grpc-multi":
		q.Set("type", "grpc")
		if p.Service != "" {
			q.Set("serviceName", p.Service)
		}
	default:
		// h2/xhttp/http：dae 的 link 沒有這一類，硬翻會做出「連得上但上行錯」的殭屍節點
		q.Set("type", "tcp")
	}
}

// setReality 寫入 REALITY 參數；public-key 缺位就不是 Reality 節點，回 false
// 讓呼叫端退回普通 tls（很多站會殘留空的 reality 段）。
func (p *nodeSpec) setReality(q url.Values) bool {
	if p.RealityPBK == "" {
		return false
	}
	q.Set("security", "reality")
	q.Set("pbk", p.RealityPBK)
	if p.RealitySID != "" {
		q.Set("sid", p.RealitySID)
	}
	return true
}

func (p *nodeSpec) ssLink() (string, error) {
	if p.Cipher == "" {
		return "", fmt.Errorf("ss 節點缺少加密方式")
	}
	userinfo := base64.RawURLEncoding.EncodeToString([]byte(p.Cipher + ":" + p.Password))
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
		Host:     p.hostPort(),
		RawQuery: q.Encode(),
		Fragment: p.remark(),
	}
	return u.String(), nil
}

func (p *nodeSpec) vmessLink() (string, error) {
	if p.UUID == "" {
		return "", fmt.Errorf("vmess 節點缺少 uuid")
	}
	// dae 的 vmess JSON 裡 `type` 是**標題混淆類型**，只認 none / "" / http
	// （dialer/v2ray/v2ray.go:206 那個 switch），不是加密方式。把客戶端訂閱裡的
	// cipher（常見值 auto）直接塞進 type，會讓 link 被 dae 回
	// "unexpected field: type: auto"（2026-09-26 拿 chromego 訂閱實測踩到）。
	// 加密方式 dae 不讀——它只吃 AEAD。
	headerType := ""
	if strings.EqualFold(p.Cipher, "http") {
		headerType = "http"
	}
	m := map[string]string{
		"v":    "2",
		"ps":   p.remark(),
		"add":  p.Server,
		"port": strconv.Itoa(p.Port),
		"id":   p.UUID,
		"aid":  "0",
		"type": headerType,
		"net":  p.normalizedNetwork(),
		"host": p.Host,
		"path": p.Path,
		"sni":  p.SNI,
		"alpn": strings.Join(p.ALPN, ","),
	}
	if p.TLS {
		m["tls"] = "tls"
	}
	if p.RealityPBK != "" {
		// vmess 沒有 REALITY；帶過去會被當成別的東西，寧可丟掉並說明原因
		return "", fmt.Errorf("vmess 不支援 reality")
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	// 不附 `#名稱`：dae 的 ParseVmessURL 取 `vmess://` 之後的整段做 base64 解碼，
	// 尾巴塞 fragment 會解不動（實測報 unrecognized vmess address）。節點名由
	// JSON 裡的 ps 帶，dialer 的 Name 讀的就是它。
	return "vmess://" + base64.StdEncoding.EncodeToString(b), nil
}

func (p *nodeSpec) vlessLink() (string, error) {
	if p.UUID == "" {
		return "", fmt.Errorf("vless 節點缺少 uuid")
	}
	q := p.query()
	p.setTransport(q)
	q.Set("encryption", "none")
	if p.Flow != "" {
		q.Set("flow", p.Flow)
	}
	if !p.setReality(q) && p.TLS {
		q.Set("security", "tls")
	}
	u := url.URL{
		Scheme:   "vless",
		User:     url.User(p.UUID),
		Host:     p.hostPort(),
		RawQuery: q.Encode(),
		Fragment: p.remark(),
	}
	return u.String(), nil
}

func (p *nodeSpec) trojanLink() (string, error) {
	if p.Password == "" {
		return "", fmt.Errorf("trojan 節點缺少密碼")
	}
	q := p.query()
	p.setTransport(q)
	if !p.setReality(q) && p.TLS {
		q.Set("security", "tls")
	}
	u := url.URL{
		Scheme:   "trojan",
		User:     url.User(p.Password),
		Host:     p.hostPort(),
		RawQuery: q.Encode(),
		Fragment: p.remark(),
	}
	return u.String(), nil
}

func (p *nodeSpec) hysteria2Link() (string, error) {
	if p.Password == "" {
		return "", fmt.Errorf("hysteria2 節點缺少密碼")
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
		Host:     p.hostPort(),
		RawQuery: q.Encode(),
		Fragment: p.remark(),
	}
	return u.String(), nil
}

func (p *nodeSpec) tuicLink() (string, error) {
	if p.UUID == "" {
		return "", fmt.Errorf("tuic 節點缺少 uuid")
	}
	q := p.query()
	if p.CongestionControl != "" {
		q.Set("congestion_control", p.CongestionControl)
	}
	if p.UDPRelayMode != "" {
		q.Set("udp_relay_mode", p.UDPRelayMode)
	}
	u := url.URL{
		Scheme:   "tuic",
		User:     url.UserPassword(p.UUID, p.Password),
		Host:     p.hostPort(),
		RawQuery: q.Encode(),
		Fragment: p.remark(),
	}
	return u.String(), nil
}

// ssrLink 照 dae 的 ParseSSRURL：`ssr://host:port:proto:method:obfs:b64(pass)/?
// remarks=&protoparam=&obfsparam=`，三個參數都是 base64url；它對「host 內含冒號」
// （IPv6）有專門的再切分邏輯，所以這裡直接照原樣拼。
func (p *nodeSpec) ssrLink() (string, error) {
	if p.Cipher == "" {
		return "", fmt.Errorf("ssr 節點缺少加密方式")
	}
	enc := func(v string) string { return base64.URLEncoding.EncodeToString([]byte(v)) }
	body := fmt.Sprintf("%s:%s:%s:%s:%s", p.hostPort(), p.Proto, p.Cipher, p.SsrObfs, enc(p.Password))
	q := fmt.Sprintf("remarks=%s&protoparam=%s&obfsparam=%s", enc(p.remark()), enc(p.ProtoParam), enc(p.ObfsParam))
	return "ssr://" + body + "/?" + q, nil
}

func (p *nodeSpec) juicityLink() (string, error) {
	if p.Password == "" {
		return "", fmt.Errorf("juicity 節點缺少密碼")
	}
	// dae 把 link 的 username 位置當 UUID 用，沒有合法 UUID 就建不起 dialer
	if !uuidRE.MatchString(p.User) {
		return "", errUnsupportedProtocol
	}
	q := p.query()
	if p.CongestionControl != "" {
		q.Set("congestion_control", p.CongestionControl)
	}
	if p.PinnedCert != "" {
		q.Set("pinned_certchain_sha256", p.PinnedCert)
	}
	u := url.URL{Scheme: "juicity", User: url.UserPassword(p.User, p.Password), Host: p.hostPort(), RawQuery: q.Encode(), Fragment: p.remark()}
	return u.String(), nil
}

// plainProxyLink 給 socks*/http/https 用：dae 的 outbound 有註冊這幾種
// （mihomo 訂閱裡常見，多為上游鏈），之前被我一併誤列為「不支援」。
func (p *nodeSpec) plainProxyLink() (string, error) {
	u := &url.URL{Scheme: strings.ToLower(p.Type), Host: p.hostPort(), Fragment: p.remark()}
	switch {
	case p.User != "" && p.Password != "":
		u.User = url.UserPassword(p.User, p.Password)
	case p.Password != "":
		u.User = url.User(p.Password)
	}
	return u.String(), nil
}

func (p *nodeSpec) anytlsLink() (string, error) {
	if p.Password == "" {
		return "", fmt.Errorf("anytls 節點缺少密碼")
	}
	q := p.query()
	u := url.URL{Scheme: "anytls", User: url.User(p.Password), Host: p.hostPort(), RawQuery: q.Encode(), Fragment: p.remark()}
	return u.String(), nil
}

// naiveLink：dae 的 naive dialer 註冊了兩種 scheme，但 `naive+quic` 在
// dialer/naive/naive.go 的 toDialer 裡明確回 "naive+quic is not supported yet"
// （連測試都斷言這句話）→ 寧可跳過並計數，也不吐一條建不起來的 link。
func (p *nodeSpec) naiveLink() (string, error) {
	if p.NaiveScheme == "naive+quic" {
		return "", errUnsupportedProtocol
	}
	user := url.User(p.Password)
	if p.User != "" {
		user = url.UserPassword(p.User, p.Password)
	}
	u := url.URL{Scheme: "naive+https", User: user, Host: p.hostPort(), Fragment: p.remark()}
	return u.String(), nil
}

// uuidRE：juicity 把 username 位置當 UUID 解析（ParseJuicityURL 不檢查，
// 下游 toDialer 才丟 "parse UUID: invalid UUID length: N"），所以生成端就得擋。
var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func (p *nodeSpec) normalizedNetwork() string {
	switch strings.ToLower(p.Network) {
	case "", "tcp", "raw", "system":
		return "tcp"
	case "ws", "websocket":
		return "ws"
	case "grpc", "grpc-multi":
		return "grpc"
	default:
		return "tcp"
	}
}
