/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package subscription

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

// NB4A（以及 sing-box 系客戶端）能匯入/匯出的另外兩種格式：
//   - sing-box JSON：`outbounds[].type`
//   - v2rayN(NG) JSON：`outbounds[].protocol` + `settings.vnext/servers` + `streamSettings`
// 兩者都翻成 nodeSpec，URI 產生邏輯與 Clash 共用 nodespec.go。
//
// 只吃「訂閱」語境下的配置：`outbounds` 是節點清單，其餘段（inbounds/route/
// dns）對 dae 沒意義，忽略。

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// resolveNodeSpecs 把一批 spec 轉成 URI，不支援的協定按名稱計數後跳過。
// 一個節點轉不動不影響其餘節點；全空才回 error，讓呼叫端續試下一種格式。
func resolveNodeSpecs(log *logrus.Logger, format string, specs []*nodeSpec) ([]string, error) {
	var nodes []string
	skipped := make(map[string]int)
	for i, p := range specs {
		if p == nil {
			continue
		}
		link, err := p.toDaeLink()
		if err != nil {
			if err == errUnsupportedProtocol {
				skipped[strings.ToLower(p.Type)]++
			} else {
				log.Warnf("%s 節點 #%d (%q) 無法轉換：%v", format, i+1, p.Name, err)
			}
			continue
		}
		nodes = append(nodes, link)
	}
	for proto, n := range skipped {
		log.Warnf("%s 訂閱裡有 %d 個 %s 節點 dae 不支援，已跳過", format, n, proto)
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("%s subscription resolved to 0 usable nodes", format)
	}
	return nodes, nil
}

// ---------- sing-box JSON ----------

type singBoxConfig struct {
	Outbounds []singBoxOutbound `json:"outbounds"`
}

type singBoxOutbound struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
	UUID       string `json:"uuid"`
	Password   string `json:"password"`
	Method     string `json:"method"`
	Security   string `json:"security"` // vmess 的 cipher 在这一栏
	Flow       string `json:"flow"`

	CongestionControl string `json:"congestion_control"`
	UDPRelayMode      string `json:"udp_relay_mode"`
	UpMbps            int    `json:"up_mbps"`
	DownMbps          int    `json:"down_mbps"`

	TLS *struct {
		Enabled    bool     `json:"enabled"`
		ServerName string   `json:"server_name"`
		SNI        string   `json:"sni"` // 兩種寫法都見過
		ALPN       []string `json:"alpn"`
		Insecure   bool     `json:"insecure"`
		Reality    struct {
			Enabled   bool   `json:"enabled"`
			PublicKey string `json:"public_key"`
			ShortID   string `json:"short_id"`
		} `json:"reality"`
		UTLS struct {
			Enabled     bool   `json:"enabled"`
			Fingerprint string `json:"fingerprint"`
		} `json:"utls"`
	} `json:"tls"`

	Transport *struct {
		Type        string            `json:"type"`
		Path        string            `json:"path"`
		Host        json.RawMessage   `json:"host"` // 字串或字串陣列
		Headers     map[string]string `json:"headers"`
		ServiceName string            `json:"service_name"`
	} `json:"transport"`

	Obfs json.RawMessage `json:"obfs"` // shadowsocks 是物件、shadowsocksr 是字串，同一個 key 兩種型別

	// shadowsocksr 專用
	Protocol      string `json:"protocol"`
	ProtocolParam string `json:"protocol_param"`
	ObfsParam     string `json:"obfs_param"`

	// anytls 可給一組密碼；naive / juicity 帶帳號
	Passwords []string `json:"passwords"`
	Username  string   `json:"username"`

	// sing-box 的 plugin 在 shadowsocks 下是字串（"v2ray-plugin"），別處見過物件寫法；
	// 同一個 key 兩種型別，宣告成具體型別會讓整份 JSON 解析失敗。
	Plugin     json.RawMessage `json:"plugin"`
	PluginOpts json.RawMessage `json:"plugin-opts"`
}

// singBoxPluginOptsToString 把 plugin-opts 物件轉成 dae 的 `k=v;k=v`。
// sing-box 的 simple-obfs 用 mode 這個名字，dae 要的是 obfs，必須換掉——
// 否則生成的 link 是 `plugin=obfs-local;`（obfs 值為空），dae 會回
// "unsupported obfs  of plugin simple-obfs"（實測踩到）。
func singBoxPluginOptsToString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		name := k
		if k == "mode" {
			name = "obfs"
		}
		parts = append(parts, name+"="+fmt.Sprint(m[k]))
	}
	return strings.Join(parts, ";")
}

// rawStringOrType 處理「字串或 {type:...} 物件」兩種寫法。
func rawStringOrType(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var o struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &o); err == nil {
		return o.Type
	}
	return ""
}

// ResolveSubscriptionAsSingBox 吃 sing-box 的 JSON 配置（NB4A 的匯出格式）。
func ResolveSubscriptionAsSingBox(log *logrus.Logger, b []byte) (nodes []string, err error) {
	log.Debugln("Try to resolve as sing-box")
	var cfg singBoxConfig
	if err = json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal sing-box subscription: %w", err)
	}
	specs := make([]*nodeSpec, 0, len(cfg.Outbounds))
	for i := range cfg.Outbounds {
		if s := cfg.Outbounds[i].toSpec(); s != nil {
			specs = append(specs, s)
		}
	}
	if len(specs) == 0 {
		return nil, fmt.Errorf("does not seem like a sing-box subscription")
	}
	return resolveNodeSpecs(log, "sing-box", specs)
}

func (o *singBoxOutbound) toSpec() *nodeSpec {
	// direct/block/dns/reject 與 selector/urltest（sing-box 的「群組」，等价於 mihomo
	// 的 proxy-group）不是節點，是路由骨架，丟掉且不計數；
	// hysteria v1、wireguard、socks/http 等 dae 的 outbound 沒註冊的類型，
	// 交給 resolveNodeSpecs 按協定計數後跳過。ssr / anytls / naive / juicity
	// 這四種 2026-09-26 起已能翻成 dae link，不再算跳過。
	switch strings.ToLower(o.Type) {
	case "", "direct", "block", "dns", "reject", "selector", "urltest", "packet-tunnel":
		return nil
	}
	s := &nodeSpec{
		Name:     firstNonEmpty(o.Tag, fmt.Sprintf("%s:%d", o.Server, o.ServerPort)),
		Type:     normalizeSingBoxType(o.Type),
		Server:   o.Server,
		Port:     o.ServerPort,
		UUID:     o.UUID,
		Password: o.Password,
		Cipher:   firstNonEmpty(o.Method, o.Security),
		Flow:     o.Flow,
		// socks / http / juicity 的帳號；sing-box 統一叫 username
		User:              o.Username,
		CongestionControl: o.CongestionControl,
		UDPRelayMode:      o.UDPRelayMode,
	}
	if o.UpMbps > 0 {
		s.Up = strconv.Itoa(o.UpMbps)
	}
	if o.DownMbps > 0 {
		s.Down = strconv.Itoa(o.DownMbps)
	}
	if o.TLS != nil {
		s.TLS = o.TLS.Enabled || o.TLS.Reality.Enabled
		s.SNI = firstNonEmpty(o.TLS.ServerName, o.TLS.SNI)
		s.SkipVerify = o.TLS.Insecure
		s.ALPN = o.TLS.ALPN
		s.Fingerprint = o.TLS.UTLS.Fingerprint
		if o.TLS.Reality.Enabled || o.TLS.Reality.PublicKey != "" {
			s.RealityPBK = o.TLS.Reality.PublicKey
			s.RealitySID = o.TLS.Reality.ShortID
		}
	}
	if o.Transport != nil {
		s.Network = o.Transport.Type
		s.Path = o.Transport.Path
		s.Service = o.Transport.ServiceName
		s.Host = firstNonEmpty(jsonStringOrFirst(o.Transport.Host), o.Transport.Headers["Host"])
	}
	if len(o.Obfs) > 0 {
		// shadowsocks 的 obfs 是 {"type":..,"password":..}；shadowsocksr 的 obfs 是 "plain"/"http_simple" 字串
		var obj struct {
			Type     string `json:"type"`
			Password string `json:"password"`
		}
		if err := json.Unmarshal(o.Obfs, &obj); err == nil {
			s.Obfs = obj.Type
			s.ObfsPassword = obj.Password
		} else {
			var str string
			if err2 := json.Unmarshal(o.Obfs, &str); err2 == nil {
				s.SsrObfs = str
			}
		}
	}
	switch strings.ToLower(o.Type) {
	case "shadowsocksr", "ssr":
		s.Proto = firstNonEmpty(o.Protocol, "origin")
		s.ProtoParam = o.ProtocolParam
		s.ObfsParam = o.ObfsParam
		if s.SsrObfs == "" {
			s.SsrObfs = "plain"
		}
	case "anytls":
		if s.Password == "" && len(o.Passwords) > 0 {
			s.Password = o.Passwords[0]
		}
		// anytls 的 obfs 是 reality 之外的第二層混淆，放在 tls 段裡；dae 的 anytls link 不吃它
		s.Obfs, s.ObfsPassword = "", ""
	case "naive":
		// sing-box 的 naive 用 protocol 欄位選 http3 / https，對應 dae 的 naive+quic / naive+https
		s.NaiveScheme = "naive+https"
		if strings.EqualFold(o.Protocol, "http3") || strings.EqualFold(o.Protocol, "quic") {
			s.NaiveScheme = "naive+quic"
		}
		s.User = firstNonEmpty(o.Username, o.UUID)
	case "juicity":
		// dae 把 link 的 username 位置當 UUID，sing-box 兩邊欄位名都見過
		s.User = firstNonEmpty(o.Username, o.UUID)
	}
	s.Plugin = rawStringOrType(o.Plugin)
	s.PluginOpts = singBoxPluginOptsToString(o.PluginOpts)
	return s
}

func normalizeSingBoxType(t string) string {
	switch strings.ToLower(t) {
	case "shadowsocks", "ss":
		return "ss"
	case "vmess":
		return "vmess"
	case "vless":
		return "vless"
	case "trojan":
		return "trojan"
	case "hysteria2":
		return "hysteria2"
	case "tuic":
		return "tuic"
	default:
		return strings.ToLower(t)
	}
}

// jsonStringOrFirst：sing-box 的 transport.host 可以是字串或陣列。
func jsonStringOrFirst(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return one
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil && len(many) > 0 {
		return many[0]
	}
	return ""
}

// ---------- v2rayN(NG) JSON ----------

type v2rayNConfig struct {
	Outbounds []v2rayNOutbound `json:"outbounds"`
}

type v2rayNOutbound struct {
	Tag      string          `json:"tag"`
	Protocol string          `json:"protocol"`
	Settings json.RawMessage `json:"settings"`
	Stream   struct {
		Network     string `json:"network"`
		Security    string `json:"security"`
		TLSSettings struct {
			ServerName  string `json:"serverName"`
			Alpn        string `json:"alpn"`
			Fingerprint string `json:"fingerprint"`
			Insecure    bool   `json:"allowInsecure"`
			SNI         string `json:"sni"`
		} `json:"tlsSettings"`
		RealitySettings struct {
			Fingerprint string `json:"fingerprint"`
			PublicKey   string `json:"publicKey"`
			ShortID     string `json:"shortId"`
			SpiderX     string `json:"spiderX"`
			ServerName  string `json:"serverName"`
		} `json:"realitySettings"`
		WsSettings struct {
			Path    string            `json:"path"`
			Headers map[string]string `json:"headers"`
		} `json:"wsSettings"`
		GrpcSettings struct {
			ServiceName string `json:"serviceName"`
			MultiMode   bool   `json:"multiMode"`
		} `json:"grpcSettings"`
		HttpSettings struct {
			Path string `json:"path"`
			Host any    `json:"host"`
		} `json:"httpSettings"`
	} `json:"streamSettings"`
}

type v2rayNSettings struct {
	VNext []struct {
		Address string `json:"address"`
		Port    int    `json:"port"`
		Users   []struct {
			ID         string   `json:"id"`
			AlterID    any      `json:"alterId"`
			Security   string   `json:"security"`
			Flow       string   `json:"flow"`
			Flows      []string `json:"flows"` // v2rayN 新版本用陣列
			Encryption string   `json:"encryption"`
			Level      string   `json:"level"`
		} `json:"users"`
	} `json:"vnext"`
	Servers []struct {
		Address  string   `json:"address"`
		Port     int      `json:"port"`
		Users    []string `json:"users"` // ss: ["method:password"]
		Password string   `json:"password"`
		Flow     string   `json:"flow"`
		Email    string   `json:"email"`
	} `json:"servers"`
}

// ResolveSubscriptionAsV2rayN 吃 v2rayN / v2rayNG 的匯出 JSON。
func ResolveSubscriptionAsV2rayN(log *logrus.Logger, b []byte) (nodes []string, err error) {
	log.Debugln("Try to resolve as v2rayN")
	var cfg v2rayNConfig
	if err = json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal v2rayN subscription: %w", err)
	}
	specs := make([]*nodeSpec, 0, len(cfg.Outbounds))
	for i := range cfg.Outbounds {
		if s := cfg.Outbounds[i].toSpec(); s != nil {
			specs = append(specs, s)
		}
	}
	if len(specs) == 0 {
		return nil, fmt.Errorf("does not seem like a v2rayN subscription")
	}
	return resolveNodeSpecs(log, "v2rayN", specs)
}

func (o *v2rayNOutbound) toSpec() *nodeSpec {
	protocol := strings.ToLower(o.Protocol)
	if protocol == "" || protocol == "freedom" || protocol == "blackhole" || protocol == "dns" {
		return nil
	}
	var st v2rayNSettings
	if len(o.Settings) > 0 {
		if err := json.Unmarshal(o.Settings, &st); err != nil {
			return nil
		}
	}
	s := &nodeSpec{
		Name:    o.Tag,
		Type:    protocol,
		Network: o.Stream.Network,
	}
	switch protocol {
	case "vmess", "vless":
		if len(st.VNext) == 0 || len(st.VNext[0].Users) == 0 {
			return nil
		}
		v := st.VNext[0]
		u := v.Users[0]
		s.Server = v.Address
		s.Port = v.Port
		s.UUID = u.ID
		s.Cipher = u.Security
		s.Flow = firstNonEmpty(u.Flow, strings.Join(u.Flows, ","))
	case "trojan":
		if len(st.Servers) == 0 {
			return nil
		}
		s.Server = st.Servers[0].Address
		s.Port = st.Servers[0].Port
		s.Password = st.Servers[0].Password
		s.Flow = st.Servers[0].Flow
	case "shadowsocks":
		if len(st.Servers) == 0 {
			return nil
		}
		srv := st.Servers[0]
		s.Server = srv.Address
		s.Port = srv.Port
		s.Type = "ss"
		// v2rayN 把 ss 的 users 寫成 ["method:password"]
		if len(srv.Users) > 0 {
			if method, pw, ok := strings.Cut(srv.Users[0], ":"); ok {
				s.Cipher, s.Password = method, pw
			} else {
				s.Password = srv.Users[0]
			}
		}
	default:
		// 交給 toDaeLink 統一計數跳過
		s.Server, s.Port = "", 0
		return s
	}

	// TLS / REALITY
	switch strings.ToLower(o.Stream.Security) {
	case "tls":
		s.TLS = true
		s.SkipVerify = o.Stream.TLSSettings.Insecure
		s.Fingerprint = o.Stream.TLSSettings.Fingerprint
	case "reality":
		s.TLS = true
		s.RealityPBK = o.Stream.RealitySettings.PublicKey
		s.RealitySID = o.Stream.RealitySettings.ShortID
		s.Fingerprint = firstNonEmpty(o.Stream.RealitySettings.Fingerprint, o.Stream.TLSSettings.Fingerprint)
		s.SNI = firstNonEmpty(o.Stream.RealitySettings.ServerName, o.Stream.TLSSettings.ServerName)
	}
	if s.SNI == "" {
		s.SNI = firstNonEmpty(o.Stream.TLSSettings.ServerName, o.Stream.TLSSettings.SNI)
	}
	if alpn := o.Stream.TLSSettings.Alpn; alpn != "" {
		s.ALPN = strings.Split(alpn, ",")
	}

	// 傳輸層
	switch strings.ToLower(o.Stream.Network) {
	case "ws":
		s.Path = firstNonEmpty(s.Path, o.Stream.WsSettings.Path)
		s.Host = o.Stream.WsSettings.Headers["Host"]
	case "grpc":
		s.Service = o.Stream.GrpcSettings.ServiceName
		if o.Stream.GrpcSettings.MultiMode {
			s.Network = "grpc-multi"
		}
	case "http":
		s.Path = o.Stream.HttpSettings.Path
		if h, ok := o.Stream.HttpSettings.Host.(string); ok {
			s.Host = h
		}
	}
	if s.Name == "" {
		s.Name = fmt.Sprintf("%s:%d", s.Server, s.Port)
	}
	return s
}
