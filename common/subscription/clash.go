/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package subscription

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// Clash 系（Clash/Mihomo/Surge-Clash 混排）訂閱的相容層。市面上大量站點只發
// Clash 配置，而 dae 原本只認 SIP008 與 base64 的節點 URI 清單（見
// ResolveSubscription），這類源對 dae 等於不可用。這裡把它們翻成 dae 的
// link 寫法，讓 `subscription:` 直接吃。URI 的產生在 nodespec.go，三種格式共用。
//
// 欄位名照 Mihomo 的寫法，目的是對齊「真實訂閱長什麼樣」而不是「希望它長什麼樣」。

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
	Method   string `yaml:"method"` // 有些配置把 ss 的加密寫成 method
	UDP      *bool  `yaml:"udp"`

	TLS         bool              `yaml:"tls"`
	SNI         string            `yaml:"servername"`
	SkipVerify  bool              `yaml:"skip-cert-verify"`
	ALPN        []string          `yaml:"alpn"`
	Fingerprint string            `yaml:"client-fingerprint"`
	Network     string            `yaml:"network"`
	WsPath      string            `yaml:"ws-path"`
	WsHeaders   map[string]string `yaml:"ws-headers"`
	GrpcService string            `yaml:"grpc-service-name"`
	Host        string            `yaml:"host"`
	Path        string            `yaml:"path"`
	Flow        string            `yaml:"flow"`
	RealityOpts struct {
		PublicKey string `yaml:"public-key"`
		ShortID   string `yaml:"short-id"`
	} `yaml:"reality-opts"`
	Obfs              string `yaml:"obfs"`
	ObfsPassword      string `yaml:"obfs-password"`
	Up                string `yaml:"up"`
	Down              string `yaml:"down"`
	CongestionControl string `yaml:"congestion-controller"`
	UDPRelayMode      string `yaml:"udp-relay-mode"`
	Plugin            string `yaml:"plugin"`
	PluginOpts        any    `yaml:"plugin-opts"` // 字串或映射，兩種都見過
}

// ResolveSubscriptionAsClash 把 Clash YAML 訂閱翻成 dae 的節點 URI 清單。
// 內容不是 Clash（沒有可用的 proxies 段）時回 error，讓呼叫端續試下一種格式。
func ResolveSubscriptionAsClash(log *logrus.Logger, b []byte) (nodes []string, err error) {
	log.Debugln("Try to resolve as clash")
	var sub clashSubscription
	if err = yaml.Unmarshal(b, &sub); err != nil {
		return nil, fmt.Errorf("failed to unmarshal clash subscription: %w", err)
	}
	if len(sub.Proxies) == 0 {
		return nil, fmt.Errorf("does not seem like a clash subscription")
	}
	specs := make([]*nodeSpec, 0, len(sub.Proxies))
	for i := range sub.Proxies {
		specs = append(specs, sub.Proxies[i].toSpec())
	}
	return resolveNodeSpecs(log, "clash", specs)
}

func (p *clashProxy) toSpec() *nodeSpec {
	return &nodeSpec{
		Name:              p.Name,
		Type:              p.Type,
		Server:            p.Server,
		Port:              p.Port,
		UUID:              p.UUID,
		Password:          p.Password,
		Cipher:            firstNonEmpty(p.Cipher, p.Method),
		UDP:               p.UDP,
		TLS:               p.TLS,
		SNI:               p.SNI,
		SkipVerify:        p.SkipVerify,
		ALPN:              p.ALPN,
		Fingerprint:       p.Fingerprint,
		Network:           p.Network,
		Path:              firstNonEmpty(p.WsPath, p.Path),
		Host:              p.wsHost(),
		Service:           p.GrpcService,
		RealityPBK:        p.RealityOpts.PublicKey,
		RealitySID:        p.RealityOpts.ShortID,
		Flow:              p.Flow,
		Obfs:              p.Obfs,
		ObfsPassword:      p.ObfsPassword,
		Up:                p.Up,
		Down:              p.Down,
		CongestionControl: p.CongestionControl,
		UDPRelayMode:      p.UDPRelayMode,
		Plugin:            p.Plugin,
		PluginOpts:        clashPluginOptsToString(p.PluginOpts),
	}
}

// wsHost 取 ws 的 Host 標頭：Clash 可能寫在 host，也可能藏在 ws-headers 裡。
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

// clashPluginOptsToString 把 simple-obfs 的 plugin-opts 歸一成 `k=v;k=v`：
// Clash 允許寫成映射，而 SIP008 與 dae 的 plugin 參數是字串形式。
func clashPluginOptsToString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case map[string]any:
		parts := make([]string, 0, len(t))
		for k, val := range t {
			parts = append(parts, k+"="+fmt.Sprint(val))
		}
		return strings.Join(parts, ";")
	default:
		return fmt.Sprint(v)
	}
}
