/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package subscription

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/daeuniverse/dae/component/outbound" // 觸發各協議 dialer 的 init 註冊
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/sirupsen/logrus"
)

// sing-box 的匯出格式（NB4A 用的就是這份）。含 direct（路由骨架，不該變節點）
// 與 hysteria v1 / wireguard（dae 沒有 dialer，該跳過並計數）。
const singBoxSample = `{
  "log": {"level": "info"},
  "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "port": 2080}],
  "outbounds": [
    {"type": "direct", "tag": "direct"},
    {"type": "block", "tag": "block-out"},
    {"type": "shadowsocks", "tag": "sb-ss2022", "server": "1.2.3.4", "server_port": 32605,
      "method": "2022-blake3-aes-128-gcm", "password": "MDEyMzQ1Njc4OTFiY2RlZg=="},
    {"type": "vmess", "tag": "sb-vmess", "server": "example.com", "server_port": 443,
      "uuid": "11111111-2222-3333-4444-555555555555", "security": "auto",
      "tls": {"enabled": true, "server_name": "a.example.com", "utls": {"enabled": true, "fingerprint": "chrome"}},
      "transport": {"type": "ws", "path": "/vmess", "headers": {"Host": "a.example.com"}}},
    {"type": "vless", "tag": "sb-reality", "server": "2a12:a304:4:781::b", "server_port": 18376,
      "uuid": "3ad286d4-1b91-42fc-aaa6-83ff47452168", "flow": "xtls-rprx-vision",
      "tls": {"enabled": true, "server_name": "www.microsoft.com",
        "reality": {"enabled": true, "public_key": "f4HvU9XwDRls4fmIt-1VHd9UXME8S3uHvC9aau1mtSY", "short_id": "6b18fe17d0a104f6"},
        "utls": {"enabled": true, "fingerprint": "chrome"}},
      "transport": {"type": "tcp"}},
    {"type": "trojan", "tag": "sb-trojan-ws", "server": "tr.example.com", "server_port": 443,
      "password": "t0ps3cret",
      "tls": {"enabled": true, "server_name": "tr.example.com", "insecure": true, "alpn": ["h2", "http/1.1"]},
      "transport": {"type": "ws", "path": "/trojan", "host": ["tr.example.com"]}},
    {"type": "hysteria2", "tag": "sb-hy2", "server": "5.6.7.8", "server_port": 443,
      "password": "hy2pass", "up_mbps": 30, "down_mbps": 200,
      "obfs": {"type": "salamander", "password": "hy2obfs"},
      "tls": {"enabled": true, "server_name": "apple.com", "insecure": true}},
    {"type": "tuic", "tag": "sb-tuic", "server": "9.10.11.12", "server_port": 38057,
      "uuid": "3ad286d4-1b91-42fc-aaa6-83ff47452168", "password": "tuicpass",
      "congestion_control": "bbr", "udp_relay_mode": "native",
      "tls": {"enabled": true, "alpn": ["h3"]}},
    {"type": "hysteria", "tag": "sb-hy1-unsupported", "server": "6.6.6.6", "server_port": 443},
    {"type": "wireguard", "tag": "sb-wg-unsupported", "server": "7.7.7.7", "server_port": 51820}
  ]
}`

// v2rayN(NG) 的匯出格式。
const v2rayNSample = `{
  "version": "2.0.0",
  "outbounds": [
    {"tag": "ng-vmess-ws", "protocol": "vmess",
      "settings": {"vnext": [{"address": "example.com", "port": 443,
        "users": [{"id": "11111111-2222-3333-4444-555555555555", "alterId": "0", "security": "auto", "level": "0"}]}]},
      "streamSettings": {"network": "ws", "security": "tls",
        "tlsSettings": {"serverName": "a.example.com", "alpn": "h2,http/1.1", "fingerprint": "chrome"},
        "wsSettings": {"path": "/vmess", "headers": {"Host": "a.example.com"}}}},
    {"tag": "ng-vless-reality", "protocol": "vless",
      "settings": {"vnext": [{"address": "2a12:a304:4:781::b", "port": 24826,
        "users": [{"id": "3ad286d4-1b91-42fc-aaa6-83ff47452168", "encryption": "none", "flows": ["xtls-rprx-vision"]}]}]},
      "streamSettings": {"network": "grpc", "security": "reality",
        "realitySettings": {"fingerprint": "chrome", "publicKey": "f4HvU9XwDRls4fmIt-1VHd9UXME8S3uHvC9aau1mtSY", "shortId": "6b18fe17d0a104f6", "serverName": "www.microsoft.com"},
        "grpcSettings": {"serviceName": "grpc", "multiMode": false}}},
    {"tag": "ng-trojan", "protocol": "trojan",
      "settings": {"servers": [{"address": "tr.example.com", "port": 443, "password": "t0ps3cret", "level": "0"}]},
      "streamSettings": {"network": "ws", "security": "tls",
        "tlsSettings": {"serverName": "tr.example.com", "allowInsecure": true},
        "wsSettings": {"path": "/trojan"}}},
    {"tag": "ng-ss", "protocol": "shadowsocks",
      "settings": {"servers": [{"address": "1.2.3.4", "port": 8443, "users": ["aes-256-gcm:s3cret"]}]},
      "streamSettings": {"network": "tcp"}},
    {"tag": "ng-freedom", "protocol": "freedom", "settings": {}}
  ]
}`

func mustParseAll(t *testing.T, nodes []string) {
	t.Helper()
	for _, link := range nodes {
		if _, _, err := D.NewNetproxyDialerFromLink(direct.SymmetricDirect, &D.ExtraOption{}, link); err != nil {
			t.Errorf("dae 自己的解析器不吃這條：%v\nerr=%v", link, err)
		}
	}
}

func TestResolveSubscriptionAsSingBox(t *testing.T) {
	nodes, err := ResolveSubscriptionAsSingBox(logrus.New(), []byte(singBoxSample))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// 6 個可用：ss2022 / vmess / vless / trojan / hy2 / tuic。
	// direct、block 不算節點；hysteria(v1) 與 wireguard 沒有 dialer，跳過。
	if len(nodes) != 6 {
		t.Fatalf("want 6 nodes, got %d: %v", len(nodes), nodes)
	}
	mustParseAll(t, nodes)
}

func TestResolveSubscriptionAsSingBoxKeepsRealityAndIPv6(t *testing.T) {
	nodes, err := ResolveSubscriptionAsSingBox(logrus.New(), []byte(singBoxSample))
	if err != nil {
		t.Fatal(err)
	}
	var vless string
	for _, n := range nodes {
		if strings.HasPrefix(n, "vless://") {
			vless = n
		}
	}
	if vless == "" {
		t.Fatal("沒有 vless 節點")
	}
	for _, want := range []string{
		"security=reality",
		"pbk=f4HvU9XwDRls4fmIt-1VHd9UXME8S3uHvC9aau1mtSY",
		"sid=6b18fe17d0a104f6",
		"flow=xtls-rprx-vision",
		"fp=chrome",
		"sni=www.microsoft.com",
		"@[2a12:a304:4:781::b]:18376",
		"#sb-reality",
	} {
		if !strings.Contains(vless, want) {
			t.Errorf("sing-box 轉出來的 vless 少了 %q：%v", want, vless)
		}
	}
}

func TestResolveSubscriptionAsV2rayN(t *testing.T) {
	nodes, err := ResolveSubscriptionAsV2rayN(logrus.New(), []byte(v2rayNSample))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// 4 個可用（freedom 是路由骨架，丟掉不計數）
	if len(nodes) != 4 {
		t.Fatalf("want 4 nodes, got %d: %v", len(nodes), nodes)
	}
	mustParseAll(t, nodes)

	var reality string
	for _, n := range nodes {
		if strings.Contains(n, "security=reality") {
			reality = n
		}
	}
	if reality == "" {
		t.Fatal("v2rayN 的 reality 節點沒了")
	}
	for _, want := range []string{"pbk=f4HvU9XwDRls4fmIt-1VHd9UXME8S3uHvC9aau1mtSY", "sid=6b18fe17d0a104f6", "type=grpc", "serviceName=grpc", "flow=xtls-rprx-vision"} {
		if !strings.Contains(reality, want) {
			t.Errorf("v2rayN 轉出來的 reality 節點少了 %q：%v", want, reality)
		}
	}
}

// 格式之間不能互相誤判：分派鏈是 SIP008 → clash → sing-box → v2rayN → base64。
func TestSubscriptionFormatsDoNotCollide(t *testing.T) {
	log := logrus.New()
	if _, err := ResolveSubscriptionAsSingBox(log, []byte(v2rayNSample)); err == nil {
		t.Error("sing-box 解析器不該吃 v2rayN 的 JSON（欄位名不同）")
	}
	if _, err := ResolveSubscriptionAsV2rayN(log, []byte(singBoxSample)); err == nil {
		t.Error("v2rayN 解析器不該吃 sing-box 的 JSON")
	}
	if _, err := ResolveSubscriptionAsClash(log, []byte(singBoxSample)); err == nil {
		t.Error("clash 解析器不該吃 JSON 訂閱")
	}
	if _, err := ResolveSubscriptionAsSingBox(log, []byte(clashSample)); err == nil {
		t.Error("sing-box 解析器不該吃 Clash YAML")
	}
}

// 端到端：一份 sing-box 訂閱走完整分派鏈也要解得出來。
func TestResolveSubscriptionDispatchesSingBox(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sb.json"), []byte(singBoxSample), 0o600); err != nil {
		t.Fatal(err)
	}
	_, nodes, err := ResolveSubscription(logrus.New(), http.DefaultClient, dir, "file://sb.json")
	if err != nil {
		t.Fatalf("ResolveSubscription: %v", err)
	}
	if len(nodes) != 6 {
		t.Fatalf("want 6 nodes, got %d", len(nodes))
	}
}
