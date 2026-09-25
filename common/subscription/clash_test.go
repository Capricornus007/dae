/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package subscription

import (
	"encoding/base64"
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

// 一份把 dae 支援與不支援的協議都塞進去的 Clash 訂閱。欄位名照 Mihomo 的寫法，
// 目的是證明「真實訂閱長什麼樣」而不是我們希望它長什麼樣。
const clashSample = `
mixed-port: 7890
proxies:
  - name: ss-node
    type: ss
    server: 1.2.3.4
    port: 8443
    cipher: aes-256-gcm
    password: "s3cret"
    udp: true
  - name: vmess-ws
    type: vmess
    server: example.com
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
    alterId: 0
    cipher: auto
    network: ws
    tls: true
    servername: a.example.com
    ws-path: /vmess
    ws-headers:
      Host: a.example.com
  - name: vless-reality
    type: vless
    server: 2a12:a304:4:781::b
    port: 18376
    uuid: 3ad286d4-1b91-42fc-aaa6-83ff47452168
    network: tcp
    tls: true
    flow: xtls-rprx-vision
    servername: www.microsoft.com
    client-fingerprint: chrome
    reality-opts:
      public-key: f4HvU9XwDRls4fmIt-1VHd9UXME8S3uHvC9aau1mtSY
      short-id: 6b18fe17d0a104f6
  - name: trojan-ws
    type: trojan
    server: tr.example.com
    port: 443
    password: t0ps3cret
    network: ws
    ws-path: /trojan
    tls: true
    servername: tr.example.com
  - name: hy2-node
    type: hysteria2
    server: 5.6.7.8
    port: 443
    password: hy2pass
    sni: apple.com
    skip-cert-verify: true
    obfs: salamander
    obfs-password: hy2obfs
    up: 30
    down: 200
  - name: tuic-node
    type: tuic
    server: 9.10.11.12
    port: 38057
    uuid: 3ad286d4-1b91-42fc-aaa6-83ff47452168
    password: tuicpass
    congestion-controller: bbr
    udp-relay-mode: native
    alpn:
      - h3
  - name: snell-node
    type: snell
    server: 13.14.15.16
    port: 443
    psk: whatever
`

func TestResolveSubscriptionAsClash(t *testing.T) {
	nodes, err := ResolveSubscriptionAsClash(logrus.New(), []byte(clashSample))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// 6 個可轉（snell 不在內）
	if len(nodes) != 6 {
		t.Fatalf("want 6 nodes, got %d: %v", len(nodes), nodes)
	}
	for _, link := range nodes {
		if _, _, err := D.NewNetproxyDialerFromLink(direct.SymmetricDirect, &D.ExtraOption{}, link); err != nil {
			t.Errorf("dae 自己的解析器不吃這條：%v\nerr=%v", link, err)
		}
	}
}

func TestResolveSubscriptionAsClashKeepsRealityParams(t *testing.T) {
	nodes, err := ResolveSubscriptionAsClash(logrus.New(), []byte(clashSample))
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
	// REALITY 的三個關鍵參數少一個，做出來的就是「連得上但握手錯」的殭屍節點
	for _, want := range []string{
		"security=reality",
		"pbk=f4HvU9XwDRls4fmIt-1VHd9UXME8S3uHvC9aau1mtSY",
		"sid=6b18fe17d0a104f6",
		"flow=xtls-rprx-vision",
		"fp=chrome",
		"sni=www.microsoft.com",
		// IPv6 字面量一定要帶中括號，否則 host:port 會歧義
		"@[2a12:a304:4:781::b]:18376",
	} {
		if !strings.Contains(vless, want) {
			t.Errorf("vless link 少了 %q：%v", want, vless)
		}
	}
}

func TestResolveSubscriptionAsClashIgnoresOtherFormats(t *testing.T) {
	log := logrus.New()
	// base64 的 URI 清單不能被誤判成 clash
	b64 := base64.StdEncoding.EncodeToString([]byte("ss://YWVzLTI1Ni1nY206cHc@1.2.3.4:8388#n1\nvmess://e30=#n2\n"))
	if _, err := ResolveSubscriptionAsClash(log, []byte(b64)); err == nil {
		t.Error("base64 訂閱被誤判成 clash")
	}
	// SIP008 也沒有 proxies 段
	if _, err := ResolveSubscriptionAsClash(log, []byte(`{"version":1,"servers":[{"id":"a","remarks":"a","server":"1.2.3.4","server_port":8388,"password":"pw","method":"aes-128-gcm"}]}`)); err == nil {
		t.Error("SIP008 訂閱被誤判成 clash")
	}
	// 有 proxies 但全是 dae 不支援的協議 → 也要回 error，讓呼叫端續試下一種
	if _, err := ResolveSubscriptionAsClash(log, []byte("proxies:\n  - name: x\n    type: snell\n    server: 1.2.3.4\n    port: 4430\n")); err == nil {
		t.Error("全不支援的訂閱應該回 error")
	}
}

func TestResolveSubscriptionDispatchesClash(t *testing.T) {
	// 端到端：走 ResolveSubscription 的分派鏈，確認一份 Clash 訂閱能一路解出節點
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "mixed.sub"), []byte(clashSample), 0o600); err != nil {
		t.Fatal(err)
	}
	_, nodes, err := ResolveSubscription(logrus.New(), http.DefaultClient, dir, "file://mixed.sub")
	if err != nil {
		t.Fatalf("ResolveSubscription: %v", err)
	}
	if len(nodes) != 6 {
		t.Fatalf("want 6 nodes, got %d", len(nodes))
	}
}
