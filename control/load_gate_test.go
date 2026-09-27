//go:build !dae_stub_ebpf && (amd64 || arm64)

package control

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"
)

// TestLoadGate 是「建完 eBPF 就先丟進核心驗一次」的閘門，不是功能測試。
//
// 為什麼需要它：編 eBPF 的 clang 版本一漂，產物可能直接過不了核心驗證器，
// 而**症状是用戶斷網**（dae 起不來）。2026-09-27 實測：同一份源碼在
// LLVM 23 下 `tproxy_wan_cg_connect4` 被拒（invalid variable-offset read from stack），
// LLVM 19 下可載入。CI 的編譯環境與目標機器的核心版本是兩件事，所以需要這道閘。
//
// 關鍵：**必須注入 dae 執行期真正用的常數值**。`PARAM.useRedirectPeer` 與
// `PARAM.hasBpfGetCurrentTask` 在支援的核心上是 1，那兩條分支只有在注入 1 時
// 才會被驗證器看到；用出廠預設（0）載入會得到「假通過」。
//
// 跑法（要 root 與一個 bpffs 目錄；不建 netkit、不掛介面，所以不影響現行網路）：
//
//	sudo mkdir -p /sys/fs/bpf/dae-load-gate && sudo mount -t bpf bpf /sys/fs/bpf/dae-load-gate
//	sudo DAE_LOAD_GATE=1 go test -tags '' -run TestLoadGate ./control/
//
// 沒設 DAE_LOAD_GATE=1 時整個測試 Skip，所以不會影響一般 `go test ./...`。
func TestLoadGate(t *testing.T) {
	if os.Getenv("DAE_LOAD_GATE") != "1" {
		t.Skip("set DAE_LOAD_GATE=1 and run as root to load the datapath into the kernel")
	}
	pin := os.Getenv("DAE_LOAD_GATE_PIN")
	if pin == "" {
		pin = "/sys/fs/bpf/dae-load-gate"
	}

	constants := map[string]any{
		"PARAM": struct {
			tproxyPort           uint32
			controlPlanePid      uint32
			dae0Ifindex          uint32
			daeNetnsId           uint32
			dae0peerMac          [6]byte
			paddingAfterMac      [2]uint8
			useRedirectPeer      uint8
			hasBpfGetCurrentTask uint8
			datapathGeneration   uint16
			daeSocketMark        uint32
		}{
			tproxyPort:           0x39300000,
			controlPlanePid:      uint32(os.Getpid()),
			useRedirectPeer:      1,
			hasBpfGetCurrentTask: 1,
		},
		"EVENT_RATE": eventRateValue(),
	}
	var dataplane bpfDataplane
	if err := loadBpfObjectsWithConstantsAndCustomizer(
		&dataplane,
		&ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: pin}},
		constants,
		nil,
	); err != nil {
		t.Fatalf("這顆核心拒絕載入本次建置的 eBPF（換掉的 clang 版本多半就是原因）: %v", err)
	}
	// bpfDataplane 沒有 Close（它是 Assign 進去的欄位集合）；測試行程結束時
	// fd 自然釋放，pinned map 留在 DAE_LOAD_GATE_PIN 那個目錄，由跑它的人清。
}
