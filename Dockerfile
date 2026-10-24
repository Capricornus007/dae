# TODO: pin the base images by digest. `docker manifest inspect` and
# skopeo cannot reach registry-1.docker.io from the audit environment, so no
# digest is recorded here — do not invent one. Replace the tags below with
# `<repo>@sha256:<digest>` once a registry lookup is available.
# ── builder：吃尖端（golang/go master），而且是「一個原生 amd64 builder 交叉編全部
# 目標平台」的結構。
# 兩個理由寫在一起：
#   1) 尖端（用戶 2026-10-11：「docker 的隨便，但我必須看到結果運行的包含最尖端」）：
#      官方不提供未發佈版本的二進位，所以用 base 镜像那顆發布版 Go 當 GOROOT_BOOTSTRAP
#      從源碼編尖端，裝進 /usr/local/go 蓋掉發布版。
#   2) 省時：尖端只在 **builder 架構** 編一次，且以 commit 為鍵存進 BuildKit cache mount
#      （/opt/gotip-cache）——同一個尖端只編那 15-25 分鐘一次，之後每次 build 只是幾秒的
#      cp。原本的逐平台寫法（沒有 $BUILDPLATFORM）要在 QEMU 模擬下為 arm/v7、386 各編
#      一遍 Go，那才是真的省不下來；Go 的交叉編譯本来就支援任意 GOARCH，eBPF 那側的
#      目標架構由 Makefile 的 BPF_TARGET/BPF_TRACE_TARGET（取自 GOARCH）决定，所以改成交叉
#      結構不會把 BPF 物件編錯架構。
# GO_TIP_SHA 一定要傳、沒傳就紅：留空靠 layer 快取的話，命中時會拿到「上一次的尖端」
# 還聲稱是尖端，那是騙人。取法：git ls-remote https://github.com/golang/go master | cut -f1
# （.github/workflows/docker.yml 就是這樣算出來再 --build-arg 進來的。）
# 結尾兩道 `go version | grep -- -devel`（toolchain 一道、產物一道）是硬驗：裝到的或編出來
# 的不是尖端就讓 build 失敗，不准退回發布版、不准靜默放過。
FROM --platform=$BUILDPLATFORM golang:1.27-bookworm AS builder
ARG GO_TIP_SHA
RUN --mount=type=cache,target=/opt/gotip-cache \
    --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    set -eux; \
    test -n "${GO_TIP_SHA}" || { echo "ERROR: 沒傳 --build-arg GO_TIP_SHA=<golang/go master 的 commit sha>"; exit 1; }; \
    apt-get update; \
    apt-get install -y --no-install-recommends git ca-certificates; \
    tip="/opt/gotip-cache/${GO_TIP_SHA}/go"; \
    if [ ! -x "$tip/bin/go" ]; then \
        git init -q /tmp/gosrc; \
        git -C /tmp/gosrc remote add origin https://github.com/golang/go; \
        git -C /tmp/gosrc fetch -q --depth 1 origin "${GO_TIP_SHA}"; \
        git -C /tmp/gosrc checkout -q --detach FETCH_HEAD; \
        ( cd /tmp/gosrc/src && GOTOOLCHAIN=local GOROOT_BOOTSTRAP=/usr/local/go ./make.bash ) || { echo "ERROR: 尖端的 make.bash 失敗"; exit 1; }; \
        mkdir -p "$(dirname "$tip")"; \
        mv /tmp/gosrc "$tip"; \
    fi; \
    rm -rf /usr/local/go; \
    cp -a "$tip" /usr/local/go; \
    go version; \
    go version | grep -q -- '-devel' || { echo "ERROR: 裝進 /usr/local/go 的不是尖端（go version 沒帶 -devel）"; exit 1; }
# 不許 go 去下載發布版頂替尖端（同 feed 倉 setup-feed-go 的釘法）。
ENV GOTOOLCHAIN=local
RUN apt-get update && apt-get install -y --no-install-recommends llvm-15 clang-15 make \
    && rm -rf /var/lib/apt/lists/*
ENV CLANG=clang-15
WORKDIR /build/
# 目標平台由 buildx 給的 TARGET* 决定；不再靠「容器刚好跑在哪個架構」。
ARG TARGETOS TARGETARCH
ARG VERSION=unstable-docker
ENV GOOS=${TARGETOS} GOARCH=${TARGETARCH} CGO_ENABLED=0
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN make OUTPUT=dae VERSION="${VERSION}" GOFLAGS="-buildvcs=false" CC=clang CGO_ENABLED=0
# 產物層級的硬驗：`go version <binary>` 讀的是二進位埋的 build info，印出來就是這顆
# dae 是哪個 toolchain、哪個 GOARCH 編的；不是尖端就紅。
RUN go version /build/dae
RUN go version /build/dae | grep -q -- '-devel' \
    || { echo "ERROR: 產物 dae 不是尖端編出來的"; exit 1; }

# TODO: same digest pin pending (the `alpine` tag is mutable).
FROM alpine

# Geo data is pinned by upstream release tag and verified with sha256sum -c.
# The ARG defaults are asserted against scripts/fetch-geo-data.sh by
# scripts/check-build-env.sh (that script is the single owner of the pins).
ARG GEOIP_VERSION=202609050329
ARG GEOIP_SHA256=1cba1f0982cf62502fa079c66047c3d0c608196da5b3305671e68f60e917a482
ARG GEOSITE_VERSION=20260908094002
ARG GEOSITE_SHA256=35ed26a24cafa1256bd7261414224b7bcef5c944cea7760e172b030a8b266450

RUN mkdir -p /usr/local/share/dae/
RUN mkdir -p /etc/dae/
RUN set -eux; \
    wget -O /usr/local/share/dae/geoip.dat "https://github.com/v2fly/geoip/releases/download/${GEOIP_VERSION}/geoip.dat"; \
    echo "${GEOIP_SHA256}  /usr/local/share/dae/geoip.dat" | sha256sum -c -; \
    wget -O /usr/local/share/dae/geosite.dat "https://github.com/v2fly/domain-list-community/releases/download/${GEOSITE_VERSION}/dlc.dat"; \
    echo "${GEOSITE_SHA256}  /usr/local/share/dae/geosite.dat" | sha256sum -c -
COPY --from=builder /build/dae /usr/local/bin
COPY --from=builder /build/install/empty.dae /etc/dae/config.dae
RUN chmod 0600 /etc/dae/config.dae

CMD ["dae"]
ENTRYPOINT ["dae", "run", "-c", "/etc/dae/config.dae"]
