# DNS

dae 会拦截所有经它路由或从本机发出、发往 53 端口的 UDP 和 TCP 流量，并嗅探 DNS。只有命中 `must_direct` 的流量不经过 dae；仅写 `direct` 仍会交给 DNS 模块处理。局域网客户端发往 dae 主机自身 socket（例如本机监听 53 端口的 dnsmasq）的查询和其它报文一样走路由，UDP 与 TCP 都会进入 DNS 模块。要把这类查询直接交给该 socket（dae 看不到应答），靠的是 `must_direct` 规则，例如 `l4proto(udp) && dport(53) && dip(<dae 主机地址>) -> must_direct`。只有经 loopback 接口的查询不会经过 dae 的任何 hook。以下为 DNS 配置的示例和模板。

dae 不重组 IP 分片：只处理数据报的第一个分片，后续分片原样放行，因此被分片的 UDP DNS 报文无法被正确拦截。若为局域网客户端应答的解析器自己的上游查询走了 `must_direct` 规则，dae 看不到这些应答，也就学不到返回 IP 对应的域名，`domain()` 规则不会匹配客户端的流量。

## URI 格式

### DoH3

```
h3://<host>:<port>/<path>
http3://<host>:<port>/<path>

默认端口: 443
默认 path: /dns-query
```

### DoH

```
https://<host>:<port>/<path>

默认端口: 443
默认 path: /dns-query
```

### DoT

```
tls://<host>:<port>

默认端口: 853
```

### DoQ

```
quic://<host>:<port>

默认端口: 853
```

### UDP

```
udp://<host>:<port>

默认端口: 53
```

### TCP

```
tcp://<host>:<port>

默认端口: 53
```

### TCP 和 UDP

```
tcp+udp://<host>:<port>

默认端口: 53
```

对于 dae 代替客户端转发的查询，收到截断的响应（`TC=1`，RFC 1035 §4.2.1）时，dae 会按 RFC 7766 §5 的要求通过 TCP 重试。`udp://` 上游只在响应被截断后重试；`tcp+udp://` 上游在任何 UDP 失败后都会重试。由 `sub()`、`node()` 和 `subnode()` 选中的 dae 自身查询在 `udp://` 上游没有这种重试。响应被截断时查询直接失败，错误为 `internal dns response truncated`。只有 `tcp+udp://` 上游会通过 TCP 重试这些查询，因此预期响应较大时，这些规则应指向 `tcp+udp://` 或 `tcp://` 上游。

内置目标 `asis` 沿用客户端所用的地址和端口，但不沿用客户端的传输方式：dae 总是通过 UDP 查询该服务器，即使客户端是通过 TCP 发起查询。`asis` 不会通过 TCP 重试。该服务器回复 `TC=1` 时，dae 丢弃服务器的响应。dae 改为根据客户端的查询构造一条消息回复客户端：ID 和 Question 段与查询相同，`NOERROR`、`RA=1`、`TC=1`，Answer 段为空。之后由客户端决定是否通过 TCP 重试。其他协议仍使用各自指定的传输方式。

`ipversion_prefer` 不会让 dae 主动查询首选的地址族。设置 `ipversion_prefer: 4` 时，只有 dae 已经知道该域名有 `A` 记录，才会把 `AAAA` 响应替换成空的 `NOERROR` 回复。已知有 `A` 记录指两种情况之一：缓存中存在未过期的 `A` 响应；或者 `AAAA` 响应最多等待 50 ms（RFC 8305 的解析延迟），在此期间收到了带记录的 `A` 响应。否则 dae 原样返回 `AAAA` 响应。`ipversion_prefer: 6` 的行为相同，只是两个地址族对调。

`fixed_domain_ttl` 设为 `0` 不会关闭缓存。dae 仍会保存响应，并把缓存截止时间设为收到响应的时刻，因此该条目在下次查询时已经过期。`optimistic_cache` 默认为 `true`。因此在 `optimistic_cache_ttl`（默认 `60` 秒；`0` 表示不限）内，dae 用这条过期条目回答后续查询，并在后台向上游刷新一次。回复中的记录 TTL 不超过 `optimistic_stale_reply_ttl`（默认 `30`）。设置 `optimistic_cache: false` 后，该域名的每次查询都同步发往上游。

## 示例

```shell
dns {
    # 若 ipversion_prefer 设为 4，且域名同时有 A 和 AAAA 记录，dae 只回应 A 类型的请求，并返回空回复给 AAAA 请求。
    ipversion_prefer: 4

    # 为域名设定固定的 ttl。若设为 0，dae 不缓存该域名 DNS 记录，收到请求时每次向上游查询。
    fixed_domain_ttl {
        ddns.example.org: 10
        test.example.org: 3600
    }

    # 绑定到本地地址以监听 DNS 查询请求
    #bind: '127.0.0.1:5353'

    upstream {
        # 支持协议：tcp, udp, tcp+udp, https, tls, http3, h3, quic, 详情见上面的 Schema。
        # 若主机为域名且具有 A 和 AAAA 记录，dae 自动选择 IPv4 或 IPv6 进行连接，
        # 是否走代理取决于全局的 routing（不是下面 dns 配置部分的 routing），节点选择取决于 group 的策略。
        # 请确保 DNS 流量经过 dae 且由 dae 转发，按域名分流需要如此！
        # 若 dial_mode 设为 'ip'，请确保上游 DNS 无污染，不推荐使用国内公共 DNS。

        alidns: 'udp://dns.alidns.com:53'
        googledns: 'tcp+udp://dns.google:53'

        # alih3: 'h3://dns.alidns.com:443'
        # alih3_path: 'h3://dns.alidns.com:443/dns-query'
        # alihttp3: 'http3://dns.alidns.com:443'
        # alihttp3_path: 'http3://dns.alidns.com:443/dns-query'
        # ali_quic: 'quic://dns.alidns.com:853'

        # h3_custom_path: 'h3://dns.example.com:443/custom-path'
        # http3_custom_path: 'http3://dns.example.com:443/custom-path'

        # ali_doh: 'https://dns.alidns.com:443'
        # ali_dot: 'tls://dns.alidns.com:853'

        # doh_custom_path: 'https://dns.example.com:443/custom-path'
    }
    # 'request' 和 'response' 的 routing 格式和全局的 'routing' 类似。
    # 参考 https://github.com/daeuniverse/dae/blob/main/docs/zh/configuration/routing.md
    routing {
        # 根据 DNS 查询，决定使用哪个 DNS 上游。
        # 按由上到下的顺序匹配。
        request {
            # 'request' 具有预置出站：asis, reject。
            # asis 即向收到的 DNS 请求中的目标服务器查询，请勿将其他局域网设备 DNS 服务器设为 dae:53（小心回环）。
            # 你可以使用在 upstream 中配置的 DNS 上游。

            # 普通 DNS 请求可使用：qname, qtype。
            # 同一个块里还支持 dae 自身使用的内部选择器：sub, node, subnode。
            # - sub(): 订阅拉取时的解析请求
            # - node(): 节点地址解析请求
            # - subnode(): 订阅节点的地址解析请求，并且优先级高于 node()
            # 这些内部选择器：
            # - 只影响 dae 自身发起的解析
            # - 目标只能是 dns.upstream 中定义的名称
            # - 不使用 fallback
            # - 不能和 qname/qtype 混写在同一条规则里

            # DNS 查询域名（省略后缀点 '.'）。
            qname(geosite:category-ads-all) -> reject
            qname(geosite:google@cn) -> alidns # 参考：https://github.com/v2fly/domain-list-community#attributes
            qname(suffix: abc.com, keyword: google) -> googledns
            qname(full: ok.com, regex: '^yes') -> googledns
            # DNS 查询类型
            qtype(a, aaaa) -> alidns
            qtype(cname) -> googledns
            # 禁用 ECH 避免影响分流
            qtype(https) -> reject

            # 将 dae 自身拉取订阅时的 DNS 查询发到 googledns。
            # sub(my_sub) -> googledns
            # 名称里包含 "hk" 的节点解析走 googledns。
            # node(name_keyword: hk) -> googledns
            # 来自订阅 "my_sub" 的节点优先走 alidns，再考虑 node()。
            # subnode(subtag: my_sub) -> alidns

            # fallback 意为 default。
            # 如果上面的都不匹配，使用这个 upstream。
            fallback: asis
        }
        # 根据 DNS 查询的回复，决定接受或使用其他 upstream 重新查询。
        # 按由上到下的顺序匹配。
        response {
            # 具有预置出站：accept, reject。
            # 你可以使用在 upstream 中配置的 DNS 上游。

            # 可以使用：qname, qtype, upstream, ip。
            # 接受 upstream 'googledns' 回复的 DNS 响应。有助于避免回环。
            upstream(googledns) -> accept
            # 若 DNS 请求的域名不属于 CN 且回复包含私有 IP，大抵是被污染了，向 'googledns' 重查。
            ip(geoip:private) && !qname(geosite:cn) -> googledns
            fallback: accept
        }
    }

}
```

## 引导解析器（`global`）

三类查询由 dae 直接发往 `global.bootstrap_resolver`，从不经过代理。第一类是 `dns.upstream` 中非 IP 字面量条目的主机名。第二类是 `dial_mode: domain`（默认值）对嗅探到的域名执行的后台探测，前提是 dae 的 DNS 缓存中没有该域名的 `A` 或 `AAAA` 记录。`domain+` 和 `domain++` 跳过该探测；`ip` 从不按域名建立连接。`dial_mode` 只接受 `ip`、`domain`、`domain+` 和 `domain++`。

第三类在 `dns.routing.request` 含有任何规则时生效，此时 dae 的内部 DNS 路由已启用。当没有 `sub()`、`node()` 或 `subnode()` 规则把订阅 URL 的主机或某个节点的服务器主机名分配给上游，或者分配到的上游未返回地址时，dae 要解析该主机名。这些查询绕过 `qname` 和 `qtype` 规则，并且在 DNS 路由运行期间随时发生，不只在启动时。

未被 `dns.routing` 中任何 `node`/`sub` 规则选中上游的节点地址，会同时通过系统解析器与引导解析器解析，先返回可用答案的一方生效。系统视图取自 `/etc/resolv.conf` 中的第一个非回环服务器；当该文件缺失、不可读或只给出回环地址时，改用 `global.fallback_resolver`；这条查询直接发出，不经过 dae 的 DNS 路由。两者并发的好处是任何一条腿被阻断都不会让全部节点失效：系统解析器不可用时仍能到达引导解析器，引导解析器被屏蔽时仍能经系统视图解析。并发中每条腿都有 10 秒的超时上限，静默丢弃查询的解析器拖不住节点拨号；更早返回的可用答案仍立即生效。由于先返回者生效，若本机系统解析器会过滤或改写该节点的解析结果，就以它的答案为准；不可互换时，可把该节点的主机名写入 `dns.routing.node` 指定上游，dae 会优先使用它。

有两点后果需要说明。即使显式设置了 `global.bootstrap_resolver`，节点主机名现在也会到达系统解析器；若必须避免代理主机名进入本机解析器，应在 `dns.routing.node` 中为该节点指定上游。另外，启动阶段拉取的、未被任何 `dns.routing.sub` 规则选中的订阅主机仍只通过引导解析器解析——被 `sub` 规则选中的订阅主机仍走该规则指定的上游，而彼时尚无运行时代际，上述并发从第一个代际开始。

未设置时，dae 依次尝试 `119.29.29.29:53` 和 `223.5.5.5:53`。设置后只使用指定的解析器，完全替代这两个默认值。中国大陆以外的主机通常应选择距离更近的解析器：

```shell
global {
  bootstrap_resolver: '9.9.9.9:53'
}
```

## 模板

根据所需的 DNS 行为选择一种模板。

```shell
# 对于中国大陆域名使用 alidns，其他使用 googledns 查询。
dns {
  upstream {
    googledns: 'tcp+udp://dns.google:53'
    alidns: 'udp://dns.alidns.com:53'
  }
  routing {
    # 根据 DNS 查询，决定使用哪个 DNS 上游。
    # 按由上到下的顺序匹配。
    request {
      # 对于中国大陆域名使用 alidns，其他使用 googledns 查询。
      qname(geosite:cn) -> alidns
      # fallback 意为 default。
      fallback: googledns
    }
  }
}
```

```shell
# 默认使用 alidns，如果疑似污染使用 googledns 重查。
dns {
  upstream {
    googledns: 'tcp+udp://dns.google:53'
    alidns: 'udp://dns.alidns.com:53'
  }
  routing {
    # 根据 DNS 查询，决定使用哪个 DNS 上游。
    # 按由上到下的顺序匹配。
    request {
      # fallback 意为 default。
      fallback: alidns
    }
    # 根据 DNS 查询的回复，决定接受或使用其他 upstream 重新查询。
    # 按由上到下的顺序匹配。
    response {
      # 可信的 upstream。总是接受它的回复。
      upstream(googledns) -> accept
      # 疑似被污染结果，向 'googledns' 重查。
      ip(geoip:private) && !qname(geosite:cn) -> googledns
      # fallback 意为 default。
      fallback: accept
    }
  }
}
```
