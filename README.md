# reality-sni-check

在 HK / JP / US VPS 上直接测试候选域名，输出 **TLS 初筛首选 + 最多 5 个备用**，保存 TXT、CSV、JSON 报告。内置 61 个去重候选（用户提供的 48 个、补充候选、233boy/Xray 的 4 个默认域名）。

## 一键运行

需要 Bash、Python 3（支持 TLS 1.3 / ALPN）、OpenSSL、系统 CA 证书；推荐 Debian 12 / Ubuntu 22.04 或更新版本。无需 root，无 Python 第三方依赖，不自动安装软件，不改代理配置，不上传报告。

```bash
curl -fsSL https://raw.githubusercontent.com/zzjsman/reality-sni-check/main/run.sh -o reality-sni-check.sh && bash reality-sni-check.sh --region HK
```

日本改 `--region JP`，美国改 `--region US`。地区仅是报告标签，程序不会自动推断线路或替你挑其他区域的结果。下载到本地后可直接重复运行。

```bash
bash reality-sni-check.sh --region JP --rounds 8 --timeout 6
bash reality-sni-check.sh --region US --family 6
bash reality-sni-check.sh --region HK -f my-domains.txt
bash reality-sni-check.sh --region HK --xray /usr/local/bin/xray
```

`--xray` 必须指向 **Xray 核心二进制**，不要填 233boy 管理脚本；实际位置以安装情况为准。对 TLS 初筛通过的域名执行 `xray tls ping` 并保存原始输出，供检查 X25519MLKEM768 等信息。未安装核心不会自动下载。默认结果目录 `./results`，可用 `--out` 修改。

## 检测与排序

- 每个域名默认 5 轮独立 DNS → TCP → TLS 1.3 握手；检查系统 CA 信任链、主机名、证书有效期及 ALPN h2，记录 IP、成功率、中位数和 p95。
- 再用 OpenSSL 强制 X25519、TLS 1.3、h2，检查握手和证书验证输出。工具版本不支持、超时或无法确认时会进入复核，不误报成功。
- 独立 HTTP/1.1 HEAD `/` 检查状态和重定向；不下载文件、不跟随重定向。403 / 404 不是 TLS 失败；重定向和 HEAD 失败进入人工复核。
- 所有采样 TLS 1.3 + h2 成功、至少 3 轮、X25519 确认、HTTP 检查完成且无重定向的候选才参与优选，按中位数和 p95 排序。没有合格项就明确报告没有。
- `dl.google.com`、DNS 基础设施域名、`github.io` 保留为对照或需人工复核项，不自动当作首选。其他域名也没有“保证不被封”的标签。
- 生成首选的 `target` / `serverNames` 参考片段，不改配置。不同备用域名是独立目标，切换时必须让 target 和 serverNames 匹配，不能把所有备用填进一个目标的 serverNames。

时间包含 DNS、TCP、TLS 和 Python 证书上下文初始化，不是 RTT。不同检测会重新解析 DNS，CDN 可能返回不同节点；JSON 保留每次 TLS 采样实际 IP。默认 IPv4，IPv6 需另测。socket 不使用 HTTP_PROXY 等环境变量，但系统 VPN / TUN / 透明代理仍可改变路线。

## 结果的边界

**这是 VPS 到目标站的技术初筛，不是大陆 GFW 检测或 REALITY 成功认证。** ALPN h2 成功不是完整 HTTP/2 请求测试；OpenSSL 握手不是浏览器指纹，也不是 REALITY 握手。脚本不根据品牌推断流量“伪装效果”，不声称持续下载或视频流量更安全。

选好后仍须用对应 Xray 版本检查诊断、配置 REALITY，并从你自己的大陆线路测试实际连接和长连接稳定性。海外运行结果不能证明大陆 SNI 未被阻断。一次失败也不等于域名不支持 TLS 或被墙。

## 来源与开发

独立实现，没有执行或复制第三方检测脚本。参考：

- [REALITY 官方文档](https://xtls.github.io/en/config/transports/reality.html)
- [233boy/Xray 默认域名库](https://github.com/233boy/Xray/blob/66e04223735ba551762fa08cf46dce57827bc6c6/src/core.sh)：www.amazon.com、www.ebay.com、www.paypal.com、aws.amazon.com
- [SNI-TLS-test](https://github.com/harenaNow/SNI-TLS-test)：作为方法比较参考。单独成功的 TLS 请求或 curl HTTP/2 输出不足以证明全部条件。

```bash
python3 -m unittest discover -s tests -v
python3 build.py
bash -n run.sh
```

`run.sh` 是由 `check.py` 生成的自包含入口；默认域名嵌入 `check.py`，`domains.txt` 为可编辑清单。更改默认清单时须同步嵌入值并重建入口。测试包含本地 TLS 服务的真实握手、证书主机名不匹配、HEAD 和 X25519 检查；老版本 Python 会明确跳过该集成测试。
