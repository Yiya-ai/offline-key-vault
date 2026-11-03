# 密钥工具箱 · 浏览器版

[English](README.md) · [桌面版](../README.zh-CN.md)

独立的纯静态网页工具：生成、读取、转换、校对和下载当前密钥。没有密钥库、账号、数据库、上传接口或历史记录。桌面版仍完全离线，不依赖网页。

此前的 WASM 依赖阻断项已于 2026-11-03 修复：从已校验的官方源码构建 cryptography 50.0.2 与 OpenSSL 3.6.5，并通过真实浏览器回归。当日 15 个 Python 运行依赖的通告检查均通过，门禁继续保留；这不等于保证不存在未知漏洞。详情见[安全报告](security_best_practices_report.md)。

## 构建和使用

准备 Python 3.12+、Node.js 22+ 和支持 Linux 容器的 Docker，在项目根目录运行：

```sh
npm ci --prefix web --ignore-scripts
python web/build_wasm.py
python web/build_web.py --fetch
python web/verify_build.py
python -m http.server 8766 --bind 127.0.0.1 --directory web/dist
```

打开 `http://127.0.0.1:8766/`。前三步仅下载公开开发依赖；后续构建可省略 `--fetch`。依赖版本固定，Python 下载文件校验 SHA-256。构建只输出到 `web/dist/`，不会读取密钥库或设置。
WASM 包已缓存且摘要匹配时不重复编译；首次构建需要 Docker。构建上下文仅包含允许列表中的公开构建文件，不挂载项目、密钥或用户目录。详细过程见[构建说明](wasm-build/README.md)。

上线时，**只发布 `web/dist/` 内的文件**到可信 HTTPS 静态托管。无需后端、环境密钥或服务器密钥解析器。不要部署整个仓库、测试、`.vendor`、`node_modules` 或本地输出。更新时确保资源和清单一致，不要插入统计、CDN 优化脚本、Service Worker 或第三方组件。建议使用没有已有 Service Worker 的独立站点；支持响应头的服务另加 `frame-ancestors 'none'` 和 `X-Content-Type-Options: nosniff`。页面也会拒绝在框架内处理密钥。

公开运行资源约 18 MB；加载和校验完成前不能输入密钥，之后断网仍可使用。不是可安装的离线 PWA，关闭页面后会丢弃会话。本机实际测试 Chrome/Edge 同类浏览器；Firefox、Safari 仍需原生浏览器验证。必须使用 HTTPS 或 localhost。

## 功能与边界

GitHub Pages 可在仓库 **Settings → Pages → Source** 选择 **GitHub Actions**；通过下述浏览器检查后，手动运行 **Deploy browser toolbox (manual)**。流程审查源码、构建和校验静态产物后发布；普通推送不会自动上线，本地构建也不会操作远程站点。

工作流会先构建修复版 WASM，再组装网页；保留漏洞与完整性门禁，不能通过移除检查或随意接受新摘要来发布。

- 生成 RSA 2048/3072/4096、NIST ECDSA、secp256k1、Ed25519/Ed448、X25519/X448、SM2、OpenPGP RSA-3072。
- 支持适配算法的 PEM、DER、无头尾 Base64 DER、PKCS#1、SEC1、OpenSSH、JWK、PPK v2/v3、OpenPGP、原始 X25519 格式。
- 读取 PFX/PKCS#12、JKS 条目；导出随附 X.509 证书、证书集合、P7B 和 SSH 证书。JKS 可逐项选择；JKS/PFX 导出保留读入的证书附件。
- 在资源限制内导入传统 PEM 加密头、PBES1、3DES、RC2 和 scrypt 容器。
- 比较私钥推导的公钥参数；格式或口令错误独立提示，不当作不匹配。可预览公钥、主动显示私钥、自定义下载文件名。
- “原样下载”逐字节保留输入；重新编码可能改变换行、注释、随机校验值、盐或密文，但密钥本身不变。

算法和格式不能任意组合。传统 PKCS#1/SEC1、JWK、原始私钥导出需明确允许明文。JKS、PPK v2 的口令保护较弱，仅作兼容，优先使用加密 PKCS#8 或 PPK v3。SM2 PFX 限于无证书的单密钥容器；当前运行库未暴露 SM2 X.509 证书解析。每次最多 128 KiB；拒绝不支持的算法、超限 KDF、多私钥 PFX、OpenPGP v5/v6。不签发证书、不构建可信链、不在线检查吊销状态。

PFX 必须包含参数受限的 SHA 系列 MAC，摘要长度及盐也需有效。缺少 MAC、使用 PBMAC1 或累计 KDF 超限的容器会在原生解析前被拒绝；MAC 运算也计入累计预算，因此部分旧容器不再接受。

密钥库管理、找回、自毁、任意默认磁盘路径和原生 PKCS#11 驱动属于桌面版功能，浏览器不能直接加载桌面硬件驱动。下载位置由浏览器设置决定。

## 安全和隐私

1. 页面先从本站加载公开程序，校验资源大小和摘要，再添加严格 CSP；之后才创建计算线程和开放密钥输入。使用中不需访问外部 CDN。资源摘要能发现文件不一致，不能防止托管方同时篡改程序和清单。
2. Blob Worker 继承 `connect-src 'none'`；fetch 只能返回预载的公开内存资源，没有真实网络回退，其他网络接口禁用。用户输入作为 JSON 数据传给固定函数，绝不作为 Python 代码执行。密码运算在 Worker 的 WASM 内存中完成。
3. 不将密钥、口令或结果写入 Cookie、localStorage、sessionStorage、IndexedDB、OPFS 或本地挂载目录；不含统计、遥测或错误上传。托管方仍可能记录访问 IP 和首次静态资源请求。
4. 主动清空、离开/刷新页面、空闲五分钟都会丢弃会话。清空终止计算线程并撤销下载链接；操作超过两分钟会终止。下载文件是用户主动保留的本地副本。
   浏览器挂起会延迟计时器；切回前台、获得焦点和首次活动会先检查是否过期。失焦或切换工具时隐藏已显示的私钥和密码。敏感输入关闭拼写检查和自动纠正，但不能控制浏览器扩展或云输入法。
5. 网页无法保证物理擦除托管内存或系统交换区，也不会清除剪贴板、下载文件。浏览器扩展、浏览器、设备、托管账号和实际提供的程序仍须可信。没有经过独立安全审计。

不要为兼容而启用 `unsafe-eval`。引擎或资源校验失败时，输入保持禁用。第三方许可见 [THIRD_PARTY.md](THIRD_PARTY.md)。

已有 Service Worker 控制页面时拒绝启动；控制器变化时终止当前会话，不自动注销其他应用的 Worker。加载完成后也禁止新增样式请求。
开放输入之前还会检查实际加载的 cryptography/OpenSSL 版本，旧包改名或修改版本清单不能绕过检查。发布校验独立对照受审依赖摘要，防止修改产物清单后混入旧库。

开发阶段的发布检查：

```sh
npm audit --prefix web --audit-level=low
python web/audit_dependencies.py --online
python web/verify_build.py
python web/tests/test_build_security.py
```

OSV 查询仅发送公开依赖名称和锁定版本，不发送项目内容、路径、密钥或口令。任何安全通告、查询失败或不完整响应都会阻止发布；此脚本不会进入网站。完整发布清单会拒绝多余的嵌套文件、被改动的文件和链接文件，但不能认证托管方，也不能防止托管方同时替换代码与清单。

## 测试

复现命令见 [英文文档的 Verification](README.md#verification)。测试仅使用自动生成的合成密钥，不使用用户库或真实密钥。覆盖算法和格式往返、桌面生成的证书/旧容器、配对校验、明文导出保护、网络阻断、存储检查、断网操作、显示隐藏和清空。测试注入的 Worker 捕获接口不包含在网页产品内。

Argon2 单线程适配保留原有 lanes 参数，已与原生库核对三种变体及 1/2/4/16 lanes。任何 `ok:false` 均视为失败，不应发布未通过测试的构建。

手动部署流程校验构建内容与依赖漏洞通告，不代替上述真实浏览器交互检查。
