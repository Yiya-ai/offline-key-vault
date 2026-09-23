# 格式兼容与安全边界

兼容性记录日期：2026-09-20。开发依赖在独立环境准备。应用运行时不下载、不更新、不启动外部命令、不调用网络。

| 类型 | 已实现范围 | 说明 |
| --- | --- | --- |
| OpenPGP | v4 RSA / 受支持的 EC、EdDSA 密钥导入；生成 RSA-3072 签名主密钥和加密子密钥；ASCII / 二进制公私钥导出 | 保留 UID、签名及子密钥；私钥默认 AES-256 + 迭代加盐 S2K；不把文档伪装成 PEM |
| PuTTY PPK | v2 / v3；RSA 2048–4096、NIST ECDSA、Ed25519 | 校验公私钥和 MAC；v3 支持 Argon2d/i/id 导入，导出默认 Argon2id 64 MiB、3 次、2 路；v2 仅作旧系统兼容 |
| SM2 | OpenSSL EVP 生成、校验；PKCS#8 私钥及 SPKI 公钥 PEM / DER | 加密私钥使用现代 PBES2；不使用 Python 随机数或自编椭圆曲线算法 |
| JKS | 多别名私钥及可信证书导入，证书链保留；选中记录导出为 JKS | 支持存储口令与条目口令分离；多条目一次提交；JKS 本身使用旧式口令保护，仅用于兼容 |
| PKCS#11 | 显式加载本地驱动、枚举设备及 RSA/EC 公钥、RSA 密钥生成、RSA SHA-256 签名验证 | PIN 不落盘；生成模板设置 sensitive=true、extractable=false；不读取私钥值、不初始化或重置设备 |
| SSH 证书 | OpenSSH 证书导入、签名校验、加密存储和原证书导出 | 保留 CA、主体、有效期、选项等证书原文；签名正确不等于 CA 受信任 |
| 证书集合 | X.509 PEM/DER、P12 附带证书保留；叶证书 PEM、PEM 链及 P7B 导出 | 首张证书须与密钥匹配；保留导入集合，不声称已构建可信路径；不在线检查吊销 |
| PKCS#12 | 单私钥及附带证书导入；带证书或仅私钥导出 | 导出 AES-256-CBC/PBKDF2 与 SHA-256 MAC 均设为 600000 次；多私钥 PFX 明确拒绝 |
| 旧容器 | 传统 PEM Proc-Type/DEK-Info、PBES1 MD5/SHA1 + DES/RC2、PKCS#12 SHA1/3DES；PBES2 PBKDF2/AES/3DES 或 scrypt/AES 导入 | 旧算法用于迁移，默认导出仍为现代 PKCS#8；不通过修改后缀完成转换 |

## 资源与存储限制

- 输入最多 128 KiB；加密库最多 16 MiB / 1000 条记录。
- PBKDF2 / PBES1 单项最多 2000000 次；容器累计派生预算 4000000。
- scrypt 最多 256 MiB，N 必须为 2 的幂，r ≤ 32、p ≤ 16，N×r×p ≤ 4194304。
- PPK Argon2 最多 256 MiB、32 次、16 路，内存 KiB×次数 ≤ 1048576；先校验参数再调用 KDF。
- OpenPGP 最多 256 个包、16 个子密钥，S2K 累计哈希数据预算 256 MiB；不接受压缩消息、无限长度或未知包。
- JKS 每批最多 50 个条目。证书集合最多 50 张。原有 bcrypt、RSA 尺寸、文件路径、权限及主口令复核保持有效。
- 旧 OKV1 记录向后兼容；新增附件放在同一 AES-GCM 密文内。导出列表只返回公钥和公有附件，不返回私钥。

## 明确的边界

OpenPGP v5/v6、GNU 智能卡占位符、JCEKS/BKS、PPK v1、DSA、RSA-1024 私钥、未知曲线/算法及超出预算的 KDF 不作降级解析。OpenPGP 目前一次接受一把主密钥文档。PGPy 序列化会排除标记为不可导出的签名，因此不是原文件逐字节无损归档；需要原样保留这些本地签名时请另外保存原始文件。JWK 的使用策略字段、普通 SSH/PPK 注释和 P12 friendlyName 不保留为密钥使用策略；名称、标签、备注可在应用中管理。

用户明确选择的 PKCS#11 驱动是本机可执行代码。Python 审计钩子不能限制第三方原生驱动的网络行为；严格离线使用须在断网设备或受操作系统网络隔离的环境运行。驱动不自动发现、不自动下载。当前没有硬件设备，只有模拟会话测试，不能声称已在真实令牌上验证。macOS 仍需对应架构依赖与真实设备验证。

## 验证

扩展格式阶段本地回归：118 项通过（历史基线，非当前测试总数）。实际解压便携包自检：13 种生成选项、PPK/JKS/P12、密钥库、GUI、网络阻断、篡改与缺文件拒绝均通过。新增下载依赖已与 PyPI 官方文件摘要核对。

新增覆盖：PPK v2/v3 加密及明文往返、MAC 篡改、Argon2 越界先拒绝、Ed25519 官方字节布局、OpenPGP UID/子密钥保留与错误口令、SM2 加密导入、旧 PEM、PBES1、scrypt 越界、P12 MAC 强度、JKS/证书链、SSH 证书、多记录失败回滚、PKCS#11 会话清理和不可导出模板。

独立工具验证：本机 OpenSSL 检查 SM2 并完成 SM3 签名/验签；其生成的 PBES1-3DES、PBKDF2-3DES 和 scrypt 容器可导入；本工具 P12 可由 OpenSSL 校验 MAC 并解密。Java KeyStore 可读取导出的 JKS 私钥并完成签名/验签。GnuPG 可解析导出的 OpenPGP 公钥及加密私钥包。PPK Ed25519 布局另与 PuTTY 0.85 官方源码核对。

不声称完成所有厂商、所有变体或最新 CVE 的全面审计；生成后的格式必须用于其适用协议。

## 实现依据与依赖

- [PuTTY PPK 官方格式](https://the.earth.li/~sgtatham/putty/0.85/htmldoc/AppendixC.html)；Ed25519 细节以官方源码 crypto/ecc-ssh.c 为准。
- [PGPy API](https://pgpy.readthedocs.io/en/latest/api.html)
- [pyjks JKS API](https://pyjks.readthedocs.io/en/latest/jks.html)
- [PyKCS11 API](https://pkcs11wrap.sourceforge.io/api/)

精确版本见 requirements.txt。pyjks 的包入口移除了 BKS 自动导入（未修改 JKS 密码算法），因此不会加载不需要的 Twofish 扩展；离线开发准备脚本和便携打包均重复应用该明确补丁。依赖许可证随便携包分发。
