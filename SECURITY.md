# Security / 安全说明

## English

This project has not undergone an independent third-party security audit and does not promise response times or long-term supported releases. Use a trusted operating system and protect offline backups.

The application has no upload, telemetry, update-check or network-client feature. Its Python audit hook rejects covered network and external-process calls. This is not an OS sandbox and cannot constrain malicious native drivers, modified dependencies or other processes. Use a disconnected device for strict physical offline operation.

Master/recovery passphrases, PINs and private keys are not logged. Names, tags, notes and keys are stored in the authenticated encrypted vault. The optional export directory is the only persistent preference, protected by current-user file permissions and containing no keys or passphrases. It can contain a personal path and must not be published.

Failed-attempt destruction logically removes the current vault; it cannot reliably erase SSD history, historical backups or exports, or prevent counter rollback. Recovery requires a previously configured recovery passphrase and independent recovery file. See SECURITY_RECOVERY.md. Mac safeguards and unverified behavior are documented in MACOS.md; those detailed documents are currently in Chinese.

### Reporting a vulnerability

Once a public repository is established, prefer its Security page's private vulnerability reporting feature, if the maintainer has enabled it. No dedicated email address is currently configured; do not send material to a guessed address. Without a private reporting channel, a public contact request should omit exploitation details and sensitive data while asking the maintainer for a safe channel.

Include only the version, OS, expected/actual behavior and reproduction steps using synthetic data. Do not attach real keys, passphrases, recovery files, vaults, personal paths, screenshots or full environment dumps. For cryptographic issues, describe the input structure and generate replacement samples at runtime.

After confirmation, fix and regression-test the issue before coordinating disclosure. Never paste sensitive material into public issues or CI logs. Release checks are bounded pattern scans and allowlist checks, not proof that every kind of secret is absent.

## 简体中文

本项目尚未经过独立第三方安全审计；没有承诺响应时限或长期支持版本。请使用可信操作系统并保护离线备份。

应用不含上传、遥测、更新检查或网络客户端；Python audit hook 拒绝网络和外部进程调用。该钩子不是操作系统沙箱，不能约束恶意原生驱动、被篡改的依赖或其他进程。严格物理离线使用断网设备。

主口令、恢复口令、PIN 和私钥不写入日志。名称、标签、备注及密钥保存在认证加密库中；默认导出目录是用户主动设置的唯一持久偏好，按用户权限保护，不存储密钥或口令。该偏好可能包含个人路径，禁止发布。

失败自毁为当前库的逻辑销毁，不能可靠擦除 SSD、历史备份、导出文件，也不能阻止离线回滚计数。恢复需要预先配置恢复口令和独立恢复文件。详见 SECURITY_RECOVERY.md。Mac 安全边界和未验证项见 MACOS.md。

### 报告流程

公开仓库建立后，优先使用仓库 Security 页的私密漏洞报告功能（需维护者启用）。当前没有配置专用邮箱；请勿向猜测的邮箱发送材料。若没有私密入口，可提交不含利用细节和敏感数据的联系请求，等待维护者提供安全渠道。

报告仅包含版本、操作系统、预期/实际行为及合成数据复现步骤。不要附真实密钥、口令、恢复文件、库、个人路径、截图或完整环境转储。密码学问题可先描述输入结构，使用运行时生成的替代样本。

确认问题后，应先修复并完成回归，再协调公开说明。不要在公开 issue 或 CI 日志中粘贴敏感内容。发布审查是有限的模式检查及白名单核对，不能证明没有所有类型的秘密。
