# Contributing / 贡献指南

## English

Development and validation primarily target Windows x64 with Python 3.12. Keep the application offline: do not add telemetry, update checks, remote key retrieval, cloud backup or automatic online installation of missing dependencies.

1. Read README, SECURITY and COMPATIBILITY. Use only newly generated synthetic keys. Never commit real public/private keys, vaults, recovery material, personal paths, logs or screenshots.
2. Prepare trusted wheels separately and install pinned dependencies with `python prepare_vendor.py LOCAL_WHEEL_DIRECTORY`. Tests also require local pytest (previously validated with 9.0.3). Runtime and build scripts do not download dependencies.
3. For cryptography, import parsers, permissions, matching or recovery changes, add relevant failure-case tests. Preserve KDF and input-size limits; do not invent cryptographic algorithms.
4. Run `python -I -S run_tests.py`. GUI tests need a local interactive desktop and Tk. Do not attach the generated test directory to a release.
5. Add new public source files explicitly to `tools/release_manifest.json`. Run `python -I -S tools/release.py audit`; after staging, run `python -I -S tools/release.py audit --index` and `git diff --cached --check`.
6. Explain the problem, changed behavior, verification and platform limitations in change descriptions. Packaging changes require testing the extracted package. Mac verification must be performed on a real Mac.

CI covers source privacy checks and syntax, not the full local cryptography/GUI suite. Manifest, ignore-rule, audit-tool and CI changes require manual review; these controls do not defend against a malicious maintainer. Do not silence a finding by disabling checks.

Use SECURITY.md for security reports. Original contributions remain under MIT; do not relabel third-party code as MIT. See THIRD_PARTY_NOTICES.md for dependency requirements.

## 简体中文

项目主要在 Windows x64 / Python 3.12 上开发和验证。应用必须保持离线；不得增加遥测、更新检查、远程密钥获取、云备份或缺依赖时自动安装。

1. 阅读 README、SECURITY 和 COMPATIBILITY。仅使用临时生成的合成密钥；禁止提交真实公私钥、库、恢复材料、个人路径、日志和截图。
2. 自行在开发环境准备可信 wheel，通过 `python prepare_vendor.py 本地wheel目录` 离线安装固定版本依赖。测试另需本机 pytest（本地验证版本 9.0.3）。运行时和构建脚本均不下载。
3. 修改密码学、导入解析、权限、配对校验或恢复逻辑时补充对应失败场景测试，不放宽 KDF 和输入大小限制。不要自行设计加密算法。
4. 运行 `python -I -S run_tests.py`。GUI 测试需要本机交互式桌面和 Tk；不得将测试目录作为发布附件。
5. 新增公开源码需手动加入 `tools/release_manifest.json`。运行 `python -I -S tools/release.py audit`；暂存后再次运行 `python -I -S tools/release.py audit --index` 和 `git diff --cached --check`。
6. 提交说明应解释问题、行为变化、验证结果和平台限制。打包修改应验证实际解压包；Mac 结果必须来自真实 Mac。

CI 仅进行源码隐私和语法检查，不替代本地密码学/GUI 测试。修改发布清单、忽略规则、审查器及 CI 时需要人工复核；这些文件不能防御恶意维护者。不要通过关闭检查解决告警。

安全问题按 SECURITY.md 处理。贡献的原创部分沿用 MIT；不得把第三方代码重新标记为 MIT。第三方依赖要求见 THIRD_PARTY_NOTICES.md。
