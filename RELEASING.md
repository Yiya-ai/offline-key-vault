# 本地发布流程

本流程准备可审查的源码，不会提交、推送或上传。源码包使用明确白名单；不得对整个项目目录直接压缩或执行不经审查的全量添加。

## 检查与打包

在项目根目录执行：

```powershell
python -I -S tools/release.py audit
python -I -S run_tests.py
python -I -S tools/release.py source
```

源码 ZIP 和 SHA-256 写入 dist。压缩包仅包含 `tools/release_manifest.json` 中列出的源码、文档、测试代码和发布配置；不含测试输出、密钥、恢复文件、截图、个人设置、vendor、Git 历史及便携运行时。检测器只报告文件名、行号和问题类别，不输出命中内容；它不等于全面的秘密检测。

使用本地 Git 时，先建立仓库，再以清单显式暂存：

```powershell
git init -b main
python -I -S tools/release.py stage
python -I -S tools/release.py audit --index
git diff --cached --check
git status --short
```

`stage` 先审查再添加白名单，并检查完整暂存区；原来被强制加入的私密文件会导致检查失败，工具不会擅自取消暂存或删除它们。`audit --index` 直接读取暂存对象，检查清单外文件、符号链接、源码模式、语法和工作区/暂存内容差异。默认审查不遍历被排除的运行数据。

确认文件清单及 diff 后，只有获得明确提交/发布授权才能 commit、配置精确远程地址和 push。发布前再次检查 Git 历史、作者身份和目标仓库可见性；本地审查不扫描所有旧提交。不要将真实数据放进公开 issue、release 附件或 CI 日志。

## 验证范围与发布前条件

- 推送 CI 检查已提交源码的白名单、隐私与语法；另有手动触发的 macOS 双架构构建、安装及回归工作流，通过后上传构建产物。工作流不会自动发布 Release。checkout 固定到完整提交，凭据不持久化。GitHub 运行器属于开发设施，不属于离线应用功能。
- 完整回归在本地 Windows 桌面执行，测试密钥全部合成。源码检查通过不代表 GUI、密码学或原生库已经被 CI 验证。
- Windows 本地便携构建运行 `python -I -S build_portable.py`，实际解压包必须通过隔离启动、自检、篡改和缺文件拒绝。普通测试运行成功不能代替打包测试。
- Windows 安装器必须验证首次安装、同目录升级、库与设置字节不变、快捷方式更新、无关目录拒绝；升级专项测试覆盖运行中保护、校验失败回滚与进程中断恢复。发布升级功能前还应以已发布旧版本做真实迁移验证。
- 公开 Windows 和 macOS 标准构建排除 PyKCS11，安装器拒绝包含它的载荷；逐项保留其他依赖许可并审查实际 ZIP 和 EXE。`--with-pkcs11` 的本地完整包或自行加入该依赖的 Mac 包仍需另行完成 GPL 对应源码分发检查，详见 THIRD_PARTY_NOTICES.md。标准包也不是“全包 MIT”。
- Mac 必须在对应架构的 macOS 15 原生 runner 构建与验证，包含 DMG 挂载、复制、签名检查和自检。必须明确标注未公证状态；不能将 Windows 测试当作 Mac 测试。没有硬件令牌实物测试记录。
- 摘要仅检测文件变化，不证明发布者身份。需要发布者身份保证时另行签名。

运行数据保留在本机并被忽略，不因发布准备自动删除。默认导出目录仍按用户设置持久保存；清除偏好需在应用设置中操作。
