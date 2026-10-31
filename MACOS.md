# macOS installation / macOS 安装

## Download and install

Use the DMG assets in [GitHub Releases](https://github.com/Yiya-ai/offline-key-vault/releases). Choose `arm64` for Apple Silicon (M-series), or `x86_64` for an Intel Mac. **macOS 15 or later** is required. These are separate native builds, not Universal 2; Rosetta and older macOS versions are not qualified.

1. Download the matching `.dmg` and compare its SHA-256 with the release checksums.
2. Open the DMG and drag `OfflineKeyVault.app` to **Applications**. The destination Mac does not need Python, pip or Homebrew.
3. Eject the disk image, then open the application from Applications. Add it to the Dock for quick access if desired.
4. This release is **ad-hoc signed, without Apple Developer ID signing or notarization**. If macOS blocks the first launch, review the source and checksum, then use **System Settings → Privacy & Security → Open Anyway**, if offered, to approve this specific app. Do not disable Gatekeeper globally. Managed devices may prohibit approval; no bypass is provided.

Keep vaults, recovery materials and exports in local, non-synced folders outside the application bundle. A local volume check cannot detect every cloud-sync agent. To update, quit the application and preserve these files before replacing the `.app`. Removing the app does not remove separately stored vaults.

The standard DMG omits PyKCS11, just like the Windows standard installer. The generic hardware-token interface remains, but needs a separately prepared offline source environment with its optional dependency and trusted driver. Do not inject modules into the signed `.app`; doing so invalidates its signature. No physical token has been tested.

## 下载与安装

在 [GitHub Releases](https://github.com/Yiya-ai/offline-key-vault/releases) 下载对应 DMG：Apple Silicon（M 系列）选择 `arm64`，Intel Mac 选择 `x86_64`。最低为 **macOS 15**。不提供 Universal 2，也未验证 Rosetta 或更旧系统。

1. 下载后用 Release 中的 SHA-256 核对文件。
2. 双击 DMG，将 `OfflineKeyVault.app` 拖入 **Applications / 应用程序**；目标机无需另装 Python、pip 或 Homebrew。
3. 推出磁盘映像，从“应用程序”打开；可自行保留在 Dock，方便下次启动。
4. 本版本仅作本地临时签名，**没有 Apple Developer ID 签名，也未公证**。首次启动若被阻止，在确认来源和校验值后，可在 **系统设置 → 隐私与安全性 → 仍要打开** 中批准这一应用（若系统提供该选项）。不要全局关闭 Gatekeeper；受管理的电脑可能禁止此操作，程序不提供绕过方式。

密钥库、恢复材料和导出文件应放在应用程序之外的本地非同步目录。仅检查本地卷不能识别所有云盘同步软件。升级前退出程序并保留这些文件，再替换 `.app`。删除应用不会删除另行保存的密钥库。

标准 DMG 与 Windows 标准版一样不捆绑 PyKCS11。通用硬件令牌接口保留，但需要另行准备离线源码环境、可选依赖和可信驱动。不要向签名后的 `.app` 注入模块，这会破坏签名。尚无硬件令牌实物测试记录。

## Build and verification / 构建与验证

Build on a native Mac with Xcode Command Line Tools, CPython 3.12 with working Tk, a local OpenSSL 3 library and the pinned dependencies in `requirements-macos-build.txt`. Prepare dependencies separately. The builder itself never downloads or uploads anything:

```sh
python3 -I -S build_macos.py
```

Output: `dist/offline-key-vault-macos-arm64.dmg` or `dist/offline-key-vault-macos-x86_64.dmg`, plus a checksum and verification report. `build_macos.command` is an alternative launcher; `OKV_PYTHON` may specify the absolute path to a trusted local Python. For source development, first compile the native storage bridge using `python3 -I -S build_macos.py --prepare-only`.

The manual GitHub Actions workflow uses separate macOS 15 Apple Silicon and Intel runners. Only the development preparation step downloads public dependencies. It tests native storage, cryptography, recovery, key-pair matching and Tk initialization. The builder relocates the app to a path containing spaces and Chinese characters, runs offline synthetic-key self-tests under hostile Python/Tcl environment settings, creates and mounts the DMG read-only, copies the app to a clean directory, checks its ad-hoc signature and reruns self-tests. It also invokes LaunchServices. Failed checks prevent artifact publication. This is CI validation, not a claim of manual testing on every Mac or Retina display.

请在对应架构的 Mac 上准备 Xcode 命令行工具、带 Tk 的 CPython 3.12、本地 OpenSSL 3 动态库及固定版本依赖，再运行上述命令。构建脚本本身不联网。GitHub Actions 仅在开发准备阶段下载公开依赖；应用运行时完全离线。发布前查看对应的原生 CI 结果，不以 Windows 测试代替 Mac 测试。

## Security boundaries / 安全边界

- macOS checks mounted-volume metadata before accessing paths and checks opened file descriptors; network volumes and autofs locations are refused. New sensitive files have inherited ACL entries removed and mode `0600` applied before data is written. Failure stops the operation.
- Symlink/hardlink checks, exclusive creation, file locking and atomic replacement are also used. POSIX directory checks are not equivalent to Windows mandatory parent-directory sharing locks: a concurrent same-user process with directory-write access can still race path operations. Use directories controlled only by the current user. This is not an OS sandbox or protection against a compromised account/root.
- The Python audit hook blocks Python networking and subprocess creation. Native libraries and OS services remain trusted; the application does not control macOS background security checks. Ad-hoc signatures detect bundle changes when verified but do not authenticate a publisher.
- Both platforms share the same UI source. Mac uses Command+L, Mac fonts and custom corner resize controls. Automated Tk checks do not prove every display scale, touchpad gesture or window-decoration interaction; those remain manual acceptance checks.

macOS 会在访问路径前检查挂载信息，并核查已打开的文件句柄，拒绝网络卷和自动挂载目录。新建敏感文件在写入前移除继承 ACL、设置 `0600`；保护失败则停止。链接检查、排他新建、文件锁及原子替换仍然启用，但 POSIX 路径检查不能等同于 Windows 的父目录强制共享锁，无法消除同用户恶意进程并发改名造成的所有竞态。应使用仅当前用户可写的可信目录。

这不是操作系统沙箱，也不能对抗账户或管理员权限已失陷。应用的 Python 层禁止网络和子进程，但原生库及操作系统仍属于信任边界；临时签名不认证发布者。两个平台共用界面源码，Mac 使用 Command+L 和四角缩放控件；CI 验证不代表所有屏幕缩放、触控板手势和窗口装饰已人工验收。
