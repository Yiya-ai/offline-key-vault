# macOS：实验性构建入口，尚未实机验证

目前没有已验证、可直接分发的 Mac 安装包。Windows 的 EXE 不能在 macOS 上使用。本次开发环境是 Windows，没有可用的 macOS 运行时或签名身份，因此没有生成或宣称通过验证的 `.app` / DMG。

已补充 Apple Silicon（arm64）和 Intel（x86_64）的本机离线构建脚本，修复源码启动时误设 Windows Tcl/Tk 路径，增加 Mac 字体和 Command+L 锁定。两个架构分别在对应的本机 Python 环境构建；不承诺 Universal 2，也未验证 Rosetta。

## 在 Mac 上构建实验包

构建机须预先离线准备 Python 3.12（含可用的 Tk）、`requirements-macos-build.txt` 中的依赖及其依赖包。构建脚本不会联网、运行 pip、Homebrew、下载工具或上传源码。若缺少本地依赖，会停止并提示。

在已准备好环境的 Mac 上，可在终端执行：

```sh
python3 -I -S build_macos.py
```

或者先执行 `chmod +x build_macos.command`，再双击 `build_macos.command`。可通过 `OKV_PYTHON` 指定本地可信 Python 的绝对路径。

脚本只将白名单应用源码复制到独立目录，再用本地 PyInstaller 打包。使用 macOS 本地工具保留 `.app` 所需的符号链接和执行权限，并进行本地临时签名（ad-hoc）；不联系 Apple，不进行在线公证。

生成的 ZIP 会先解压到中文、空格目录，再执行真实打包程序的 `--self-test`。自检使用合成密钥验证算法、加密 SSH、密钥库、GUI 和 Python 网络调用阻断；验证失败不会将新包写入 `dist/`。成功时输出 `dist/offline-key-vault-macos-arm64-experimental.zip` 或 `...-x86_64-experimental.zip`，另附 SHA-256。

构建完成的实验包目标用法是：解压后双击 `OfflineKeyVault.app`，目标机无需另装 Python。当前没有真实 Mac，因此尚不能确认这一流程实际成功或给出最低 macOS 版本。没有 Developer ID 签名或公证；系统可能拒绝打开。不要全局关闭 Gatekeeper 或删除系统安全策略。

## 正式支持前尚需完成

- 在对应架构的干净 Mac 上验证 Finder 启动、Tk 界面、字体、Command+L、解压移动与更新。
- 完成 macOS 本地卷/网络卷拒绝、APFS 权限及继承 ACL、文件锁、目录重命名竞态、系统临时目录等安全测试，并修复缺口。
- 当前 POSIX 存储只有 0600、文件类型/链接检查、flock 和原子替换等通用保护，不能等同于 Windows 的目录句柄固定、卷检查和受保护 DACL。尤其尚未实现 macOS 网络挂载识别和完整的继承 ACL 防护。
- 在这部分验证和加固完成前，只用合成测试数据，不能把实验构建当成达到现有安全要求的正式密钥管理器。

源码中没有联网、上传或更新功能；Python audit hook 不是 OS 沙箱。macOS 的签名、公证与系统后台网络行为不由应用的 Python 策略控制。原有 Windows 包仍是当前已进行本机验证的交付版本。

新增兼容模块需要本机架构的 Argon2/PyKCS11/PyCryptodomex 依赖和 OpenSSL 3 动态库。构建脚本将显式包含该动态库；不会把 Windows vendor 中的 .pyd 当作 macOS 模块。当前没有真实 Mac 验证记录，仍属实验构建，不提供已验证的 .app 下载。

## 本次界面调整同步情况

macOS 与 Windows 共用 `keyvault/app.py`、`widgets.py`、`tool_ui.py`、`token_ui.py` 和 `content_ui.py`。Mac 构建脚本复用 Windows 构建中的 `APP_FILES` 源码清单，已包含以上文件，无需复制另一套界面。

本次的同行路径选择、硬件令牌分组布局、圆角按钮、内嵌密码小眼睛、窗口外框约束及内容等比例缩放和按溢出自动显示滚动条均包含在共用源码中。图标与组件背景由 Python 标准库在本地生成，Tk 直接加载，不需要 Windows 字体图标、图形 DLL、网络资源或新增第三方图像库。

共用源码已在 Windows 上做交互与缩放回归；这不等于 Mac 实机验证。Mac 发布前还需要检查 PingFang SC、Retina 显示、触控板滚动、眼睛按钮鼠标/键盘操作、焦点离开后隐藏密码，以及窄窗口控件是否完整显示。目前仍没有本次版本已验证的 `.app` 或 DMG。

固定比例缩放在 Windows 使用原生四角边框；macOS 源码使用四个角的本地拖动柄，禁用原生自由拉伸。此分支已做合成事件回归，但真实 Mac 上的拖动、窗口坐标和系统装饰仍未实测。
