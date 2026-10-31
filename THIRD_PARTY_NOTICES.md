# 第三方许可说明

根目录 LICENSE 的 MIT 授权适用于本项目原创源码和文档，不替代第三方组件许可。源码发布包不包含 vendor、Python 运行时或第三方二进制。

以下为锁定依赖的许可索引；分发时以相应版本随附的完整许可、版权声明及源码义务为准，不能仅凭本表认定二进制可发布。

| 组件 | 版本 | 许可索引 |
|---|---|---|
| cryptography | 46.0.7 | Apache-2.0 OR BSD-3-Clause；另含其打包的第三方声明 |
| asn1crypto | 1.5.1 | MIT |
| bcrypt | 5.0.0 | Apache-2.0 |
| cffi | 2.0.0 | MIT |
| pycparser | 3.0 | BSD-3-Clause |
| pycryptodomex | 3.23.0 | BSD / Public Domain，详见组件文件 |
| pyasn1 | 0.6.3 | BSD-2-Clause |
| PGPy | 0.6.0 | BSD-3-Clause |
| pyjks | 20.0.0 | MIT；构建时移除 BKS 自动导入，保留 JKS |
| argon2-cffi | 25.1.0 | MIT |
| argon2-cffi-bindings | 26.1.0 | MIT，另保留捆绑组件声明 |
| PyKCS11 | 1.5.18 | GPL-2.0-or-later |
| javaobj-py3 | 0.6.1 | Apache-2.0 |
| pyasn1-modules | 0.4.2 | BSD，详见组件许可 |

Windows 便携包还包含 CPython 3.12、Tcl/Tk 及原生依赖，其声明在包内 licenses、runtime/tcl 和各组件 dist-info 中。Mac 构建另使用 PyInstaller；应保留其许可证及引导程序例外。构建工具不会使其他组件的许可证失效。

## 二进制发布检查项

PyKCS11 1.5.18 的[官方说明](https://github.com/LudovicRousseau/PyKCS11/blob/1.5.18/README.md)明确采用 GPL v2 或之后版本。不能因代码通过 SWIG 生成而假定 PyKCS11 自身具有许可例外。

公开 Windows 标准构建不捆绑 PyKCS11，安装器构建会检查 standard profile 及文件清单，拒绝包含 PyKCS11 的载荷。硬件令牌接口保留，但使用者须通过可信离线依赖构建自己的本地令牌版本。`--with-pkcs11` 生成单独命名的本地产物，不作为标准安装器的输入。

Windows 和 macOS 公开标准包均不包含 PyKCS11。本地完整版本可能包含 PyKCS11；对外分发前仍需完成组合分发许可核对，并按适用 GPL 版本提供完整对应源码及构建材料。当前流程没有生成这些材料，不应将本地完整版本直接公开。标准安装包包含其他不同许可的组件，不能称为“全包 MIT”；原创源码继续采用 MIT。包内保留 Python 的完整 Windows 二进制附加条款、Tcl/Tk 许可，以及各依赖 dist-info 中的许可和版权声明。

Tcl 8.6.15 的完整声明保存在 `packaging/licenses/Tcl-LICENSE.txt`，构建后位于 `licenses/Tcl-LICENSE.txt`。来源：https://raw.githubusercontent.com/tcltk/tcl/core-8-6-15/license.terms 。SHA-256：`c0a69a2bfd757361ec7e6143973b103c90409316b49e9c88db26ad6388e79f16`。离线 vendor 缺少 RECORD 时，构建器仍按真实 dist-info 目录保留 LICENSE/COPYING/NOTICE；缺失许可时停止构建，不复制 direct_url.json 等本机安装来源元数据。
