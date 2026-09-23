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

现有便携构建包含 PyKCS11。对外分发前必须完成组合分发许可核对，并按所选适用 GPL 版本提供完整对应源码、必要构建材料、声明和许可证；仅提供 wheel、COPYING 或上游链接不足以确认这些义务已履行。当前流程未自动生成或验证该完整对应源码集合。因此，当前源码包可供 MIT 原创代码审查，现有便携包仍是本地验证产物，不能标记为“全包 MIT、已完成许可发布审查”。本清单不把该未完成项隐藏为构建成功。
