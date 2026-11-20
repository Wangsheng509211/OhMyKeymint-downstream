# Oh My Keymint - Attestation Bridge

> 本仓库是基于 [ITxiao6666/OhMyKeymint](https://github.com/ITxiao6666/OhMyKeymint) v1.4.4 修改的下游版本，不是官方版本，也不代表上游维护者。本版本的问题请反馈至[本仓库 Issues](https://github.com/Wangsheng509211/OhMyKeymint-downstream/issues)。

面向 Android 的自定义 Keystore / KeyMint 实现，提供应用配置、Keybox 管理及配套 WebUI。

## 安装与使用

需要 **Android 12 及以上**，以 KernelSU 或 Magisk 安装。

1. 从本仓库的 [Releases](https://github.com/Wangsheng509211/OhMyKeymint-downstream/releases) 下载并安装模块。
2. 打开 WebUI，选择需要使用 OMK 的应用，按需导入 Keybox。
3. 高级设置及生效条件请参阅[配置指南](docs/CONFIGURATION.md)。

KernelSU 可直接从模块列表打开 WebUI；Magisk 需自行安装 KSUWebUIStandalone 或 WebUI X。

本版本已移除 Zygisk 组件（PIF 构建指纹伪装随之移除），不需要安装或启用 Zygisk Next 即可使用 keystore/证明链相关功能。

## 主要功能

- 应用包名、多用户及应用独立安全补丁配置。
- RSA / EC Keybox 导入与证书链信息查看。
- 安全补丁同步与恢复、本地 RKP Keybox 签发。
- 运行状态诊断、主题与语言设置。
- SOTER 本地随机身份、按应用选择 32/36 位 CPU-ID 覆盖。
- 守护进程与启动脚本去特征：进程名统一为 `keymaster`，运行期不暴露模块路径。
- 可选的内嵌 keymint 运行库（默认关闭，需手动启用）。

Keybox 至少需要一个完整的 RSA 或 EC 条目，私钥必须与证书链匹配。
仅含 EC 条目时，RSA 密钥的认证证书也使用该 EC 私钥和证书链签名。
详细配置位于 `/data/misc/keystore/omk/`，请勿公开密钥。

## 注意事项

- 软件实现不能替代真实 TEE 或生物认证，不保证通过检测或支付认证。
- 使用前请备份重要数据，实验性功能请谨慎开启。
- 卸载会删除 OMK 配置及密钥数据，可能需要相关应用重新登录或注册；禁用模块不会删除这些数据。

## Restarting keymint and injector

需要手动重启服务时，可执行对应命令：

```sh
touch /data/adb/omk/restart.keymint
touch /data/adb/omk/restart.injector
touch /data/adb/omk/restart.all
```

哪些设置需要重启服务或设备，请参阅[生效说明](docs/CONFIGURATION.md#how-changes-are-loaded)。

## 更新源

```
https://raw.githubusercontent.com/Wangsheng509211/OhMyKeymint-downstream/master/update.json
```

## 许可与致谢

使用前须阅读并同时遵守 [General License Agreement v4 或后续版本](LICENSE.md) 和 [Oh My Keymint License](LICENSE-2)。
本软件按原样提供，不作任何担保。独立标明的第三方部分仍遵循各自原有许可。

Copyright (C) 2025, 2026 James Clef <qwq233@qwq2333.top>

部分代码来自 [AOSP](https://source.android.com/)，采用 [Apache-2.0](template/AOSP.Apache-license-2.0.txt)。
Copyright 2022, The Android Open Source Project

其他第三方来源与许可见[第三方软件说明](docs/THIRD_PARTY.md)。
