# 验迹 (VeriTrail) 核验核心组件

![Platform](https://img.shields.io/badge/platform-iOS-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)
![Standard](https://img.shields.io/badge/standard-RFC%203161-blue)

> **验迹 (VeriTrail) 数字取证系统的官方开源核验工具包。**
>
> 本项目包含核心校验逻辑，允许第三方机构在**完全离线**环境下，独立验证由验迹 iOS App 生成的数字证据包在完整性、链条连续性、签名真实性与时间有效性方面是否可信。

## 核心能力

本工具遵循 **ISO/IEC 27037** 数字取证国际标准参考设计，核心逻辑透明可见：

- **离线核验 (Offline Verification)**：全程本地计算与校验，无需联网，降低证据泄露风险。
- **链式完整性 (Chain Integrity)**：校验 SHA-256 哈希链（内容 + 关键元数据 + 前序关系），防止篡改与未授权重排。
- **签名审计 (Signature Audit)**：验证对链条指纹的 ECDSA P-256 数字签名，用于锚定记录来源与不可抵赖性（若缺签名则仅能证明一致性）。
- **时间戳校验 (RFC 3161，可选)**：验证第三方可信时间戳回执（TSA token）的有效性。
- **采集来源识别 (Capture Source Traceability)**：支持识别 `photo` / `video` / `audio` / `imported`，并在核验输出中展示来源信息。
- **新旧备份兼容**：旧备份缺少 `captureSource` 字段时，脚本按“未记录(旧版本备份)”处理，不影响哈希链/签名/TSA 校验。

## iOS 端对齐更新（2026-02）

本 README 已与 iOS 端与核验脚本最新实现对齐，关键变更如下：

1. **Python 核验脚本同步支持来源识别**  
   `veritrail-verify.py` 已支持读取并输出 `captureSource`，并对异常值给出提示。

## 使用方法

### 1. 环境准备

需要 Python 3.6+ 环境以及密码学库支持：

```bash
pip install cryptography asn1crypto
```

### 2. 运行核验

将导出的案件包（解压后的文件夹）路径作为参数传入：

```bash
python3 veritrail-verify.py "/path/to/your/evidence_folder"
```

### 3. 输出示例

运行成功后，终端将输出如下详细审计日志（示例包含采集来源与 TSA）：

```text
Running VeriTrail Verification Protocol v1.1.1
============================================================
案件 [1/1]: Demo Case
------------------------------------------------------------
[1] 录音_20260209_135901.m4a
    📍 采集来源: App 直接录音（传感器直连）
    ✅ 文件完整
    ✅ 创世节点
    ✅ 指纹验证通过
    🔐 签名验证通过
    🛡️  TSA 校验通过 (时间: 2026-02-09 05:59:27+00:00, 权威机构签名有效)

============================================================
🏆 验证成功! 所有数据完整，哈希链闭合。
```

## 备份格式兼容说明

当前脚本识别以下关键字段（位于 `data.json` 的 entry 节点）：

- `fileHash` / `entryHash` / `previousHash`
- `signature` / `publicKey`
- `timestampToken` / `timestampNonce`
- `captureSource`（可选）

`captureSource` 取值约定：

- `photo`：App 直接拍照
- `video`：App 直接录像
- `audio`：App 直接录音
- `imported`：导入文件

兼容策略：

- 缺失该字段：输出 `采集来源: 未记录 (旧版本备份)`。
- 字段值异常：输出 `采集来源字段异常` 警告，但不阻断其余完整性核验流程。

## 免责声明 (Disclaimer)

1. **技术边界**：本工具仅用于验证验迹 App 生成数据的**电子完整性**与**未篡改性**。验证通过仅代表数据自生成后未被修改，并不代表对现实世界事件真实性的背书。
2. **法律效力**：尽管本工具遵循 ISO/IEC 27037 参考设计，数字证据在法律诉讼中的采信度仍取决于当地法律法规与司法鉴定要求。
3. **使用责任**：开发者不对因使用本工具产生的直接或间接后果承担法律责任。

## 🤝 贡献与反馈

本存储库作为验迹 (VeriTrail) 的核心开源组件，欢迎安全审计与代码贡献。

* **Bug 反馈**：如果您发现验证逻辑存在漏洞，请通过 [Issues](../../issues) 提交报告。
* **代码贡献**：欢迎提交 Pull Request，请确保您的代码包含相应的单元测试。
* **联系与支持**：如有其他疑问或需要私下联络，请发送邮件至 `help@locallens.cn`。
    > **安全通信建议**：**若涉及敏感技术问题，建议注册使用 Tuta Mail 与我们联系。作为开源端到端加密邮件服务，它能确保邮件在传输过程中全程加密，且仅能由我方解密查阅。**

© 2026 LocalLens Project. Distributed under the MIT License.
