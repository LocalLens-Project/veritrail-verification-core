# 验迹 (VeriTrail) 核验核心组件

![Platform](https://img.shields.io/badge/platform-iOS-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)
![Standard](https://img.shields.io/badge/standard-RFC%203161-blue)

> 验迹 (VeriTrail) iOS 端导出包的官方离线核验脚本与说明。
>
> 目标是让第三方在**不联网**条件下，独立验证证据包的内容完整性、哈希链连续性、主签名、硬件背书签名、时间戳回执，以及关键设备元数据。

## 核心能力

- 离线核验：全程本地计算，不上传文件。
- 链式完整性：验证 `fileHash`、`entryHash`、`previousHash` 与链条顺序。
- 主签名验签：验证条目哈希上的 ECDSA P-256 主签名（设备签名）。
- 硬件背书验签：验证第二签名槽（`hardwareEndorsement*`），支持 `publicKey` 与 `certificate` 路径。
- 可信时间戳校验：校验 RFC 3161 `timestampToken` 的 imprint、nonce、CMS 签名、证书链信任与 EKU（`id-kp-timeStamping`）。
- 元数据审计：输出设备型号/系统/设备指纹ID、签名模式、10分钟窗口相关字段、采集来源。
- 兼容旧备份：字段缺失时按“旧版本备份”处理，并给出告警而非直接中断。

## 双重签名说明（YubiKey 硬件背书）

当用户启用 YubiKey 硬件背书并形成“主签名 + 硬件背书签名”双重签名时，证据在技术抗篡改与抗抵赖层面的强度最高。  
在司法或合规场景中，这通常意味着更高的技术证明力与更清晰的签名主体隔离。  
但最终法律效力仍由具体司法辖区、取证程序、证据规则与审理机关综合认定。

## 与 iOS v1.3.0 对齐

本仓库已对齐当前 iOS 端的大改动：

1. 设备签名元数据
- `deviceModelCode`
- `deviceModelName`
- `deviceSystemVersion`
- `deviceFingerprintID`
- `deviceSignatureMode` (`secure_enclave` / `software_fallback` / `unknown`)

2. 10分钟窗口相关元数据
- `captureMonotonicNanos`
- `captureBootSessionID`
- `onsiteWindowSeconds`

3. 硬件背书（第二签名）
- `hardwareEndorsementSignature`
- `hardwareEndorsementPublicKey`
- `hardwareEndorsementCertificate`
- `hardwareEndorsementKeyName`
- `hardwareEndorsementSignedAt`
- `hardwareEndorsementLevel` (`onsite_witness` / `post_archived`)
- `hardwareEndorsementError`

4. 采集来源字段
- `captureSource`: `photo` / `video` / `audio` / `imported`

## 使用方法

### 1) 依赖

```bash
pip install cryptography asn1crypto
```

### 2) 运行

```bash
python3 veritrail-verify.py "/path/to/VeriTrail_Backup"
```

备份目录应至少包含：
- `data.json`
- `files/`

### 3) 结果解释

- `✅`：关键校验通过。
- `⚠️`：告警（字段异常、兼容性问题、非关键信息不完整）。
- `❌`：关键错误（文件/链条/签名/TSA 校验失败）。

只要出现 `❌`，脚本退出码为 `1`。

## 输出示例（节选）

```text
Running VeriTrail Verification Protocol v1.3.0
Backup format version: 3
==============================================================================
案件 [1/1]: Demo Case
------------------------------------------------------------------------------
[1] 照片_20260212_214012.jpg
    🕒 记录时间: 2026-02-12 13:40:12 UTC
    📍 采集来源: App 直接拍照（传感器直连）
    ✅ 文件完整
    ✅ 创世节点
    ✅ 指纹验证通过
    🔐 主签名: 签名验证通过
    📱 设备签名元数据: iPad Pro 11寸 (第三代, M1) • iOS 26.2.1 • Secure Enclave（原生保护）
    ⏱️ 现场窗口元数据: captureMonotonicNanos=1406712821488000, captureBootSessionID=1769496921, onsiteWindowSeconds=600
    🪪 硬件背书: 现场身份亲签 • YubiKey 5C Nano · FW 5.4.3 • 2026-02-12 13:40:44 UTC
    🪪 硬件签名校验: 签名验证通过 (publicKey)
    🪪 硬件证书: 已附带并解析成功
    🪪 硬件签名校验: 证书验签通过 (certificate)
    🪪 硬件公钥与证书公钥一致
    🪪 硬件背书时间差: XXs
    🛡️  TSA 校验通过 (时间: 2026-02-12T13:40:12+00:00, CMS 签名验证通过; 证书链验证通过 (certifi, openssl verify))

==============================================================================
🏆 验证成功! 所有关键校验项通过。
```

## data.json 关键字段（当前脚本识别）

- 基础完整性：
`fileHash` `entryHash` `previousHash` `timestamp` `fileName` `fileSize` `relativeFilePath`

- 主签名：
`signature` `publicKey`

- 设备签名元数据：
`deviceModelCode` `deviceModelName` `deviceSystemVersion` `deviceFingerprintID` `deviceSignatureMode`

- 10分钟窗口：
`captureMonotonicNanos` `captureBootSessionID` `onsiteWindowSeconds`

- 硬件背书：
`hardwareEndorsementSignature` `hardwareEndorsementPublicKey` `hardwareEndorsementCertificate`
`hardwareEndorsementKeyName` `hardwareEndorsementSignedAt` `hardwareEndorsementLevel` `hardwareEndorsementError`

- 时间戳：
`timestampToken` `timestampNonce`

- 采集来源：
`captureSource`

## 兼容策略

- 旧备份缺少新字段：脚本给出 `⚪` 或 `⚠️`，仍可完成核心完整性核验。
- 字段存在但格式异常：标记 `⚠️` 或 `❌`，具体取决于是否影响关键校验路径。

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
