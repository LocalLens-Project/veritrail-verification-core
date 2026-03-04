# 验迹 (VeriTrail) 核验核心组件
![Platform](https://img.shields.io/badge/platform-iOS%20%7C%20macOS-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)
![Standard](https://img.shields.io/badge/standard-RFC%203161-blue)

> 验迹 (VeriTrail) iOS 导出包的官方离线核验脚本与说明（当前协议版本 `v1.3.1`）。
>
> 目标是让第三方在不联网条件下，独立验证证据包完整性、链条连续性、签名真实性、时间戳有效性、见证槽一致性与关键设备审计字段。

## 核心能力

- 离线核验：全程本地计算，不上传文件。
- 双模式核验：
- `standard`：常规完整性核验（`data.json` + `files/`）。
- `judicial`：在 `standard` 基础上，额外交叉核验 `judicial_witnesses.json` 与 `LEGAL_NOTICE.txt`。
- 条目哈希核验：支持 `entryHashVersion` v1/v2/v3。
- v2：绑定 `locationHash`。
- v3：绑定 `locationHash` + `witnessAggregateHash`（无见证时按占位组件参与哈希）。
- 见证槽核验：解析 `witnessSlotsData`，校验每个槽位 `packetHash`，复算 `witnessAggregateHash`，并校验 `boundEntryHash` 绑定关系。
- 主签名验签：验证条目哈希上的 ECDSA P-256 主签名（设备签名）。
- 硬件背书验签：验证第二签名槽（`hardwareEndorsement*`），支持 `publicKey` 与 `certificate` 路径。
- 可信时间戳校验：校验 RFC 3161 `timestampToken` 的 imprint、nonce、CMS 签名、证书链信任与 EKU（`id-kp-timeStamping`）。
- 元数据审计：输出设备型号/系统版本/设备指纹ID/签名模式、现场窗口字段、采集来源、位置风险标记。
- App Attest 回执审计：解析并展示 `appAttest*` 字段并做一致性告警（离线模式不复验在线挑战流程）。
- 服务端 App Attest 报告交叉核验：可选传入服务端报告（`v1/v2`），核验“整案 entryHash 范围 + 见证锚点”与本地案件包是否一致。
- 司法导出隐私保护：默认脱敏输出实名见证字段；可用 `--reveal-pii` 显示明文。
- 路径安全检查：严格防止 `relativeFilePath` 路径穿越与符号链接越界。

## 双重签名说明（YubiKey 硬件背书）

当用户启用 YubiKey 硬件背书并形成“主签名 + 硬件背书签名”双重签名时，证据在技术抗篡改与抗抵赖层面的强度更高。  
在司法或合规场景中，这通常意味着更高的技术证明力与更清晰的签名主体隔离。  
但最终法律效力仍由具体司法辖区、取证程序、证据规则与审理机关综合认定。

## 与当前 iOS 发布版本对齐

- iOS: `v1.3.1`
- macOS: `v1.0.1`
- Python 协议版本常量：`PROTOCOL_VERSION = "v1.3.1"`

## 使用方法

### 1) 依赖安装

```bash
pip install cryptography asn1crypto certifi
```

`certifi` 不是硬依赖，但建议安装，便于 TSA 证书链校验稳定。

### 2) 标准核验（默认）

```bash
python3 veritrail-verify.py "/path/to/VeriTrail_Case_xxx"
```

或显式写法：

```bash
python3 veritrail-verify.py "/path/to/VeriTrail_Case_xxx" --mode standard
```

### 3) 司法核验（默认脱敏）

```bash
python3 veritrail-verify.py "/path/to/VeriTrail_Judicial_xxx" --mode judicial
```

### 4) 司法核验（显示明文身份字段）

```bash
python3 veritrail-verify.py "/path/to/VeriTrail_Judicial_xxx" --mode judicial --reveal-pii
```

### 5) 目录要求

标准导出包至少包含：

- `data.json`
- `files/`

司法导出包额外要求：

- `judicial_witnesses.json`
- `LEGAL_NOTICE.txt`

### 6) 交叉核验服务端 App Attest 报告（可选）

```bash
python3 veritrail-verify.py "/path/to/VeriTrail_Case_xxx" --mode standard --attest-report "/path/to/app_attest_report_xxx.json"
```

若是司法包，也可叠加：

```bash
python3 veritrail-verify.py "/path/to/VeriTrail_Judicial_xxx" --mode judicial --attest-report "/path/to/app_attest_report_xxx.json"
```

## 环境变量（可选）

脚本支持以下运行时策略控制：

- `VERITRAIL_CA_BUNDLE`
- 指向自定义根证书包（PEM 或 DER）。
- `VERITRAIL_REQUIRE_TSA_EKU`
- 是否强制 TSA 证书带 `timeStamping` EKU，默认 `true`。
- `VERITRAIL_ALLOW_TSA_SHA1`
- 是否允许 SHA-1 时间戳链路，默认 `false`。

示例：

```bash
export VERITRAIL_CA_BUNDLE="/path/to/roots.pem"
export VERITRAIL_REQUIRE_TSA_EKU=true
export VERITRAIL_ALLOW_TSA_SHA1=false
python3 veritrail-verify.py "/path/to/VeriTrail_Case_xxx" --mode standard
```

## 结果解释

- `✅`：关键校验通过。
- `⚠️`：告警（兼容性问题、审计字段异常、非关键缺失）。
- `❌`：关键错误（完整性/链条/签名/TSA/司法交叉核验失败）。

出现任意 `❌`，脚本退出码为 `1`。

## 输出示例（节选）

```text
Running VeriTrail Verification Protocol v1.3.1
Backup format version: 4
TSA policy: requireEKU=True, allowSHA1=False, trustStoreEnv=VERITRAIL_CA_BUNDLE
Verification mode: standard (revealPII=False)
==============================================================================
案件 [1/1]: Demo Case
------------------------------------------------------------------------------
[1] 照片_20260212_214012.jpg
    🕒 记录时间: 2026-02-12 13:40:12 UTC
    🔢 条目哈希版本: v3
    📍 采集来源: App 直接拍照（传感器直连）
    📡 位置证据: 状态=已采集 • 置信度=中 • provider=core_location
    👥 见证槽数量: 1
    👥 WitnessHash(recorded)=aabbcc...
    👥 WitnessHash(recalculated)=aabbcc...
    ✅ 文件完整
    ✅ 创世节点
    ✅ 指纹验证通过
    🔐 主签名: 签名验证通过
    🍎 App Attest 远程验签: 已通过 • keyID=... • verificationID=... • verifiedAt=... • server=https://www.locallens.cn
    🪪 硬件签名校验: 签名验证通过 (publicKey)
    🛡️  TSA 校验通过 (...)
==============================================================================
🏆 验证成功! 所有关键校验项通过。
```

## data.json 关键字段（当前脚本识别）

- 基础完整性：
`fileHash` `entryHash` `previousHash` `timestamp` `fileName` `fileSize` `relativeFilePath`

- 条目哈希版本：
`entryHashVersion`

- 主签名：
`signature` `publicKey`

- 见证相关：
`witnessAggregateHash` `witnessSlotsData`

- 设备签名元数据：
`deviceModelCode` `deviceModelName` `deviceSystemVersion` `deviceFingerprintID` `deviceSignatureMode`

- App Attest 远程验签回执：
`appAttestStatus` `appAttestKeyID` `appAttestVerificationID` `appAttestVerifiedAt` `appAttestServerURL` `appAttestError`

- 位置证据（GPS）：
`locationHash` `locationStatus` `locationConfidence` `locationRiskFlags`
`locationLatitude` `locationLongitude` `locationAccuracyMeters`
`locationCapturedAt` `locationProvider` `locationIsSimulatedBySoftware` `locationIsProducedByAccessory`

- 10分钟窗口：
`captureMonotonicNanos` `captureBootSessionID` `onsiteWindowSeconds`

- 硬件背书：
`hardwareEndorsementSignature` `hardwareEndorsementPublicKey` `hardwareEndorsementCertificate`
`hardwareEndorsementKeyName` `hardwareEndorsementSignedAt` `hardwareEndorsementLevel` `hardwareEndorsementError`

- 时间戳：
`timestampToken` `timestampNonce`

- 采集来源：
`captureSource`

## 司法模式附加核验点

- 要求存在 `judicial_witnesses.json` 与 `LEGAL_NOTICE.txt`。
- 逐条比对 `judicial_witnesses.json.entries[]` 与 `data.json` 条目：
- `entryID` / `entryHash` / `witnessAggregateHash` / `witnessCount`。
- 逐见证槽比对 `slotID` / `packetHash` / `sessionID` / `mode` / `aliasHash`。
- 检查司法清单是否遗漏或伪造见证槽。
- 对 `decryptedPayload` 做摘要展示：
- 默认脱敏。
- `--reveal-pii` 时显示明文。

## 兼容与判定规则

- 旧备份缺少新字段：输出 `⚪` 或 `⚠️`，核心路径仍继续核验。
- `entryHashVersion=1`：按旧版规则核验（不要求位置/见证字段）。
- `entryHashVersion=2`：要求有效 `locationHash` 且与位置元数据复算一致。
- `entryHashVersion>=3`：
- 要求有效 `locationHash`。
- 若无见证回传，可无 `witnessAggregateHash`，条目哈希按无见证占位组件计算。
- 若存在 `witnessSlotsData`，则必须可复算并匹配 `witnessAggregateHash`。
- App Attest 属离线审计项：仅核验字段一致性，不复验 Apple 在线挑战。
- 出现关键错误（`❌`）即整体失败并返回退出码 `1`。

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
