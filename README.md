# 验迹 (VeriTrail) 核验核心组件

![Platform](https://img.shields.io/badge/platform-iOS-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)
![Standard](https://img.shields.io/badge/standard-RFC%203161-blue)

> **验迹 (VeriTrail) 数字取证系统的官方开源核验工具包。**
> 
> 本项目包含核心校验逻辑，允许第三方机构在**完全离线**的环境下，独立验证由验迹 iOS App 生成的数字证据包的真实性、完整性与时间有效性。

## 🛡 核心能力

本工具遵循 **ISO/IEC 27037** 数字取证国际标准参考设计，核心逻辑透明可见：

- ✅ **离线核验 (Offline Verification)**：全程本地计算与校验，无需联网，降低证据泄露风险。
- ✅ **链式完整性 (Chain Integrity)**：校验 SHA-256 哈希链（内容 + 关键元数据 + 前序关系），防止篡改与未授权重排。
- ✅ **签名审计 (Signature Audit)**：验证对链条指纹的 ECDSA P-256 数字签名，用于锚定记录来源与不可抵赖性（若缺签名则仅能证明一致性）。
- ✅ **时间戳校验 (RFC 3161，可选)**：解析 RFC 3161 回执并校验其 MessageImprint/Nonce 与本地证据哈希一致。

## 🚀 使用方法

### 1. 环境准备
需要 Python 3.6+ 环境以及密码学库支持。

```bash
pip install cryptography asn1crypto
```

### 2. 运行核验
将您导出的案件包（解压后的文件夹）路径作为参数传入：

```bash
python3 veritrail-verify.py "/path/to/your/evidence_folder"
```

### 3. 输出示例
运行成功后，终端将输出如下详细审计日志（以包含 TSA 时间戳的案件为例）：

```
Running VeriTrail Verification Protocol v1.1
============================================================
案件 [1/1]: veritrail-verify
------------------------------------------------------------
[1] veritrail-verify.py  
    ✅ 文件完整  
    ✅ 创世节点  
    ✅ 指纹验证通过
    🔐 签名验证通过  
    🛡️ TSA 校验通过 (时间 : 2026-02-04 10:47:27+00:00, 权威机构签名有效)

============================================================
🏆 验证成功！所有数据完整，哈希链闭合。
```

## 📂 验证包样本 (Sample Evidence)

为了方便测试与审计，我们提供了一个经过签名的标准验证包样本（即上述输出示例对应的案件包）。您可以在本仓库的 [Releases](https://github.com/LocalLens-Project/veritrail-verification-core/releases/) 页面 下载 `veritrail-verify-v1.1.zip` 进行试运行。

该样本包包含了本脚本的源代码作为“证据文件”，实现了代码自证（Self-Verification）。

© 2026 LocalLens Project. Distributed under the MIT License.
