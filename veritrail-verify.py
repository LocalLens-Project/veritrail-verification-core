import argparse
import base64
import binascii
import datetime
import hashlib
import json
import math
import os
import re
import ssl
import subprocess
import sys
import tempfile
import uuid
import warnings
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from asn1crypto import tsp
    from cryptography import x509 as crypto_x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.utils import CryptographyDeprecationWarning
    from cryptography.x509.oid import ExtensionOID
    from cryptography.x509.verification import PolicyBuilder, Store, VerificationError
except ImportError:
    print("❌ 错误: 缺少必要的库。")
    print("请运行: pip install asn1crypto cryptography")
    sys.exit(1)

# TSA 时间戳签名 EKU OID (id-kp-timeStamping)
TSA_TIMESTAMPING_EKU_OID = "1.3.6.1.5.5.7.3.8"

# iOS (Cocoa) 时间戳起始点: 2001-01-01 00:00:00 UTC
COCOA_EPOCH_OFFSET = 978307200

PROTOCOL_VERSION = "v1.3.1"
CURRENT_ENTRY_HASH_VERSION = 3
MISSING_LOCATION_HASH_COMPONENT = "no_location_hash"
MISSING_WITNESS_HASH_COMPONENT = "no_witness_hash"

TRUST_STORE_ENV = "VERITRAIL_CA_BUNDLE"
REQUIRE_TSA_EKU_ENV = "VERITRAIL_REQUIRE_TSA_EKU"
ALLOW_TSA_SHA1_ENV = "VERITRAIL_ALLOW_TSA_SHA1"

DIGEST_OID_SHA1 = "1.3.14.3.2.26"
DIGEST_OID_SHA256 = "2.16.840.1.101.3.4.2.1"
DIGEST_OID_SHA384 = "2.16.840.1.101.3.4.2.2"
DIGEST_OID_SHA512 = "2.16.840.1.101.3.4.2.3"

RSA_WITH_SHA1_OID = "1.2.840.113549.1.1.5"
RSA_WITH_SHA256_OID = "1.2.840.113549.1.1.11"
RSA_WITH_SHA384_OID = "1.2.840.113549.1.1.12"
RSA_WITH_SHA512_OID = "1.2.840.113549.1.1.13"
RSA_ENCRYPTION_OID = "1.2.840.113549.1.1.1"

ECDSA_WITH_SHA1_OID = "1.2.840.10045.4.1"
ECDSA_WITH_SHA256_OID = "1.2.840.10045.4.3.2"
ECDSA_WITH_SHA384_OID = "1.2.840.10045.4.3.3"
ECDSA_WITH_SHA512_OID = "1.2.840.10045.4.3.4"

_TRUST_ROOTS_CACHE: Optional[List[crypto_x509.Certificate]] = None
_TRUST_STORE_SOURCE: Optional[str] = None
_TRUST_STORE_ERROR: Optional[str] = None

KEYS = {
    "version": "version",
    "case_id": "id",
    "cases": "cases",
    "entries": "entries",
    "entry_id": "id",
    "timestamp": "timestamp",
    "rel_path": "relativeFilePath",
    "file_name": "fileName",
    "file_size": "fileSize",
    "file_hash": "fileHash",
    "prev_hash": "previousHash",
    "entry_hash": "entryHash",
    "entry_hash_version": "entryHashVersion",
    "location_hash": "locationHash",
    "case_name": "name",
    "signature": "signature",
    "public_key": "publicKey",
    "device_model_code": "deviceModelCode",
    "device_model_name": "deviceModelName",
    "device_system_version": "deviceSystemVersion",
    "device_fingerprint_id": "deviceFingerprintID",
    "device_signature_mode": "deviceSignatureMode",
    "app_attest_status": "appAttestStatus",
    "app_attest_key_id": "appAttestKeyID",
    "app_attest_verification_id": "appAttestVerificationID",
    "app_attest_verified_at": "appAttestVerifiedAt",
    "app_attest_server_url": "appAttestServerURL",
    "app_attest_error": "appAttestError",
    "location_status": "locationStatus",
    "location_confidence": "locationConfidence",
    "location_risk_flags": "locationRiskFlags",
    "location_latitude": "locationLatitude",
    "location_longitude": "locationLongitude",
    "location_accuracy_meters": "locationAccuracyMeters",
    "location_captured_at": "locationCapturedAt",
    "location_provider": "locationProvider",
    "location_is_simulated_by_software": "locationIsSimulatedBySoftware",
    "location_is_produced_by_accessory": "locationIsProducedByAccessory",
    "capture_monotonic_nanos": "captureMonotonicNanos",
    "capture_boot_session_id": "captureBootSessionID",
    "onsite_window_seconds": "onsiteWindowSeconds",
    "witness_aggregate_hash": "witnessAggregateHash",
    "witness_slots_data": "witnessSlotsData",
    "hardware_signature": "hardwareEndorsementSignature",
    "hardware_public_key": "hardwareEndorsementPublicKey",
    "hardware_certificate": "hardwareEndorsementCertificate",
    "hardware_key_name": "hardwareEndorsementKeyName",
    "hardware_signed_at": "hardwareEndorsementSignedAt",
    "hardware_level": "hardwareEndorsementLevel",
    "hardware_error": "hardwareEndorsementError",
    "ts_token": "timestampToken",
    "ts_nonce": "timestampNonce",
    "capture_source": "captureSource",
}

CAPTURE_SOURCE_LABELS = {
    "photo": "App 直接拍照（传感器直连）",
    "video": "App 直接录像（传感器直连）",
    "audio": "App 直接录音（传感器直连）",
    "imported": "导入文件",
}

DEVICE_SIGNATURE_MODE_LABELS = {
    "secure_enclave": "Secure Enclave（原生保护）",
    "software_fallback": "本地软件签名（安全降级）",
    "unknown": "未知",
}

APP_ATTEST_STATUS_LABELS = {
    "not_attempted": "未执行",
    "pending": "验签中",
    "verified": "已通过",
    "failed": "验签失败",
    "disabled": "已关闭",
    "unsupported": "设备不支持",
}

DEVICE_MODEL_CODE_LABELS = {
    "iPhone11,2": "iPhone XS",
    "iPhone11,4": "iPhone XS Max",
    "iPhone11,6": "iPhone XS Max",
    "iPhone11,8": "iPhone XR",
    "iPhone12,1": "iPhone 11",
    "iPhone12,3": "iPhone 11 Pro",
    "iPhone12,5": "iPhone 11 Pro Max",
    "iPhone12,8": "iPhone SE (第2代)",
    "iPhone13,1": "iPhone 12 mini",
    "iPhone13,2": "iPhone 12",
    "iPhone13,3": "iPhone 12 Pro",
    "iPhone13,4": "iPhone 12 Pro Max",
    "iPhone14,2": "iPhone 13 Pro",
    "iPhone14,3": "iPhone 13 Pro Max",
    "iPhone14,4": "iPhone 13 mini",
    "iPhone14,5": "iPhone 13",
    "iPhone14,6": "iPhone SE (第3代)",
    "iPhone14,7": "iPhone 14",
    "iPhone14,8": "iPhone 14 Plus",
    "iPhone15,2": "iPhone 14 Pro",
    "iPhone15,3": "iPhone 14 Pro Max",
    "iPhone15,4": "iPhone 15",
    "iPhone15,5": "iPhone 15 Plus",
    "iPhone16,1": "iPhone 15 Pro",
    "iPhone16,2": "iPhone 15 Pro Max",
    "iPhone17,3": "iPhone 16",
    "iPhone17,4": "iPhone 16 Plus",
    "iPhone17,1": "iPhone 16 Pro",
    "iPhone17,2": "iPhone 16 Pro Max",
    "iPhone17,5": "iPhone 16e",
    "iPhone18,3": "iPhone 17",
    "iPhone18,1": "iPhone 17 Pro",
    "iPhone18,2": "iPhone 17 Pro Max",
    "iPhone18,4": "iPhone Air",
    "iPad7,11": "iPad (第7代)",
    "iPad7,12": "iPad (第7代)",
    "iPad8,1": "iPad Pro 11寸 (第一代)",
    "iPad8,2": "iPad Pro 11寸 (第一代)",
    "iPad8,3": "iPad Pro 11寸 (第一代)",
    "iPad8,4": "iPad Pro 11寸 (第一代)",
    "iPad8,5": "iPad Pro 12.9寸 (第三代)",
    "iPad8,6": "iPad Pro 12.9寸 (第三代)",
    "iPad8,7": "iPad Pro 12.9寸 (第三代)",
    "iPad8,8": "iPad Pro 12.9寸 (第三代)",
    "iPad8,9": "iPad Pro 11寸 (第二代)",
    "iPad8,10": "iPad Pro 11寸 (第二代)",
    "iPad8,11": "iPad Pro 12.9寸 (第四代)",
    "iPad8,12": "iPad Pro 12.9寸 (第四代)",
    "iPad11,1": "iPad mini (第五代)",
    "iPad11,2": "iPad mini (第五代)",
    "iPad11,3": "iPad Air (第三代)",
    "iPad11,4": "iPad Air (第三代)",
    "iPad11,6": "iPad (第8代)",
    "iPad11,7": "iPad (第8代)",
    "iPad12,1": "iPad (第9代)",
    "iPad12,2": "iPad (第9代)",
    "iPad13,1": "iPad Air (第四代)",
    "iPad13,2": "iPad Air (第四代)",
    "iPad13,4": "iPad Pro 11寸 (第三代, M1)",
    "iPad13,5": "iPad Pro 11寸 (第三代, M1)",
    "iPad13,6": "iPad Pro 11寸 (第三代, M1)",
    "iPad13,7": "iPad Pro 11寸 (第三代, M1)",
    "iPad13,8": "iPad Pro 12.9寸 (第五代, M1)",
    "iPad13,9": "iPad Pro 12.9寸 (第五代, M1)",
    "iPad13,10": "iPad Pro 12.9寸 (第五代, M1)",
    "iPad13,11": "iPad Pro 12.9寸 (第五代, M1)",
    "iPad13,16": "iPad Air (第五代, M1)",
    "iPad13,17": "iPad Air (第五代, M1)",
    "iPad13,18": "iPad (第10代)",
    "iPad13,19": "iPad (第10代)",
    "iPad14,1": "iPad mini (第六代)",
    "iPad14,2": "iPad mini (第六代)",
    "iPad14,3": "iPad Pro 11寸 (第四代, M2)",
    "iPad14,4": "iPad Pro 11寸 (第四代, M2)",
    "iPad14,5": "iPad Pro 12.9寸 (第六代, M2)",
    "iPad14,6": "iPad Pro 12.9寸 (第六代, M2)",
    "iPad14,8": "iPad Air 11寸 (M2)",
    "iPad14,9": "iPad Air 11寸 (M2)",
    "iPad14,10": "iPad Air 13寸 (M2)",
    "iPad14,11": "iPad Air 13寸 (M2)",
    "iPad16,1": "iPad mini (A17 Pro)",
    "iPad16,2": "iPad mini (A17 Pro)",
    "iPad16,3": "iPad Pro 11寸 (M4)",
    "iPad16,4": "iPad Pro 11寸 (M4)",
    "iPad16,5": "iPad Pro 13寸 (M4)",
    "iPad16,6": "iPad Pro 13寸 (M4)",
}

HARDWARE_LEVEL_LABELS = {
    "onsite_witness": "现场身份亲签",
    "post_archived": "事后归档确认",
}

LOCATION_STATUS_LABELS = {
    "captured": "已采集",
    "unavailable": "不可用",
    "permission_denied": "权限拒绝",
    "timed_out": "超时",
    "failed": "采集失败",
}

LOCATION_CONFIDENCE_LABELS = {
    "high": "高",
    "medium": "中",
    "low": "低",
    "untrusted": "不可信",
    "unavailable": "不可用",
}

LOCATION_RISK_FLAG_LABELS = {
    "simulated_by_software": "软件模拟定位",
    "external_accessory": "外接定位源",
    "low_accuracy": "定位精度较低",
    "stale_sample": "定位样本过旧",
    "speed_anomaly": "速度异常",
    "device_compromised": "设备安全状态异常",
    "location_services_disabled": "系统定位服务已关闭",
    "location_permission_denied": "定位权限被拒绝",
    "location_permission_not_determined": "定位权限未确定",
    "location_authorization_unknown": "定位授权状态未知",
    "location_request_already_active": "定位请求重复触发",
    "location_timeout": "定位超时",
    "timeout_fallback_cached": "超时后回退到缓存定位",
    "prewarm_cache_hit": "命中预热定位缓存",
    "location_not_available": "暂未获得可用定位",
    "location_request_failed": "定位请求失败",
    "invalid_accuracy": "定位精度数据异常",
}


def parse_bool_env(name: str, default: bool) -> bool:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default

    normalized = raw_value.strip().lower()
    if normalized in ("1", "true", "yes", "on"):
        return True
    if normalized in ("0", "false", "no", "off"):
        return False
    print(f"⚠️ 环境变量 {name}={raw_value!r} 无法识别，使用默认值 {default}")
    return default


def get_runtime_tsa_policy() -> Tuple[bool, bool]:
    require_eku = parse_bool_env(REQUIRE_TSA_EKU_ENV, True)
    allow_sha1 = parse_bool_env(ALLOW_TSA_SHA1_ENV, False)
    return require_eku, allow_sha1


def normalize_relative_backup_path(relative_path: Any) -> Tuple[Optional[str], Optional[str]]:
    if not isinstance(relative_path, str):
        return None, "relativeFilePath 类型异常"

    normalized = relative_path.strip().replace("\\", "/")
    if not normalized:
        return None, "relativeFilePath 为空"
    if normalized.startswith("/") or normalized.startswith("~"):
        return None, f"relativeFilePath 非法（绝对路径）: {relative_path}"

    path_parts = [part for part in normalized.split("/") if part]
    if any(part == ".." for part in path_parts):
        return None, f"relativeFilePath 存在路径穿越片段: {relative_path}"

    candidate = os.path.normpath("/".join(path_parts))
    if candidate in ("", ".", "..") or candidate.startswith("../"):
        return None, f"relativeFilePath 非法: {relative_path}"
    return candidate, None


def resolve_file_in_backup(files_root: str, relative_path: Any) -> Tuple[Optional[str], Optional[str]]:
    normalized_rel, rel_err = normalize_relative_backup_path(relative_path)
    if normalized_rel is None:
        return None, rel_err

    root_abs = os.path.abspath(files_root)
    root_real = os.path.realpath(root_abs)
    candidate_abs = os.path.abspath(os.path.join(root_abs, normalized_rel))
    candidate_real = os.path.realpath(candidate_abs)

    if os.path.commonpath([root_abs, candidate_abs]) != root_abs:
        return None, f"relativeFilePath 越界: {relative_path}"
    if os.path.commonpath([root_real, candidate_real]) != root_real:
        return None, f"relativeFilePath 解析后越界(可能为符号链接): {relative_path}"
    return candidate_real, None


def _hashlib_name_from_digest_oid(oid: str, allow_sha1: bool) -> Optional[str]:
    if oid == DIGEST_OID_SHA256:
        return "sha256"
    if oid == DIGEST_OID_SHA384:
        return "sha384"
    if oid == DIGEST_OID_SHA512:
        return "sha512"
    if oid == DIGEST_OID_SHA1 and allow_sha1:
        return "sha1"
    return None


def _hash_algorithm_from_digest_oid(oid: str, allow_sha1: bool) -> Optional[hashes.HashAlgorithm]:
    if oid == DIGEST_OID_SHA256:
        return hashes.SHA256()
    if oid == DIGEST_OID_SHA384:
        return hashes.SHA384()
    if oid == DIGEST_OID_SHA512:
        return hashes.SHA512()
    if oid == DIGEST_OID_SHA1 and allow_sha1:
        return hashes.SHA1()
    return None


def _digest_bytes(data: bytes, digest_oid: str, allow_sha1: bool) -> Optional[bytes]:
    hashlib_name = _hashlib_name_from_digest_oid(digest_oid, allow_sha1)
    if hashlib_name is None:
        return None
    return hashlib.new(hashlib_name, data).digest()


def _read_certificates_from_pem_bundle(pem_data: bytes) -> List[crypto_x509.Certificate]:
    pattern = re.compile(
        br"-----BEGIN CERTIFICATE-----\s+.*?-----END CERTIFICATE-----",
        re.DOTALL,
    )
    blocks = pattern.findall(pem_data)
    if not blocks:
        return []

    certs: List[crypto_x509.Certificate] = []
    skipped = 0
    for block in blocks:
        pem_block = block if block.endswith(b"\n") else block + b"\n"
        try:
            # Future cryptography versions may reject deprecated serial formats.
            with warnings.catch_warnings():
                warnings.filterwarnings(
                    "error",
                    category=CryptographyDeprecationWarning,
                    message=r".*serial number which wasn't positive.*",
                )
                cert = crypto_x509.load_pem_x509_certificate(pem_block)
            certs.append(cert)
        except Exception:
            skipped += 1
            continue

    if skipped > 0:
        print(f"⚠️ 根证书加载时跳过 {skipped} 张不兼容证书（序列号/格式问题）")
    return certs


def _load_trust_roots_from_env_bundle() -> Tuple[List[crypto_x509.Certificate], Optional[str]]:
    custom_bundle = os.getenv(TRUST_STORE_ENV)
    if not custom_bundle:
        return [], None
    if not os.path.isfile(custom_bundle):
        return [], f"{TRUST_STORE_ENV} 指向的文件不存在: {custom_bundle}"

    try:
        with open(custom_bundle, "rb") as cert_file:
            raw = cert_file.read()
        if b"-----BEGIN CERTIFICATE-----" in raw:
            certs = _read_certificates_from_pem_bundle(raw)
            return certs, None if certs else f"{TRUST_STORE_ENV} 未包含可解析证书"
        cert = crypto_x509.load_der_x509_certificate(raw)
        return [cert], None
    except Exception as exc:
        return [], f"加载 {TRUST_STORE_ENV} 失败: {exc}"


def _load_trust_roots_from_certifi() -> Tuple[List[crypto_x509.Certificate], Optional[str]]:
    try:
        import certifi
    except Exception:
        return [], None

    try:
        with open(certifi.where(), "rb") as cert_file:
            certs = _read_certificates_from_pem_bundle(cert_file.read())
        return certs, None if certs else "certifi 证书包为空"
    except Exception as exc:
        return [], f"certifi 证书包加载失败: {exc}"


def _load_trust_roots_from_macos_keychain() -> Tuple[List[crypto_x509.Certificate], Optional[str]]:
    if sys.platform != "darwin":
        return [], None

    command = [
        "security",
        "find-certificate",
        "-a",
        "-p",
        "/System/Library/Keychains/SystemRootCertificates.keychain",
    ]
    try:
        result = subprocess.run(command, capture_output=True, check=True)
        certs = _read_certificates_from_pem_bundle(result.stdout)
        return certs, None if certs else "macOS 系统根证书为空"
    except Exception as exc:
        return [], f"macOS 系统根证书加载失败: {exc}"


def _load_trust_roots_from_ssl() -> Tuple[List[crypto_x509.Certificate], Optional[str]]:
    try:
        ctx = ssl.create_default_context()
        der_certs = ctx.get_ca_certs(binary_form=True)
        certs = [crypto_x509.load_der_x509_certificate(raw) for raw in der_certs]
        return certs, None if certs else "ssl default context 未提供根证书"
    except Exception as exc:
        return [], f"ssl 根证书加载失败: {exc}"


def get_trust_roots() -> Tuple[Optional[List[crypto_x509.Certificate]], Optional[str], Optional[str]]:
    global _TRUST_ROOTS_CACHE, _TRUST_STORE_SOURCE, _TRUST_STORE_ERROR
    if _TRUST_ROOTS_CACHE is not None:
        return _TRUST_ROOTS_CACHE, _TRUST_STORE_SOURCE, None
    if _TRUST_STORE_ERROR is not None:
        return None, None, _TRUST_STORE_ERROR

    loaders = [
        ("环境变量 CA Bundle", _load_trust_roots_from_env_bundle),
        ("certifi", _load_trust_roots_from_certifi),
        ("macOS 系统根证书", _load_trust_roots_from_macos_keychain),
        ("ssl 默认根证书", _load_trust_roots_from_ssl),
    ]
    loader_errors: List[str] = []

    for source, loader in loaders:
        certs, err = loader()
        if certs:
            _TRUST_ROOTS_CACHE = certs
            _TRUST_STORE_SOURCE = source
            return _TRUST_ROOTS_CACHE, _TRUST_STORE_SOURCE, None
        elif err:
            loader_errors.append(f"{source}: {err}")

    _TRUST_STORE_ERROR = "无法加载任何受信任根证书。请设置 VERITRAIL_CA_BUNDLE 指向 PEM/DER 根证书包。"
    if loader_errors:
        _TRUST_STORE_ERROR += " 细节: " + " | ".join(loader_errors)
    return None, None, _TRUST_STORE_ERROR


def calculate_file_sha256(file_path: str) -> Optional[str]:
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest().lower()
    except FileNotFoundError:
        return None


def parse_date_value(raw_value: Any) -> Optional[datetime.datetime]:
    if raw_value is None:
        return None

    if isinstance(raw_value, (int, float)):
        unix_ts = float(raw_value) + COCOA_EPOCH_OFFSET
        return datetime.datetime.fromtimestamp(unix_ts, datetime.timezone.utc)

    if isinstance(raw_value, str):
        text = raw_value.strip()
        if not text:
            return None
        try:
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            dt = datetime.datetime.fromisoformat(text)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            return dt.astimezone(datetime.timezone.utc)
        except ValueError:
            return None

    return None


def format_date(raw_value: Any) -> str:
    dt = parse_date_value(raw_value)
    if dt is None:
        return "N/A"
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def timestamp_to_hash_iso8601(raw_value: Any) -> str:
    dt = parse_date_value(raw_value)
    if dt is None:
        return "N/A"
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_entry_hash_version(raw_value: Any) -> int:
    if isinstance(raw_value, bool):
        return 1
    if isinstance(raw_value, int):
        return max(1, raw_value)
    if isinstance(raw_value, float) and raw_value.is_integer():
        return max(1, int(raw_value))
    if isinstance(raw_value, str):
        text = raw_value.strip()
        if not text:
            return 1
        try:
            return max(1, int(text))
        except ValueError:
            return 1
    return 1


def normalize_hex64(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    if re.fullmatch(r"[0-9a-f]{64}", normalized):
        return normalized
    return None


def normalize_uuid_text(value: Any) -> Optional[str]:
    if isinstance(value, uuid.UUID):
        return str(value).lower()
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    try:
        return str(uuid.UUID(text)).lower()
    except (ValueError, AttributeError):
        return None


def mask_text(value: Any, keep_head: int = 2, keep_tail: int = 2) -> str:
    if value is None:
        return "N/A"
    text = str(value)
    if text == "":
        return "(空)"
    if len(text) <= keep_head + keep_tail:
        return "*" * len(text)
    return f"{text[:keep_head]}***{text[-keep_tail:]}"


def mask_email(value: Any) -> str:
    if not isinstance(value, str) or "@" not in value:
        return mask_text(value, 1, 1)

    local, domain = value.split("@", 1)
    if not local:
        local_masked = "*"
    elif len(local) == 1:
        local_masked = "*"
    else:
        local_masked = local[0] + "***"

    domain_masked = mask_text(domain, 1, 2)
    return f"{local_masked}@{domain_masked}"


def mask_identity_token(value: Any) -> str:
    if not isinstance(value, str):
        return "N/A"
    parts = value.split(".")
    if len(parts) == 3:
        return f"{mask_text(parts[0], 4, 4)}.{mask_text(parts[1], 4, 4)}.{mask_text(parts[2], 3, 3)}"
    return mask_text(value, 8, 6)


def format_sensitive(value: Any, kind: str, reveal_pii: bool) -> str:
    if reveal_pii:
        if value is None:
            return "N/A"
        text = str(value)
        return text if text else "(空)"

    if kind == "email":
        return mask_email(value)
    if kind == "token":
        return mask_identity_token(value)
    return mask_text(value, 3, 3)


def summarize_judicial_payload(payload: Any, reveal_pii: bool) -> str:
    if not isinstance(payload, dict):
        return "N/A"

    mode_raw = payload.get("modeRaw", "N/A")
    apple_user = format_sensitive(payload.get("appleUserID"), "user", reveal_pii)
    email = format_sensitive(payload.get("email"), "email", reveal_pii)
    token = format_sensitive(payload.get("identityToken"), "token", reveal_pii)
    full_name = format_sensitive(payload.get("fullName"), "name", reveal_pii)
    attested_at = format_date(payload.get("attestedAt"))
    legal_statement = payload.get("legalStatementAccepted")

    return (
        f"mode={mode_raw}, appleUserID={apple_user}, email={email}, "
        f"fullName={full_name}, identityToken={token}, "
        f"attestedAt={attested_at}, legalStatementAccepted={legal_statement}"
    )


def format_iso8601_with_fractional(raw_value: Any) -> str:
    dt = parse_date_value(raw_value)
    if dt is None:
        return "na"
    dt_utc = dt.astimezone(datetime.timezone.utc)

    # Match Foundation ISO8601DateFormatter(.withFractionalSeconds):
    # round to nearest millisecond instead of truncating.
    rounded_ms = int((dt_utc.microsecond + 500) // 1000)
    if rounded_ms == 1000:
        dt_utc = dt_utc + datetime.timedelta(seconds=1)
        rounded_ms = 0
    dt_utc = dt_utc.replace(microsecond=rounded_ms * 1000)

    return dt_utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{rounded_ms:03d}Z"


def calculate_pre_witness_entry_hash(entry: Dict[str, Any], hash_version: int) -> Optional[str]:
    if hash_version < CURRENT_ENTRY_HASH_VERSION:
        return None

    prev_hash = entry.get(KEYS["prev_hash"])
    file_hash = entry.get(KEYS["file_hash"])
    file_name = entry.get(KEYS["file_name"])
    file_size = entry.get(KEYS["file_size"])
    iso_date = timestamp_to_hash_iso8601(entry.get(KEYS["timestamp"]))

    if not isinstance(prev_hash, str):
        return None
    if not isinstance(file_hash, str):
        return None
    if not isinstance(file_name, str):
        return None
    if iso_date == "N/A":
        return None

    location_hash = normalize_hex64(entry.get(KEYS["location_hash"])) if hash_version >= 2 else None
    if hash_version >= 2 and location_hash is None:
        return None

    return calculate_entry_hash(
        prev_hash,
        iso_date,
        file_hash,
        file_name,
        file_size,
        hash_version=hash_version,
        location_hash=location_hash if hash_version >= 2 else None,
        witness_hash=None,
    )


def format_location_decimal(value: Any, decimals: int) -> str:
    if value is None:
        return "na"

    numeric: Optional[float]
    if isinstance(value, bool):
        return "na"
    elif isinstance(value, (int, float)):
        numeric = float(value)
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            return "na"
        try:
            numeric = float(text)
        except ValueError:
            return "na"
    else:
        return "na"

    if numeric is None or not math.isfinite(numeric):
        return "na"
    return f"{numeric:.{decimals}f}"


def normalize_optional_bool(value: Any) -> Optional[bool]:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in ("1", "true", "yes", "on"):
            return True
        if normalized in ("0", "false", "no", "off"):
            return False
    return None


def location_bool_component(value: Optional[bool]) -> str:
    if value is None:
        return "na"
    return "1" if value else "0"


def parse_location_risk_flags(raw_value: Any) -> List[str]:
    if not isinstance(raw_value, str) or raw_value == "":
        return []
    return [part for part in raw_value.split(",") if part != ""]


def format_location_risk_flags(flags: List[str]) -> str:
    if not flags:
        return "无"
    translated = [LOCATION_RISK_FLAG_LABELS.get(flag, flag) for flag in sorted(set(flags))]
    return "、".join(translated)


def calculate_location_hash_from_entry(entry: Dict[str, Any]) -> Tuple[Optional[str], Optional[str], List[str], List[str]]:
    warnings: List[str] = []
    errors: List[str] = []

    status_raw = entry.get(KEYS["location_status"])
    confidence_raw = entry.get(KEYS["location_confidence"])

    if not isinstance(status_raw, str) or not status_raw:
        return None, None, warnings, errors
    if not isinstance(confidence_raw, str) or not confidence_raw:
        return None, None, warnings, errors

    status_normalized = status_raw.strip().lower()
    confidence_normalized = confidence_raw.strip().lower()

    if status_normalized not in LOCATION_STATUS_LABELS:
        warnings.append(f"locationStatus 取值未知: {status_raw}")
        status_normalized = "unavailable"
    if confidence_normalized not in LOCATION_CONFIDENCE_LABELS:
        warnings.append(f"locationConfidence 取值未知: {confidence_raw}")
        confidence_normalized = "unavailable"

    provider_raw = entry.get(KEYS["location_provider"])
    if isinstance(provider_raw, str) and provider_raw != "":
        provider = provider_raw
    else:
        if provider_raw not in (None, ""):
            warnings.append(f"locationProvider 类型异常: {provider_raw}")
        provider = "core_location"

    latitude_component = format_location_decimal(entry.get(KEYS["location_latitude"]), 7)
    longitude_component = format_location_decimal(entry.get(KEYS["location_longitude"]), 7)
    accuracy_component = format_location_decimal(entry.get(KEYS["location_accuracy_meters"]), 2)
    captured_at_component = format_iso8601_with_fractional(entry.get(KEYS["location_captured_at"]))

    simulated_value = normalize_optional_bool(entry.get(KEYS["location_is_simulated_by_software"]))
    accessory_value = normalize_optional_bool(entry.get(KEYS["location_is_produced_by_accessory"]))

    if entry.get(KEYS["location_is_simulated_by_software"]) is not None and simulated_value is None:
        warnings.append("locationIsSimulatedBySoftware 类型异常")
    if entry.get(KEYS["location_is_produced_by_accessory"]) is not None and accessory_value is None:
        warnings.append("locationIsProducedByAccessory 类型异常")

    risk_flags = parse_location_risk_flags(entry.get(KEYS["location_risk_flags"]))
    sorted_flags = ",".join(sorted(set(risk_flags)))

    canonical_payload = ";".join(
        [
            f"status={status_normalized}",
            f"lat={latitude_component}",
            f"lon={longitude_component}",
            f"acc={accuracy_component}",
            f"capturedAt={captured_at_component}",
            f"simulated={location_bool_component(simulated_value)}",
            f"accessory={location_bool_component(accessory_value)}",
            f"confidence={confidence_normalized}",
            f"provider={provider}",
            f"flags={sorted_flags}",
        ]
    )

    recalculated_hash = hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest().lower()
    return recalculated_hash, canonical_payload, warnings, errors


def calculate_entry_hash(
    prev_hash: str,
    iso_date: str,
    file_hash: str,
    file_name: str,
    file_size: Any,
    hash_version: int = 1,
    location_hash: Optional[str] = None,
    witness_hash: Optional[str] = None,
) -> str:
    normalized_version = max(1, hash_version)
    if normalized_version >= CURRENT_ENTRY_HASH_VERSION:
        location_component = location_hash or MISSING_LOCATION_HASH_COMPONENT
        witness_component = witness_hash or MISSING_WITNESS_HASH_COMPONENT
        content = (
            f"{prev_hash}|{iso_date}|{file_hash}|{file_name}|{str(file_size)}"
            f"|v{normalized_version}|{location_component}|{witness_component}"
        )
    elif normalized_version == 2:
        location_component = location_hash or MISSING_LOCATION_HASH_COMPONENT
        content = (
            f"{prev_hash}|{iso_date}|{file_hash}|{file_name}|{str(file_size)}"
            f"|v2|{location_component}"
        )
    else:
        content = f"{prev_hash}|{iso_date}|{file_hash}|{file_name}|{str(file_size)}"
    return hashlib.sha256(content.encode("utf-8")).hexdigest().lower()


def normalize_capture_source(raw_value: Any) -> Optional[str]:
    if not isinstance(raw_value, str):
        return None
    normalized = raw_value.strip().lower()
    return normalized if normalized in CAPTURE_SOURCE_LABELS else None


def compute_witness_slot_packet_hash(
    encrypted_evidence_packet: bytes,
    session_id: Optional[str],
    bound_entry_hash: Optional[str],
    mode_raw: str,
    alias_hash: Optional[str],
    app_attest_status_raw: Optional[str],
    app_attest_key_id: Optional[str],
    app_attest_verification_id: Optional[str],
    app_attest_verified_at: Any,
    transport_raw: Optional[str],
) -> str:
    payload_digest = hashlib.sha256(encrypted_evidence_packet).hexdigest().lower()
    verified_dt = parse_date_value(app_attest_verified_at)
    verified_at_epoch = str(int(verified_dt.timestamp())) if verified_dt is not None else ""

    canonical = "|".join(
        [
            f"payload={payload_digest}",
            f"sid={session_id or ''}",
            f"entry={(bound_entry_hash or '').lower()}",
            f"mode={mode_raw}",
            f"alias={alias_hash or ''}",
            f"as={app_attest_status_raw or ''}",
            f"ak={app_attest_key_id or ''}",
            f"av={app_attest_verification_id or ''}",
            f"at={verified_at_epoch}",
            f"tp={transport_raw or ''}",
        ]
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest().lower()


def decode_b64(value: Any, field_name: str) -> Tuple[Optional[bytes], Optional[str]]:
    if value is None:
        return None, f"{field_name} 缺失"
    if not isinstance(value, str):
        return None, f"{field_name} 不是字符串"

    normalized = "".join(value.split())
    if not normalized:
        return None, f"{field_name} 为空"

    try:
        return base64.b64decode(normalized, validate=True), None
    except (binascii.Error, ValueError):
        return None, f"{field_name} Base64 非法（严格模式）"


def signature_to_der(signature_data: bytes) -> Tuple[Optional[bytes], Optional[str]]:
    if len(signature_data) == 64:
        r = int.from_bytes(signature_data[:32], "big")
        s = int.from_bytes(signature_data[32:], "big")
        return encode_dss_signature(r, s), None

    if len(signature_data) > 8 and signature_data[0] == 0x30:
        return signature_data, None

    return None, f"签名大小/格式异常: {len(signature_data)} 字节"


def build_p256_candidate_keys(public_key_data: bytes) -> Tuple[List[ec.EllipticCurvePublicKey], Optional[str]]:
    candidates: List[ec.EllipticCurvePublicKey] = []

    # secp256r1 params
    p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
    b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

    if len(public_key_data) == 65 and public_key_data[0] == 0x04:
        try:
            key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key_data)
            return [key], None
        except ValueError as exc:
            return [], f"未压缩公钥解析失败: {exc}"

    if len(public_key_data) == 33:
        prefix = public_key_data[0]
        if prefix not in (0x02, 0x03):
            return [], f"压缩公钥前缀错误: 0x{prefix:02x}"

        x = int.from_bytes(public_key_data[1:], "big")
        y_squared = (pow(x, 3, p) + a * x + b) % p
        y = pow(y_squared, (p + 1) // 4, p)
        y_is_even = (y % 2 == 0)
        if (prefix == 0x02 and not y_is_even) or (prefix == 0x03 and y_is_even):
            y = p - y

        x_bytes = x.to_bytes(32, "big")
        y_bytes = y.to_bytes(32, "big")
        uncompressed = b"\x04" + x_bytes + y_bytes
        try:
            key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), uncompressed)
            return [key], None
        except ValueError as exc:
            return [], f"压缩公钥恢复失败: {exc}"

    if len(public_key_data) == 32:
        x = int.from_bytes(public_key_data, "big")
        y_squared = (pow(x, 3, p) + a * x + b) % p
        y = pow(y_squared, (p + 1) // 4, p)

        x_bytes = x.to_bytes(32, "big")
        for y_candidate in (y, p - y):
            try:
                y_bytes = y_candidate.to_bytes(32, "big")
                uncompressed = b"\x04" + x_bytes + y_bytes
                key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), uncompressed)
                candidates.append(key)
            except ValueError:
                continue

        if candidates:
            return candidates, None
        return [], "32 字节紧凑公钥恢复失败"

    return [], f"公钥长度不受支持: {len(public_key_data)} 字节"


def verify_ecdsa_signature_bytes(signature_data: bytes, public_key_data: bytes, message: bytes) -> Tuple[bool, str]:
    der_signature, sig_err = signature_to_der(signature_data)
    if der_signature is None:
        return False, sig_err or "签名格式无效"

    keys, key_err = build_p256_candidate_keys(public_key_data)
    if not keys:
        return False, key_err or "公钥无效"

    for key in keys:
        try:
            key.verify(der_signature, message, ec.ECDSA(hashes.SHA256()))
            return True, "签名验证通过"
        except InvalidSignature:
            continue
        except Exception as exc:
            return False, f"签名验证异常: {exc}"

    return False, "签名无效"


def verify_ecdsa_signature_b64(signature_b64: Any, public_key_b64: Any, message: bytes, label: str) -> Tuple[bool, str]:
    signature_data, sig_err = decode_b64(signature_b64, f"{label}签名")
    if signature_data is None:
        return False, sig_err or f"{label}签名缺失"

    public_key_data, pub_err = decode_b64(public_key_b64, f"{label}公钥")
    if public_key_data is None:
        return False, pub_err or f"{label}公钥缺失"

    return verify_ecdsa_signature_bytes(signature_data, public_key_data, message)


def verify_signature_with_certificate(
    signature_data: bytes, cert: crypto_x509.Certificate, message: bytes
) -> Tuple[bool, str]:
    der_signature, sig_err = signature_to_der(signature_data)
    if der_signature is None:
        return False, sig_err or "签名格式无效"

    public_key = cert.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        return False, "证书公钥不是 EC 类型"

    try:
        public_key.verify(der_signature, message, ec.ECDSA(hashes.SHA256()))
        return True, "证书验签通过"
    except InvalidSignature:
        return False, "证书验签失败"
    except Exception as exc:
        return False, f"证书验签异常: {exc}"


def compressed_p256_pubkey_from_cert(cert: crypto_x509.Certificate) -> Optional[bytes]:
    key = cert.public_key()
    if not isinstance(key, ec.EllipticCurvePublicKey):
        return None

    numbers = key.public_numbers()
    x = numbers.x.to_bytes(32, "big")
    prefix = b"\x02" if numbers.y % 2 == 0 else b"\x03"
    return prefix + x


def compare_public_key_with_certificate(public_key_data: bytes, cert: crypto_x509.Certificate) -> Optional[bool]:
    cert_compressed = compressed_p256_pubkey_from_cert(cert)
    if cert_compressed is None:
        return None

    if len(public_key_data) == 33:
        return cert_compressed == public_key_data

    if len(public_key_data) == 32:
        return cert_compressed[1:] == public_key_data

    if len(public_key_data) == 65 and public_key_data[0] == 0x04:
        x = public_key_data[1:33]
        y_last = public_key_data[64]
        expected_prefix = b"\x02" if y_last % 2 == 0 else b"\x03"
        return cert_compressed == expected_prefix + x

    return None


def _resolve_signature_profile(
    signature_oid: str, digest_oid: str, allow_sha1: bool
) -> Tuple[Optional[str], Optional[hashes.HashAlgorithm], Optional[str]]:
    if signature_oid in (RSA_WITH_SHA256_OID,):
        return "rsa", hashes.SHA256(), None
    if signature_oid in (RSA_WITH_SHA384_OID,):
        return "rsa", hashes.SHA384(), None
    if signature_oid in (RSA_WITH_SHA512_OID,):
        return "rsa", hashes.SHA512(), None
    if signature_oid in (RSA_WITH_SHA1_OID,):
        if allow_sha1:
            return "rsa", hashes.SHA1(), None
        return None, None, "TSA 使用 SHA-1（已按策略拒绝）"

    if signature_oid in (ECDSA_WITH_SHA256_OID,):
        return "ecdsa", hashes.SHA256(), None
    if signature_oid in (ECDSA_WITH_SHA384_OID,):
        return "ecdsa", hashes.SHA384(), None
    if signature_oid in (ECDSA_WITH_SHA512_OID,):
        return "ecdsa", hashes.SHA512(), None
    if signature_oid in (ECDSA_WITH_SHA1_OID,):
        if allow_sha1:
            return "ecdsa", hashes.SHA1(), None
        return None, None, "TSA 使用 ECDSA-SHA1（已按策略拒绝）"

    if signature_oid in (RSA_ENCRYPTION_OID,):
        hash_algorithm = _hash_algorithm_from_digest_oid(digest_oid, allow_sha1)
        if hash_algorithm is None:
            return None, None, f"不支持的 digestAlgorithm OID: {digest_oid}"
        return "rsa", hash_algorithm, None

    return None, None, f"不支持的 signatureAlgorithm OID: {signature_oid}"


def _signed_attrs_der_for_signature(signer_info: Any) -> Tuple[Optional[bytes], Optional[str]]:
    signed_attrs = signer_info["signed_attrs"]
    if signed_attrs is None:
        return None, "SignerInfo 缺少 signed_attrs"

    der = signed_attrs.dump()
    if not der:
        return None, "SignerInfo signed_attrs 为空"

    if der[0] == 0xA0:
        return b"\x31" + der[1:], None
    if der[0] == 0x31:
        return der, None
    return None, "SignerInfo signed_attrs DER 标签异常"


def _extract_signer_message_digest(signer_info: Any) -> Tuple[Optional[bytes], Optional[str]]:
    signed_attrs = signer_info["signed_attrs"]
    if signed_attrs is None:
        return None, "SignerInfo 缺少 signed_attrs"

    for attr in signed_attrs:
        attr_oid = attr["type"].dotted
        if attr_oid != "1.2.840.113549.1.9.4":  # messageDigest
            continue
        values = attr["values"]
        if len(values) != 1:
            return None, "messageDigest 属性值数量异常"
        digest_value = values[0].native
        if not isinstance(digest_value, bytes):
            return None, "messageDigest 属性类型异常"
        return digest_value, None

    return None, "SignerInfo 缺少 messageDigest 属性"


def _select_signer_certificate(
    signer_info: Any, cert_pairs: List[Tuple[Any, crypto_x509.Certificate]]
) -> Tuple[Optional[crypto_x509.Certificate], Optional[str]]:
    sid = signer_info["sid"]
    if sid.name == "issuer_and_serial_number":
        sid_value = sid.chosen
        sid_issuer_der = sid_value["issuer"].dump()
        sid_serial = sid_value["serial_number"].native
        for cert_asn1, cert_obj in cert_pairs:
            if cert_asn1.issuer.dump() == sid_issuer_der and cert_asn1.serial_number == sid_serial:
                return cert_obj, None
        return None, "未找到与 SignerInfo sid 匹配的证书 (issuer+serial)"

    if sid.name == "subject_key_identifier":
        sid_ski = sid.chosen.native
        for _, cert_obj in cert_pairs:
            try:
                cert_ski = cert_obj.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_KEY_IDENTIFIER
                ).value.digest
                if cert_ski == sid_ski:
                    return cert_obj, None
            except Exception:
                continue
        return None, "未找到与 SignerInfo sid 匹配的证书 (subjectKeyIdentifier)"

    return None, f"不支持的 SignerIdentifier 类型: {sid.name}"


def _verify_signer_signature(
    signer_info: Any, signer_cert: crypto_x509.Certificate, econtent_bytes: bytes, allow_sha1: bool
) -> Tuple[bool, str]:
    digest_oid = signer_info["digest_algorithm"]["algorithm"].dotted
    signature_oid = signer_info["signature_algorithm"]["algorithm"].dotted

    computed_digest = _digest_bytes(econtent_bytes, digest_oid, allow_sha1)
    if computed_digest is None:
        return False, f"不支持的 digestAlgorithm OID: {digest_oid}"

    signed_attr_digest, digest_err = _extract_signer_message_digest(signer_info)
    if signed_attr_digest is None:
        return False, digest_err or "messageDigest 属性缺失"
    if signed_attr_digest != computed_digest:
        return False, "SignerInfo messageDigest 与 TSTInfo 内容哈希不一致"

    signed_attrs_der, attrs_err = _signed_attrs_der_for_signature(signer_info)
    if signed_attrs_der is None:
        return False, attrs_err or "signed_attrs 无法用于验签"

    signature_bytes = signer_info["signature"].native
    if not isinstance(signature_bytes, bytes):
        return False, "SignerInfo signature 类型异常"

    profile, hash_algorithm, profile_err = _resolve_signature_profile(
        signature_oid, digest_oid, allow_sha1
    )
    if profile is None or hash_algorithm is None:
        return False, profile_err or "无法解析签名算法"

    public_key = signer_cert.public_key()
    try:
        if profile == "rsa":
            public_key.verify(signature_bytes, signed_attrs_der, asym_padding.PKCS1v15(), hash_algorithm)
        elif profile == "ecdsa":
            public_key.verify(signature_bytes, signed_attrs_der, ec.ECDSA(hash_algorithm))
        else:
            return False, f"不支持的签名类型: {profile}"
    except InvalidSignature:
        return False, "CMS 签名验证失败"
    except Exception as exc:
        return False, f"CMS 签名验证异常: {exc}"

    return True, "CMS 签名验证通过"


def _verify_signer_certificate_trust(
    signer_cert: crypto_x509.Certificate,
    all_certs: List[crypto_x509.Certificate],
    validation_time: datetime.datetime,
) -> Tuple[bool, str]:
    trust_roots, trust_source, trust_err = get_trust_roots()
    if trust_roots is None:
        return False, trust_err or "未加载信任根证书"

    signer_fingerprint = signer_cert.fingerprint(hashes.SHA256())
    intermediates = [
        cert for cert in all_certs if cert.fingerprint(hashes.SHA256()) != signer_fingerprint
    ]

    # 优先使用 openssl verify，行为更贴近 iOS SecPolicyCreateBasicX509（不附带 TLS EKU 约束）
    with tempfile.TemporaryDirectory(prefix="veritrail-trust-") as temp_dir:
        signer_path = os.path.join(temp_dir, "signer.pem")
        roots_path = os.path.join(temp_dir, "roots.pem")
        intermediates_path = os.path.join(temp_dir, "intermediates.pem")

        with open(signer_path, "wb") as signer_file:
            signer_file.write(signer_cert.public_bytes(Encoding.PEM))
        with open(roots_path, "wb") as roots_file:
            for cert in trust_roots:
                roots_file.write(cert.public_bytes(Encoding.PEM))
        with open(intermediates_path, "wb") as interm_file:
            for cert in intermediates:
                interm_file.write(cert.public_bytes(Encoding.PEM))

        verify_cmd = ["openssl", "verify", "-purpose", "any", "-CAfile", roots_path]
        verify_cmd.extend(["-attime", str(int(validation_time.timestamp()))])
        if intermediates:
            verify_cmd.extend(["-untrusted", intermediates_path])
        verify_cmd.append(signer_path)

        try:
            openssl_result = subprocess.run(verify_cmd, capture_output=True, text=True)
            if openssl_result.returncode == 0:
                source_text = trust_source or "unknown trust source"
                return True, f"证书链验证通过 ({source_text}, openssl verify)"

            openssl_error = (openssl_result.stderr or openssl_result.stdout or "").strip()
            if not openssl_error:
                openssl_error = f"openssl verify 返回码 {openssl_result.returncode}"
            return False, f"证书链验证失败: {openssl_error}"
        except FileNotFoundError:
            pass
        except Exception as exc:
            return False, f"证书链验证异常(openssl): {exc}"

    # 回退到 cryptography verifier（当系统无 openssl 时）
    try:
        trust_store = Store(trust_roots)
        verifier = (
            PolicyBuilder()
            .store(trust_store)
            .time(validation_time)
            .max_chain_depth(10)
            .build_client_verifier()
        )
        verifier.verify(signer_cert, intermediates)
        source_text = trust_source or "unknown trust source"
        return True, f"证书链验证通过 ({source_text}, cryptography fallback)"
    except VerificationError as exc:
        return False, f"证书链验证失败: {exc}"
    except Exception as exc:
        return False, f"证书链验证异常: {exc}"


def _signer_has_timestamping_eku(signer_cert: crypto_x509.Certificate) -> bool:
    try:
        eku_values = signer_cert.extensions.get_extension_for_oid(
            ExtensionOID.EXTENDED_KEY_USAGE
        ).value
        return any(oid.dotted_string == TSA_TIMESTAMPING_EKU_OID for oid in eku_values)
    except Exception:
        return False


def _normalize_expected_nonce(expected_nonce: Any) -> Tuple[Optional[int], Optional[str]]:
    if expected_nonce is None:
        return None, None
    if isinstance(expected_nonce, int):
        return expected_nonce, None
    try:
        return int(str(expected_nonce).strip()), None
    except Exception:
        return None, f"timestampNonce 类型异常: {expected_nonce}"


def verify_tsa_token(
    token_b64: Any,
    expected_entry_hash_hex: str,
    expected_nonce: Any,
    require_eku: bool,
    allow_sha1: bool,
) -> Tuple[bool, str]:
    token_data, decode_err = decode_b64(token_b64, "timestampToken")
    if token_data is None:
        return False, decode_err or "时间戳令牌缺失"

    try:
        expected_hash_bytes = bytes.fromhex(expected_entry_hash_hex)
    except Exception:
        return False, f"entryHash 不是有效十六进制: {expected_entry_hash_hex}"

    normalized_nonce, nonce_err = _normalize_expected_nonce(expected_nonce)
    if nonce_err:
        return False, nonce_err

    try:
        ts_resp = tsp.TimeStampResp.load(token_data)
    except Exception as exc:
        return False, f"TSA 响应 ASN.1 解析失败: {exc}"

    try:
        status_native = ts_resp["status"]["status"].native
    except Exception as exc:
        return False, f"TSA 状态字段异常: {exc}"
    if status_native not in ("granted", "granted_with_mods"):
        return False, f"TSA 状态未授权: {status_native}"

    cms_content_info = ts_resp["time_stamp_token"]
    if cms_content_info is None:
        return False, "TSA 响应缺少 time_stamp_token"
    if cms_content_info["content_type"].native != "signed_data":
        return False, "TSA token 不是 SignedData"

    signed_data = cms_content_info["content"]
    encap_content_info = signed_data["encap_content_info"]
    if encap_content_info["content_type"].native != "tst_info":
        return False, "SignedData 封装内容不是 TSTInfo"

    econtent = encap_content_info["content"]
    econtent_native = econtent.native

    econtent_bytes: Optional[bytes] = None
    if isinstance(econtent_native, bytes):
        econtent_bytes = econtent_native
    else:
        try:
            econtent_contents = econtent.contents
            if isinstance(econtent_contents, bytes):
                econtent_bytes = econtent_contents
        except Exception:
            econtent_bytes = None

    if not isinstance(econtent_bytes, bytes):
        return False, "TSTInfo 内容类型异常"

    try:
        parsed_tst = getattr(econtent, "parsed", None)
        if parsed_tst is not None:
            tst_info = parsed_tst
        else:
            tst_info = tsp.TSTInfo.load(econtent_bytes)
    except Exception:
        try:
            tst_info = tsp.TSTInfo.load(econtent_bytes)
        except Exception as exc:
            return False, f"TSTInfo 解析失败: {exc}"

    hashed_message = tst_info["message_imprint"]["hashed_message"].native
    if hashed_message != expected_hash_bytes:
        return (
            False,
            f"哈希不匹配! TSA中为: {hashed_message.hex()}, 期望: {expected_entry_hash_hex}",
        )

    tsa_nonce = tst_info["nonce"].native if tst_info["nonce"].native is not None else None
    if normalized_nonce is not None and tsa_nonce != normalized_nonce:
        return False, f"Nonce 不匹配! TSA中为: {tsa_nonce}, 记录为: {normalized_nonce}"

    gen_time = tst_info["gen_time"].native
    if not isinstance(gen_time, datetime.datetime):
        return False, "TSA gen_time 类型异常"
    if gen_time.tzinfo is None:
        gen_time = gen_time.replace(tzinfo=datetime.timezone.utc)
    validation_time = gen_time.astimezone(datetime.timezone.utc)

    cert_pairs: List[Tuple[Any, crypto_x509.Certificate]] = []
    certificates = signed_data["certificates"]
    if certificates:
        for cert_choice in certificates:
            if cert_choice.name != "certificate":
                continue
            try:
                cert_asn1 = cert_choice.chosen
                cert_obj = crypto_x509.load_der_x509_certificate(cert_asn1.dump())
                cert_pairs.append((cert_asn1, cert_obj))
            except Exception:
                continue

    if not cert_pairs:
        return False, "SignedData 未携带可用证书"

    signer_infos = signed_data["signer_infos"]
    if not signer_infos:
        return False, "SignedData 缺少 signerInfos"

    signer_errors: List[str] = []
    for signer_info in signer_infos:
        signer_cert, signer_err = _select_signer_certificate(signer_info, cert_pairs)
        if signer_cert is None:
            signer_errors.append(signer_err or "SignerInfo 未匹配到证书")
            continue

        signature_ok, signature_msg = _verify_signer_signature(
            signer_info, signer_cert, econtent_bytes, allow_sha1
        )
        if not signature_ok:
            signer_errors.append(signature_msg)
            continue

        trust_ok, trust_msg = _verify_signer_certificate_trust(
            signer_cert, [cert for _, cert in cert_pairs], validation_time
        )
        if not trust_ok:
            signer_errors.append(trust_msg)
            continue

        if require_eku and not _signer_has_timestamping_eku(signer_cert):
            signer_errors.append("签名者证书缺少 id-kp-timeStamping EKU")
            continue

        return True, f"TSA 校验通过 (时间: {validation_time.isoformat()}, {signature_msg}; {trust_msg})"

    return False, "TSA 签名校验失败: " + "; ".join(signer_errors)


def _resolve_device_model_name(model_name: Any, model_code: Any) -> str:
    code = model_code.strip() if isinstance(model_code, str) else ""
    mapped = DEVICE_MODEL_CODE_LABELS.get(code) if code else None

    if isinstance(model_name, str):
        name = model_name.strip()
        if name:
            if mapped and code:
                generic_names = {
                    code,
                    f"iPhone ({code})",
                    f"iPad ({code})",
                    f"iPod touch ({code})",
                    f"Apple Watch ({code})",
                }
                if name in generic_names:
                    return mapped
            return name

    if mapped:
        return mapped
    if code:
        return code
    return "Unknown Device"


def inspect_device_metadata(entry: Dict[str, Any]) -> Tuple[Optional[str], List[str]]:
    warnings: List[str] = []

    model_name = entry.get(KEYS["device_model_name"])
    model_code = entry.get(KEYS["device_model_code"])
    system_version = entry.get(KEYS["device_system_version"])
    fingerprint_id = entry.get(KEYS["device_fingerprint_id"])
    signature_mode = entry.get(KEYS["device_signature_mode"])

    has_any = any(
        value is not None
        for value in (model_name, model_code, system_version, fingerprint_id, signature_mode)
    )
    if not has_any:
        return None, warnings

    if signature_mode not in DEVICE_SIGNATURE_MODE_LABELS:
        warnings.append(f"设备签名模式异常: {signature_mode}")
    protection = DEVICE_SIGNATURE_MODE_LABELS.get(signature_mode, str(signature_mode))

    model_text = _resolve_device_model_name(model_name, model_code)
    version_text = f"iOS {system_version}" if system_version else "iOS N/A"
    summary = f"{model_text} • {version_text} • {protection}"

    if fingerprint_id:
        try:
            uuid.UUID(str(fingerprint_id))
        except Exception:
            warnings.append(f"设备指纹ID格式异常: {fingerprint_id}")
    else:
        warnings.append("缺少设备指纹ID (deviceFingerprintID)")

    return summary, warnings


def normalize_app_attest_status(raw_value: Any) -> Optional[str]:
    if not isinstance(raw_value, str):
        return None
    normalized = raw_value.strip().lower()
    if normalized in APP_ATTEST_STATUS_LABELS:
        return normalized
    return None


def inspect_app_attest_metadata(entry: Dict[str, Any]) -> Tuple[Optional[str], List[str]]:
    warnings: List[str] = []

    status_raw = entry.get(KEYS["app_attest_status"])
    key_id = entry.get(KEYS["app_attest_key_id"])
    verification_id = entry.get(KEYS["app_attest_verification_id"])
    verified_at = entry.get(KEYS["app_attest_verified_at"])
    server_url = entry.get(KEYS["app_attest_server_url"])
    error_message = entry.get(KEYS["app_attest_error"])

    has_any = any(
        value is not None
        for value in (status_raw, key_id, verification_id, verified_at, server_url, error_message)
    )
    if not has_any:
        return None, warnings

    status = normalize_app_attest_status(status_raw)
    if status is None:
        if status_raw is None:
            status_text = "状态未记录"
            warnings.append("缺少 App Attest 状态 (appAttestStatus)")
        else:
            status_text = f"状态异常: {status_raw}"
            warnings.append(f"App Attest 状态异常: {status_raw}")
    else:
        status_text = APP_ATTEST_STATUS_LABELS[status]

    parts: List[str] = [status_text]

    key_id_text = None
    if key_id is not None:
        if isinstance(key_id, str) and key_id.strip():
            key_id_text = key_id.strip()
            parts.append(f"keyID={key_id_text}")
        else:
            warnings.append("appAttestKeyID 类型或内容异常")

    verification_id_text = None
    if verification_id is not None:
        if isinstance(verification_id, str) and verification_id.strip():
            verification_id_text = verification_id.strip()
            parts.append(f"verificationID={verification_id_text}")
        else:
            warnings.append("appAttestVerificationID 类型或内容异常")

    verified_dt = parse_date_value(verified_at)
    if verified_at is not None:
        if verified_dt is None:
            warnings.append(f"appAttestVerifiedAt 格式异常: {verified_at}")
        else:
            parts.append(f"verifiedAt={format_date(verified_at)}")

    server_url_text = None
    if server_url is not None:
        if isinstance(server_url, str) and server_url.strip():
            server_url_text = server_url.strip()
            parts.append(f"server={server_url_text}")
            if not server_url_text.startswith("https://"):
                warnings.append(f"App Attest 服务地址不是 HTTPS: {server_url_text}")
        else:
            warnings.append("appAttestServerURL 类型或内容异常")

    error_text = None
    if error_message is not None:
        if isinstance(error_message, str) and error_message.strip():
            error_text = error_message.strip()
            parts.append(f"error={error_text}")
        else:
            warnings.append("appAttestError 类型或内容异常")

    if status == "verified":
        if key_id_text is None:
            warnings.append("App Attest 状态为 verified，但缺少 appAttestKeyID")
        if verification_id_text is None:
            warnings.append("App Attest 状态为 verified，但缺少 appAttestVerificationID")
        if verified_dt is None:
            warnings.append("App Attest 状态为 verified，但缺少或无法解析 appAttestVerifiedAt")
        if error_text is not None:
            warnings.append("App Attest 状态为 verified，但同时记录了 appAttestError")

    if status == "failed" and error_text is None:
        warnings.append("App Attest 状态为 failed，但缺少 appAttestError")

    if status in ("disabled", "unsupported", "not_attempted"):
        if verification_id_text is not None or verified_dt is not None:
            warnings.append("App Attest 状态与回执字段不一致（含 verificationID/verifiedAt）")

    if status in ("verified", "pending", "failed") and server_url_text is None:
        warnings.append("缺少 App Attest 服务地址 (appAttestServerURL)")

    summary = " • ".join(parts)
    return summary, warnings


def inspect_location_metadata(entry: Dict[str, Any], hash_version: int) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "present": False,
        "lines": [],
        "warnings": [],
        "errors": [],
        "recorded_hash": None,
        "recalculated_hash": None,
    }

    location_fields = (
        KEYS["location_hash"],
        KEYS["location_status"],
        KEYS["location_confidence"],
        KEYS["location_risk_flags"],
        KEYS["location_latitude"],
        KEYS["location_longitude"],
        KEYS["location_accuracy_meters"],
        KEYS["location_captured_at"],
        KEYS["location_provider"],
        KEYS["location_is_simulated_by_software"],
        KEYS["location_is_produced_by_accessory"],
    )
    result["present"] = any(entry.get(field) is not None for field in location_fields)

    recorded_location_hash = normalize_hex64(entry.get(KEYS["location_hash"]))
    raw_recorded_location_hash = entry.get(KEYS["location_hash"])
    if raw_recorded_location_hash is not None and recorded_location_hash is None:
        result["errors"].append("locationHash 不是有效 64 位十六进制")
    result["recorded_hash"] = recorded_location_hash

    status_raw = entry.get(KEYS["location_status"])
    confidence_raw = entry.get(KEYS["location_confidence"])
    status_normalized = status_raw.strip().lower() if isinstance(status_raw, str) else None
    confidence_normalized = confidence_raw.strip().lower() if isinstance(confidence_raw, str) else None

    if hash_version >= 2:
        if recorded_location_hash is None:
            result["errors"].append("entryHashVersion>=2 但缺少有效 locationHash")
        if not isinstance(status_raw, str) or not status_raw:
            result["errors"].append("entryHashVersion>=2 但缺少 locationStatus")
        if not isinstance(confidence_raw, str) or not confidence_raw:
            result["errors"].append("entryHashVersion>=2 但缺少 locationConfidence")

    if status_normalized:
        status_label = LOCATION_STATUS_LABELS.get(status_normalized, status_normalized)
    else:
        status_label = "未记录"
    if confidence_normalized:
        confidence_label = LOCATION_CONFIDENCE_LABELS.get(confidence_normalized, confidence_normalized)
    else:
        confidence_label = "未记录"

    provider = entry.get(KEYS["location_provider"]) or "core_location"
    latitude = entry.get(KEYS["location_latitude"])
    longitude = entry.get(KEYS["location_longitude"])
    accuracy = entry.get(KEYS["location_accuracy_meters"])
    captured_at = format_date(entry.get(KEYS["location_captured_at"]))
    risk_flags = parse_location_risk_flags(entry.get(KEYS["location_risk_flags"]))
    risk_text = format_location_risk_flags(risk_flags)

    result["lines"].append(
        f"位置证据: 状态={status_label} • 置信度={confidence_label} • provider={provider}"
    )
    result["lines"].append(
        f"位置数据: lat={latitude}, lon={longitude}, acc(m)={accuracy}, capturedAt={captured_at}"
    )
    result["lines"].append(f"位置风险标记: {risk_text}")

    recalculated_hash, _, hash_warnings, hash_errors = calculate_location_hash_from_entry(entry)
    result["warnings"].extend(hash_warnings)
    result["errors"].extend(hash_errors)
    result["recalculated_hash"] = recalculated_hash

    if hash_version >= 2 and recorded_location_hash and recalculated_hash:
        if recorded_location_hash != recalculated_hash:
            result["errors"].append("locationHash 与位置元数据不一致（疑似篡改）")

    if recorded_location_hash:
        result["lines"].append(f"LocationHash(recorded)={recorded_location_hash}")
    if recalculated_hash:
        result["lines"].append(f"LocationHash(recalculated)={recalculated_hash}")

    return result


def inspect_witness_metadata(entry: Dict[str, Any], hash_version: int) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "present": False,
        "lines": [],
        "warnings": [],
        "errors": [],
        "recorded_hash": None,
        "recalculated_hash": None,
        "slot_count": 0,
        "slots": [],
        "slots_by_packet_hash": {},
        "slots_by_id": {},
    }

    raw_witness_hash = entry.get(KEYS["witness_aggregate_hash"])
    witness_hash = normalize_hex64(raw_witness_hash)
    if raw_witness_hash is not None and witness_hash is None:
        result["errors"].append("witnessAggregateHash 不是有效 64 位十六进制")
    result["recorded_hash"] = witness_hash

    raw_slots_data = entry.get(KEYS["witness_slots_data"])
    if raw_slots_data is None:
        if witness_hash is not None:
            result["errors"].append("存在 witnessAggregateHash 但缺少 witnessSlotsData")
        return result

    result["present"] = True

    slots_blob, decode_err = decode_b64(raw_slots_data, "witnessSlotsData")
    if decode_err or slots_blob is None:
        result["errors"].append(decode_err or "witnessSlotsData 解码失败")
        return result

    try:
        decoded = json.loads(slots_blob.decode("utf-8"))
    except Exception:
        result["errors"].append("witnessSlotsData 不是有效 JSON")
        return result

    if not isinstance(decoded, list):
        result["errors"].append("witnessSlotsData JSON 不是数组")
        return result

    entry_hash = normalize_hex64(entry.get(KEYS["entry_hash"]))
    pre_witness_entry_hash = calculate_pre_witness_entry_hash(entry, hash_version)
    packet_hashes: List[str] = []
    for idx, slot in enumerate(decoded, start=1):
        slot_label = f"见证槽[{idx}]"
        if not isinstance(slot, dict):
            result["errors"].append(f"{slot_label} 结构异常")
            continue

        slot_id = normalize_uuid_text(slot.get("id"))
        if slot.get("id") is not None and slot_id is None:
            result["errors"].append(f"{slot_label} id 非法（非 UUID）")

        mode_raw = slot.get("modeRaw")
        if not isinstance(mode_raw, str) or mode_raw.strip() == "":
            result["warnings"].append(f"{slot_label} modeRaw 缺失或非法")
            mode_raw = "unknown"
        else:
            mode_raw = mode_raw.strip()

        session_id_raw = slot.get("sessionID")
        if not isinstance(session_id_raw, str) or session_id_raw.strip() == "":
            result["warnings"].append(f"{slot_label} sessionID 缺失或非法")
            session_id = None
        else:
            session_id = session_id_raw.strip()

        alias_hash_raw = slot.get("aliasHash")
        alias_hash = normalize_hex64(alias_hash_raw) if alias_hash_raw is not None else None
        if alias_hash_raw is not None and alias_hash is None:
            result["warnings"].append(f"{slot_label} aliasHash 不是有效 64 位十六进制")

        bound_hash_raw = slot.get("boundEntryHash")
        bound_hash = normalize_hex64(bound_hash_raw) if bound_hash_raw is not None else None
        if bound_hash_raw is not None and bound_hash is None:
            result["warnings"].append(f"{slot_label} boundEntryHash 不是有效 64 位十六进制")
        if bound_hash is not None and entry_hash is not None and bound_hash != entry_hash:
            if pre_witness_entry_hash is not None and bound_hash == pre_witness_entry_hash:
                # In current iOS flow, slot is bound to the pre-witness tail hash,
                # then entry hash is resealed after witnessAggregateHash is updated.
                pass
            else:
                result["errors"].append(f"{slot_label} boundEntryHash 与条目 entryHash 不一致")

        packet_hash = normalize_hex64(slot.get("packetHash"))
        if packet_hash is None:
            result["errors"].append(f"{slot_label} packetHash 非法")

        app_attest_verification_id = normalize_uuid_text(slot.get("appAttestVerificationID"))
        if slot.get("appAttestVerificationID") is not None and app_attest_verification_id is None:
            result["warnings"].append(f"{slot_label} appAttestVerificationID 非法（非 UUID）")
        app_attest_status_raw_value = slot.get("appAttestStatusRaw")
        if isinstance(app_attest_status_raw_value, str):
            app_attest_status_raw_for_hash = app_attest_status_raw_value.strip() or None
            app_attest_status = (app_attest_status_raw_for_hash or "").lower() or None
        else:
            app_attest_status_raw_for_hash = None
            app_attest_status = None

        app_attest_key_id_raw = slot.get("appAttestKeyID")
        if isinstance(app_attest_key_id_raw, str):
            app_attest_key_id = app_attest_key_id_raw.strip() or None
        else:
            app_attest_key_id = None
            if app_attest_key_id_raw is not None:
                result["warnings"].append(f"{slot_label} appAttestKeyID 类型异常")

        app_attest_verified_at_raw = slot.get("appAttestVerifiedAt")
        if app_attest_verified_at_raw is not None and parse_date_value(app_attest_verified_at_raw) is None:
            result["warnings"].append(f"{slot_label} appAttestVerifiedAt 格式异常")

        transport_raw_value = slot.get("transportRaw")
        if isinstance(transport_raw_value, str):
            transport_raw = transport_raw_value.strip() or None
        else:
            transport_raw = None
            if transport_raw_value is not None:
                result["warnings"].append(f"{slot_label} transportRaw 类型异常")

        encrypted_packet, encrypted_err = decode_b64(slot.get("encryptedEvidencePacket"), f"{slot_label}.encryptedEvidencePacket")
        recalculated_packet_hash: Optional[str] = None
        if encrypted_err or encrypted_packet is None:
            result["errors"].append(encrypted_err or f"{slot_label} encryptedEvidencePacket 解码失败")
        else:
            recalculated_packet_hash = compute_witness_slot_packet_hash(
                encrypted_evidence_packet=encrypted_packet,
                session_id=session_id,
                bound_entry_hash=bound_hash,
                mode_raw=mode_raw,
                alias_hash=alias_hash,
                app_attest_status_raw=app_attest_status_raw_for_hash,
                app_attest_key_id=app_attest_key_id,
                app_attest_verification_id=app_attest_verification_id,
                app_attest_verified_at=app_attest_verified_at_raw,
                transport_raw=transport_raw,
            )
            if packet_hash and recalculated_packet_hash != packet_hash:
                result["errors"].append(f"{slot_label} packetHash 与密文包内容不一致")

        slot_record = {
            "slot_id": slot_id,
            "packet_hash": packet_hash,
            "session_id": session_id,
            "mode_raw": mode_raw,
            "alias_hash": alias_hash,
            "bound_entry_hash": bound_hash,
            "recalculated_packet_hash": recalculated_packet_hash,
            "app_attest_verification_id": app_attest_verification_id,
            "app_attest_status": app_attest_status,
        }
        result["slots"].append(slot_record)

        if packet_hash:
            packet_hashes.append(packet_hash)
            if packet_hash in result["slots_by_packet_hash"]:
                result["errors"].append(f"{slot_label} packetHash 与其他见证槽重复")
            else:
                result["slots_by_packet_hash"][packet_hash] = slot_record

        if slot_id:
            if slot_id in result["slots_by_id"]:
                result["errors"].append(f"{slot_label} slotID 与其他见证槽重复")
            else:
                result["slots_by_id"][slot_id] = slot_record

    result["slot_count"] = len(decoded)

    if packet_hashes:
        joined = "|".join(sorted(packet_hashes))
        recalculated = hashlib.sha256(joined.encode("utf-8")).hexdigest().lower()
        result["recalculated_hash"] = recalculated

        if witness_hash is None:
            result["errors"].append("存在 witnessSlotsData 但缺少 witnessAggregateHash")
        elif witness_hash != recalculated:
            result["errors"].append("witnessAggregateHash 与见证槽聚合结果不一致（疑似篡改）")

    if result["slot_count"] == 0 and witness_hash is not None:
        result["errors"].append("witnessSlotsData 为空但存在 witnessAggregateHash")

    result["lines"].append(f"见证槽数量: {result['slot_count']}")
    if witness_hash:
        result["lines"].append(f"WitnessHash(recorded)={witness_hash}")
    if result["recalculated_hash"]:
        result["lines"].append(f"WitnessHash(recalculated)={result['recalculated_hash']}")

    if hash_version >= CURRENT_ENTRY_HASH_VERSION and result["slot_count"] == 0 and witness_hash is not None:
        result["warnings"].append("entryHashVersion>=3 下 witnessAggregateHash 已记录但见证槽为空")

    return result


def verify_judicial_manifest(
    backup_root: str,
    case_catalog: Dict[str, Dict[str, Any]],
    reveal_pii: bool = False,
) -> Tuple[int, int]:
    print("\n" + "=" * 78)
    print("⚖️ 司法导出附加核验")

    warning_count = 0
    error_count = 0

    manifest_path = os.path.join(backup_root, "judicial_witnesses.json")
    legal_notice_path = os.path.join(backup_root, "LEGAL_NOTICE.txt")

    if not os.path.isfile(manifest_path):
        print("❌ 缺少 judicial_witnesses.json（该包不是司法导出包，或导出不完整）")
        return 1, 0

    if not os.path.isfile(legal_notice_path):
        print("❌ 缺少 LEGAL_NOTICE.txt（司法导出法律告知文件缺失）")
        error_count += 1

    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except Exception as exc:
        print(f"❌ judicial_witnesses.json 读取失败: {exc}")
        return 1 + error_count, warning_count

    if not isinstance(manifest, dict):
        print("❌ judicial_witnesses.json 顶层结构不是对象")
        return 1 + error_count, warning_count

    manifest_version = manifest.get("version")
    if manifest_version != 1:
        print(f"⚠️ 司法清单版本异常: {manifest_version}")
        warning_count += 1

    case_id = normalize_uuid_text(manifest.get("caseID"))
    case_name = manifest.get("caseName", "Unknown")
    if case_id is None:
        print("❌ judicial_witnesses.json.caseID 非法")
        return 1 + error_count, warning_count

    print(f"📦 司法包案件: {case_name} ({case_id})")
    print(f"🕒 导出时间: {format_date(manifest.get('exportedAt'))}")

    case_record = case_catalog.get(case_id)
    if case_record is None:
        print("❌ data.json 中找不到与司法清单匹配的 caseID")
        return 1 + error_count, warning_count

    data_case_name = case_record.get("case_name")
    if isinstance(data_case_name, str) and isinstance(case_name, str):
        if data_case_name != case_name:
            print(f"⚠️ caseName 不一致: data.json={data_case_name} / judicial={case_name}")
            warning_count += 1

    entries = manifest.get("entries")
    if not isinstance(entries, list):
        print("❌ judicial_witnesses.json.entries 不是数组")
        return 1 + error_count, warning_count

    entries_by_hash = case_record.get("entries_by_hash", {})
    entries_by_id = case_record.get("entries_by_id", {})

    for idx, judicial_entry in enumerate(entries, start=1):
        entry_prefix = f"[司法条目 {idx}]"
        if not isinstance(judicial_entry, dict):
            print(f"{entry_prefix} ❌ 条目结构异常")
            error_count += 1
            continue

        judicial_entry_hash = normalize_hex64(judicial_entry.get("entryHash"))
        judicial_entry_id = normalize_uuid_text(judicial_entry.get("entryID"))
        recorded_witness_hash = normalize_hex64(judicial_entry.get("witnessAggregateHash"))
        witness_count = judicial_entry.get("witnessCount")
        witness_records = judicial_entry.get("witnesses")

        if judicial_entry_hash is None:
            print(f"{entry_prefix} ❌ entryHash 非法")
            error_count += 1
            continue
        if judicial_entry_id is None:
            print(f"{entry_prefix} ❌ entryID 非法")
            error_count += 1
            continue
        if not isinstance(witness_records, list):
            print(f"{entry_prefix} ❌ witnesses 不是数组")
            error_count += 1
            continue
        if not isinstance(witness_count, int) or witness_count < 0:
            print(f"{entry_prefix} ❌ witnessCount 非法: {witness_count}")
            error_count += 1
            continue

        data_entry = entries_by_hash.get(judicial_entry_hash)
        if data_entry is None:
            data_entry = entries_by_id.get(judicial_entry_id)
        if data_entry is None:
            print(f"{entry_prefix} ❌ 在 data.json 中找不到对应条目")
            error_count += 1
            continue

        data_entry_hash = data_entry.get("entry_hash")
        data_entry_id = data_entry.get("entry_id")
        data_witness_hash = data_entry.get("witness_hash")
        data_slot_count = data_entry.get("slot_count", 0)
        data_slots_by_packet_hash = data_entry.get("slots_by_packet_hash", {})
        data_slots_by_id = data_entry.get("slots_by_id", {})

        print(f"{entry_prefix} entryHash={judicial_entry_hash}")

        if data_entry_hash != judicial_entry_hash:
            print(f"{entry_prefix} ❌ entryHash 与 data.json 不一致")
            error_count += 1
        if data_entry_id != judicial_entry_id:
            print(f"{entry_prefix} ❌ entryID 与 data.json 不一致")
            error_count += 1

        if recorded_witness_hash is None and witness_count > 0:
            print(f"{entry_prefix} ❌ 有见证记录但 witnessAggregateHash 缺失")
            error_count += 1
        elif recorded_witness_hash is not None and data_witness_hash is not None and recorded_witness_hash != data_witness_hash:
            print(f"{entry_prefix} ❌ witnessAggregateHash 与 data.json 不一致")
            error_count += 1

        if witness_count != len(witness_records):
            print(f"{entry_prefix} ❌ witnessCount={witness_count} 与 witnesses 数组长度={len(witness_records)} 不一致")
            error_count += 1

        if witness_count != data_slot_count:
            print(f"{entry_prefix} ❌ witnessCount={witness_count} 与 data.json 见证槽数量={data_slot_count} 不一致")
            error_count += 1

        manifest_packet_hashes: List[str] = []
        for widx, witness in enumerate(witness_records, start=1):
            witness_prefix = f"{entry_prefix}/见证[{widx}]"
            if not isinstance(witness, dict):
                print(f"{witness_prefix} ❌ 结构异常")
                error_count += 1
                continue

            slot_id = normalize_uuid_text(witness.get("slotID"))
            packet_hash = normalize_hex64(witness.get("packetHash"))
            session_id = witness.get("sessionID")
            mode = witness.get("mode")
            alias_hash = normalize_hex64(witness.get("aliasHash")) if witness.get("aliasHash") is not None else None

            if slot_id is None:
                print(f"{witness_prefix} ❌ slotID 非法")
                error_count += 1
                continue
            if packet_hash is None:
                print(f"{witness_prefix} ❌ packetHash 非法")
                error_count += 1
                continue
            if not isinstance(session_id, str) or not session_id.strip():
                print(f"{witness_prefix} ❌ sessionID 非法")
                error_count += 1
                continue
            if not isinstance(mode, str) or not mode.strip():
                print(f"{witness_prefix} ❌ mode 非法")
                error_count += 1
                continue

            manifest_packet_hashes.append(packet_hash)
            data_slot = data_slots_by_packet_hash.get(packet_hash) or data_slots_by_id.get(slot_id)
            if data_slot is None:
                print(f"{witness_prefix} ❌ 在 data.json 的 witnessSlotsData 中找不到对应槽位")
                error_count += 1
                continue

            data_slot_id = data_slot.get("slot_id")
            data_packet_hash = data_slot.get("packet_hash")
            data_session_id = data_slot.get("session_id")
            data_mode_raw = data_slot.get("mode_raw")
            data_alias_hash = data_slot.get("alias_hash")

            if data_slot_id and data_slot_id != slot_id:
                print(f"{witness_prefix} ❌ slotID 与 data.json 不一致")
                error_count += 1
            if data_packet_hash and data_packet_hash != packet_hash:
                print(f"{witness_prefix} ❌ packetHash 与 data.json 不一致")
                error_count += 1
            if isinstance(data_session_id, str) and data_session_id != session_id:
                print(f"{witness_prefix} ❌ sessionID 与 data.json 不一致")
                error_count += 1
            if isinstance(data_mode_raw, str) and data_mode_raw != mode:
                print(f"{witness_prefix} ❌ mode 与 data.json 不一致")
                error_count += 1
            if data_alias_hash is not None and alias_hash is not None and data_alias_hash != alias_hash:
                print(f"{witness_prefix} ❌ aliasHash 与 data.json 不一致")
                error_count += 1

            decrypted_payload = witness.get("decryptedPayload")
            decrypt_error = witness.get("decryptError")

            if decrypted_payload is not None and decrypt_error not in (None, ""):
                print(f"{witness_prefix} ❌ decryptedPayload 与 decryptError 同时存在")
                error_count += 1
            elif decrypted_payload is None and decrypt_error in (None, ""):
                print(f"{witness_prefix} ⚠️ decryptedPayload 与 decryptError 同时为空（信息不足）")
                warning_count += 1

            if decrypted_payload is not None:
                print(f"{witness_prefix} 🔎 解密摘要: {summarize_judicial_payload(decrypted_payload, reveal_pii)}")
            elif isinstance(decrypt_error, str) and decrypt_error.strip():
                print(f"{witness_prefix} ⚠️ 解密失败: {mask_text(decrypt_error, 8, 8)}")

        data_packet_set = set(data_slots_by_packet_hash.keys())
        manifest_packet_set = set(manifest_packet_hashes)
        missing_from_manifest = data_packet_set - manifest_packet_set
        extra_in_manifest = manifest_packet_set - data_packet_set
        if missing_from_manifest:
            print(f"{entry_prefix} ❌ 司法清单缺少 {len(missing_from_manifest)} 个 data.json 中的见证槽")
            error_count += 1
        if extra_in_manifest:
            print(f"{entry_prefix} ❌ 司法清单包含 {len(extra_in_manifest)} 个 data.json 中不存在的见证槽")
            error_count += 1

    if error_count == 0:
        print("✅ 司法清单与 data.json 交叉核验通过")
    else:
        print(f"❌ 司法清单核验失败，共 {error_count} 处关键错误")
    if warning_count > 0:
        print(f"⚠️ 司法清单核验警告 {warning_count} 条")

    return error_count, warning_count


def inspect_onsite_window_metadata(entry: Dict[str, Any]) -> Tuple[Optional[str], List[str]]:
    warnings: List[str] = []

    mono = entry.get(KEYS["capture_monotonic_nanos"])
    boot_id = entry.get(KEYS["capture_boot_session_id"])
    window = entry.get(KEYS["onsite_window_seconds"])

    has_any = mono is not None or boot_id is not None or window is not None
    if not has_any:
        return None, warnings

    if mono is not None and (not isinstance(mono, int) or mono < 0):
        warnings.append(f"captureMonotonicNanos 异常: {mono}")

    if boot_id is not None and not isinstance(boot_id, str):
        warnings.append(f"captureBootSessionID 类型异常: {boot_id}")

    if window is not None and (not isinstance(window, int) or window <= 0):
        warnings.append(f"onsiteWindowSeconds 异常: {window}")

    summary = f"captureMonotonicNanos={mono}, captureBootSessionID={boot_id}, onsiteWindowSeconds={window}"
    return summary, warnings


def verify_hardware_endorsement(entry: Dict[str, Any], entry_hash: str, entry_timestamp: Any) -> Dict[str, Any]:
    result = {
        "present": False,
        "lines": [],
        "warnings": [],
        "errors": [],
    }

    hw_signature_b64 = entry.get(KEYS["hardware_signature"])
    hw_public_key_b64 = entry.get(KEYS["hardware_public_key"])
    hw_cert_b64 = entry.get(KEYS["hardware_certificate"])
    hw_key_name = entry.get(KEYS["hardware_key_name"])
    hw_signed_at = entry.get(KEYS["hardware_signed_at"])
    hw_level = entry.get(KEYS["hardware_level"])
    hw_error = entry.get(KEYS["hardware_error"])

    result["present"] = any(
        value is not None
        for value in (
            hw_signature_b64,
            hw_public_key_b64,
            hw_cert_b64,
            hw_key_name,
            hw_signed_at,
            hw_level,
            hw_error,
        )
    )

    if not result["present"]:
        return result

    key_name_text = hw_key_name or "其他PIV硬件密钥"
    level_text = HARDWARE_LEVEL_LABELS.get(hw_level, hw_level or "未标注")
    signed_at_text = format_date(hw_signed_at)
    result["lines"].append(f"硬件背书: {level_text} • {key_name_text} • {signed_at_text}")

    if hw_error:
        result["warnings"].append(f"iOS 记录硬件错误: {hw_error}")

    message = entry_hash.encode("utf-8")

    signature_data: Optional[bytes] = None
    if hw_signature_b64 is not None:
        signature_data, sig_decode_err = decode_b64(hw_signature_b64, "hardwareEndorsementSignature")
        if sig_decode_err:
            result["errors"].append(sig_decode_err)
    elif hw_public_key_b64 is not None or hw_cert_b64 is not None:
        result["warnings"].append("缺少 hardwareEndorsementSignature")

    verified_by_pub = False
    if hw_signature_b64 is not None and hw_public_key_b64 is not None:
        ok, msg = verify_ecdsa_signature_b64(hw_signature_b64, hw_public_key_b64, message, "硬件背书")
        if ok:
            verified_by_pub = True
            result["lines"].append(f"硬件签名校验: {msg} (publicKey)")
        else:
            result["warnings"].append(f"硬件签名 publicKey 校验失败: {msg}")
    elif hw_signature_b64 is not None and hw_public_key_b64 is None:
        result["warnings"].append("存在硬件签名但缺少 hardwareEndorsementPublicKey")

    cert_obj: Optional[crypto_x509.Certificate] = None
    cert_data: Optional[bytes] = None
    if hw_cert_b64 is not None:
        cert_data, cert_decode_err = decode_b64(hw_cert_b64, "hardwareEndorsementCertificate")
        if cert_decode_err:
            result["warnings"].append(cert_decode_err)
        elif cert_data is not None:
            try:
                cert_obj = crypto_x509.load_der_x509_certificate(cert_data)
                result["lines"].append("硬件证书: 已附带并解析成功")
            except Exception as exc:
                result["warnings"].append(f"硬件证书解析失败: {exc}")

    verified_by_cert = False
    if signature_data is not None and cert_obj is not None:
        ok, msg = verify_signature_with_certificate(signature_data, cert_obj, message)
        if ok:
            verified_by_cert = True
            result["lines"].append(f"硬件签名校验: {msg} (certificate)")
        else:
            result["warnings"].append(f"硬件签名 certificate 校验失败: {msg}")

    if hw_public_key_b64 is not None and cert_obj is not None:
        pub_data, pub_err = decode_b64(hw_public_key_b64, "hardwareEndorsementPublicKey")
        if pub_err:
            result["warnings"].append(pub_err)
        elif pub_data is not None:
            match = compare_public_key_with_certificate(pub_data, cert_obj)
            if match is True:
                result["lines"].append("硬件公钥与证书公钥一致")
            elif match is False:
                result["warnings"].append("硬件公钥与证书公钥不一致")

    if hw_signature_b64 is not None and not (verified_by_pub or verified_by_cert):
        result["errors"].append("硬件背书签名无法被 publicKey/certificate 验证")

    signed_dt = parse_date_value(hw_signed_at)
    captured_dt = parse_date_value(entry_timestamp)
    onsite_window = entry.get(KEYS["onsite_window_seconds"])

    if signed_dt is not None and captured_dt is not None:
        delta_seconds = int((signed_dt - captured_dt).total_seconds())
        result["lines"].append(f"硬件背书时间差: {delta_seconds}s")

        if isinstance(onsite_window, int) and hw_level == "onsite_witness":
            if delta_seconds > onsite_window + 120:
                result["warnings"].append(
                    "等级标记为现场亲签，但背书时间差超过窗口上限 (含120秒容差)"
                )

    return result


def verify_app_attest_report(
    report_path: str,
    case_catalog: Dict[str, Dict[str, Any]],
) -> Tuple[int, int]:
    print("\n" + "=" * 78)
    print("🍎 App Attest 服务端报告交叉核验")

    if not os.path.isfile(report_path):
        print(f"❌ 报告文件不存在: {report_path}")
        return 1, 0

    try:
        with open(report_path, "r", encoding="utf-8") as f:
            report = json.load(f)
    except Exception as exc:
        print(f"❌ App Attest 报告读取失败: {exc}")
        return 1, 0

    if not isinstance(report, dict):
        print("❌ App Attest 报告顶层结构不是对象")
        return 1, 0

    schema_version = report.get("schemaVersion")
    print(f"📄 报告 schemaVersion: {schema_version}")

    if schema_version == "app-attest-judicial-report.v2":
        return verify_app_attest_report_v2(report, case_catalog)
    if schema_version == "app-attest-judicial-report.v1":
        return verify_app_attest_report_v1(report, case_catalog)

    print("❌ 不支持的 App Attest 报告版本")
    return 1, 0


def verify_app_attest_report_v1(
    report: Dict[str, Any],
    case_catalog: Dict[str, Dict[str, Any]],
) -> Tuple[int, int]:
    error_count = 0
    warning_count = 0

    request = report.get("request")
    if not isinstance(request, dict):
        print("❌ v1 报告缺少 request 对象")
        return 1, 0

    case_id = normalize_uuid_text(request.get("caseId"))
    entry_hash = normalize_hex64(request.get("entryHash"))
    if case_id is None:
        print("❌ v1 报告 request.caseId 非法")
        return 1, 0
    if entry_hash is None:
        print("❌ v1 报告 request.entryHash 非法")
        return 1, 0

    case_record = case_catalog.get(case_id)
    if case_record is None:
        print("❌ v1 报告 caseId 在 data.json 中不存在")
        return 1, 0

    local_hashes = case_record.get("case_entry_hashes", set())
    if entry_hash not in local_hashes:
        print("❌ v1 报告 request.entryHash 不属于该案件")
        error_count += 1
    else:
        print("✅ request.entryHash 与案件条目匹配")

    assertions = report.get("assertions")
    if not isinstance(assertions, list):
        print("❌ v1 报告 assertions 不是数组")
        return error_count + 1, warning_count

    for idx, item in enumerate(assertions, start=1):
        if not isinstance(item, dict):
            print(f"❌ assertions[{idx}] 结构非法")
            error_count += 1
            continue
        row_entry_hash = normalize_hex64(item.get("entryHash"))
        if row_entry_hash != entry_hash:
            print(f"❌ assertions[{idx}] entryHash 与 request.entryHash 不一致")
            error_count += 1

    if error_count == 0:
        print("✅ v1 报告与案件包交叉核验通过")

    return error_count, warning_count


def verify_app_attest_report_v2(
    report: Dict[str, Any],
    case_catalog: Dict[str, Dict[str, Any]],
) -> Tuple[int, int]:
    error_count = 0
    warning_count = 0

    request = report.get("request")
    if not isinstance(request, dict):
        print("❌ v2 报告缺少 request 对象")
        return 1, 0

    case_id = normalize_uuid_text(request.get("caseId"))
    if case_id is None:
        print("❌ v2 报告 request.caseId 非法")
        return 1, 0

    case_record = case_catalog.get(case_id)
    if case_record is None:
        print("❌ v2 报告 caseId 在 data.json 中不存在")
        return 1, 0

    local_entry_hashes = set(case_record.get("case_entry_hashes", set()))
    local_anchor_map = case_record.get("witness_anchors_by_verification_id", {})
    if not isinstance(local_anchor_map, dict):
        local_anchor_map = {}

    scope = report.get("scope")
    if not isinstance(scope, dict):
        print("❌ v2 报告缺少 scope 对象")
        return 1, 0

    scope_entry_hashes_raw = scope.get("caseEntryHashes")
    if not isinstance(scope_entry_hashes_raw, list):
        print("❌ v2 报告 scope.caseEntryHashes 不是数组")
        return 1, 0

    scope_entry_hashes: List[str] = []
    seen_scope_hashes: Set[str] = set()
    for idx, raw in enumerate(scope_entry_hashes_raw, start=1):
        normalized = normalize_hex64(raw)
        if normalized is None:
            print(f"❌ scope.caseEntryHashes[{idx}] 非法")
            error_count += 1
            continue
        if normalized not in seen_scope_hashes:
            seen_scope_hashes.add(normalized)
            scope_entry_hashes.append(normalized)

    missing_in_local = [h for h in scope_entry_hashes if h not in local_entry_hashes]
    if missing_in_local:
        print(f"❌ scope.caseEntryHashes 有 {len(missing_in_local)} 条不属于该案件")
        error_count += len(missing_in_local)
    else:
        print(f"✅ scope.caseEntryHashes 共 {len(scope_entry_hashes)} 条，均可在案件包中匹配")

    local_not_in_scope = sorted(local_entry_hashes - set(scope_entry_hashes))
    if local_not_in_scope:
        print(f"⚠️ 案件中有 {len(local_not_in_scope)} 条 entryHash 未纳入 scope.caseEntryHashes")
        warning_count += len(local_not_in_scope)

    case_assertions = report.get("caseAssertions")
    if not isinstance(case_assertions, list):
        print("❌ v2 报告 caseAssertions 不是数组")
        return error_count + 1, warning_count

    seen_case_assertion_ids: Set[str] = set()
    for idx, item in enumerate(case_assertions, start=1):
        if not isinstance(item, dict):
            print(f"❌ caseAssertions[{idx}] 结构非法")
            error_count += 1
            continue
        verification_id = normalize_uuid_text(item.get("verificationId"))
        entry_hash = normalize_hex64(item.get("entryHash"))
        if verification_id is None:
            print(f"❌ caseAssertions[{idx}] verificationId 非法")
            error_count += 1
        elif verification_id in seen_case_assertion_ids:
            print(f"❌ caseAssertions[{idx}] verificationId 重复")
            error_count += 1
        else:
            seen_case_assertion_ids.add(verification_id)
        if entry_hash is None:
            print(f"❌ caseAssertions[{idx}] entryHash 非法")
            error_count += 1
            continue
        if entry_hash not in local_entry_hashes:
            print(f"❌ caseAssertions[{idx}] entryHash 不属于案件")
            error_count += 1
        if entry_hash not in seen_scope_hashes:
            print(f"❌ caseAssertions[{idx}] entryHash 不在 scope.caseEntryHashes 中")
            error_count += 1

    scope_witness_anchors = scope.get("witnessAnchors")
    if scope_witness_anchors is not None and not isinstance(scope_witness_anchors, list):
        print("❌ v2 报告 scope.witnessAnchors 不是数组")
        error_count += 1
        scope_witness_anchors = []
    if scope_witness_anchors is None:
        scope_witness_anchors = []

    for idx, item in enumerate(scope_witness_anchors, start=1):
        if not isinstance(item, dict):
            print(f"❌ scope.witnessAnchors[{idx}] 结构非法")
            error_count += 1
            continue
        verification_id = normalize_uuid_text(item.get("appAttestVerificationId"))
        bound_entry_hash = normalize_hex64(item.get("boundEntryHash"))
        if verification_id is None:
            print(f"❌ scope.witnessAnchors[{idx}] appAttestVerificationId 非法")
            error_count += 1
            continue
        if bound_entry_hash is None:
            print(f"❌ scope.witnessAnchors[{idx}] boundEntryHash 非法")
            error_count += 1
            continue
        local_anchor = local_anchor_map.get(verification_id)
        if local_anchor is None:
            print(f"⚠️ scope.witnessAnchors[{idx}] 在案件包见证槽中找不到同 verificationId")
            warning_count += 1
            continue
        local_bound_hash = normalize_hex64(local_anchor.get("bound_entry_hash"))
        if local_bound_hash != bound_entry_hash:
            print(f"❌ scope.witnessAnchors[{idx}] boundEntryHash 与案件包不一致")
            error_count += 1

    witness_assertions = report.get("witnessAssertions")
    if not isinstance(witness_assertions, list):
        print("❌ v2 报告 witnessAssertions 不是数组")
        return error_count + 1, warning_count

    seen_witness_assertion_ids: Set[str] = set()
    for idx, item in enumerate(witness_assertions, start=1):
        if not isinstance(item, dict):
            print(f"❌ witnessAssertions[{idx}] 结构非法")
            error_count += 1
            continue
        anchor = item.get("anchor")
        assertion = item.get("assertion")
        match_status = item.get("matchStatus")
        if not isinstance(anchor, dict):
            print(f"❌ witnessAssertions[{idx}].anchor 非法")
            error_count += 1
            continue
        anchor_verification_id = normalize_uuid_text(anchor.get("appAttestVerificationId"))
        anchor_bound_hash = normalize_hex64(anchor.get("boundEntryHash"))
        if anchor_verification_id is None or anchor_bound_hash is None:
            print(f"❌ witnessAssertions[{idx}].anchor 关键字段非法")
            error_count += 1
            continue
        if anchor_verification_id in seen_witness_assertion_ids:
            print(f"❌ witnessAssertions[{idx}] anchor.appAttestVerificationId 重复")
            error_count += 1
        else:
            seen_witness_assertion_ids.add(anchor_verification_id)

        local_anchor = local_anchor_map.get(anchor_verification_id)
        if local_anchor is not None:
            local_bound_hash = normalize_hex64(local_anchor.get("bound_entry_hash"))
            if local_bound_hash != anchor_bound_hash:
                print(f"❌ witnessAssertions[{idx}] anchor.boundEntryHash 与案件包不一致")
                error_count += 1
        else:
            warning_count += 1
            print(f"⚠️ witnessAssertions[{idx}] 在案件包见证槽中找不到同 verificationId")

        if match_status == "matched" and not isinstance(assertion, dict):
            print(f"❌ witnessAssertions[{idx}] 标记 matched 但 assertion 为空")
            error_count += 1
        if isinstance(assertion, dict):
            assertion_verification_id = normalize_uuid_text(assertion.get("verificationId"))
            assertion_entry_hash = normalize_hex64(assertion.get("entryHash"))
            if assertion_verification_id != anchor_verification_id:
                print(f"❌ witnessAssertions[{idx}] assertion.verificationId 与 anchor 不一致")
                error_count += 1
            if assertion_entry_hash is None:
                print(f"❌ witnessAssertions[{idx}] assertion.entryHash 非法")
                error_count += 1

    summary = report.get("summary")
    if isinstance(summary, dict):
        summary_case = summary.get("caseAssertions")
        if isinstance(summary_case, dict):
            total_claimed = summary_case.get("total")
            if isinstance(total_claimed, int) and total_claimed != len(case_assertions):
                print("⚠️ summary.caseAssertions.total 与 caseAssertions 数量不一致")
                warning_count += 1
        summary_witness = summary.get("witnessAnchors")
        if isinstance(summary_witness, dict):
            total_claimed = summary_witness.get("total")
            if isinstance(total_claimed, int):
                anchors_count = len(scope_witness_anchors)
                if total_claimed != anchors_count:
                    print("⚠️ summary.witnessAnchors.total 与 scope.witnessAnchors 数量不一致")
                    warning_count += 1

    if error_count == 0:
        print("✅ v2 报告与案件包交叉核验通过")

    return error_count, warning_count


def entry_sort_key(entry: Dict[str, Any]) -> float:
    dt = parse_date_value(entry.get(KEYS["timestamp"]))
    if dt is None:
        return 0.0
    return dt.timestamp()


def verify_backup(
    backup_root: str,
    mode: str = "standard",
    reveal_pii: bool = False,
    attest_report_path: Optional[str] = None,
) -> None:
    json_path = os.path.join(backup_root, "data.json")
    files_root = os.path.join(backup_root, "files")
    require_tsa_eku, allow_tsa_sha1 = get_runtime_tsa_policy()

    print(f"📂 打开备份: {backup_root}")

    if not os.path.exists(json_path):
        print(f"❌ 致命错误: 找不到索引文件 {json_path}")
        sys.exit(1)

    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        print(f"❌ 致命错误: JSON 读取失败 - {exc}")
        sys.exit(1)

    backup_version = data.get(KEYS["version"], "Unknown")
    cases = data.get(KEYS["cases"], [])
    if not isinstance(cases, list):
        print("❌ 致命错误: data.json 中 cases 不是数组")
        sys.exit(1)

    print(f"Running VeriTrail Verification Protocol {PROTOCOL_VERSION}")
    print(f"Backup format version: {backup_version}")
    print(
        f"TSA policy: requireEKU={require_tsa_eku}, allowSHA1={allow_tsa_sha1}, trustStoreEnv={TRUST_STORE_ENV}"
    )
    print(f"Verification mode: {mode} (revealPII={reveal_pii})")
    if attest_report_path:
        print(f"App Attest report: {attest_report_path}")
    print("=" * 78)

    total_error_entries = 0
    total_warnings = 0
    case_catalog: Dict[str, Dict[str, Any]] = {}

    for case_idx, case in enumerate(cases, start=1):
        case_name = case.get(KEYS["case_name"], "Unknown")
        case_id = normalize_uuid_text(case.get(KEYS["case_id"]))
        entries = case.get(KEYS["entries"], [])
        if not isinstance(entries, list):
            print(f"\n案件 [{case_idx}/{len(cases)}]: {case_name}")
            print("-" * 78)
            print("    ❌ 案件 entries 字段不是数组")
            total_error_entries += 1
            continue

        if case_id is None:
            case_id = f"invalid-case-{case_idx}"

        case_record = {
            "case_id": case_id,
            "case_name": case_name,
            "entries_by_hash": {},
            "entries_by_id": {},
            "case_entry_hashes": set(),
            "witness_anchors_by_verification_id": {},
        }
        case_catalog[case_id] = case_record

        entries = sorted(entries, key=entry_sort_key)

        print(f"\n案件 [{case_idx}/{len(cases)}]: {case_name}")
        print("-" * 78)

        for i, entry in enumerate(entries, start=1):
            entry_errors: List[str] = []
            entry_warnings: List[str] = []

            fname = entry.get(KEYS["file_name"], "Unknown")
            rel_path = entry.get(KEYS["rel_path"], "")
            fsize = entry.get(KEYS["file_size"], 0)
            timestamp_raw = entry.get(KEYS["timestamp"])
            rec_file_hash = entry.get(KEYS["file_hash"], "")
            rec_prev_hash = entry.get(KEYS["prev_hash"], "")
            rec_entry_hash = entry.get(KEYS["entry_hash"], "")
            rec_entry_hash_normalized = normalize_hex64(rec_entry_hash)
            entry_id_normalized = normalize_uuid_text(entry.get(KEYS["entry_id"]))
            entry_hash_version = normalize_entry_hash_version(entry.get(KEYS["entry_hash_version"]))
            rec_location_hash = normalize_hex64(entry.get(KEYS["location_hash"]))
            rec_witness_hash = normalize_hex64(entry.get(KEYS["witness_aggregate_hash"]))
            ts_token_b64 = entry.get(KEYS["ts_token"])
            ts_nonce = entry.get(KEYS["ts_nonce"])
            capture_source_raw = entry.get(KEYS["capture_source"])

            iso_date = timestamp_to_hash_iso8601(timestamp_raw)
            print(f"[{i}] {fname}")
            print(f"    🕒 记录时间: {format_date(timestamp_raw)}")
            print(f"    🔢 条目哈希版本: v{entry_hash_version}")

            capture_source = normalize_capture_source(capture_source_raw)
            if capture_source:
                print(f"    📍 采集来源: {CAPTURE_SOURCE_LABELS[capture_source]}")
            elif capture_source_raw is None:
                print("    ⚪ 采集来源: 未记录 (旧版本备份)")
            else:
                entry_warnings.append(f"采集来源字段异常: {capture_source_raw}")

            location_result = inspect_location_metadata(entry, entry_hash_version)
            if location_result["present"] or entry_hash_version >= CURRENT_ENTRY_HASH_VERSION:
                for line in location_result["lines"]:
                    print(f"    📡 {line}")
                entry_warnings.extend(location_result["warnings"])
                entry_errors.extend(location_result["errors"])
            else:
                print("    ⚪ 位置证据: 未记录 (legacy)")

            witness_result = inspect_witness_metadata(entry, entry_hash_version)
            if witness_result["present"] or rec_witness_hash is not None:
                for line in witness_result["lines"]:
                    print(f"    👥 {line}")
                entry_warnings.extend(witness_result["warnings"])
                entry_errors.extend(witness_result["errors"])
            elif entry_hash_version >= CURRENT_ENTRY_HASH_VERSION:
                if i == len(entries):
                    print("    ⚪ 见证槽: 未记录（尾条当前尚无见证回传）")
                else:
                    print("    ⚪ 见证槽: 未记录（默认仅尾条写入，本条无见证属正常）")

            entry_record = {
                "entry_id": entry_id_normalized,
                "entry_hash": rec_entry_hash_normalized,
                "witness_hash": witness_result["recorded_hash"],
                "slot_count": witness_result["slot_count"],
                "slots": witness_result["slots"],
                "slots_by_packet_hash": witness_result["slots_by_packet_hash"],
                "slots_by_id": witness_result["slots_by_id"],
            }
            if rec_entry_hash_normalized:
                if rec_entry_hash_normalized in case_record["entries_by_hash"]:
                    entry_warnings.append("同一案件中存在重复 entryHash")
                case_record["entries_by_hash"][rec_entry_hash_normalized] = entry_record
                case_record["case_entry_hashes"].add(rec_entry_hash_normalized)
            else:
                entry_warnings.append("entryHash 非法，无法用于司法清单交叉核验")
            if entry_id_normalized:
                if entry_id_normalized in case_record["entries_by_id"]:
                    entry_warnings.append("同一案件中存在重复 entryID")
                case_record["entries_by_id"][entry_id_normalized] = entry_record

            for slot_record in witness_result["slots"]:
                verification_id = slot_record.get("app_attest_verification_id")
                bound_entry_hash = slot_record.get("bound_entry_hash")
                if verification_id is None or bound_entry_hash is None:
                    continue
                if verification_id in case_record["witness_anchors_by_verification_id"]:
                    entry_warnings.append("同一案件中存在重复 witness appAttestVerificationID")
                    continue
                case_record["witness_anchors_by_verification_id"][verification_id] = {
                    "entry_hash": rec_entry_hash_normalized,
                    "bound_entry_hash": bound_entry_hash,
                    "slot_id": slot_record.get("slot_id"),
                    "session_id": slot_record.get("session_id"),
                    "mode_raw": slot_record.get("mode_raw"),
                    "app_attest_status": slot_record.get("app_attest_status"),
                }

            # 文件完整性
            real_file_path, rel_path_err = resolve_file_in_backup(files_root, rel_path)
            if rel_path_err:
                entry_errors.append(rel_path_err)
            else:
                calc_file_hash = calculate_file_sha256(real_file_path or "")
                if calc_file_hash is None:
                    entry_errors.append(f"文件丢失: {rel_path}")
                elif calc_file_hash != rec_file_hash:
                    entry_errors.append("文件哈希不匹配，文件可能被篡改")
                else:
                    print("    ✅ 文件完整")

            # 链条连续性
            if i > 1:
                prev_entry_hash = entries[i - 2].get(KEYS["entry_hash"], "")
                if rec_prev_hash != prev_entry_hash:
                    entry_errors.append("链条断裂: previousHash 与上一条 entryHash 不一致")
                else:
                    print("    ✅ 链条连贯")
            else:
                print("    ✅ 创世节点")

            # 条目哈希
            calc_entry_hash = calculate_entry_hash(
                rec_prev_hash,
                iso_date,
                rec_file_hash,
                fname,
                fsize,
                hash_version=entry_hash_version,
                location_hash=rec_location_hash if entry_hash_version >= 2 else None,
                witness_hash=rec_witness_hash if entry_hash_version >= CURRENT_ENTRY_HASH_VERSION else None,
            )
            if not rec_entry_hash_normalized:
                entry_errors.append("entryHash 不是有效 64 位十六进制")
            elif calc_entry_hash != rec_entry_hash_normalized:
                entry_errors.append(f"条目哈希不匹配 (v{entry_hash_version} 元数据可能被篡改)")
            else:
                print("    ✅ 指纹验证通过")

            # 主签名
            signature_b64 = entry.get(KEYS["signature"])
            public_key_b64 = entry.get(KEYS["public_key"])
            if signature_b64 and public_key_b64:
                ok, msg = verify_ecdsa_signature_b64(
                    signature_b64,
                    public_key_b64,
                    rec_entry_hash.encode("utf-8"),
                    "主签名",
                )
                if ok:
                    print(f"    🔐 主签名: {msg}")
                else:
                    entry_errors.append(f"主签名校验失败: {msg}")
            elif signature_b64 or public_key_b64:
                entry_warnings.append("主签名字段不完整 (signature/publicKey 仅存在一项)")
            else:
                print("    ⚪ 无主签名")

            # App Attest 远程验签回执（审计信息）
            app_attest_summary, app_attest_warnings = inspect_app_attest_metadata(entry)
            if app_attest_summary:
                print(f"    🍎 App Attest 远程验签: {app_attest_summary}")
            entry_warnings.extend(app_attest_warnings)

            # 设备签名元数据
            metadata_summary, metadata_warnings = inspect_device_metadata(entry)
            if metadata_summary:
                print(f"    📱 设备签名元数据: {metadata_summary}")
            entry_warnings.extend(metadata_warnings)

            onsite_summary, onsite_warnings = inspect_onsite_window_metadata(entry)
            if onsite_summary:
                print(f"    ⏱️ 现场窗口元数据: {onsite_summary}")
            entry_warnings.extend(onsite_warnings)

            # 硬件背书 (第二签名)
            hw_result = verify_hardware_endorsement(entry, rec_entry_hash, timestamp_raw)
            if hw_result["present"]:
                for line in hw_result["lines"]:
                    print(f"    🪪 {line}")
                entry_warnings.extend(hw_result["warnings"])
                entry_errors.extend(hw_result["errors"])
            else:
                print("    ⚪ 无硬件背书")

            # TSA
            if ts_token_b64:
                is_valid, msg = verify_tsa_token(
                    ts_token_b64,
                    rec_entry_hash,
                    ts_nonce,
                    require_eku=require_tsa_eku,
                    allow_sha1=allow_tsa_sha1,
                )
                if is_valid:
                    print(f"    🛡️  {msg}")
                else:
                    entry_errors.append(f"TSA 校验失败: {msg}")
            else:
                print("    ⚪ 无时间戳 (本地证据)")

            # 输出告警与错误
            for warning in entry_warnings:
                print(f"    ⚠️ {warning}")

            if entry_errors:
                total_error_entries += 1
                for err in entry_errors:
                    print(f"    ❌ {err}")

            total_warnings += len(entry_warnings)

    if mode == "judicial":
        judicial_errors, judicial_warnings = verify_judicial_manifest(
            backup_root,
            case_catalog,
            reveal_pii=reveal_pii,
        )
        total_error_entries += judicial_errors
        total_warnings += judicial_warnings

    if attest_report_path:
        report_errors, report_warnings = verify_app_attest_report(
            attest_report_path,
            case_catalog,
        )
        total_error_entries += report_errors
        total_warnings += report_warnings

    print("\n" + "=" * 78)
    if total_error_entries == 0:
        print("🏆 验证成功! 所有关键校验项通过。")
        if total_warnings > 0:
            print(f"⚠️ 共发现 {total_warnings} 条警告（不影响关键完整性结论）。")
    else:
        print(f"⚠️ 验证失败! 有 {total_error_entries} 条记录存在关键错误。")
        if total_warnings > 0:
            print(f"⚠️ 另外存在 {total_warnings} 条警告。")
        sys.exit(1)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="VeriTrail 备份核验脚本（支持标准模式与司法模式）"
    )
    parser.add_argument(
        "backup_path",
        help="备份目录路径（目录内应包含 data.json 与 files/）",
    )
    parser.add_argument(
        "--mode",
        choices=["standard", "judicial"],
        default="standard",
        help="核验模式：standard=常规完整性核验；judicial=额外核验 judicial_witnesses.json",
    )
    parser.add_argument(
        "--reveal-pii",
        action="store_true",
        help="司法模式下显示明文身份信息（默认脱敏）",
    )
    parser.add_argument(
        "--attest-report",
        help="可选：服务端导出的 App Attest 报告 JSON 路径（支持 v1/v2，执行交叉核验）",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    verify_backup(
        args.backup_path,
        mode=args.mode,
        reveal_pii=args.reveal_pii,
        attest_report_path=args.attest_report,
    )


if __name__ == "__main__":
    main()
