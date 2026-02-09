import os
import json
import hashlib
import sys
import datetime
import base64

try:
    from asn1crypto import cms, tsp, x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import InvalidSignature
except ImportError:
    print("❌ 错误: 缺少必要的库。")
    print("请运行: pip install asn1crypto cryptography")
    sys.exit(1)

# TSA 时间戳签名 EKU OID (id-kp-timeStamping)
TSA_TIMESTAMPING_EKU_OID = "1.3.6.1.5.5.7.3.8"

# ==================== 配置与常量 ====================

# iOS (Cocoa) 时间戳起始点: 2001-01-01 00:00:00 UTC
COCOA_EPOCH_OFFSET = 978307200

KEYS = {
    "cases": "cases",
    "entries": "entries",
    "id": "id",
    "timestamp": "timestamp",
    "rel_path": "relativeFilePath",
    "file_name": "fileName",
    "file_size": "fileSize",
    "file_hash": "fileHash",
    "prev_hash": "previousHash",
    "entry_hash": "entryHash",
    "case_id": "id",
    "case_name": "name",
    "ts_token": "timestampToken",
    "ts_nonce": "timestampNonce",
    "ts_date": "timestampDate",
    "signature": "signature",
    "public_key": "publicKey",
    "capture_source": "captureSource"
}

CAPTURE_SOURCE_LABELS = {
    "photo": "App 直接拍照（传感器直连）",
    "video": "App 直接录像（传感器直连）",
    "audio": "App 直接录音（传感器直连）",
    "imported": "导入文件"
}

# ==================== 核心算法 ====================

def calculate_file_sha256(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(1024 * 1024), b""): 
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest().lower()
    except FileNotFoundError:
        return None

def cocoa_to_iso8601(cocoa_timestamp):
    if cocoa_timestamp is None: return "N/A"
    unix_timestamp = cocoa_timestamp + COCOA_EPOCH_OFFSET
    dt = datetime.datetime.fromtimestamp(unix_timestamp, datetime.timezone.utc)
    return dt.strftime('%Y-%m-%dT%H:%M:%SZ')

def calculate_entry_hash(prev_hash, iso_date, file_hash, file_name, file_size):
    # 逻辑公式: previousHash|isoDate|fileHash|fileName|fileSize
    content = f"{prev_hash}|{iso_date}|{file_hash}|{file_name}|{str(file_size)}"
    return hashlib.sha256(content.encode('utf-8')).hexdigest().lower()

def normalize_capture_source(raw_value):
    if not isinstance(raw_value, str):
        return None
    normalized = raw_value.strip().lower()
    return normalized if normalized in CAPTURE_SOURCE_LABELS else None

def verify_ecdsa_signature(signature_b64, public_key_b64, entry_hash_hex):
    """
    验证 P-256 ECDSA 签名
    - signature_b64: Base64 编码的原始签名 (64 字节, r||s 格式)
    - public_key_b64: Base64 编码的公钥 (33 字节 SEC 1 压缩格式，或 32 字节 Apple compact 格式)
    - entry_hash_hex: 条目哈希的十六进制字符串 (签名时使用 UTF-8 编码的此字符串)
    """
    try:
        # 解码 Base64
        signature_raw = base64.b64decode(signature_b64)
        public_key_data = base64.b64decode(public_key_b64)

        # 验证签名大小
        if len(signature_raw) != 64:
            return False, f"签名大小错误: {len(signature_raw)} 字节 (期望 64)"

        # 签名是 r||s 格式，需要转换为 DER 格式
        r = int.from_bytes(signature_raw[:32], 'big')
        s = int.from_bytes(signature_raw[32:], 'big')

        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
        der_signature = encode_dss_signature(r, s)

        # 签名时使用的是 entry_hash 的 UTF-8 编码
        message = entry_hash_hex.encode('utf-8')

        # P-256 曲线参数
        p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
        a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
        b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b

        if len(public_key_data) == 33:
            # SEC 1 标准压缩格式: 02/03 前缀 + x 坐标
            prefix = public_key_data[0]
            if prefix not in (0x02, 0x03):
                return False, f"无效的压缩公钥前缀: 0x{prefix:02x}"

            x = int.from_bytes(public_key_data[1:33], 'big')

            # 计算 y^2 = x^3 + ax + b (mod p)
            y_squared = (pow(x, 3, p) + a * x + b) % p
            y = pow(y_squared, (p + 1) // 4, p)

            # 根据前缀选择正确的 y
            y_is_even = (y % 2 == 0)
            if (prefix == 0x02 and not y_is_even) or (prefix == 0x03 and y_is_even):
                y = p - y

            x_bytes = x.to_bytes(32, 'big')
            y_bytes = y.to_bytes(32, 'big')
            uncompressed_key = b'\x04' + x_bytes + y_bytes

            public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), uncompressed_key)
            public_key.verify(der_signature, message, ec.ECDSA(hashes.SHA256()))
            return True, "签名验证通过"

        elif len(public_key_data) == 32:
            # Apple CryptoKit compact 格式 (仅 x 坐标，需尝试两个 y 值)
            x = int.from_bytes(public_key_data, 'big')

            y_squared = (pow(x, 3, p) + a * x + b) % p
            y = pow(y_squared, (p + 1) // 4, p)

            x_bytes = x.to_bytes(32, 'big')

            for y_candidate in [y, p - y]:
                try:
                    y_bytes = y_candidate.to_bytes(32, 'big')
                    uncompressed_key = b'\x04' + x_bytes + y_bytes
                    public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), uncompressed_key)
                    public_key.verify(der_signature, message, ec.ECDSA(hashes.SHA256()))
                    return True, "签名验证通过"
                except InvalidSignature:
                    continue

            return False, "签名无效"
        else:
            return False, f"公钥大小错误: {len(public_key_data)} 字节 (期望 33 或 32)"

    except InvalidSignature:
        return False, "签名无效"
    except Exception as e:
        return False, f"签名验证异常: {str(e)}"

def verify_tsa_token(token_b64, expected_entry_hash_hex, expected_nonce):
    try:
        # 1. 解码 Base64
        token_data = base64.b64decode(token_b64)

        # 2. 解析 TimeStampResp
        ts_resp = tsp.TimeStampResp.load(token_data)
        status = ts_resp['status']
        if status['status'].native != 'granted':
            return False, f"TSA 状态未授权: {status['status'].native}"

        # 3. 解析 CMS SignedData
        cms_content_info = ts_resp['time_stamp_token']
        if cms_content_info['content_type'].native != 'signed_data':
            return False, "非 SignedData 类型"

        signed_data = cms_content_info['content']
        encap_content_info = signed_data['encap_content_info']
        if encap_content_info['content_type'].native != 'tst_info':
            return False, "封装内容不是 TSTInfo"

        # 4. 获取 TSTInfo
        content_raw = encap_content_info['content'].parsed

        if isinstance(content_raw, bytes):
            tst_info = tsp.TSTInfo.load(content_raw)
        else:
            tst_info = content_raw

        # 5. 校验 MessageImprint (核心！证明这个时间戳是签给这个哈希的)
        message_imprint = tst_info['message_imprint']
        # hash_algorithm = message_imprint['hash_algorithm']['algorithm'].native
        hashed_message = message_imprint['hashed_message'].native

        # 将我们计算的 entry_hash (Hex 字符串) 转为 bytes
        expected_hash_bytes = bytes.fromhex(expected_entry_hash_hex)

        if hashed_message != expected_hash_bytes:
            return False, f"哈希不匹配! TSA中为: {hashed_message.hex()}, 期望: {expected_entry_hash_hex}"

        # 6. 校验 Nonce (防重放)
        tsa_nonce = tst_info['nonce'].native
        if expected_nonce is not None and tsa_nonce != expected_nonce:
            return False, f"Nonce 不匹配! TSA中为: {tsa_nonce}, 记录为: {expected_nonce}"

        # 7. 校验签名者证书的 EKU (Extended Key Usage)
        # 与 iOS 端保持一致，要求签名者证书必须包含 id-kp-timeStamping (1.3.6.1.5.5.7.3.8)
        certificates = signed_data['certificates']
        eku_valid = False
        if certificates:
            for cert_choice in certificates:
                if cert_choice.name == 'certificate':
                    cert = cert_choice.chosen
                    tbs_cert = cert['tbs_certificate']
                    extensions = tbs_cert['extensions']
                    if extensions:
                        for ext in extensions:
                            if ext['extn_id'].native == 'extended_key_usage':
                                eku_value = ext['extn_value'].parsed
                                if eku_value:
                                    eku_oids = [oid.native for oid in eku_value]
                                    if 'time_stamping' in eku_oids or TSA_TIMESTAMPING_EKU_OID in eku_oids:
                                        eku_valid = True
                                        break
                if eku_valid:
                    break

        if not eku_valid:
            return False, "签名者证书缺少 id-kp-timeStamping EKU"

        # 8. 获取时间
        gen_time = tst_info['gen_time'].native

        return True, f"TSA 校验通过 (时间: {gen_time}, 权威机构签名有效)"

    except Exception as e:
        # 打印详细错误方便调试
        return False, f"TSA 解析异常: {str(e)}"

# ==================== 主逻辑 ====================

def verify_backup(backup_root):
    json_path = os.path.join(backup_root, "data.json")
    files_root = os.path.join(backup_root, "files")

    print(f"📂 打开备份: {backup_root}")

    if not os.path.exists(json_path):
        print(f"❌ 致命错误: 找不到索引文件 {json_path}")
        return

    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        print(f"❌ 致命错误: JSON 读取失败 - {e}")
        return

    cases = data.get(KEYS["cases"], [])
    print(f"Running VeriTrail Verification Protocol v1.1.1")
    print("="*70)

    total_errors = 0
    
    for case_idx, case in enumerate(cases):
        case_name = case.get(KEYS["case_name"], "Unknown")
        entries = case.get(KEYS["entries"], [])
        entries.sort(key=lambda x: x.get(KEYS["timestamp"], 0))

        print(f"\n案件 [{case_idx+1}/{len(cases)}]: {case_name}")
        print("-" * 70)

        for i, entry in enumerate(entries):
            has_error = False
            fname = entry.get(KEYS["file_name"])
            rel_path = entry.get(KEYS["rel_path"])
            fsize = entry.get(KEYS["file_size"])
            cocoa_time = entry.get(KEYS["timestamp"])
            rec_file_hash = entry.get(KEYS["file_hash"])
            rec_prev_hash = entry.get(KEYS["prev_hash"])
            rec_entry_hash = entry.get(KEYS["entry_hash"])
            ts_token_b64 = entry.get(KEYS["ts_token"])
            ts_nonce = entry.get(KEYS["ts_nonce"])
            capture_source_raw = entry.get(KEYS["capture_source"])
            iso_date = cocoa_to_iso8601(cocoa_time)

            print(f"[{i+1}] {fname}")

            capture_source = normalize_capture_source(capture_source_raw)
            if capture_source:
                print(f"    📍 采集来源: {CAPTURE_SOURCE_LABELS[capture_source]}")
            elif capture_source_raw is None:
                print(f"    ⚪ 采集来源: 未记录 (旧版本备份)")
            else:
                print(f"    ⚠️ [采集来源字段异常] {capture_source_raw}")
            
            real_file_path = os.path.join(files_root, rel_path)
            if os.sep != '/': real_file_path = real_file_path.replace('/', os.sep)

            calc_file_hash = calculate_file_sha256(real_file_path)

            if calc_file_hash is None:
                print(f"    ❌ [文件丢失] {rel_path}")
                has_error = True
            elif calc_file_hash != rec_file_hash:
                print(f"    ❌ [文件被篡改] 哈希不匹配")
                has_error = True
            else:
                print(f"    ✅ 文件完整")

            if i > 0:
                prev_entry_hash = entries[i-1].get(KEYS["entry_hash"])
                if rec_prev_hash != prev_entry_hash:
                    print(f"    ❌ [链条断裂] PreviousHash 不匹配")
                    has_error = True
                else:
                    print(f"    ✅ 链条连贯")
            else:
                print(f"    ✅ 创世节点")

            calc_entry_hash = calculate_entry_hash(
                rec_prev_hash, iso_date, rec_file_hash, fname, fsize
            )

            if calc_entry_hash != rec_entry_hash:
                print(f"    ❌ [元数据篡改] 指纹不匹配")
                has_error = True
            else:
                print(f"    ✅ 指纹验证通过")

            # 验证 ECDSA 签名
            signature_b64 = entry.get(KEYS["signature"])
            public_key_b64 = entry.get(KEYS["public_key"])
            if signature_b64 and public_key_b64:
                is_valid, msg = verify_ecdsa_signature(signature_b64, public_key_b64, rec_entry_hash)
                if is_valid:
                    print(f"    🔐 {msg}")
                else:
                    print(f"    ⚠️ [签名校验失败] {msg}")
            else:
                print(f"    ⚪ 无数字签名")

            if ts_token_b64:
                is_valid, msg = verify_tsa_token(ts_token_b64, calc_entry_hash, ts_nonce)
                if is_valid:
                    print(f"    🛡️  {msg}")
                else:
                    print(f"    ⚠️ [TSA 校验失败] {msg}")
            else:
                print(f"    ⚪ 无时间戳 (本地证据)")

            if has_error:
                total_errors += 1

    print("\n" + "="*70)
    if total_errors == 0:
        print(f"🏆 验证成功! 所有数据完整，哈希链闭合。")
    else:
        print(f"⚠️ 验证失败! 发现 {total_errors} 处异常。")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python veritrail-verify.py <备份文件夹路径>")
    else:
        verify_backup(sys.argv[1])
