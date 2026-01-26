import os
import json
import hashlib
import sys
import datetime
import base64

try:
    from asn1crypto import cms, tsp
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("❌ 错误: 缺少必要的库。")
    print("请运行: pip install asn1crypto cryptography")
    sys.exit(1)

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
    "ts_date": "timestampDate"
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

        # 7. 获取时间
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
    print(f"Running VeriTrail Verification Protocol v1.0")
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
            iso_date = cocoa_to_iso8601(cocoa_time)

            print(f"[{i+1}] {fname}")
            
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
        print(f"🏆 验证成功! 所有数据完整，哈希链闭合，数字签名有效。")
    else:
        print(f"⚠️ 验证失败! 发现 {total_errors} 处异常。")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python veritrail-verify.py <备份文件夹路径>")
    else:
        verify_backup(sys.argv[1])