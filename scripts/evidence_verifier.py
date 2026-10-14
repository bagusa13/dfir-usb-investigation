#!/usr/bin/env python3
"""
Digital Evidence Cryptographic Integrity Verifier
Author: Mohammad Bagus Satrio (https://github.com/bagusa13)
Repository: dfir-usb-investigation
Case Reference: KASUS-USB-01 / EVD-USB-01

Description:
    Computes dual cryptographic hashes (MD5 and SHA-1) of forensic images (RAW/E01/DD)
    and verifies them against baseline acquisition values to validate chain-of-custody.
"""

import sys
import os
import hashlib
import argparse
from datetime import datetime

# Baseline hashes from FTK Imager acquisition log
BASELINE_HASHES = {
    "MD5": "a2b1b05dc8b3f3535445437c64b5aae6",
    "SHA1": "97ba63c1c53e91e5d6d5b985ba2467ce5b0218b5"
}

CHUNK_SIZE = 1048576  # 1 MB buffer for fast hashing of large disk images


def calculate_hashes(file_path: str):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Target file not found: {file_path}")

    md5 = hashlib.md5()
    sha1 = hashlib.sha1()

    total_size = os.path.getsize(file_path)
    processed = 0

    print(f"[*] Hashing: {file_path}")
    print(f"[*] File Size: {total_size:,} bytes ({total_size / (1024**3):.2f} GiB)")
    print(f"[*] Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    with open(file_path, "rb") as stream:
        while chunk := stream.read(CHUNK_SIZE):
            md5.update(chunk)
            sha1.update(chunk)
            processed += len(chunk)
            percent = (processed / total_size) * 100
            sys.stdout.write(f"\r[+] Progress: {percent:6.2f}% ({processed:,} / {total_size:,} bytes)")
            sys.stdout.flush()

    print("\n")
    return md5.hexdigest(), sha1.hexdigest()


def main():
    parser = argparse.ArgumentParser(description="Forensic Image Hash Integrity Verifier")
    parser.add_argument("image_path", help="Path to evidence image (e.g., USB_Toshiba_Evidence.E01)")
    parser.add_argument("--expected-md5", default=BASELINE_HASHES["MD5"], help="Expected MD5 hash value")
    parser.add_argument("--expected-sha1", default=BASELINE_HASHES["SHA1"], help="Expected SHA-1 hash value")
    args = parser.parse_args()

    computed_md5, computed_sha1 = calculate_hashes(args.image_path)

    md5_match = computed_md5.lower() == args.expected_md5.lower()
    sha1_match = computed_sha1.lower() == args.expected_sha1.lower()

    print("=" * 64)
    print("CHAIN OF CUSTODY VERIFICATION RESULTS")
    print("=" * 64)
    print(f"MD5 Computed : {computed_md5}")
    print(f"MD5 Stored   : {args.expected_md5}")
    print(f"MD5 Status   : {'[VERIFIED - MATCH]' if md5_match else '[FAILED - MISMATCH]'}\n")

    print(f"SHA1 Computed: {computed_sha1}")
    print(f"SHA1 Stored  : {args.expected_sha1}")
    print(f"SHA1 Status  : {'[VERIFIED - MATCH]' if sha1_match else '[FAILED - MISMATCH]'}")
    print("=" * 64)

    if md5_match and sha1_match:
        print("[SUCCESS] Evidence integrity confirmed. Zero bit alteration detected.")
        sys.exit(0)
    else:
        print("[CRITICAL] Hash mismatch detected! Evidence may be altered or corrupted.")
        sys.exit(1)


if __name__ == "__main__":
    main()
