#!/usr/bin/env python3
"""
File Signature & MIME Mismatch Carver
Author: Mohammad Bagus Satrio (https://github.com/bagusa13)
Repository: dfir-usb-investigation
Case Reference: KASUS-USB-01 / Finding 1 (Extension Spoofing)

Description:
    Analyzes binary file headers against known magic numbers (signatures)
    to detect anti-forensics extension spoofing (e.g. ZIP disguised as JPG)
    and extracts embedded compressed payloads.
"""

import os
import sys
import argparse
import zipfile

MAGIC_SIGNATURES = {
    b"\x50\x4b\x03\x04": ("ZIP/Archive", [".zip", ".docx", ".xlsx", ".jar"]),
    b"\xff\xd8\xff": ("JPEG Image", [".jpg", ".jpeg"]),
    b"\x89PNG\r\n\x1a\n": ("PNG Image", [".png"]),
    b"%PDF-": ("PDF Document", [".pdf"]),
    b"\x7fELF": ("ELF Executable", [".bin", ".elf", ""]),
    b"MZ": ("Windows PE Executable", [".exe", ".dll", ".sys"]),
    b"SQLite format 3\x00": ("SQLite Database", [".db", ".sqlite", ".db3"])
}


def check_signature(file_path: str):
    with open(file_path, "rb") as f:
        header = f.read(32)

    detected_type = None
    expected_extensions = []

    for sig, (name, valid_exts) in MAGIC_SIGNATURES.items():
        if header.startswith(sig):
            detected_type = name
            expected_extensions = valid_exts
            break

    _, ext = os.path.splitext(file_path)
    ext = ext.lower()

    is_mismatch = False
    if detected_type:
        if ext not in expected_extensions:
            is_mismatch = True

    return {
        "file_name": os.path.basename(file_path),
        "actual_extension": ext,
        "magic_bytes_hex": header[:8].hex(" ").upper(),
        "detected_type": detected_type or "Unknown / Unregistered Signature",
        "is_spoofed": is_mismatch,
        "expected_extensions": expected_extensions
    }


def extract_zip_payload(file_path: str, output_dir: str):
    if not zipfile.is_zipfile(file_path):
        print(f"[!] {file_path} is not a valid ZIP container.")
        return False

    os.makedirs(output_dir, exist_ok=True)
    with zipfile.ZipFile(file_path, 'r') as archive:
        print(f"[+] Carving embedded ZIP entries from: {file_path}")
        for member in archive.infolist():
            archive.extract(member, path=output_dir)
            print(f"    -> Extracted: {member.filename} ({member.file_size} bytes)")
    return True


def main():
    parser = argparse.ArgumentParser(description="Forensic File Signature Mismatch Scanner & Carver")
    parser.add_argument("target", help="Path to file or directory to inspect")
    parser.add_argument("--extract-to", default=None, help="Directory to extract concealed ZIP payloads into")
    args = parser.parse_args()

    targets = []
    if os.path.isfile(args.target):
        targets.append(args.target)
    elif os.path.isdir(args.target):
        for root, _, files in os.walk(args.target):
            for file in files:
                targets.append(os.path.join(root, file))
    else:
        print(f"[!] Path not found: {args.target}", file=sys.stderr)
        sys.exit(1)

    print("=" * 72)
    print("FORENSIC FILE SIGNATURE ANALYSIS REPORT")
    print("=" * 72)

    spoofed_count = 0
    for p in targets:
        result = check_signature(p)
        status = "[!] MISMATCH DETECTED (SPOOFED)" if result["is_spoofed"] else "[OK] Match"
        if result["is_spoofed"]:
            spoofed_count += 1

        print(f"File      : {result['file_name']}")
        print(f"Header    : {result['magic_bytes_hex']}")
        print(f"Declared  : {result['actual_extension'] or '(none)'}")
        print(f"Detected  : {result['detected_type']}")
        print(f"Verdict   : {status}\n")

        if result["is_spoofed"] and result["detected_type"] == "ZIP/Archive" and args.extract_to:
            extract_zip_payload(p, args.extract_to)

    print("=" * 72)
    print(f"Audit Summary: {len(targets)} files inspected, {spoofed_count} spoofed anomalies detected.")


if __name__ == "__main__":
    main()
