#!/usr/bin/env python3
"""
Windows CLSID Shell Namespace Camouflage Detector
Author: Mohammad Bagus Satrio (https://github.com/bagusa13)
Repository: dfir-usb-investigation
Case Reference: KASUS-USB-01 / Finding 2 (CLSID Directory Camouflage)

Description:
    Scans directory listings and raw volumes to identify folders appended with
    Windows Shell Class ID (CLSID) GUIDs used to disguise directories as system
    applets (such as All Control Panel Tasks / GodMode) in Windows Explorer.
"""

import os
import re
import sys
import argparse

# Common CLSID GUIDs used in anti-forensics / masquerading
KNOWN_CLSIDS = {
    "{21EC2020-3AEA-1069-A2DD-08002B30309D}": "All Control Panel Tasks / God Mode Applet",
    "{ED7BA470-8E54-465E-825C-99712043E01C}": "Windows Special Master Control Panel",
    "{645FF040-5081-101B-9F08-00AA002F954E}": "Recycle Bin Virtual Folder",
    "{20D04FE0-3AEA-1069-A2D8-08002B30309D}": "My Computer / This PC Root Namespace",
    "{2559A1F3-21D7-11D4-BDAF-00C04F60B9F0}": "Run / Shell Search Folder"
}

CLSID_REGEX = re.compile(r"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}")


def scan_directory(root_path: str):
    findings = []
    for dirpath, dirnames, _ in os.walk(root_path):
        for d in dirnames:
            match = CLSID_REGEX.search(d)
            if match:
                guid = match.group().upper()
                desc = KNOWN_CLSIDS.get(guid, "Uncommon or Custom Registered COM CLSID")
                full_path = os.path.join(dirpath, d)
                findings.append({
                    "folder_name": d,
                    "full_path": full_path,
                    "guid": guid,
                    "description": desc
                })
    return findings


def main():
    parser = argparse.ArgumentParser(description="Windows CLSID Anti-Forensics Directory Scanner")
    parser.add_argument("path", help="Root directory or mounted volume drive path to scan")
    args = parser.parse_args()

    print("=" * 72)
    print("WINDOWS SHELL CLSID CAMOUFLAGE AUDIT REPORT")
    print("=" * 72)
    print(f"[*] Scanning path: {args.path}\n")

    results = scan_directory(args.path)

    if not results:
        print("[+] No CLSID directory camouflage detected.")
    else:
        for r in results:
            print(f"[!] DETECTED CAMOUFLAGED FOLDER:")
            print(f"    Name  : {r['folder_name']}")
            print(f"    Path  : {r['full_path']}")
            print(f"    GUID  : {r['guid']}")
            print(f"    Impact: Masks folder icon and redirection behavior as '{r['description']}' in Windows GUI.")
            print(f"    Mitigation: Direct filesystem / Sleuth Kit table parsing bypasses shell redirection.\n")

    print("=" * 72)
    print(f"Audit completed: {len(results)} camouflaged structures identified.")


if __name__ == "__main__":
    main()
