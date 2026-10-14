# 🔍 Digital Forensics Examination: Physical USB Investigation

Investigasi forensik digital independen terhadap media penyimpanan fisik USB flash drive untuk menganalisis integritas bukti (*cryptographic dual-hashing*), memetakan struktur volume/partisi, merekonstruksi berkas terhapus (*data carving*), serta membongkar teknik penyamaran anti-forensik (*file extension spoofing* dan *CLSID directory camouflage*).

📄 **[Lihat Laporan Lengkap Formal (PDF)](./reports/Digital_Forensics_Report.pdf)**

---

## 📋 1. Case & Evidence Summary

* **Case Identifier:** `KASUS-USB-01`
* **Evidence Item Identifier:** `EVD-USB-01`
* **Original Device Model:** TOSHIBA TransMemory USB Device (Removable Media)
* **Labeled / Source Capacity:** 16 GB (~14.45 GiB / 15,518,924,800 bytes)
* **Sector Count:** 30,310,400 sectors (512 bytes per sector)
* **Image Filename & Format:** `USB_Toshiba_Evidence.E01` (Expert Witness Format)

### Cryptographic Dual-Hash Integrity
Akuisisi dilakukan melalui metode *bit-stream physical acquisition* dengan mode *read-only*. Integritas barang bukti terverifikasi identik tanpa perubahan bit (0 *bad blocks*):

| Algorithm | Stored Acquisition Hash | Computed Verification Hash | Status |
| :--- | :--- | :--- | :--- |
| **MD5** | `a2b1b05dc8b3f3535445437c64b5aae6` | `a2b1b05dc8b3f3535445437c64b5aae6` | **MATCH / VERIFIED** |
| **SHA-1** | `97ba63c1c53e91e5d6d5b985ba2467ce5b0218b5` | `97ba63c1c53e91e5d6d5b985ba2467ce5b0218b5` | **MATCH / VERIFIED** |

![Hash Verification](./assets/ftk-hash-verify.png)

---

## 🛠️ 2. Forensic Tools & Methodology

* **FTK Imager (v8.3.0.27):** Digunakan untuk akuisisi fisik *bit-stream*, kompresi E01, dan validasi *dual-hashing* integritas.
* **Autopsy Forensic Browser (v4.23.1):** Parsing sistem berkas MBR/exFAT, analisis *unallocated space*, ekstraksi *embedded files*, serta *keyword indexing*.
* **HxD Hex Editor (v2.5.0.0):** Inspeksi biner mentah (*low-level sector inspection*) dan validasi *magic bytes / file signature*.

---

## 🗂️ 3. Partition Architecture & File System

Pemeriksaan struktur partisi berbasis Master Boot Record (MBR) mengidentifikasi 3 volume:
1. **Volume 1 (Unallocated):** Sector 0 – 2,047 (~1 MB) berisi MBR dan *alignment slack*.
2. **Volume 2 (exFAT):** Sector 2,048 – 30,244,863 (~14.42 GiB) dengan label volume `Ventoy`.
3. **Volume 3 (FAT / EFI):** Sector 30,244,864 – 30,310,399 (32 MB) dengan label volume `VTOYEFI`.

![File System Structure](./assets/autopsy-file-structure.png)

---

## 🚨 4. Key Findings & Anti-Forensics Analysis

### Finding 1: File Extension Spoofing & Archive Concealment
* **Artefak:** `foto_kegiatan.jpg` (460 Bytes).
* **Temuan Teknis:** Ekstensi berkas sengaja diubah menjadi gambar `.jpg` untuk mengelabui inspeksi visual. Namun, pemeriksaan heksadesimal pada *offset* `0x00` menunjukkan *file signature / magic bytes* **`50 4B 03 04` (`PK..`)**, yang merupakan penanda arsip format **ZIP**.
* **Ekstraksi Payload:** Modul *Embedded Extractor* membongkar isi kontainer dan menemukan folder `Dokumen_penting/isidokumenpenting.txt` yang memuat teks:
  ```text
  halo ini adalah dokumen penyamaran yang isinya file txt
