# OpenSearch — Yuhan's LAB v2.0 (High-Precision Anti-Scam Edition)

**OpenSearch — Yuhan's LAB** adalah framework **OSINT (Open Source Intelligence)** dan **Anti-Scam Investigation** berbasis Python 3.14 dengan **17 modul investigasi**, **Mesin Eliminasi False-Positive**, **Ekstraktor Chat Penipu**, dan **Web Dashboard** lokal.

> **Disclaimer Etika & Hukum:** Tool ini dirancang khusus untuk investigasi penipuan (*anti-scam*), verifikasi identitas, riset keamanan siber defensif, dan pengumpulan bukti dari sumber terbuka publik (*open source intelligence*). Pengguna bertanggung jawab penuh mematuhi hukum yang berlaku (UU PDP, UU ITE, dan peraturan privasi setempat).

---

## Pembaruan Utama v2.0 (Zero False-Positive & Fitur Anti-Penipu Maksimal)

- **Mesin Eliminasi False-Positive (`verifier.py`, `domain_utils.py`, `known_entities.py`)**:
  - **Public Suffix & Subdomain Awareness**: Memahami multi-part TLD Indonesia (`.co.id`, `.go.id`, `.ac.id`, `.my.id`, dll.) sehingga `www.bca.co.id` tidak lagi dianggap subdomain berlapis dan RDAP/MX/DMARC mengecek apex domain (`bca.co.id`).
  - **Allowlist Domain & Hotline Resmi**: Daftar bank, e-wallet, marketplace, regulator, dan platform global resmi (`bca.co.id`, `bri.co.id`, `dana.id`, `github.com`, `1500888`, `157`, dll.).
  - **Precision Brand Impersonation Matcher**: Menghindari salah deteksi pada kata kamus normal seperti `perdana.co.id` (mengandung `"dana"`), `pineapple`, `bridge`, sambil tetap menangkap typosquatting (`bcaa`, `d4na`, `danakaget`).
  - **Tiered Risk Scoring + Trust Credit**: Sinyal kelemahan ringan (misal missing DMARC/SPF atau shared-hosting cPanel ports) tidak menaikkan skor menjadi `MEDIUM`/`HIGH` jika domain memiliki sinyal kepercayaan mapan (usia domain >= 2 tahun, sertifikat OV/EV, arsip Wayback).
  - **Cross-Tool Profile Deduplication & Soft-404 Filtering**: Menggabungkan hasil Maigret/Sherlock/Public Profiles yang sama (`corroborated`), menandai situs login-wall (`LOGIN-WALL`), serta menyaring halaman soft-404 ke audit drawer `False Positives Tersaring`.
- **Web Content & Phishing Kit Analyzer (`web_content`)**: Memindai HTML halaman untuk mendeteksi form pencuri OTP/PIN/CVV/KTP, skrip phishing kit pengirim data ke `api.telegram.org/bot...`, judul halaman peniruan bank, serta mengekstrak nomor `wa.me` / `t.me` / email / wallet tersembunyi.
- **Public Threat Feeds Gratis (`threat_feeds`)**: Cek IOC otomatis ke **abuse.ch URLhaus**, **ThreatFox**, dan **StopForumSpam**.
- **Bank Account & CekRekening OSINT (`bank_account`)**: Mendeteksi & memvalidasi digit rekening Indonesia (`BCA 1234567890`, `BRI`, `Mandiri`, `BNI`, `BSI`, `SeaBank`, `Jago`, `DANA`, `OVO`, dll.) serta membuat pivot 1-klik ke CekRekening Komdigi, Kredibel, dan dork laporan korban.
- **Analisis Chat Penipu & Ekstraktor IOC (`analyze-text` / Tab Web UI)**: Tempel pesan WhatsApp/SMS/DM untuk mendeteksi 6 modus penipuan (file `.apk` undangan/kurir, DANA kaget, job scam Telegram, titip dana, bukti transfer palsu, impersonasi aparat) dan mengekstrak seluruh IOC secara otomatis.
- **Image Forensics XMP & Perceptual Hash (`image_forensics`)**: Mendeteksi jejak editor (Photoshop, Canva, PicsArt) serta AI generator (Midjourney/Stable Diffusion/C2PA) di XMP/chunk gambar dan menghitung **64-bit dHash** untuk mencocokkan foto penipu yang diunggah ulang.

---

## Cara Penggunaan Cepat (CLI)

```powershell
# 1. Lihat seluruh 17 modul & status API key
python opensearch.py modules

# 2. Scan URL/Domain (aman dari false positive)
python opensearch.py scan "https://www.bca.co.id" --fast --no-pivot
python opensearch.py scan "http://hadiah-dana-resmi.xyz/login" --fast --export json,md,html,pdf,graph

# 3. Cek Nomor HP, Hotline Resmi, atau Rekening Bank
python opensearch.py scan "081234567890" --fast
python opensearch.py scan "BCA 1234567890" --fast

# 4. Analisis teks chat/SMS penipu & scan otomatis seluruh IOC terekstrak
python opensearch.py analyze-text "Buka undangan.apk atau transfer ke BCA 1234567890, WA 081234567890, klik http://hadiah-dana.xyz/claim" --scan-all

# 5. Lacak Username (Maigret + Sherlock + Public Profiles + Verifikasi Soft-404)
python opensearch.py scan "target_username" --maigret-top 80 --export html,graph

# 6. Forensik foto profil / bukti transfer
python opensearch.py scan "C:\path\ke\bukti_transfer.jpg"

# 7. Jalankan Web Dashboard di http://127.0.0.1:5000
python opensearch.py web
```

---

## Menambah Modul Baru (Arsitektur Modular)

1. Buat class baru turunan `BaseOSINTModule` di `opensearch_lab/modules/`.
2. Tentukan `name`, `display_name`, `supported_targets`, dan implementasikan `async def run(self, target, target_type, ctx) -> ModuleResult`.
3. Daftarkan modul di `opensearch_lab/modules/__init__.py`.
"# eqwewq" 
"# eqwewq" 
"# asu" 
