# Civic Sentinel

Tool defensif untuk peneliti keamanan yang ingin melakukan pemantauan awal terhadap website yang mereka miliki izin untuk audit. Civic Sentinel tidak mengeksploitasi target, tidak brute force, dan tidak mencoba mengambil alih sistem. Ia melakukan pemeriksaan pasif dan probe ringan yang aman untuk menemukan sinyal risiko sebelum ancaman siber menjadi insiden.

## Fitur

- Validasi target dan konfirmasi otorisasi eksplisit.
- Pemeriksaan TLS: masa berlaku sertifikat, issuer, versi TLS yang dipakai.
- Pemeriksaan header keamanan: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
- Pemeriksaan cookie: flag `Secure`, `HttpOnly`, dan `SameSite`.
- Pemeriksaan HTTP method pada root melalui `OPTIONS`.
- Pemeriksaan DNS dasar: A dan AAAA melalui resolver lokal.
- Pemeriksaan file kebijakan publik: `/.well-known/security.txt` dan `/robots.txt`.
- Skor risiko, prioritas temuan, rekomendasi mitigasi, laporan JSON dan HTML.

## Instalasi

Tool ini memakai Python standard library, jadi tidak perlu dependency eksternal.

```bash
python3 -m civic_sentinel --help
```

## Contoh penggunaan

```bash
python3 -m civic_sentinel scan https://example.go.id --i-am-authorized --html report.html --json report.json
```

Untuk mode yang lebih tenang:

```bash
python3 -m civic_sentinel scan example.go.id --i-am-authorized --timeout 6
```

## Batas Etis

Gunakan hanya pada aset yang Anda miliki atau secara tertulis diizinkan untuk diuji. Tool ini dirancang untuk membantu hardening, monitoring, dan pelaporan risiko. Ia bukan alat eksploitasi, bukan alat intrusi, dan bukan alat untuk mengendalikan website pihak lain.

## Interpretasi Skor

- `0-24`: rendah
- `25-49`: sedang
- `50-74`: tinggi
- `75-100`: kritis

Skor tinggi berarti target memperlihatkan banyak sinyal pra-insiden yang sebaiknya segera ditangani.

## Struktur Proyek

```text
civic_sentinel/
  cli.py        # argumen CLI dan output terminal
  scanner.py    # orkestrasi pemeriksaan
  checks.py     # aturan deteksi dini defensif
  network.py    # HTTP, DNS, dan TLS helper
  scoring.py    # perhitungan skor risiko
  report.py     # laporan HTML
tests/          # unit test ringan
examples/       # contoh daftar target berizin
```

## Catatan Operasional

- Jalankan dari jaringan yang memang diizinkan untuk memonitor aset tersebut.
- Simpan laporan JSON untuk integrasi SIEM, ticketing, atau baseline mingguan.
- Temuan “high” dan “critical” sebaiknya diperlakukan sebagai pekerjaan hardening prioritas.
