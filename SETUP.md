# iocscan — Kurulum ve Silme Rehberi

Bu dosya, iocscan projesinin geliştirilmesi sırasında bilgisayara **ne kurulduğunu** ve projeyi sildiğinde **sadece bu projeye özel olanları nasıl temizleyeceğini** gösterir. Genel kullanımda olan (başka projelerin de kullandığı) şeylere DOKUNULMAZ.

Hedef sistem: macOS (Darwin), zsh shell.

---

## 1. Kurulan Şeyler

### A. Sistem seviyesinde (HER yerden kullanılır — silmeyeceğiz)

Bu paketler büyük ihtimalle bilgisayarında zaten kurulu ve başka projeler için de kullanılıyor. iocscan kaldırılırken bunlara **dokunmuyoruz**:

| Şey | Kontrol komutu | Açıklama |
|-----|----------------|----------|
| Python 3.13 | `python3 --version` | `/Library/Frameworks/Python.framework/Versions/3.13/` altında, sistem geneli |
| git | `git --version` | Versiyon kontrol |
| gh (GitHub CLI) | `gh --version` | PR'lar için kullandık |

> Not: Bunları silmek istersen, başka projelerini etkileyebilir. Bu rehber **dokunmaz**.

### B. Yalnızca iocscan için (silinebilir)

Bu klasörler ve dosyalar tamamen iocscan'e özel. Proje silinirken bunlar da silinir:

```
/Users/garfield/Programs/iocscan/.venv/        # Python sanal ortamı — projeye özel
/Users/garfield/Programs/iocscan/              # Kaynak kod, testler, docs
/Users/garfield/.iocscan/                      # Çalışma sırasında oluşan config + cache
  ├── config.toml                              # API key'ler (chmod 0600)
  ├── cache.db                                 # SQLite TI sonuç cache'i
  └── tranco-1k.txt                            # Whitelist için Tranco top-1K kopyası
```

### C. Sanal ortam (.venv) içindeki Python paketleri

`pyproject.toml` dosyasında tanımlı. Hepsi `.venv/` klasörü içinde, **sistem Python'ını etkilemez**:

**Runtime:**
- `httpx[http2]>=0.27,<0.29` — HTTP istemcisi
- `rich>=13.7,<15` — Terminal tablo render
- `tomli-w>=1.0,<2` — TOML yazma (`tomllib` okumayı standart kütüphane sağlıyor)

**Dev (testler için):**
- `pytest>=8.0,<9`
- `pytest-asyncio>=0.23,<0.30`
- `pytest-cov>=4.1,<7`

**Transitif (otomatik gelen):**
anyio, certifi, h11, h2, hpack, httpcore, hyperframe, idna, iniconfig, markdown-it-py, mdurl, packaging, pluggy, Pygments, coverage

> Not: `.venv/` silinince hepsi gider, sistem Python'ını etkilemez. Korkma.

### D. GitHub remote'u

- Repo: `git@github.com:erhanersoyy/iocscan.git`
- SSH kullanıyor (HTTPS fallback ile)

---

## 2. İlk kurulumda hangi komutlar çalıştı?

Sırasıyla:

```bash
# Proje klasörünü oluştur
mkdir -p ~/Programs/iocscan && cd ~/Programs/iocscan

# Python sanal ortamı kur (.venv klasörü oluşur)
python3 -m venv .venv

# Sanal ortamı aktive et (her terminal oturumunda yeniden gerekir)
source .venv/bin/activate

# iocscan'ı editable modda kur (kod değişiklikleri anında yansır)
.venv/bin/pip install -e ".[dev]"

# Testleri çalıştır
.venv/bin/python -m pytest tests/ -q

# (İsteğe bağlı) API key'lerini config'e ekle
iocscan config set virustotal AAAAA...
iocscan config set otx BBBBB...
# vs.

# Tranco top-1K whitelist'ini indir (ilk kullanım öncesi)
iocscan whitelist update
```

---

## 3. Sadece iocscan'i Sil (Adım Adım)

Aşağıdaki adımlar **sıralı** çalıştırılmalı. Her komut bir önceki tamamlandıktan sonra.

### Adım 1 — Kullanıcı verilerini sil (API key'ler + cache)

```bash
# DİKKAT: bu komut config.toml'daki API key'lerini siler. Önce yedek alabilirsin:
cp ~/.iocscan/config.toml ~/iocscan-config-backup.toml  # (opsiyonel yedek)

rm -rf ~/.iocscan/
```

**Ne yaptık:** `~/.iocscan/` altındaki cache.db, config.toml, tranco-1k.txt — hepsi gitti. Sistem geneli bir şeye dokunmadık.

### Adım 2 — Sanal ortamı sil (.venv)

```bash
cd ~/Programs/iocscan
rm -rf .venv/
```

**Ne yaptık:** `.venv/` içindeki httpx, rich, pytest vs. — hepsi gitti. Sistem Python'ı etkilenmedi.

**Doğrulama:**
```bash
.venv/bin/python --version  # Hata vermeli — .venv yok artık
python3 -c "import httpx"   # Sistem Python'ında ya zaten yok ya da varsa başka proje için — bizim sildiğimiz değildi
```

### Adım 3 — Proje klasörünü sil

```bash
cd ~
rm -rf ~/Programs/iocscan/
```

**Ne yaptık:** Tüm kaynak kod, testler, docs, git geçmişi (lokal) silindi.

### Adım 4 — GitHub remote'u temizle (opsiyonel)

Remote repo silinmez, sen istersen GitHub'dan elle silebilirsin:
```bash
gh repo delete erhanersoyy/iocscan --yes
```
**Bu eylem geri alınamaz**, dikkat. Çoğu durumda repo kalsın — referans olarak işine yarayabilir.

### Adım 5 — Doğrula (hiçbir iz kalmadı mı?)

```bash
ls ~/.iocscan/        # No such file or directory
ls ~/Programs/iocscan # No such file or directory
which iocscan         # iocscan not found (sanal ortam silindi)
```

Bu üç komut "yok" dediyse: temiz.

---

## 4. Korunan Şeyler (Silinmedi)

Bu rehber takip edildiğinde aşağıdakiler **bilgisayarında kalır** (başka projeler kullanabilir):

- Python 3.13 (sistem)
- git, gh, pip
- Homebrew, Xcode CLT, vs.
- `~/.ssh/` (GitHub SSH anahtarları)
- `~/.gitconfig`
- Diğer projelerinin `.venv`'leri

---

## 5. Tekrar kurmak istersem?

Bu dosyanın 2. bölümündeki komutları sırayla çalıştır. ~5 dakika sürer.
