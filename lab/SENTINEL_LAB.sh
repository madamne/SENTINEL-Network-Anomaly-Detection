#!/usr/bin/env bash
# SENTINEL — Tam Lab Başlatıcı
# Çalıştırır: Dashboard + Demo + Testleri

set -e
cd /home/kali/sentinel
source venv/bin/activate

# Renk kodları
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'

echo -e "${CYAN}"
cat << 'EOF'
███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
EOF
echo -e "${YELLOW}  Network Behavioral Anomaly Detection System${NC}"
echo -e "${YELLOW}  Bilgisayar Mühendisliği Bitirme Projesi${NC}\n"

echo -e "${BOLD}[1/4] Veritabanı hazırlanıyor...${NC}"
python3 -c "import sys; sys.path.insert(0,'.'); from core.database import init_db; init_db()"
echo -e "${GREEN}      ✓ DB hazır${NC}"

echo -e "\n${BOLD}[2/4] Dashboard başlatılıyor...${NC}"
pkill -f "uvicorn.*8501" 2>/dev/null || true
sleep 0.5
nohup python3 -m uvicorn dashboard.api:app \
    --host 0.0.0.0 --port 8501 --log-level error \
    >> /tmp/sentinel_dash.log 2>&1 &
sleep 2
if pgrep -f "uvicorn.*8501" > /dev/null; then
    echo -e "${GREEN}      ✓ Dashboard → http://192.168.111.131:8501${NC}"
else
    echo -e "${RED}      ✗ Dashboard başlamadı. Log: /tmp/sentinel_dash.log${NC}"
fi

echo -e "\n${BOLD}[3/4] Demo simülasyonu başlatılıyor...${NC}"
echo -e "      4 saldırı tipi sırayla çalışacak (~40 sn)\n"
python3 sentinel.py --demo --no-dashboard &
DEMO_PID=$!

echo -e "\n${BOLD}[4/4] Demo tamamlanınca otomatik test çalışır.${NC}"
echo -e "      Dashboard: ${CYAN}http://192.168.111.131:8501${NC}"
echo -e "      Durdurmak için: ${YELLOW}Ctrl+C${NC}\n"

# Demo bitmesini bekle
wait $DEMO_PID 2>/dev/null || true

echo -e "\n${BOLD}[TEST] Otomatik test çalıştırılıyor...${NC}"
python3 run_tests.py 2>&1 | tail -20

echo -e "\n${GREEN}${BOLD}SENTINEL Lab oturumu tamamlandı.${NC}"
echo -e "Dashboard hâlâ çalışıyor: ${CYAN}http://192.168.111.131:8501${NC}"
echo -e "Durdurmak: ${YELLOW}pkill -f uvicorn${NC}\n"
