#!/bin/bash
set -e
echo -e "\033[36m"
echo "███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗"
echo "██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║"
echo "███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║"
echo "╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║"
echo "███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗"
echo "╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝"
echo -e "\033[0m"

echo "[1/5] Hosts düzeltiliyor..."
grep -q "127.0.1.1 kali" /etc/hosts || echo "127.0.1.1 kali" >> /etc/hosts

echo "[2/5] Sistem paketleri..."
apt-get update -qq
apt-get install -y python3 python3-pip python3-venv aircrack-ng tshark -qq

echo "[3/5] Python ortamı..."
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip -q

echo "[4/5] Kütüphaneler yükleniyor..."
pip install scapy pandas numpy torch plotly joblib reportlab -q

echo "[5/5] Klasörler..."
mkdir -p core models dashboard data reports
touch core/__init__.py dashboard/__init__.py

echo ""
echo -e "\033[32m✅ Kurulum tamamlandı!\033[0m"
echo ""
echo "Komutlar:"
echo "  source venv/bin/activate"
echo "  python3 sentinel.py --demo              # Demo mod"
echo "  python3 sentinel.py --collect --demo    # 48 saat veri topla"
echo "  python3 sentinel.py --train             # Modeli eğit"
echo "  python3 sentinel.py --simulate exfiltration  # Saldırı simüle et"
echo "  Dashboard: http://localhost:8501"
