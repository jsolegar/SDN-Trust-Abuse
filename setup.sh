#!/bin/bash
# =============================================================
# SDN Trust Abuse - Setup Script
# Ejecutar como: sudo ./setup.sh
# =============================================================

set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==================================================="
echo " SDN Trust Abuse - Setup"
echo "==================================================="

# ==================================================
# 1. Dependencias del sistema
# ==================================================
echo ""
echo "=== [1/8] Instalando dependencias del sistema ==="
apt-get update -qq
apt-get install -y \
    \
    openvswitch-switch \
    snort \
    nmap \
    hping3 \
    hydra \
    python3-pip \
    net-tools \
    libfontconfig1

# ==================================================
# 2. Ryu
# ==================================================
echo ""
echo "=== [2/8] Instalando Ryu ==="
# pip3 install ryu 2>/dev/null || pip3 install ryu --break-system-packages

# ==================================================
# 3. InfluxDB
# ==================================================
echo ""
echo "=== [3/8] Instalando InfluxDB ==="
if ! command -v influx &> /dev/null; then
    wget -q https://dl.influxdata.com/influxdb/releases/influxdb_1.8.4_amd64.deb
    dpkg -i influxdb_1.8.4_amd64.deb
    apt-get install -y python3-influxdb
    rm influxdb_1.8.4_amd64.deb
fi
systemctl enable influxdb
systemctl start influxdb

# ==================================================
# 4. Telegraf
# ==================================================
echo ""
echo "=== [4/8] Instalando Telegraf ==="
if ! command -v telegraf &> /dev/null; then
    wget -q https://dl.influxdata.com/telegraf/releases/telegraf_1.17.3-1_amd64.deb
    dpkg -i telegraf_1.17.3-1_amd64.deb
    rm telegraf_1.17.3-1_amd64.deb
fi
mv /etc/telegraf/telegraf.conf /etc/telegraf/telegraf.conf.bup 2>/dev/null || true
cp "$PROJECT_DIR/config/telegraf.conf" /etc/telegraf/telegraf.conf
systemctl enable telegraf
systemctl restart telegraf

# ==================================================
# 5. Grafana
# ==================================================
echo ""
echo "=== [5/8] Instalando Grafana ==="
if ! command -v grafana-server &> /dev/null; then
    wget -q https://dl.grafana.com/oss/release/grafana_7.4.3_amd64.deb
    dpkg -i grafana_7.4.3_amd64.deb
    rm grafana_7.4.3_amd64.deb
fi
systemctl enable grafana-server
systemctl start grafana-server

# ==================================================
# 6. Configurar Snort
# ==================================================
echo ""
echo "=== [6/8] Configurando Snort ==="
cp "$PROJECT_DIR/config/Myrules.rules" /etc/snort/rules/Myrules.rules
cp "$PROJECT_DIR/config/snort.conf" /etc/snort/snort.conf
echo "Snort configurado."

# ==================================================
# 7. Crear usuario sdsh2
# ==================================================
echo ""
echo "=== [7/8] Creando usuario sdsh2 ==="
if ! id "sdsh2" &>/dev/null; then
    useradd -m sdsh2
    echo "sdsh2:sds" | chpasswd
    usermod -aG sudo sdsh2
    echo "Usuario sdsh2 creado (password: sds)"
else
    echo "Usuario sdsh2 ya existe"
fi

# ==================================================
# 8. Permisos
# ==================================================
echo ""
echo "=== [8/8] Configurando permisos ==="
chmod +x "$PROJECT_DIR/cleanup_snort.sh"
chmod +x "$PROJECT_DIR/start_network.py"

# ==================================================
# Verificación final
# ==================================================
echo ""
echo "==================================================="
echo " Verificación de servicios:"
echo "==================================================="
systemctl is-active influxdb && echo "✓ InfluxDB corriendo" || echo "✗ InfluxDB no está corriendo"
systemctl is-active telegraf && echo "✓ Telegraf corriendo" || echo "✗ Telegraf no está corriendo"
systemctl is-active grafana-server && echo "✓ Grafana corriendo" || echo "✗ Grafana no está corriendo"
command -v ryu-manager &>/dev/null && echo "✓ Ryu instalado" || echo "✗ Ryu no instalado"
command -v snort &>/dev/null && echo "✓ Snort instalado" || echo "✗ Snort no instalado"
command -v mn &>/dev/null && echo "✓ Mininet instalado" || echo "✗ Mininet no instalado"

echo ""
echo "==================================================="
echo " Setup completado."
echo " Proyecto en: $PROJECT_DIR"
echo " Siguiente paso: ver DEMO.md"
echo "==================================================="

