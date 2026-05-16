# Instalación y Configuración

## Requisitos Previos

- Ubuntu 20.04 o superior
- Python 3.8+
- Acceso sudo

---

## Instalación Automática

```bash
chmod +x setup.sh
sudo ./setup.sh
```

El script instala y configura todo automáticamente. Si prefieres hacerlo manualmente, sigue los pasos a continuación.

---

## Instalación Manual

### 1. Dependencias del sistema

```bash
sudo apt-get update
sudo apt-get install -y \
    mininet \
    openvswitch-switch \
    snort \
    nmap \
    hping3 \
    hydra \
    python3-pip \
    net-tools
```

### 2. Ryu Controller

```bash
pip3 install ryu --break-system-packages
# o
pip3 install ryu
```

### 3. InfluxDB 1.8

```bash
wget https://dl.influxdata.com/influxdb/releases/influxdb_1.8.4_amd64.deb
sudo dpkg -i influxdb_1.8.4_amd64.deb
sudo apt-get install -y python3-influxdb
rm influxdb_1.8.4_amd64.deb
sudo systemctl enable influxdb
sudo systemctl start influxdb
```

### 4. Telegraf

```bash
wget https://dl.influxdata.com/telegraf/releases/telegraf_1.17.3-1_amd64.deb
sudo dpkg -i telegraf_1.17.3-1_amd64.deb
rm telegraf_1.17.3-1_amd64.deb
```

Copiar configuración:
```bash
sudo mv /etc/telegraf/telegraf.conf /etc/telegraf/telegraf.conf.bup
sudo cp config/telegraf.conf /etc/telegraf/telegraf.conf
sudo systemctl enable telegraf
sudo systemctl restart telegraf
```

### 5. Grafana

```bash
sudo apt-get install -y libfontconfig1
wget https://dl.grafana.com/oss/release/grafana_7.4.3_amd64.deb
sudo dpkg -i grafana_7.4.3_amd64.deb
rm grafana_7.4.3_amd64.deb
sudo systemctl enable grafana-server
sudo systemctl start grafana-server
```

### 6. Configurar Snort

Copiar reglas custom:
```bash
sudo cp config/Myrules.rules /etc/snort/rules/Myrules.rules
sudo cp config/snort.conf /etc/snort/snort.conf
```

### 7. Crear usuario sdsh2 (víctima del brute force)

```bash
sudo useradd -m sdsh2
echo "sdsh2:sds" | sudo chpasswd
sudo usermod -aG sudo sdsh2
```

### 8. Permisos de ejecución

```bash
chmod +x setup_snort_mirror.sh
chmod +x cleanup_snort.sh
chmod +x start_network.py
```

---

## Verificación de la instalación

```bash
# Verificar Mininet
sudo mn --version

# Verificar Ryu
ryu-manager --version

# Verificar Snort
snort --version

# Verificar InfluxDB
sudo systemctl status influxdb

# Verificar Telegraf
sudo systemctl status telegraf

# Verificar Grafana
sudo systemctl status grafana-server
```

---

## Estructura de directorios esperada

```
~/SDS_Project/
├── SDNTrustTopo.py
├── start_network.py
├── sdn_trust_controller.py
├── proxy_h2.py
├── users.txt
├── passwords.txt
├── cleanup_snort.sh
└── config/
    ├── Myrules.rules
    ├── snort.conf
    └── telegraf.conf
```

Asegúrate de que el proyecto esté en `~/SDS_Project/` ya que algunos scripts usan rutas absolutas.

