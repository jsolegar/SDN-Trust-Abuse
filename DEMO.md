# Demo - SDN Trust Abuse

## Arranque del Sistema

### Terminal 1 - Ryu Controller
```bash
cd ~/SDS_Project
sudo ryu-manager sdn_trust_controller.py
```
Esperar hasta ver: `[snort][INFO] Unix socket start listening...`

### Terminal 2 - Mininet
```bash
cd ~/SDS_Project
sudo python3 start_network.py
```
Esperar hasta ver: `Red lista. Lanza Snort en otra terminal`

### Terminal 3 - Snort
```bash
sudo snort -i s1-snort -A unsock -N -l /tmp -c /etc/snort/snort.conf
```

### Verificar estado inicial
```bash
curl http://localhost:8080/trust/status
```
Esperado:
```json
{"trust_state": {"10.0.0.20": "ok"}, "attack_count": {"10.0.0.20": 0}, "blacklist_h1": [], "ssh_restricted": false, "rate_limit_installed": false}
```

---

## DEMO 1 - Reconocimiento (Scan)

### 1.1 Scan rápido de la red (detectado por Snort)
```bash
mininet> h1 nmap -sS --top-ports 10 -Pn 10.0.0.0/24
```
**Resultado esperado en el scan:**
- h2 → puerto 22 `open`, puerto 80 `open` ← objetivo del atacante
- h3 → todo `filtered` ← backend oculto
- h4 → puerto 25 `open` (mail)
- h5 → puerto 21 `open` (ftp)
- h6 → puerto 53 `open` (dns)
- admin → todo `filtered`

**Resultado esperado en Snort (Terminal 3):**
```
[SNORT ALERT] Port Scan - multiple ports
[SNORT ALERT] Nmap SYN Scan detected
[SNORT ALERT] SSH Port Scan detected
```
> Snort detecta pero Ryu NO bloquea. El scan no es suficiente para bloquear.

---

## DEMO 2 - Flood Externo (Detectado y Bloqueado)

### 2.1 Verificar conectividad inicial
```bash
mininet> h1 ping -c 3 10.0.0.20    # OK
mininet> h1 ping -c 3 10.0.0.30    # 100% loss (h3 bloqueado por iptables)
```

### 2.2 ICMP Flood a h2
```bash
mininet> h1 hping3 -V -1 -d 1400 --faster 10.0.0.20
```
**Resultado esperado en Ryu (Terminal 1):**
```
[SNORT ALERT] External ICMP Flood detected
[BLOCK] Bloqueando h1 (10.0.0.10) hacia toda la red
```

### 2.3 Verificar bloqueo
```bash
curl http://localhost:8080/trust/status
# blacklist_h1: ["10.0.0.10"]

mininet> h1 ping -c 3 10.0.0.20    # 100% loss - bloqueado
mininet> h1 ping -c 3 10.0.0.40    # 100% loss - bloqueado en toda la red
sudo ovs-ofctl dump-flows s1        # Ver regla DROP priority=10
```

### 2.4 Recovery manual
```bash
curl -X POST http://localhost:8080/blacklist/remove/h1
mininet> h1 ping -c 3 10.0.0.20    # OK de nuevo
```

### 2.5 TCP Flood a h4 (mail server)
```bash
mininet> h1 hping3 -S -p 25 -d 1400 --faster 10.0.0.40
```
**Resultado esperado:**
```
[SNORT ALERT] External TCP Flood detected
[BLOCK] Bloqueando h1 (10.0.0.10) hacia toda la red
```

### 2.6 Recovery manual
```bash
curl -X POST http://localhost:8080/blacklist/remove/h1
```

---

## DEMO 3 - Initial Access (Brute Force SSH)

### 3.1 Brute force rápido (detectado y bloqueado)
```bash
mininet> h1 hydra -L users.txt -P passwords.txt ssh://10.0.0.20 -f
```
**Resultado esperado en Ryu:**
```
[SNORT ALERT] SSH Brute Force detected
[BLOCK] Bloqueando h1 (10.0.0.10) hacia toda la red
```

### 3.2 Recovery manual
```bash
curl -X POST http://localhost:8080/blacklist/remove/h1
```

### 3.3 Brute force lento (evade Snort)
```bash
mininet> h1 hydra -L users.txt -P passwords.txt ssh://10.0.0.20 -t 4 -f
```
**Resultado esperado:**
- Snort NO alerta ← evade el IDS
- Hydra encuentra credenciales: `login: sdsh2 password: sds`

---

## DEMO 4 - Reconocimiento interno y Trust Abuse

### 4.1 Conectar a h2 por SSH (desde terminal del host)
```bash
ssh sdsh2@10.0.0.20
```

### 4.2 Reconocimiento interno desde h2 comprometido
```bash
# Desde la sesión SSH en h2
ls ~
cat ~/proxy_h2.py    # ← Descubre que h2 reenvía peticiones a 10.0.0.30 (h3)
```

### 4.3 Confirmar que h1 NO puede llegar a h3
```bash
# En una terminal de Mininet (mientras SSH está abierto)
mininet> h1 ping -c 3 10.0.0.30    # 100% loss - h1 no sabe que existe h3
```

### 4.4 Primer flood interno h2→h3 (revocación temporal)
```bash
# Desde la sesión SSH en h2
sudo hping3 -V -1 -d 1400 --faster 10.0.0.30
```
**Resultado esperado en Ryu:**
```
[SNORT ALERT] Internal ICMP Flood h2 to h3
[TRUST] h2 confianza REVOCADA temporalmente (ataque #1)
[FLOW] Regla DROP instalada: h2 -> h3
```

### 4.5 Verificar estado
```bash
curl http://localhost:8080/trust/status
# trust_state: {"10.0.0.20": "revoked"}
# attack_count: {"10.0.0.20": 1}
```

### 4.6 Esperar recovery automático (15 segundos)
```bash
# Esperar 15 segundos...
curl http://localhost:8080/trust/status
# trust_state: {"10.0.0.20": "ok"}
```
**Resultado esperado en Ryu:**
```
[RECOVERY] h2 confianza RESTAURADA automáticamente
```

### 4.7 Segundo flood interno h2→h3 (bloqueo permanente)
```bash
# Desde la sesión SSH en h2
sudo hping3 -S -p 80 -d 1400 --faster 10.0.0.30
```
**Resultado esperado en Ryu:**
```
[SNORT ALERT] Internal TCP Flood h2 to h3
[TRUST] h2 BLOQUEADO PERMANENTEMENTE (ataque #2)
```

### 4.8 Verificar bloqueo permanente
```bash
curl http://localhost:8080/trust/status
# trust_state: {"10.0.0.20": "blocked"}
# attack_count: {"10.0.0.20": 2}

sudo ovs-ofctl dump-flows s1    # Ver regla DROP h2->h3
```

---

## DEMO 5 - Medidas Correctivas

### 5.1 Instalar rate limit h2→h3
```bash
curl -X POST http://localhost:8080/ratelimit/h2-h3
```
**Resultado esperado en Ryu:**
```
[RATE LIMIT] Instalado: h2->h3 max 1Mbps
```

### 5.2 Restringir SSH solo a admin (corregir misconfiguration)
```bash
curl -X POST http://localhost:8080/firewall/ssh/restrict
```
**Resultado esperado en Ryu:**
```
[SSH] Restringiendo SSH h2 solo a 10.0.0.100
```

### 5.3 Verificar SSH restringido
```bash
mininet> h1 ssh sdsh2@10.0.0.20    # Bloqueado por Ryu
mininet> admin ssh sdsh2@10.0.0.20  # OK - solo admin puede conectarse
```

### 5.4 Recovery manual h2
```bash
curl -X POST http://localhost:8080/trust/restore/h2
curl http://localhost:8080/trust/status
# trust_state: {"10.0.0.20": "ok"}
# attack_count: {"10.0.0.20": 0}
```

---

## Verificaciones Finales

```bash
# Estado completo del sistema
curl http://localhost:8080/trust/status

# Flow rules instaladas en OVS
sudo ovs-ofctl dump-flows s1

# Ver datos en InfluxDB
influx
use RYU
show measurements
select * from ryu_events where time > now()-1h
select * from snort_alerts where time > now()-1h
```

---

## Limpieza

```bash
# En Mininet
mininet> exit

# En Terminal 3
sudo pkill snort

# Limpiar OVS y Mininet
sudo ./cleanup_snort.sh
```

---

## Referencia de Endpoints REST

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| GET | `/trust/status` | Estado completo del sistema |
| POST | `/blacklist/remove/h1` | Desbloquear h1 |
| POST | `/trust/restore/h2` | Recovery manual h2 |
| POST | `/ratelimit/h2-h3` | Instalar rate limit |
| POST | `/ratelimit/remove/h2-h3` | Eliminar rate limit |
| POST | `/firewall/ssh/restrict` | Restringir SSH solo a admin |

