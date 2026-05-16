# Grafana - Configuración y Dashboards

## Requisitos Previos

Antes de configurar Grafana, asegúrate de que:
- InfluxDB está corriendo: `sudo systemctl status influxdb`
- Telegraf está corriendo: `sudo systemctl status telegraf`
- El proyecto está arrancado y hay datos en InfluxDB:

```bash
influx
use RYU
show measurements
# Deberías ver: flows, ports, snort_alerts, ryu_events
```

---

## Acceder a Grafana

```
URL: http://localhost:3000
Usuario: admin
Contraseña: admin
```

---

## Configurar DataSource

1. Click en el icono de configuración (engranaje) → **Data Sources**
2. Click **Add data source**
3. Seleccionar **InfluxDB**
4. Configurar:
   - URL: `http://localhost:8086`
   - Database: `RYU`
   - Sin usuario ni contraseña
5. Click **Save & Test** → debe aparecer "Data source is working"

---

## Datos disponibles en InfluxDB

### Measurement: `ports`
Tráfico por puerto del switch (cada 10 segundos).

| Campo | Descripción |
|-------|-------------|
| `rx-bytes` | Bytes recibidos |
| `tx-bytes` | Bytes transmitidos |
| `rx-pkts` | Paquetes recibidos |
| `tx-pkts` | Paquetes transmitidos |
| `rx-error` | Errores recibidos |
| `tx-error` | Errores transmitidos |

Tags: `datapath`, `port`

Puertos del switch:
- Puerto 1 → h1 (atacante)
- Puerto 2 → h2 (frontend)
- Puerto 3 → h3 (backend)
- Puerto 4 → h4 (mail)
- Puerto 5 → h5 (ftp)
- Puerto 6 → h6 (dns)
- Puerto 7 → admin
- Puerto 8 → s1-snort (mirror)

### Measurement: `flows`
Estadísticas de flow entries OpenFlow.

| Campo | Descripción |
|-------|-------------|
| `packets` | Paquetes que han hecho match |
| `bytes` | Bytes que han hecho match |

### Measurement: `snort_alerts`
Alertas generadas por Snort.

| Campo | Descripción |
|-------|-------------|
| `value` | Siempre 1 (contador) |

Tags: `type` (tipo de alerta)

Valores posibles de `type`:
- `External_ICMP_Flood_detected`
- `External_TCP_Flood_detected`
- `Nmap_SYN_Scan_detected`
- `Port_Scan_-_multiple_ports`
- `SSH_Port_Scan_detected`
- `SSH_Brute_Force_detected`
- `Internal_ICMP_Flood_h2_to_h3`
- `Internal_TCP_Flood_h2_to_h3`

### Measurement: `ryu_events`
Eventos del controlador Ryu (bloqueos, recoveries).

| Campo | Descripción |
|-------|-------------|
| `value` | Siempre 1 (contador) |

Tags: `event`

Valores posibles de `event`:
- `block_h1` → h1 bloqueado
- `unblock_h1` → h1 desbloqueado
- `h2_trust_revoked` → confianza h2 revocada
- `h2_blocked_permanent` → h2 bloqueado permanentemente
- `h2_auto_recovery` → recovery automático h2
- `h2_manual_recovery` → recovery manual h2
- `rate_limit_installed` → rate limit instalado
- `rate_limit_removed` → rate limit eliminado
- `ssh_restricted` → SSH restringido a admin

---

## Dashboards Sugeridos

### Dashboard: SDN Trust Abuse - Security Overview

#### Panel 1: Tráfico por Puerto (rx-bytes)
```sql
SELECT mean("rx-bytes") FROM "ports" WHERE $timeFilter GROUP BY time($__interval), "port"
```
- Tipo: **Graph**
- Útil para ver el spike de tráfico durante los floods

#### Panel 2: Tráfico por Puerto (tx-bytes)
```sql
SELECT mean("tx-bytes") FROM "ports" WHERE $timeFilter GROUP BY time($__interval), "port"
```
- Tipo: **Graph**

#### Panel 3: Alertas Snort por Tipo
```sql
SELECT count("value") FROM "snort_alerts" WHERE $timeFilter GROUP BY time($__interval), "type" fill(0)
```
- Tipo: **Graph** o **Bar chart**
- Útil para ver qué tipos de ataques se detectan

#### Panel 4: Eventos Ryu
```sql
SELECT count("value") FROM "ryu_events" WHERE $timeFilter GROUP BY time($__interval), "event" fill(0)
```
- Tipo: **Graph**
- Útil para ver cuándo Ryu actúa (bloqueos, recoveries)

#### Panel 5: Total Alertas Snort (stat)
```sql
SELECT count("value") FROM "snort_alerts" WHERE $timeFilter
```
- Tipo: **Stat**
- Muestra el total de alertas en el periodo seleccionado

#### Panel 6: Estado actual del sistema
Crear un panel de texto con las instrucciones de la API REST para referencia rápida durante la demo.

---

## Configuración recomendada para la demo

- **Time range:** Last 15 minutes
- **Auto-refresh:** 5s
- Poner Grafana en pantalla completa durante la demo para ver los eventos en tiempo real

---

## Prompt para Claude (continuar configuración)

Si necesitas ayuda para configurar Grafana, puedes usar el siguiente prompt en un nuevo chat:

---

Estoy configurando Grafana para visualizar métricas de un proyecto SDN de seguridad llamado **SDN Trust Abuse**. 

El stack es: Mininet + Ryu + Snort + InfluxDB (base de datos: RYU) + Telegraf + Grafana.

Los datos en InfluxDB son:
- **ports** (tags: datapath, port) → campos: rx-bytes, tx-bytes, rx-pkts, tx-pkts, rx-error, tx-error. Tráfico por puerto del switch OVS, cada 10s.
- **flows** (tags: datapath) → campos: packets, bytes. Flow entries OpenFlow.
- **snort_alerts** (tags: type) → campo: value=1. Alertas de Snort. Tipos: External_ICMP_Flood_detected, External_TCP_Flood_detected, Nmap_SYN_Scan_detected, Port_Scan_multiple_ports, SSH_Port_Scan_detected, SSH_Brute_Force_detected, Internal_ICMP_Flood_h2_to_h3, Internal_TCP_Flood_h2_to_h3.
- **ryu_events** (tags: event) → campo: value=1. Eventos del controlador. Tipos: block_h1, unblock_h1, h2_trust_revoked, h2_blocked_permanent, h2_auto_recovery, h2_manual_recovery, rate_limit_installed, ssh_restricted.

La topología tiene estos puertos en el switch:
- Puerto 1 → h1 (atacante, 10.0.0.10)
- Puerto 2 → h2 (frontend web, 10.0.0.20)
- Puerto 3 → h3 (backend crítico, 10.0.0.30)
- Puerto 4 → h4 (mail decoy, 10.0.0.40)
- Puerto 5 → h5 (ftp decoy, 10.0.0.50)
- Puerto 6 → h6 (dns decoy, 10.0.0.60)
- Puerto 7 → admin (10.0.0.100)
- Puerto 8 → s1-snort (mirror Snort)

Quiero crear un dashboard en Grafana que muestre:
1. Tráfico por puerto en tiempo real (para ver spikes durante floods)
2. Alertas de Snort agrupadas por tipo
3. Eventos de Ryu (bloqueos y recoveries)
4. Algún panel de estado del sistema

Ayúdame a configurar los paneles con las queries correctas para InfluxDB 1.8 y Grafana 7.4.

---

