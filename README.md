# SDN Trust Abuse - Software-Defined Security Project

## Autores
- Oscar Meléndez Codina
- Jordi Solé García

## Objetivo del Proyecto

Este proyecto demuestra cómo un atacante externo puede explotar una **relación de confianza** entre hosts en una red SDN para comprometer un servidor crítico interno, y cómo un sistema de seguridad basado en SDN puede detectar, responder y recuperarse de estos ataques.

El escenario se basa en el concepto de **SDN Trust Abuse**: aunque un host interno (h2) sea de confianza para el servidor crítico (h3), si h2 es comprometido, el atacante puede usarlo como pivote para atacar h3 desde dentro, saltándose las defensas perimetrales.

---

## Arquitectura y Topología

```
                    ┌─────────────────────────────────┐
                    │         HOST MACHINE             │
                    │  Ryu Controller  │  InfluxDB     │
                    │  Snort IDS       │  Telegraf      │
                    │  Grafana         │               │
                    └──────────────────────────────────┘
                                  │ OpenFlow
                          ┌───────┴───────┐
                          │      s1        │
                          │ OVS Switch    │
                          └──┬──┬──┬──┬───┘
                             │  │  │  │
              ┌──────────────┘  │  │  └──────────────┐
              │                 │  │                  │
           ┌──┴──┐           ┌──┴──┴──┐           ┌──┴──┐
           │ h1  │           │h2   h3 │           │h4-6 │
           │Atkr │           │FE   BE │           │Dcoy │
           └─────┘           └────────┘           └─────┘
```

### Hosts

| Host | IP | Rol | Servicios |
|------|----|-----|-----------|
| h1 | 10.0.0.10 | Atacante externo | - |
| h2 | 10.0.0.20 | Frontend web (DMZ) | HTTP:80, SSH:22 (misconfigured) |
| h3 | 10.0.0.30 | Backend crítico | HTTP:80 (solo desde h2) |
| h4 | 10.0.0.40 | Decoy mail server | SMTP:25 |
| h5 | 10.0.0.50 | Decoy FTP server | FTP:21 |
| h6 | 10.0.0.60 | Decoy DNS server | DNS:53 |
| admin | 10.0.0.100 | Administrador trusted | - |

### Narrativa del Escenario

**h2** es un servidor web frontend que actúa como proxy hacia **h3** (backend crítico con datos sensibles). Los usuarios externos solo ven h2; h3 no es accesible directamente desde el exterior.

La **misconfiguration** es que el puerto SSH de h2 está abierto a cualquier IP en lugar de solo al host administrador. Esto permite que un atacante haga brute force y comprometa h2.

Una vez dentro de h2, el atacante descubre que h2 reenvía peticiones a h3 (leyendo `proxy_h2.py`) y lanza un ataque interno aprovechando la relación de confianza.

---

## Componentes de Seguridad

### Snort (IDS)
- Escucha en interfaz `s1-snort` (mirror OVS de todo el tráfico del switch)
- Detecta: floods ICMP/TCP, port scans, SSH brute force, floods internos h2→h3
- Envía alertas al controlador Ryu via Unix socket

### Ryu Controller
- Controlador OpenFlow 1.3
- Recibe alertas de Snort y aplica contramedidas automáticas
- API REST en puerto 8080 para acciones manuales del administrador

### Lógica de Defensa

```
Flood externo (h1) detectado
    → Ryu bloquea h1 hacia TODA la red (permanente)
    → Recovery manual: POST /blacklist/remove/h1

SSH Brute Force (h1) detectado
    → Ryu bloquea h1 hacia TODA la red (permanente)
    → Recovery manual: POST /blacklist/remove/h1

Internal Flood (h2→h3) - 1er ataque
    → Ryu revoca confianza h2 temporalmente (15s)
    → Recovery automático tras 15s

Internal Flood (h2→h3) - 2do ataque
    → Ryu bloquea h2→h3 PERMANENTEMENTE
    → Recovery manual: POST /trust/restore/h2

Medidas correctivas manuales:
    → Rate limit h2→h3: POST /ratelimit/h2-h3
    → Restringir SSH solo a admin: POST /firewall/ssh/restrict
```

### InfluxDB + Telegraf + Grafana
- Telegraf recibe métricas via UDP 8094
- InfluxDB almacena: port stats, flow stats, snort alerts, ryu events
- Grafana visualiza en tiempo real

---

## Estructura del Repositorio

```
SDS_Project/
├── README.md                    # Este fichero
├── INSTALL.md                   # Instrucciones de instalación
├── DEMO.md                      # Guía de la demo (ataques paso a paso)
├── GRAFANA.md                   # Instrucciones para configurar Grafana
├── setup.sh                     # Script de instalación automática
├── cleanup_snort.sh             # Script de limpieza
├── SDNTrustTopo.py              # Topología Mininet
├── start_network.py             # Script de arranque de la red
├── sdn_trust_controller.py      # Controlador Ryu
├── proxy_h2.py                  # Proxy HTTP en h2
├── users.txt                    # Wordlist usuarios (brute force demo)
├── passwords.txt                # Wordlist contraseñas (brute force demo)
└── config/
    ├── Myrules.rules            # Reglas Snort custom
    ├── snort.conf               # Configuración Snort
    └── telegraf.conf            # Configuración Telegraf
```

