# 🛡️ HoneyPI — SOC Lab: Honeypot + IA en Raspberry Pi 5

Laboratorio casero de ciberseguridad defensiva: un honeypot SSH/Telnet (Cowrie) expuesto a internet, con captura real de payloads, análisis de cada ataque por IA (local y/o vía API), enriquecimiento de IPs (geolocalización + reputación), alertas en tiempo real por Telegram, y dos dashboards (uno local, uno público en la nube) — todo corriendo sobre una Raspberry Pi 5.

📡 **Dashboard público en vivo**: https://honeypi-soc-lab.streamlit.app/
📄 **Serie de artículos**: [Capítulo 1](https://www.linkedin.com/pulse/honeypi-un-soc-casero-con-ia-local-cap%C3%ADtulo-1-pablo-rattin-ntrwf/) · [Capítulo 2](https://www.linkedin.com/pulse/honeypi-un-soc-casero-con-ia-local-cap%C3%ADtulo-2-cuando-el-pablo-rattin-wsxpf) · Capítulo 3 y 4 (próximamente)
📬 **Newsletter**: [HoneyPI Lab en LinkedIn](https://www.linkedin.com/build-relation/newsletter-follow?entityUrn=7497451464810786816)

---

## Arquitectura

```
Internet
   │
   ▼
Router (port forwarding 22, 23)
   │
   ▼
Raspberry Pi 5 (Argon ONE V3, Raspberry Pi OS Lite 64-bit)
   │
   ├── UFW (deny incoming por defecto, allow 2222 admin)
   ├── SSH real de administración ── puerto 2222
   │
   ├── Docker
   │     └── Cowrie (honeypot SSH/Telnet) ── puertos 22, 23
   │           └── Captura real de payloads (wget/curl/ftpget)
   │
   ├── Ollama (systemd) ── puerto 11434 ── Llama 3.2 (3B), usado para
   │     benchmarks locales y como alternativa gratuita/offline
   │
   ├── analista_ia_claude.py (systemd: analista.service)
   │     lee logs de Cowrie en vivo → detecta comandos reales →
   │     consulta la API de Claude (claude-haiku-4-5) pidiendo
   │     JSON estructurado (táctica/técnica MITRE ATT&CK + severidad) →
   │     protección anti-ráfaga (dedupe 60s) + circuit breaker
   │     (pausa el análisis si hay >30 eventos/60s) + rate limit
   │     propio de Telegram (máx. 5 alertas/min) →
   │     alerta SOLO en comandos genuinamente nuevos →
   │     registra temperatura/throttling → guarda en incidentes.json
   │
   ├── vigilar_payloads.py (systemd: vigilar-payloads.service)
   │     detecta archivos nuevos en downloads/ → escanea con
   │     reglas YARA locales (Mirai, Gafgyt, XMRig, dropper) →
   │     consulta VirusTotal → si VT no lo conoce, busca/sube a
   │     Hybrid Analysis (análisis dinámico) → alerta por Telegram →
   │     guarda en payloads_capturados.json
   │
   ├── enriquecer_ips.py (manual/cron)
   │     IPs atacantes → AbuseIPDB (reputación) + ip-api.com
   │     (geolocalización) → ips_enriquecidas.json
   │
   ├── backup_honeypi.sh (cron, cada 4h)
   │     respaldo rotativo (máx. 48 copias) de los JSON principales
   │
   ├── dashboard_soc.py (systemd: dashboard.service, Streamlit)
   │     dashboard completo en la LAN, puerto 8501 — incluye
   │     heatmap MITRE ATT&CK, mapa de calor por hora del día,
   │     y costo estimado del pipeline de IA
   │
   └── sincronizar_datos_github.sh (cron, cada 30 min)
         copia los JSON al repo de GitHub → dispara redeploy
         automático de dashboard_publico_cloud.py en Streamlit
         Community Cloud (dashboard público, de solo lectura)
```

---

## Componentes del pipeline de IA

| Script | Motor | Uso |
|---|---|---|
| `scripts/analista_ia_ollama.py` | Llama 3.2 (3B) local, Ollama | Versión original (Capítulo 1). Gratis, sin salir de la red, pero consume 100% CPU por respuesta. |
| `scripts/analista_ia_claude.py` | Claude API (`claude-haiku-4-5`) | **Versión en producción actual.** Libera la Pi de la carga de inferencia. Clasifica cada comando con táctica/técnica MITRE ATT&CK y severidad (JSON estructurado). Incluye protección anti-ráfaga, circuit breaker por volumen, y rate limit propio de alertas Telegram. |
| `scripts/comparar_modelos.py` | Ollama (Llama 3.2 vs modelo especializado) | Benchmark del Capítulo 2: comparación de rechazos y tiempos de respuesta. |
| `scripts/comparar_whiterabbitneo.py` / `prueba_rapida_whiterabbitneo.py` | WhiteRabbitNeo (Ollama) | Benchmark del Capítulo 4: modelo sin guardrails, falla por throughput (1.85 tok/s en CPU). |
| `scripts/generar_tabla_comparacion.py` | — | Genera la tabla Markdown comparativa a partir de los resultados de los benchmarks. |

---

## Clasificación MITRE ATT&CK y protecciones anti-saturación

Desde la última iteración, cada comando analizado por Claude devuelve un JSON estructurado con:
- **Táctica MITRE ATT&CK** (Discovery, Persistence, Defense Evasion, etc.)
- **Técnica específica** (ej. `T1057 - Process Discovery`)
- **Severidad** (Baja / Media / Alta / Crítica)

Esto permite armar un heatmap de tácticas en el dashboard, en vez de tener que leer cada análisis en texto libre.

Dos capas de protección independientes evitan que una ráfaga de ataques sature la Pi o inunde las notificaciones:

1. **Circuit breaker de análisis**: si hay más de 30 eventos reales en 60 segundos, se pausa el análisis de IA por 120 segundos (Cowrie sigue capturando normal, solo se detiene el consumo de tokens/CPU).
2. **Rate limit de Telegram**: máximo 5 alertas de "comando nuevo" por minuto, independiente del circuit breaker — protege contra atacantes que generan texto variable (contadores, timestamps) que dispararía una alerta por cada evento aunque el circuit breaker de la API todavía no se haya activado.

---

## Enriquecimiento y alertas

- **`scripts/enriquecer_ips.py`**: consulta AbuseIPDB (score de abuso, ISP, tipo de uso) e ip-api.com (país, ciudad, lat/lon) para cada IP atacante única.
- **`scripts/vigilar_payloads.py`**: vigila la carpeta de downloads de Cowrie. Por cada archivo nuevo (mayor a 0 bytes): lo escanea con **reglas YARA locales** (`reglas_honeypi.yar` — detecta Mirai, Gafgyt, XMRig/criptominers, y patrones genéricos de dropper), calcula SHA256, consulta VirusTotal, y si VirusTotal no lo conoce, busca/sube automáticamente a **Hybrid Analysis** para análisis dinámico. Envía alerta por Telegram con el veredicto completo.
- **`scripts/telegram_notificar.py`**: módulo reusable para enviar mensajes por Telegram.
- **`scripts/subir_hybrid_analysis.py`**: CLI standalone para subir/consultar payloads en Hybrid Analysis (Falcon Sandbox) manualmente. Usa `GET /search/hash` (el POST está deprecado) y `environment_id=330` (Linux Ubuntu 24.04 64-bit — verificar el ID vigente con `GET /system/environments`, ya que la API los actualiza periódicamente).
- **`reglas_honeypi.yar`**: reglas YARA básicas (no exhaustivas) como primer filtro local, gratis e instantáneo, antes de gastar cuota de APIs externas.
- **`backup_honeypi.sh`**: respaldo rotativo de `incidentes.json`, `payloads_capturados.json`, `ips_enriquecidas.json` y `comandos_vistos.json` — pensado para cron cada 4 horas, con un máximo configurable de copias retenidas.

---

## Dashboards

- **`scripts/dashboard_soc.py`** — dashboard local (Streamlit), accesible solo desde la LAN en el puerto 8501. Incluye: temperatura/throttling, estadísticas de ataques, **heatmap de tácticas MITRE ATT&CK y severidad**, **mapa de calor de ataques por hora del día**, **costo estimado del pipeline de IA** (en USD, basado en consultas reales), geolocalización con mapa, reputación de IPs, payloads capturados con veredicto de VirusTotal/YARA/Hybrid Analysis, e historial completo con el análisis de cada evento.
- **`dashboard_publico_cloud.py`** — versión pública, desplegada en Streamlit Community Cloud, que lee los datos sincronizados desde este mismo repo (carpeta `data/`, actualizada cada 30 minutos por cron). Incluye una sección de "Casos Destacados" con los ataques más reveladores.

---

## Requisitos

- Raspberry Pi 5 (recomendado: 4GB+ RAM; el proyecto corre cómodo con 8GB)
- Carcasa con ventilación activa (probado con Argon ONE V3)
- Raspberry Pi OS Lite (64-bit)
- Docker instalado
- Python 3.11+
- Cuenta de GitHub (para el dashboard público)
- Cuentas gratuitas en: Anthropic (API de Claude), AbuseIPDB, VirusTotal, Telegram (BotFather), Streamlit Community Cloud

⚠️ **Antes de exponer nada a internet**, asegurate de:
1. Mover el SSH real de administración a un puerto no estándar (ej. 2222).
2. Entender que vas a recibir tráfico malicioso real — este es un honeypot, no un simulacro.
3. Configurar permisos correctos en la carpeta de downloads (`chmod` adecuado) para que Cowrie pueda escribir los payloads capturados.

---

## Instalación paso a paso

### 1. Hardening básico

```bash
# Cambiar el puerto SSH real (editar /etc/ssh/sshd_config, Port 2222)
sudo systemctl restart ssh
```

### 2. Instalar Docker

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
```

### 3. Desplegar Cowrie con captura de payloads habilitada

```bash
docker run -d \
  --name cowrie \
  --restart always \
  -p 22:2222 \
  -p 23:2223 \
  -v cowrie_etc:/cowrie/cowrie-git/etc \
  -v ~/cowrie_logs:/cowrie/cowrie-git/var \
  cowrie/cowrie:latest
```

Habilitar SSH, Telnet y descarga real de payloads (editar `cowrie.cfg` en el volumen `cowrie_etc`):

```ini
[ssh]
enabled = true
listen_endpoints = tcp:2222:interface=0.0.0.0

[telnet]
enabled = true
listen_endpoints = tcp:2223:interface=0.0.0.0

[download]
download_path = var/lib/cowrie/downloads
download_limit_size = 10485760
```

```bash
docker restart cowrie
sudo chmod -R 777 ~/cowrie_logs/lib/cowrie/downloads/
```

### 4. Crear el entorno virtual de Python

```bash
python3 -m venv ~/soc_env
source ~/soc_env/bin/activate
pip install --upgrade pip
pip install anthropic ollama streamlit pandas requests yara-python
```

### 5. Copiar los scripts y configurar las API keys

Copiá todo `scripts/` a tu home, y configurá las variables de entorno necesarias (vía `systemctl edit <servicio>` para cada uno):

```ini
Environment="ANTHROPIC_API_KEY=..."
Environment="TELEGRAM_BOT_TOKEN=..."
Environment="TELEGRAM_CHAT_ID=..."
Environment="VIRUSTOTAL_API_KEY=..."
Environment="ABUSEIPDB_API_KEY=..."
```

### 6. Instalar los servicios systemd

Usá `scripts/setup_soc_services.sh` como base, agregando los servicios `analista.service` (apuntando a `analista_ia_claude.py`), `dashboard.service`, y `vigilar-payloads.service`, todos con `Restart=always`.

### 7. Configurar la sincronización al dashboard público

```bash
git clone https://github.com/rattinp/soc-lab-raspberry-pi.git
chmod +x soc-lab-raspberry-pi/sincronizar_datos_github.sh
crontab -e
# Agregar: */30 * * * * /home/usuario/soc-lab-raspberry-pi/sincronizar_datos_github.sh >> /home/usuario/sync.log 2>&1
```

Y desplegá `dashboard_publico_cloud.py` en [share.streamlit.io](https://share.streamlit.io).

### 8. Port forwarding en tu router

Reenviá los puertos 22 y 23 hacia la IP de la Pi. **No** reenvíes el 2222 (SSH real), ni el 8501 (dashboard local).

---

## Estructura del repo

```
.
├── README.md
├── LICENSE
├── .gitignore
├── dashboard_publico_cloud.py       # Dashboard público (Streamlit Cloud)
├── sincronizar_datos_github.sh      # Sync de datos, corre por cron
├── data/                            # JSON sincronizados (auto-generado)
├── docs/
│   └── parte1_articulo_soc_lab.md   # Artículo Capítulo 1
└── scripts/
    ├── analista_ia_ollama.py        # Analista con Llama 3.2 local (original)
    ├── analista_ia_claude.py        # Analista con Claude API + MITRE ATT&CK + circuit breaker (producción actual)
    ├── dashboard_soc.py             # Dashboard local completo (MITRE, heatmap horario, costo IA)
    ├── vigilar_payloads.py          # Captura + YARA + VirusTotal + Hybrid Analysis + Telegram
    ├── reglas_honeypi.yar           # Reglas YARA locales (Mirai, Gafgyt, XMRig, dropper)
    ├── telegram_notificar.py        # Módulo de alertas Telegram
    ├── enriquecer_ips.py            # AbuseIPDB + geolocalización
    ├── backup_honeypi.sh            # Backup rotativo de los JSON principales
    ├── comparar_modelos.py          # Benchmark Llama vs modelo especializado
    ├── comparar_whiterabbitneo.py   # Benchmark WhiteRabbitNeo (14 comandos)
    ├── prueba_rapida_whiterabbitneo.py
    ├── generar_tabla_comparacion.py # Genera tabla Markdown de resultados
    ├── subir_hybrid_analysis.py     # CLI de integración con Hybrid Analysis
    └── setup_soc_services.sh        # Instalador de servicios systemd
```

---

## Seguridad y consideraciones éticas

- Este honeypot **captura payloads reales** — Cowrie descarga de verdad lo que un atacante intenta instalar.
- **Nunca ejecutes los binarios capturados** en ningún sistema que no sea una VM completamente aislada y descartable. Analizalos solo por hash (VirusTotal) o en sandboxes dedicados (Hybrid Analysis).
- Revisá las leyes locales sobre honeypots y captura de tráfico antes de desplegar esto en un entorno de producción o corporativo.
- Los logs contienen IPs reales de terceros (atacantes) — el dashboard público las muestra enmascaradas/agregadas cuando corresponde por prudencia.

---

## Roadmap

- [x] Captura real de payloads + hash SHA256
- [x] Integración con VirusTotal (veredicto automático)
- [x] Enriquecimiento con AbuseIPDB + geolocalización
- [x] Alertas en tiempo real por Telegram
- [x] Migración de análisis a Claude API (con protección anti-ráfaga)
- [x] Dashboard público en la nube, sincronizado automáticamente
- [x] Clasificación estructurada MITRE ATT&CK (táctica/técnica/severidad)
- [x] Detección de comandos genuinamente nuevos (reduce fatiga de alertas)
- [x] Reglas YARA locales como primer filtro gratis (Mirai, Gafgyt, XMRig, dropper)
- [x] Integración funcional con Hybrid Analysis (búsqueda + subida automática)
- [x] Circuit breaker ante ráfagas sostenidas + rate limit propio de Telegram
- [x] Backup rotativo de los archivos de datos
- [x] Mapa de calor de ataques por hora del día
- [x] Costo estimado del pipeline de IA
- [ ] Perfil de ataques Telnet (a la espera de tráfico real)
- [ ] Evaluar un acelerador de hardware (Raspberry Pi AI HAT+ 2) o una placa con más RAM para correr modelos más grandes en tiempo real

---

## Licencia

MIT — usalo, modificalo, y si armás tu propia versión, ¡contame!

## Créditos

Basado en [Cowrie](https://github.com/cowrie/cowrie) y [Ollama](https://ollama.com). Desarrollado como proyecto personal de laboratorio de ciberseguridad defensiva por [Pablo Rattín](https://www.linkedin.com/in/pablorattin).
