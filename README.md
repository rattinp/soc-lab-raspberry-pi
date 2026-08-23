# 🛡️ SOC Lab — Honeypot + IA Local en Raspberry Pi 5

Laboratorio casero de ciberseguridad defensiva: un honeypot SSH/Telnet (Cowrie) expuesto a internet, cuyos ataques son analizados en tiempo real por un modelo de lenguaje corriendo 100% local (Ollama + Llama 3.2), con telemetría de hardware y un dashboard de monitoreo — todo sobre una Raspberry Pi 5.

📄 **Artículo completo (Parte 1)**: [`docs/parte1_articulo_soc_lab.md`](docs/parte1_articulo_soc_lab.md)

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
   │
   ├── Ollama (systemd) ── puerto 11434 ── modelo Llama 3.2 (3B)
   │
   ├── analista_ia.py (systemd: analista.service)
   │     lee logs de Cowrie en vivo → detecta comandos reales →
   │     consulta Ollama → registra temperatura/throttling →
   │     guarda todo en incidentes.json
   │
   └── dashboard_soc.py (systemd: dashboard.service, Streamlit)
         lee incidentes.json → dashboard en puerto 8501
```

---

## Requisitos

- Raspberry Pi 5 (recomendado: 4GB+ RAM)
- Carcasa con ventilación activa (probado con Argon ONE V3)
- Raspberry Pi OS Lite (64-bit)
- Docker instalado
- Python 3.11+
- Acceso a internet + capacidad de configurar port forwarding en tu router

⚠️ **Antes de exponer nada a internet**, asegurate de:
1. Mover el SSH real de administración a un puerto no estándar (ej. 2222).
2. Configurar UFW con `deny incoming` por defecto.
3. Entender que vas a recibir tráfico malicioso real — este es un honeypot, no un simulacro.

---

## Instalación paso a paso

### 1. Hardening básico

```bash
# Cambiar el puerto SSH real (editar /etc/ssh/sshd_config, Port 2222)
sudo systemctl restart ssh

sudo apt install ufw -y
sudo ufw default deny incoming
sudo ufw allow 2222/tcp
sudo ufw enable
```

### 2. Instalar Docker

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
# cerrar sesión y volver a entrar para que aplique el grupo
```

### 3. Desplegar Cowrie

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

Habilitar SSH y Telnet explícitamente (Telnet viene deshabilitado por defecto):

```bash
docker volume inspect cowrie_etc  # obtener el path real del volumen
sudo tee /var/lib/docker/volumes/cowrie_etc/_data/cowrie.cfg > /dev/null <<'EOF'
[ssh]
enabled = true
listen_endpoints = tcp:2222:interface=0.0.0.0

[telnet]
enabled = true
listen_endpoints = tcp:2223:interface=0.0.0.0
EOF

docker restart cowrie
```

### 4. Instalar Ollama y el modelo

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.2:3b
```

### 5. Crear el entorno virtual de Python

```bash
python3 -m venv ~/soc_env
source ~/soc_env/bin/activate
pip install --upgrade pip
pip install ollama streamlit pandas
```

### 6. Copiar los scripts

Copiá `scripts/analista_ia.py` y `scripts/dashboard_soc.py` a tu home (`~/`).

Revisá dentro de `analista_ia.py` que `CONTENEDOR_COWRIE = "cowrie"` coincida con el nombre real de tu contenedor (`docker ps`).

### 7. Instalar como servicios systemd

```bash
chmod +x scripts/setup_soc_services.sh
./scripts/setup_soc_services.sh
```

Este script crea y habilita `analista.service` y `dashboard.service`, con reinicio automático.

### 8. Port forwarding en tu router

Configurá reglas de NAT:
- Puerto externo 22 → IP de la Pi, puerto 22
- Puerto externo 23 → IP de la Pi, puerto 23

**No** reenvíes el puerto 2222 (SSH real de administración) — ese debe permanecer accesible solo desde tu LAN.

### 9. Verificar

```bash
sudo systemctl status analista.service dashboard.service
docker ps
```

Dashboard disponible en `http://<IP_de_tu_Pi>:8501` desde cualquier dispositivo en tu LAN.

---

## Estructura del repo

```
.
├── README.md
├── docs/
│   └── parte1_articulo_soc_lab.md    # Artículo técnico completo
└── scripts/
    ├── analista_ia.py                # Analista IA: Cowrie → Ollama → incidentes.json
    ├── dashboard_soc.py              # Dashboard Streamlit
    └── setup_soc_services.sh         # Instalador de servicios systemd
```

---

## Seguridad y consideraciones éticas

- Este honeypot **no ejecuta payloads reales** por defecto — Cowrie simula las respuestas de red.
- Si en el futuro se habilita la descarga real de payloads (ver roadmap), **nunca ejecutes los binarios capturados** en ningún sistema que no sea una VM completamente aislada y descartable.
- Revisá las leyes locales sobre honeypots y captura de tráfico antes de desplegar esto en un entorno de producción o corporativo.
- Los logs pueden contener IPs reales de terceros (atacantes) — considerá tu política de retención/publicación de esos datos.

---

## Roadmap (próximas partes de la serie)

- [ ] Captura real de payloads descargados por los atacantes + análisis por hash (VirusTotal)
- [ ] Comparación de Llama 3.2 (3B) contra modelos especializados en ciberseguridad y contra LLMs de frontera en la nube
- [ ] Enriquecimiento automático de IPs atacantes con threat intelligence (AbuseIPDB)
- [ ] Notificaciones en tiempo real (Telegram) por nuevo incidente
- [ ] Aislamiento de red dedicado (VLAN) para el contenedor del honeypot

---

## Licencia

MIT — usalo, modificalo, y si armás tu propia versión, ¡contame!

## Créditos

Basado en [Cowrie](https://github.com/cowrie/cowrie) y [Ollama](https://ollama.com). Desarrollado como proyecto personal de laboratorio de ciberseguridad defensiva.
