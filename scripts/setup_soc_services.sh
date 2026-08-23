#!/bin/bash
set -e

echo "=== Configurando servicios del SOC Lab ==="

USUARIO="usuario"
HOME_DIR="/home/${USUARIO}"
VENV_PY="${HOME_DIR}/soc_env/bin/python3"
VENV_STREAMLIT="${HOME_DIR}/soc_env/bin/streamlit"

# --- Verificaciones previas ---
if [ ! -f "$VENV_PY" ]; then
    echo "❌ No se encontró el Python del venv en $VENV_PY"
    echo "   Verificá que el venv soc_env exista y tenga ese path."
    exit 1
fi

if [ ! -f "${HOME_DIR}/analista_ia.py" ]; then
    echo "❌ No se encontró ${HOME_DIR}/analista_ia.py"
    exit 1
fi

if [ ! -f "${HOME_DIR}/dashboard_soc.py" ]; then
    echo "❌ No se encontró ${HOME_DIR}/dashboard_soc.py"
    exit 1
fi

echo "✅ Archivos y venv encontrados, generando servicios..."

# --- Servicio: analista_ia.py ---
sudo tee /etc/systemd/system/analista.service > /dev/null <<EOF
[Unit]
Description=Analista IA - Honeypot Cowrie + Ollama
After=network.target docker.service ollama.service

[Service]
Type=simple
User=${USUARIO}
WorkingDirectory=${HOME_DIR}
ExecStart=${VENV_PY} ${HOME_DIR}/analista_ia.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# --- Servicio: dashboard_soc.py (Streamlit) ---
sudo tee /etc/systemd/system/dashboard.service > /dev/null <<EOF
[Unit]
Description=Dashboard Streamlit - SOC Lab
After=network.target

[Service]
Type=simple
User=${USUARIO}
WorkingDirectory=${HOME_DIR}
ExecStart=${VENV_STREAMLIT} run ${HOME_DIR}/dashboard_soc.py --server.address=0.0.0.0 --server.port=8501
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

echo "✅ Archivos de servicio creados."

# --- Habilitar y arrancar ---
sudo systemctl daemon-reload
sudo systemctl enable analista.service
sudo systemctl enable dashboard.service
sudo systemctl restart analista.service
sudo systemctl restart dashboard.service

echo ""
echo "=== Estado de los servicios ==="
sudo systemctl status analista.service --no-pager -l | head -10
echo ""
sudo systemctl status dashboard.service --no-pager -l | head -10

echo ""
echo "=== Listo ==="
echo "Ver logs en vivo:"
echo "  sudo journalctl -u analista.service -f"
echo "  sudo journalctl -u dashboard.service -f"
echo ""
echo "Dashboard disponible en: http://<IP_de_la_Pi>:8501"
