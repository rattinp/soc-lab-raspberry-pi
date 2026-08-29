#!/bin/bash
# Sincroniza los datos del SOC Lab (incidentes, IPs enriquecidas, payloads)
# al repo de GitHub, para que el dashboard publico en Streamlit Cloud
# los pueda leer. Pensado para correr via cron cada hora.

set -e

REPO_PATH="$HOME/soc-lab-raspberry-pi"   # ruta local del repo clonado
DATA_DIR="$REPO_PATH/data"

# --- Verificar que el repo local existe ---
if [ ! -d "$REPO_PATH" ]; then
    echo "[-] No se encontro el repo en $REPO_PATH"
    echo "    Clonalo primero con: git clone https://github.com/rattinp/soc-lab-raspberry-pi.git"
    exit 1
fi

mkdir -p "$DATA_DIR"

# --- Copiar los archivos de datos actuales ---
# incidentes.json: se recorta a los ultimos N eventos antes de sincronizar.
# El historial completo (49k+ eventos y creciendo) queda intacto en la Pi;
# al dashboard publico solo le mandamos una ventana reciente, para que la
# app en Streamlit Cloud sea liviana y rapida de cargar.
MAX_EVENTOS_PUBLICOS=1000

python3 -c "
import json
try:
    with open('$HOME/incidentes.json', 'r') as f:
        datos = json.load(f)
    recortado = datos[-$MAX_EVENTOS_PUBLICOS:]
    with open('$DATA_DIR/incidentes.json', 'w') as f:
        json.dump(recortado, f, indent=2, ensure_ascii=False)
    print(f'[i] incidentes.json recortado a {len(recortado)} de {len(datos)} eventos totales')
except Exception as e:
    print(f'[-] Error recortando incidentes.json: {e}')
    with open('$DATA_DIR/incidentes.json', 'w') as f:
        json.dump([], f)
"

cp -f "$HOME/ips_enriquecidas.json" "$DATA_DIR/ips_enriquecidas.json" 2>/dev/null || echo "{}" > "$DATA_DIR/ips_enriquecidas.json"
cp -f "$HOME/payloads_capturados.json" "$DATA_DIR/payloads_capturados.json" 2>/dev/null || echo "[]" > "$DATA_DIR/payloads_capturados.json"

# --- Guardar tambien la temperatura/throttling actual, para que el
#     dashboard en la nube (sin acceso a vcgencmd) los pueda mostrar ---
TEMP=$(vcgencmd measure_temp 2>/dev/null | cut -d'=' -f2 || echo "N/A")
THROTTLED=$(vcgencmd get_throttled 2>/dev/null | cut -d'=' -f2 || echo "N/A")
echo "{\"temperatura\": \"$TEMP\", \"throttled\": \"$THROTTLED\", \"actualizado\": \"$(date '+%Y-%m-%d %H:%M:%S')\"}" > "$DATA_DIR/estado_hardware.json"

# --- Commit y push ---
cd "$REPO_PATH"
git add data/
if git diff --cached --quiet; then
    echo "[i] Sin cambios en los datos, no se hace commit."
else
    git commit -m "Actualizacion automatica de datos - $(date '+%Y-%m-%d %H:%M')"
    git push
    echo "[+] Datos sincronizados y subidos a GitHub."
fi
