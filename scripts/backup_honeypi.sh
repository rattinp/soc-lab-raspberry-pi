#!/bin/bash
# Backup periodico de los archivos JSON del HoneyPI (incidentes, payloads,
# IPs enriquecidas, comandos vistos). Pensado para correr por cron cada
# pocas horas, independiente de la sincronizacion al repo publico de GitHub
# (esto es un respaldo local adicional, por si algo sale mal con el repo
# o con la propia Pi).

set -e

ORIGEN="$HOME"
BACKUP_DIR="$HOME/backups_honeypi"
FECHA=$(date '+%Y%m%d_%H%M%S')
MAX_BACKUPS=48  # con backups cada 4h, esto guarda ~8 dias de historial

mkdir -p "$BACKUP_DIR"

ARCHIVOS=(
    "incidentes.json"
    "payloads_capturados.json"
    "ips_enriquecidas.json"
    "comandos_vistos.json"
)

DESTINO="$BACKUP_DIR/backup_$FECHA"
mkdir -p "$DESTINO"

for archivo in "${ARCHIVOS[@]}"; do
    if [ -f "$ORIGEN/$archivo" ]; then
        cp "$ORIGEN/$archivo" "$DESTINO/"
    fi
done

echo "[+] Backup creado en $DESTINO"

# --- Rotacion: borrar backups mas viejos que MAX_BACKUPS ---
cd "$BACKUP_DIR"
CANTIDAD=$(ls -1d backup_* 2>/dev/null | wc -l)

if [ "$CANTIDAD" -gt "$MAX_BACKUPS" ]; then
    A_BORRAR=$((CANTIDAD - MAX_BACKUPS))
    ls -1d backup_* | sort | head -n "$A_BORRAR" | while read -r viejo; do
        rm -rf "$viejo"
        echo "[i] Backup antiguo eliminado: $viejo"
    done
fi

echo "[+] Backups actuales: $(ls -1d backup_* 2>/dev/null | wc -l) de un maximo de $MAX_BACKUPS"
