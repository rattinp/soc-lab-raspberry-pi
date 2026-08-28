#!/usr/bin/env python3
"""
Analista IA - Honeypot Cowrie + Claude API + Telemetria termica (Argon ONE V3)
Version que usa la API de Claude (Anthropic) en vez de Ollama local, para
sacarle toda la carga de inferencia a la Raspberry Pi.

Incluye proteccion anti-rafaga: si el mismo comando+IP se repite muchas veces
en poco tiempo (ej. un ataque de fuerza bruta o un script en loop), no dispara
una consulta a la API por cada uno - los agrupa y analiza uno solo cada tanto.
"""

import subprocess
import json
import os
import re
import time
from datetime import datetime
from collections import defaultdict

import anthropic

# ============== CONFIGURACION ==============
CONTENEDOR_COWRIE = "cowrie"
MODELO_CLAUDE = "claude-haiku-4-5"  # rapido y barato, ideal para triage en volumen
HISTORIAL_PATH = os.path.expanduser("~/incidentes.json")

MARCADORES_COMANDO = ["CMD:", "Command found:"]
IP_REGEX = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

# --- Proteccion anti-rafaga ---
# Si el mismo (ip, comando) se repite dentro de esta ventana, no se vuelve a
# consultar a la API - se cuenta y se loguea localmente sin gastar tokens.
VENTANA_DEDUPE_SEGUNDOS = 60
ultimo_visto = {}  # (ip, comando) -> timestamp de la ultima consulta real

client = anthropic.Anthropic()  # toma ANTHROPIC_API_KEY del entorno automaticamente


def obtener_temperatura():
    try:
        salida = subprocess.check_output(["vcgencmd", "measure_temp"], text=True)
        return salida.strip().split("=")[1]
    except Exception:
        return "N/A"


def obtener_throttled():
    try:
        salida = subprocess.check_output(["vcgencmd", "get_throttled"], text=True)
        return salida.strip().split("=")[1]
    except Exception:
        return "N/A"


def extraer_ip(linea):
    match = IP_REGEX.search(linea)
    return match.group(1) if match else "desconocida"


def extraer_comando_real(linea):
    for marcador in MARCADORES_COMANDO:
        if marcador in linea:
            return linea.split(marcador, 1)[1].strip()
    return linea.strip()


def detectar_servicio(linea):
    return "Telnet" if "telnet" in linea.lower() else "SSH"


def guardar_en_historial(ip_origen, servicio, comando, analisis_ia, temperatura, throttled):
    incidente = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip_origen": ip_origen,
        "servicio": servicio,
        "comando": comando,
        "analisis": analisis_ia,
        "temperatura": temperatura,
        "throttled": throttled,
    }

    if os.path.exists(HISTORIAL_PATH):
        try:
            with open(HISTORIAL_PATH, "r") as f:
                datos = json.load(f)
            if not isinstance(datos, list):
                datos = []
        except (json.JSONDecodeError, FileNotFoundError):
            datos = []
    else:
        datos = []

    datos.append(incidente)

    with open(HISTORIAL_PATH, "w") as f:
        json.dump(datos, f, indent=2, ensure_ascii=False)


def consultar_claude(comando):
    """Envia el comando a la API de Claude y devuelve el analisis en texto."""
    prompt = (
        f"Actua como un analista experto en ciberseguridad. Analiza este comando "
        f"capturado en un honeypot: {comando}. "
        f"Responde estrictamente en un parrafo corto de maximo 3 lineas en espanol."
    )
    try:
        respuesta = client.messages.create(
            model=MODELO_CLAUDE,
            max_tokens=200,
            messages=[{"role": "user", "content": prompt}],
        )
        return respuesta.content[0].text.strip()
    except Exception as e:
        return f"[ERROR consultando Claude: {e}]"


def procesar_linea(linea):
    """Analiza una linea de log de Cowrie; solo dispara IA si es un comando REAL,
    y si no fue consultado hace menos de VENTANA_DEDUPE_SEGUNDOS para la misma IP."""
    if not any(marcador in linea for marcador in MARCADORES_COMANDO):
        return

    ip_origen = extraer_ip(linea)
    servicio = detectar_servicio(linea)
    comando_limpio = extraer_comando_real(linea)
    temperatura = obtener_temperatura()
    throttled = obtener_throttled()

    clave = (ip_origen, comando_limpio)
    ahora = time.time()
    ultima_vez = ultimo_visto.get(clave)

    if ultima_vez and (ahora - ultima_vez) < VENTANA_DEDUPE_SEGUNDOS:
        # Rafaga detectada: mismo comando+IP repetido muy rapido. No gastamos
        # una llamada a la API - solo lo dejamos anotado localmente.
        print(f"⏭️  [Rafaga] {ip_origen} repitio comando reciente, se omite consulta a Claude")
        guardar_en_historial(
            ip_origen, servicio, comando_limpio,
            "[Repetido en menos de 60s - no se volvio a consultar a la IA para ahorrar recursos]",
            temperatura, throttled,
        )
        return

    ultimo_visto[clave] = ahora

    analisis_ia = consultar_claude(comando_limpio)
    print(f"🤖 [Análisis Claude] IP={ip_origen} | Servicio={servicio}")
    print(f"    Comando: {comando_limpio}")
    print(f"    {analisis_ia}")
    print(f"    🌡️ Temp: {temperatura} | Throttled: {throttled}")

    guardar_en_historial(ip_origen, servicio, comando_limpio, analisis_ia, temperatura, throttled)
    print("-" * 60)


def main():
    print(f"=== Analista IA (Claude API) iniciado. Escuchando contenedor '{CONTENEDOR_COWRIE}' ===")
    comando_docker = ["docker", "logs", "-f", "--tail", "0", CONTENEDOR_COWRIE]

    try:
        proceso = subprocess.Popen(
            comando_docker,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError:
        print("[-] Error: 'docker' no encontrado en el PATH.")
        return

    try:
        for linea in proceso.stdout:
            procesar_linea(linea)
    except KeyboardInterrupt:
        print("\n=== Analista IA detenido manualmente ===")
    finally:
        proceso.terminate()


if __name__ == "__main__":
    main()
