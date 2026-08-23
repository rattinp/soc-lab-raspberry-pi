#!/usr/bin/env python3
"""
Analista IA - Honeypot Cowrie + Ollama + Telemetria termica (Argon ONE V3)
Lee en tiempo real los logs del contenedor Docker de Cowrie, detecta SOLO
lineas que representan comandos reales tipeados por el atacante (marcadas
por Cowrie como 'CMD:' o 'Command found:'), extrae la IP, consulta un
modelo local via Ollama y guarda cada incidente en ~/incidentes.json
"""

import subprocess
import json
import os
import re
from datetime import datetime

import ollama

# ============== CONFIGURACION ==============
CONTENEDOR_COWRIE = "cowrie"  # ajustar si tu contenedor tiene otro nombre (ver: docker ps)
MODELO_OLLAMA = "llama3.2:3b"
HISTORIAL_PATH = os.path.expanduser("~/incidentes.json")

# Cowrie marca los comandos reales del atacante con estas etiquetas en el log.
# Filtrar por esto (en vez de palabras sueltas) evita falsos positivos como
# "xterm" o "Terminal Size" que antes matcheaban por contener "rm" adentro.
MARCADORES_COMANDO = ["CMD:", "Command found:"]

# Regex simple para detectar una IPv4 en la linea de log de Cowrie
IP_REGEX = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


def obtener_temperatura():
    """Lee la temperatura de la CPU via vcgencmd."""
    try:
        salida = subprocess.check_output(["vcgencmd", "measure_temp"], text=True)
        return salida.strip().split("=")[1]
    except Exception:
        return "N/A"


def obtener_throttled():
    """Lee el estado de throttling via vcgencmd."""
    try:
        salida = subprocess.check_output(["vcgencmd", "get_throttled"], text=True)
        return salida.strip().split("=")[1]
    except Exception:
        return "N/A"


def extraer_ip(linea):
    """Busca una IPv4 en la linea de log; devuelve 'desconocida' si no encuentra."""
    match = IP_REGEX.search(linea)
    return match.group(1) if match else "desconocida"


def extraer_comando_real(linea):
    """Extrae solo el texto del comando despues del marcador CMD: o Command found:."""
    for marcador in MARCADORES_COMANDO:
        if marcador in linea:
            return linea.split(marcador, 1)[1].strip()
    return linea.strip()


def detectar_servicio(linea):
    """Determina si la linea corresponde a SSH o Telnet segun el contenido del log."""
    linea_lower = linea.lower()
    if "telnet" in linea_lower:
        return "Telnet"
    return "SSH"


def guardar_en_historial(ip_origen, servicio, comando, analisis_ia, temperatura, throttled):
    """Agrega un nuevo incidente estructurado al archivo incidentes.json."""
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


def procesar_linea(linea):
    """Analiza una linea de log de Cowrie; solo dispara IA si es un comando REAL del atacante."""
    if not any(marcador in linea for marcador in MARCADORES_COMANDO):
        return

    ip_origen = extraer_ip(linea)
    servicio = detectar_servicio(linea)
    comando_limpio = extraer_comando_real(linea)
    temperatura = obtener_temperatura()
    throttled = obtener_throttled()

    prompt = (
        f"Actua como un analista experto en ciberseguridad. Analiza este comando en un honeypot: {comando_limpio}. "
        f"Responde estrictamente en un parrafo corto de maximo 3 lineas en espanol."
    )

    try:
        respuesta = ollama.generate(model=MODELO_OLLAMA, prompt=prompt)
        analisis_ia = respuesta["response"].strip()
        print(f"🤖 [Análisis IA] IP={ip_origen} | Servicio={servicio}")
        print(f"    Comando: {comando_limpio}")
        print(f"    {analisis_ia}")
        print(f"    🌡️ Temp: {temperatura} | Throttled: {throttled}")

        guardar_en_historial(ip_origen, servicio, comando_limpio, analisis_ia, temperatura, throttled)
        print("-" * 60)
    except Exception as e:
        print(f"[-] Error al consultar a Ollama: {e}")


def main():
    print(f"=== Analista IA iniciado. Escuchando contenedor '{CONTENEDOR_COWRIE}' ===")
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
        print("[-] Error: 'docker' no encontrado en el PATH. ¿Está instalado Docker?")
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
