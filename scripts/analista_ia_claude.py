#!/usr/bin/env python3
"""
Analista IA - Honeypot Cowrie + Claude API + Telemetria termica (Argon ONE V3)
Version con clasificacion estructurada (tecnica MITRE ATT&CK + severidad) y
deteccion de comandos genuinamente nuevos (para no saturar Telegram con
alertas de la misma tecnica repetida).

Incluye proteccion anti-rafaga: si el mismo comando+IP se repite muchas veces
en poco tiempo, no dispara una consulta a la API por cada uno.
"""

import subprocess
import json
import os
import re
import time
from datetime import datetime

import anthropic

from telegram_notificar import enviar_alerta

# ============== CONFIGURACION ==============
CONTENEDOR_COWRIE = "cowrie"
MODELO_CLAUDE = "claude-haiku-4-5"
HISTORIAL_PATH = os.path.expanduser("~/incidentes.json")
COMANDOS_VISTOS_PATH = os.path.expanduser("~/comandos_vistos.json")

MARCADORES_COMANDO = ["CMD:", "Command found:"]
IP_REGEX = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

# --- Proteccion anti-rafaga (mismo comando+IP en poco tiempo) ---
VENTANA_DEDUPE_SEGUNDOS = 60
ultimo_visto = {}  # (ip, comando) -> timestamp de la ultima consulta real

client = anthropic.Anthropic()


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


def cargar_comandos_vistos():
    """Set historico de comandos (normalizados) ya analizados alguna vez,
    sin importar la IP ni cuando. Sirve para saber si esto es 'nuevo' de verdad."""
    if os.path.exists(COMANDOS_VISTOS_PATH):
        try:
            with open(COMANDOS_VISTOS_PATH, "r") as f:
                return set(json.load(f))
        except (json.JSONDecodeError, FileNotFoundError):
            return set()
    return set()


def guardar_comandos_vistos(comandos_vistos):
    with open(COMANDOS_VISTOS_PATH, "w") as f:
        json.dump(sorted(comandos_vistos), f, indent=2, ensure_ascii=False)


comandos_vistos_historico = cargar_comandos_vistos()


def guardar_en_historial(ip_origen, servicio, comando, analisis_dict, temperatura, throttled):
    incidente = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip_origen": ip_origen,
        "servicio": servicio,
        "comando": comando,
        "analisis": analisis_dict.get("analisis", ""),
        "mitre_technique": analisis_dict.get("mitre_technique", "N/A"),
        "mitre_tactic": analisis_dict.get("mitre_tactic", "N/A"),
        "severidad": analisis_dict.get("severidad", "N/A"),
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
    """Envia el comando a Claude pidiendo JSON estructurado: tecnica MITRE,
    tactica, severidad, y un analisis breve. Devuelve un dict; si el parseo
    falla, devuelve el texto crudo en el campo 'analisis' como fallback."""
    prompt = (
        "Actua como un analista SOC experto en ciberseguridad, especializado en "
        "honeypots y MITRE ATT&CK. Analiza este comando capturado en un honeypot: "
        f"{comando}\n\n"
        "Respondé EXCLUSIVAMENTE con un objeto JSON valido (sin texto antes ni "
        "despues, sin markdown, sin ```), con exactamente estas claves:\n"
        '{\n'
        '  "mitre_tactic": "<tactica MITRE ATT&CK, ej: Discovery, Execution, '
        'Persistence, Defense Evasion, Command and Control, Exfiltration, '
        'Impact, Initial Access, Credential Access>",\n'
        '  "mitre_technique": "<codigo y nombre de tecnica, ej: T1057 - Process '
        'Discovery>",\n'
        '  "severidad": "<Baja, Media, Alta o Critica>",\n'
        '  "analisis": "<explicacion tecnica breve en espanol, maximo 2 lineas>"\n'
        '}'
    )
    texto = ""
    try:
        respuesta = client.messages.create(
            model=MODELO_CLAUDE,
            max_tokens=300,
            messages=[{"role": "user", "content": prompt}],
        )
        texto = respuesta.content[0].text.strip()
        # Por si el modelo igual envuelve en markdown pese a la instruccion
        texto = texto.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        return json.loads(texto)
    except json.JSONDecodeError:
        return {
            "mitre_tactic": "N/A",
            "mitre_technique": "N/A",
            "severidad": "N/A",
            "analisis": texto or "[Error de formato en la respuesta]",
        }
    except Exception as e:
        return {
            "mitre_tactic": "N/A",
            "mitre_technique": "N/A",
            "severidad": "N/A",
            "analisis": f"[ERROR consultando Claude: {e}]",
        }


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
        print(f"⏭️  [Rafaga] {ip_origen} repitio comando reciente, se omite consulta a Claude")
        guardar_en_historial(
            ip_origen, servicio, comando_limpio,
            {"analisis": "[Repetido en menos de 60s - no se volvio a consultar a la IA]"},
            temperatura, throttled,
        )
        return

    ultimo_visto[clave] = ahora

    # --- Es la primera vez que vemos ESTE comando en TODA la historia? ---
    es_comando_nuevo = comando_limpio not in comandos_vistos_historico
    if es_comando_nuevo:
        comandos_vistos_historico.add(comando_limpio)
        guardar_comandos_vistos(comandos_vistos_historico)

    analisis_dict = consultar_claude(comando_limpio)

    print(f"🤖 [Análisis Claude] IP={ip_origen} | Servicio={servicio}")
    print(f"    Comando: {comando_limpio}")
    print(f"    Táctica: {analisis_dict.get('mitre_tactic')} | Técnica: {analisis_dict.get('mitre_technique')} | Severidad: {analisis_dict.get('severidad')}")
    print(f"    {analisis_dict.get('analisis')}")
    print(f"    🌡️ Temp: {temperatura} | Throttled: {throttled}")
    print("-" * 60)

    guardar_en_historial(ip_origen, servicio, comando_limpio, analisis_dict, temperatura, throttled)

    # --- Alerta por Telegram SOLO si es un comando genuinamente nuevo ---
    if es_comando_nuevo:
        mensaje = (
            f"🆕 <b>COMANDO NUEVO DETECTADO</b>\n"
            f"IP: {ip_origen} | Servicio: {servicio}\n"
            f"Comando: <code>{comando_limpio[:200]}</code>\n\n"
            f"Táctica MITRE: {analisis_dict.get('mitre_tactic')}\n"
            f"Técnica: {analisis_dict.get('mitre_technique')}\n"
            f"Severidad: {analisis_dict.get('severidad')}\n\n"
            f"{analisis_dict.get('analisis')}"
        )
        enviar_alerta(mensaje)


def main():
    print(f"=== Analista IA (Claude API + MITRE) iniciado. Escuchando contenedor '{CONTENEDOR_COWRIE}' ===")
    print(f"    Comandos ya conocidos en el historico: {len(comandos_vistos_historico)}")
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
