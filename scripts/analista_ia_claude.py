#!/usr/bin/env python3
"""
Analista IA - Honeypot Cowrie + Claude API + Telemetria termica (Argon ONE V3)
Version con clasificacion estructurada (tecnica MITRE ATT&CK + severidad),
deteccion de comandos genuinamente nuevos, y circuit breaker ante rafagas
sostenidas (protege la Pi si vuelve a entrar un ataque masivo de fuerza bruta).

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

# --- Circuit breaker: si hay demasiados eventos por minuto sostenidos,
#     se pausa el analisis de IA (se sigue logueando crudo, sin gastar
#     tokens/CPU) hasta que el ritmo baje. Evita repetir la saturacion
#     que casi cuelga la Pi con una rafaga de fuerza bruta. ---
CIRCUIT_BREAKER_UMBRAL_EVENTOS = 30      # eventos reales (no dedupeados) en la ventana
CIRCUIT_BREAKER_VENTANA_SEGUNDOS = 60    # ventana deslizante para contar eventos
CIRCUIT_BREAKER_PAUSA_SEGUNDOS = 120     # cuanto tiempo se mantiene abierto el breaker

timestamps_eventos_recientes = []  # timestamps de consultas reales a la API
circuit_breaker_abierto_hasta = 0  # 0 = cerrado (analisis normal)

# --- Limite propio para alertas de Telegram (independiente del circuit
#     breaker de la API). Un atacante que genera muchos comandos con texto
#     DISTINTO cada vez (ej. contadores incrementales) puede disparar una
#     alerta de "comando nuevo" por cada uno, inundando Telegram incluso
#     antes de que el circuit breaker de la API llegue a activarse. ---
ALERTA_TELEGRAM_MAX_POR_VENTANA = 5
ALERTA_TELEGRAM_VENTANA_SEGUNDOS = 60
timestamps_alertas_telegram = []
alertas_suprimidas_contador = 0  # cuantas se omitieron mientras estaba al limite

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


def puede_enviar_alerta_telegram():
    """Rate limiter propio para Telegram: maximo N alertas por ventana de
    tiempo, sin importar si cada comando es 'nuevo' o no. Evita que un
    atacante con texto variable (contadores, timestamps en el comando, etc.)
    inunde Telegram con una alerta por cada evento."""
    global alertas_suprimidas_contador
    ahora = time.time()

    while timestamps_alertas_telegram and timestamps_alertas_telegram[0] < ahora - ALERTA_TELEGRAM_VENTANA_SEGUNDOS:
        timestamps_alertas_telegram.pop(0)

    if len(timestamps_alertas_telegram) >= ALERTA_TELEGRAM_MAX_POR_VENTANA:
        alertas_suprimidas_contador += 1
        return False

    timestamps_alertas_telegram.append(ahora)

    # Si veniamos suprimiendo alertas y ahora hay lugar de nuevo, avisamos
    # cuantas se perdieron en el camino (una sola vez, no una por una)
    if alertas_suprimidas_contador > 0:
        enviar_alerta(
            f"ℹ️ Se suprimieron {alertas_suprimidas_contador} alertas adicionales "
            f"en los últimos {ALERTA_TELEGRAM_VENTANA_SEGUNDOS}s por exceso de volumen."
        )
        alertas_suprimidas_contador = 0

    return True


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

    # --- Circuit breaker: contar eventos reales en la ventana deslizante ---
    global circuit_breaker_abierto_hasta
    timestamps_eventos_recientes.append(ahora)
    # Limpiar timestamps fuera de la ventana
    while timestamps_eventos_recientes and timestamps_eventos_recientes[0] < ahora - CIRCUIT_BREAKER_VENTANA_SEGUNDOS:
        timestamps_eventos_recientes.pop(0)

    if circuit_breaker_abierto_hasta and ahora < circuit_breaker_abierto_hasta:
        # El breaker sigue abierto: no consultamos a la IA, solo logueamos crudo
        segundos_restantes = int(circuit_breaker_abierto_hasta - ahora)
        print(f"🔴 [Circuit Breaker ACTIVO] Analisis pausado ({segundos_restantes}s restantes) - solo logueo crudo")
        guardar_en_historial(
            ip_origen, servicio, comando_limpio,
            {"analisis": "[Circuit breaker activo - analisis de IA pausado por rafaga sostenida]"},
            temperatura, throttled,
        )
        return

    if len(timestamps_eventos_recientes) > CIRCUIT_BREAKER_UMBRAL_EVENTOS:
        # Se supero el umbral: abrimos el breaker
        circuit_breaker_abierto_hasta = ahora + CIRCUIT_BREAKER_PAUSA_SEGUNDOS
        print(f"🔴 [Circuit Breaker] {len(timestamps_eventos_recientes)} eventos en {CIRCUIT_BREAKER_VENTANA_SEGUNDOS}s - PAUSANDO analisis por {CIRCUIT_BREAKER_PAUSA_SEGUNDOS}s")
        enviar_alerta(
            f"🔴 <b>CIRCUIT BREAKER ACTIVADO</b>\n"
            f"Se detectaron {len(timestamps_eventos_recientes)} eventos en {CIRCUIT_BREAKER_VENTANA_SEGUNDOS}s.\n"
            f"El análisis de IA se pausa por {CIRCUIT_BREAKER_PAUSA_SEGUNDOS}s para proteger la Pi.\n"
            f"Cowrie sigue capturando normalmente, solo se pausa el análisis."
        )
        guardar_en_historial(
            ip_origen, servicio, comando_limpio,
            {"analisis": "[Circuit breaker activado - rafaga sostenida detectada]"},
            temperatura, throttled,
        )
        return

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

    # --- Alerta por Telegram SOLO si es un comando genuinamente nuevo,
    #     y si no superamos el limite de alertas por minuto ---
    if es_comando_nuevo and puede_enviar_alerta_telegram():
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
