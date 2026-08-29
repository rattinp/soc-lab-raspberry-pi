#!/usr/bin/env python3
"""
Vigila la carpeta de downloads de Cowrie. Cuando aparece un archivo nuevo
(un payload real descargado por un atacante):
1. Calcula su SHA256
2. Consulta VirusTotal por ese hash (API v3, gratis, sin subir el archivo)
3. Registra todo en payloads_capturados.json
4. Envia una alerta por Telegram con el veredicto

IMPORTANTE: este script NUNCA ejecuta los archivos capturados. Solo lee
sus bytes para calcular el hash. No abras ni ejecutes estos archivos
manualmente tampoco - son malware real.
"""

import os
import time
import json
import hashlib
import requests
from datetime import datetime

try:
    import yara
    YARA_DISPONIBLE = True
except ImportError:
    YARA_DISPONIBLE = False

from telegram_notificar import enviar_alerta

DOWNLOADS_DIR = os.path.expanduser("~/cowrie_logs/lib/cowrie/downloads")
REGISTRO_PATH = os.path.expanduser("~/payloads_capturados.json")
REGLAS_YARA_PATH = os.path.expanduser("~/reglas_honeypi.yar")
INTERVALO_SEGUNDOS = 15

_reglas_yara_compiladas = None
if YARA_DISPONIBLE and os.path.exists(REGLAS_YARA_PATH):
    try:
        _reglas_yara_compiladas = yara.compile(filepath=REGLAS_YARA_PATH)
    except Exception as e:
        print(f"[-] Error compilando reglas YARA: {e}")

VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/files/{hash}"

HYBRID_ANALYSIS_API_KEY = os.environ.get("HYBRID_ANALYSIS_API_KEY")
HYBRID_ANALYSIS_BASE = "https://www.hybrid-analysis.com/api/v2"
HYBRID_ANALYSIS_ENVIRONMENT_ID = 330  # Linux (Ubuntu 24.04, 64 bit)
HYBRID_ANALYSIS_HEADERS = {
    "api-key": HYBRID_ANALYSIS_API_KEY or "",
    "user-agent": "Falcon Sandbox",
    "accept": "application/json",
}


def cargar_registro():
    if os.path.exists(REGISTRO_PATH):
        try:
            with open(REGISTRO_PATH, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return []
    return []


def guardar_registro(registro):
    with open(REGISTRO_PATH, "w") as f:
        json.dump(registro, f, indent=2, ensure_ascii=False)


def calcular_sha256(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for bloque in iter(lambda: f.read(65536), b""):
            sha256.update(bloque)
    return sha256.hexdigest()


def escanear_yara(filepath):
    """Escanea el archivo con las reglas YARA locales. Gratis e instantaneo,
    corre ANTES de gastar cuota de VirusTotal/Hybrid Analysis. Devuelve una
    lista de nombres de reglas que matchearon (vacia si no coincide con nada
    conocido, o si YARA no esta disponible)."""
    if not _reglas_yara_compiladas:
        return []
    try:
        matches = _reglas_yara_compiladas.match(filepath)
        return [m.rule for m in matches]
    except Exception as e:
        print(f"    [-] Error escaneando con YARA: {e}")
        return []


def consultar_virustotal(sha256):
    """Consulta VirusTotal por hash. Devuelve dict con el veredicto, o None
    si no esta configurada la API key o el archivo no es conocido todavia."""
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VIRUSTOTAL_API_KEY no configurada"}

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        resp = requests.get(VIRUSTOTAL_URL.format(hash=sha256), headers=headers, timeout=15)

        if resp.status_code == 404:
            return {"conocido": False, "mensaje": "Hash no encontrado en VirusTotal todavia"}

        resp.raise_for_status()
        data = resp.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})

        return {
            "conocido": True,
            "maliciosos": stats.get("malicious", 0),
            "sospechosos": stats.get("suspicious", 0),
            "inofensivos": stats.get("harmless", 0),
            "sin_detectar": stats.get("undetected", 0),
            "nombre_sugerido": data.get("meaningful_name", "N/A"),
            "tipo": data.get("type_description", "N/A"),
            "tags": data.get("tags", []),
        }
    except Exception as e:
        return {"error": str(e)}


def consultar_o_subir_hybrid_analysis(sha256, filepath):
    """Se llama SOLO cuando VirusTotal no conoce el hash. Primero busca si ya
    esta en Hybrid Analysis (otro honeypot pudo haberlo subido antes); si no,
    lo sube para analisis dinamico real. Devuelve dict con el link y el estado
    ('encontrado' | 'subido' | 'error' | 'no_configurado')."""
    link_reporte = f"https://www.hybrid-analysis.com/sample/{sha256}"

    if not HYBRID_ANALYSIS_API_KEY:
        return {"estado": "no_configurado", "link": None}

    # Paso 1: buscar si ya existe (GET /search/hash, el metodo POST esta deprecado)
    try:
        resp = requests.get(
            f"{HYBRID_ANALYSIS_BASE}/search/hash",
            headers=HYBRID_ANALYSIS_HEADERS,
            params={"hash": sha256},
            timeout=20,
        )
        if resp.status_code == 200 and resp.json():
            return {"estado": "encontrado", "link": link_reporte}
    except Exception as e:
        print(f"    [-] Error buscando en Hybrid Analysis: {e}")

    # Paso 2: no estaba, lo subimos para analisis dinamico
    try:
        with open(filepath, "rb") as f:
            files = {"file": (os.path.basename(filepath), f)}
            data = {"environment_id": HYBRID_ANALYSIS_ENVIRONMENT_ID}
            resp = requests.post(
                f"{HYBRID_ANALYSIS_BASE}/submit/file",
                headers=HYBRID_ANALYSIS_HEADERS,
                files=files,
                data=data,
                timeout=60,
                allow_redirects=False,
            )
        if resp.status_code in (301, 302, 307, 308):
            nueva_url = resp.headers.get("Location")
            with open(filepath, "rb") as f:
                files = {"file": (os.path.basename(filepath), f)}
                resp = requests.post(
                    nueva_url, headers=HYBRID_ANALYSIS_HEADERS, files=files, data=data, timeout=60
                )

        if resp.status_code in (200, 201):
            return {"estado": "subido", "link": link_reporte}
        else:
            print(f"    [-] Hybrid Analysis respondio {resp.status_code}: {resp.text[:300]}")
            return {"estado": "error", "link": None}
    except Exception as e:
        print(f"    [-] Error subiendo a Hybrid Analysis: {e}")
        return {"estado": "error", "link": None}


def main():
    print(f"=== Vigilando {DOWNLOADS_DIR} ===")
    if _reglas_yara_compiladas:
        print("    Reglas YARA locales: cargadas y activas")
    elif not YARA_DISPONIBLE:
        print("    [!] Modulo 'yara-python' no instalado, se omite el escaneo YARA")
    else:
        print(f"    [!] No se encontraron reglas YARA en {REGLAS_YARA_PATH}, se omite el escaneo")

    if not os.path.exists(DOWNLOADS_DIR):
        print(f"[!] La carpeta {DOWNLOADS_DIR} todavia no existe.")
        print("    Se creara automaticamente cuando Cowrie capture el primer archivo.")

    registro = cargar_registro()
    archivos_conocidos = {r["nombre_archivo"] for r in registro}

    while True:
        if os.path.exists(DOWNLOADS_DIR):
            archivos_actuales = set(os.listdir(DOWNLOADS_DIR))
            nuevos = archivos_actuales - archivos_conocidos

            for nombre in nuevos:
                filepath = os.path.join(DOWNLOADS_DIR, nombre)
                if not os.path.isfile(filepath):
                    continue

                try:
                    tamano = os.path.getsize(filepath)

                    if tamano == 0:
                        # Puede que Cowrie todavia este escribiendo el archivo
                        # (descarga en curso) o que la descarga haya fallado.
                        # NO lo marcamos como conocido: se vuelve a revisar en
                        # el proximo ciclo, por si para entonces ya tiene contenido.
                        print(f"[i] {nombre} tiene 0 bytes todavia, se reintenta en el proximo ciclo")
                        continue

                    sha256 = calcular_sha256(filepath)

                    print("=" * 70)
                    print(f"🎯 NUEVO PAYLOAD CAPTURADO")
                    print(f"   Archivo: {nombre}")
                    print(f"   Tamano: {tamano} bytes")
                    print(f"   SHA256: {sha256}")

                    print("   Escaneando con reglas YARA locales...")
                    yara_matches = escanear_yara(filepath)
                    if yara_matches:
                        print(f"   YARA detecto: {', '.join(yara_matches)}")
                    else:
                        print("   YARA: sin coincidencias con las reglas locales")

                    print("   Consultando VirusTotal...")
                    vt_info = consultar_virustotal(sha256)
                    print(f"   VirusTotal: {vt_info}")

                    # Si VirusTotal no lo conoce, intentamos Hybrid Analysis
                    # (busca primero; si tampoco esta ahi, lo sube para analisis dinamico)
                    ha_info = {"estado": "no_intentado", "link": None}
                    if vt_info.get("conocido") is False:
                        print("   VirusTotal no lo conoce, probando Hybrid Analysis...")
                        ha_info = consultar_o_subir_hybrid_analysis(sha256, filepath)
                        print(f"   Hybrid Analysis: {ha_info}")

                    print("=" * 70)

                    entrada = {
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "nombre_archivo": nombre,
                        "tamano_bytes": tamano,
                        "sha256": sha256,
                        "ruta_local": filepath,
                        "yara_matches": yara_matches,
                        "virustotal": vt_info,
                        "hybrid_analysis": ha_info,
                    }
                    registro.append(entrada)
                    archivos_conocidos.add(nombre)
                    guardar_registro(registro)

                    yara_linea = f"\n🔍 YARA: {', '.join(yara_matches)}" if yara_matches else ""

                    # --- Armar mensaje de Telegram segun el resultado de VT ---
                    if vt_info.get("conocido"):
                        maliciosos = vt_info.get("maliciosos", 0)
                        total_motores = maliciosos + vt_info.get("sospechosos", 0) + vt_info.get("inofensivos", 0) + vt_info.get("sin_detectar", 0)
                        veredicto = f"🔴 {maliciosos}/{total_motores} motores lo detectan como MALICIOSO" if maliciosos > 0 else "🟢 No detectado como malicioso"
                        nombre_sugerido = vt_info.get("nombre_sugerido", "N/A")
                        tags = ", ".join(vt_info.get("tags", [])[:5]) or "sin tags"

                        mensaje = (
                            f"🎯 <b>NUEVO PAYLOAD CAPTURADO</b>\n"
                            f"Archivo: {nombre}\n"
                            f"Tamaño: {tamano} bytes\n"
                            f"SHA256: {sha256}"
                            f"{yara_linea}\n\n"
                            f"<b>Veredicto VirusTotal:</b>\n{veredicto}\n"
                            f"Nombre conocido: {nombre_sugerido}\n"
                            f"Tags: {tags}\n\n"
                            f"https://www.virustotal.com/gui/file/{sha256}"
                        )
                    else:
                        ha_linea = ""
                        if ha_info.get("link"):
                            estado_txt = {
                                "encontrado": "ya estaba en Hybrid Analysis",
                                "subido": "subido para análisis dinámico",
                            }.get(ha_info["estado"], ha_info["estado"])
                            ha_linea = f"\nHybrid Analysis ({estado_txt}): {ha_info['link']}"

                        mensaje = (
                            f"🎯 <b>NUEVO PAYLOAD CAPTURADO</b>\n"
                            f"Archivo: {nombre}\n"
                            f"Tamaño: {tamano} bytes\n"
                            f"SHA256: {sha256}"
                            f"{yara_linea}\n\n"
                            f"VirusTotal: {vt_info.get('mensaje', vt_info.get('error', 'sin datos'))}\n"
                            f"https://www.virustotal.com/gui/file/{sha256}"
                            f"{ha_linea}"
                        )

                    enviar_alerta(mensaje)

                except Exception as e:
                    print(f"[-] Error procesando {nombre}: {e}")

        time.sleep(INTERVALO_SEGUNDOS)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n=== Vigilancia detenida manualmente ===")
