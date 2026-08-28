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

from telegram_notificar import enviar_alerta

DOWNLOADS_DIR = os.path.expanduser("~/cowrie_logs/lib/cowrie/downloads")
REGISTRO_PATH = os.path.expanduser("~/payloads_capturados.json")
INTERVALO_SEGUNDOS = 15

VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/files/{hash}"


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


def main():
    print(f"=== Vigilando {DOWNLOADS_DIR} ===")

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
                    sha256 = calcular_sha256(filepath)

                    print("=" * 70)
                    print(f"🎯 NUEVO PAYLOAD CAPTURADO")
                    print(f"   Archivo: {nombre}")
                    print(f"   Tamano: {tamano} bytes")
                    print(f"   SHA256: {sha256}")

                    print("   Consultando VirusTotal...")
                    vt_info = consultar_virustotal(sha256)
                    print(f"   VirusTotal: {vt_info}")
                    print("=" * 70)

                    entrada = {
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "nombre_archivo": nombre,
                        "tamano_bytes": tamano,
                        "sha256": sha256,
                        "ruta_local": filepath,
                        "virustotal": vt_info,
                    }
                    registro.append(entrada)
                    archivos_conocidos.add(nombre)
                    guardar_registro(registro)

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
                            f"SHA256: {sha256}\n\n"
                            f"<b>Veredicto VirusTotal:</b>\n{veredicto}\n"
                            f"Nombre conocido: {nombre_sugerido}\n"
                            f"Tags: {tags}\n\n"
                            f"https://www.virustotal.com/gui/file/{sha256}"
                        )
                    else:
                        mensaje = (
                            f"🎯 <b>NUEVO PAYLOAD CAPTURADO</b>\n"
                            f"Archivo: {nombre}\n"
                            f"Tamaño: {tamano} bytes\n"
                            f"SHA256: {sha256}\n\n"
                            f"VirusTotal: {vt_info.get('mensaje', vt_info.get('error', 'sin datos'))}\n"
                            f"https://www.virustotal.com/gui/file/{sha256}"
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
