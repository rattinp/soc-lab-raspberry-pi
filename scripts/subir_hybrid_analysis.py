#!/usr/bin/env python3
"""
Sube un archivo capturado por el honeypot a Hybrid Analysis (Falcon Sandbox)
via API, y espera el resultado del analisis dinamico (ejecucion real en
entorno aislado).

Requiere una API key con "upgrade" aprobado (vetting) para poder subir
archivos - con una key restringida sin vetting, solo se puede buscar por hash.

Uso: python3 subir_hybrid_analysis.py <ruta_al_archivo>
"""

import sys
import os
import time
import requests

API_KEY = os.environ.get("HYBRID_ANALYSIS_API_KEY")
BASE_URL = "https://www.hybrid-analysis.com/api/v2"

# Entorno de analisis: 300 = Linux (Ubuntu 16.04, 64 bit) - el mas relevante
# para malware de honeypot SSH/Telnet tipo Mirai/Gafgyt
ENVIRONMENT_ID = 300

HEADERS = {
    "api-key": API_KEY,
    "user-agent": "Falcon Sandbox",
}


def buscar_por_hash(sha256):
    """Busca si el hash ya fue analizado antes por la comunidad (no gasta cuota)."""
    url = f"{BASE_URL}/search/hash"
    resp = requests.post(url, headers=HEADERS, data={"hash": sha256}, timeout=20)
    resp.raise_for_status()
    resultados = resp.json()
    return resultados


def subir_archivo(filepath):
    """Sube el archivo para analisis dinamico. Devuelve el job_id/sha256."""
    url = f"{BASE_URL}/submit/file"
    with open(filepath, "rb") as f:
        files = {"file": (os.path.basename(filepath), f)}
        data = {"environment_id": ENVIRONMENT_ID}
        resp = requests.post(url, headers=HEADERS, files=files, data=data, timeout=60)
    resp.raise_for_status()
    return resp.json()


def consultar_estado(sha256):
    """Consulta el estado/resultado del analisis por hash."""
    url = f"{BASE_URL}/overview/{sha256}"
    resp = requests.get(url, headers=HEADERS, timeout=20)
    resp.raise_for_status()
    return resp.json()


def main():
    if not API_KEY:
        print("[-] Falta configurar HYBRID_ANALYSIS_API_KEY como variable de entorno.")
        sys.exit(1)

    if len(sys.argv) < 2:
        print("Uso: python3 subir_hybrid_analysis.py <ruta_al_archivo>")
        sys.exit(1)

    filepath = sys.argv[1]
    if not os.path.isfile(filepath):
        print(f"[-] No se encontro el archivo: {filepath}")
        sys.exit(1)

    print(f"=== Procesando {filepath} ===\n")

    print("[1/2] Verificando si ya fue analizado antes...")
    import hashlib
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for bloque in iter(lambda: f.read(65536), b""):
            sha256.update(bloque)
    sha256_hex = sha256.hexdigest()
    print(f"    SHA256: {sha256_hex}")

    try:
        busqueda = buscar_por_hash(sha256_hex)
        if busqueda:
            print("[+] Este hash YA fue analizado antes por la comunidad:")
            print(f"    Reporte: https://www.hybrid-analysis.com/sample/{sha256_hex}")
            return
    except Exception as e:
        print(f"    (no se pudo verificar busqueda previa: {e})")

    print("\n[2/2] No encontrado previamente, subiendo para analisis nuevo...")
    try:
        resultado_envio = subir_archivo(filepath)
        print(f"    Enviado. Respuesta: {resultado_envio}")
    except Exception as e:
        print(f"[-] Error al subir el archivo: {e}")
        print("    Si el error es de autorizacion, tu API key puede no tener el")
        print("    'upgrade' (vetting) aprobado todavia para subir archivos.")
        sys.exit(1)

    print("\n=== Esperando que termine el analisis (puede tardar varios minutos) ===")
    for intento in range(30):
        time.sleep(20)
        try:
            estado = consultar_estado(sha256_hex)
            if estado.get("state") == "SUCCESS" or "verdict" in estado:
                print("\n[+] Analisis completo:")
                print(f"    Veredicto: {estado.get('verdict', 'N/A')}")
                print(f"    Threat score: {estado.get('threat_score', 'N/A')}")
                print(f"    Reporte completo: https://www.hybrid-analysis.com/sample/{sha256_hex}")
                return
            else:
                print(f"    [{intento+1}/30] Todavia procesando...")
        except Exception:
            print(f"    [{intento+1}/30] Esperando resultado...")

    print("\n[!] Se agoto el tiempo de espera. Revisa manualmente en:")
    print(f"    https://www.hybrid-analysis.com/sample/{sha256_hex}")


if __name__ == "__main__":
    main()
