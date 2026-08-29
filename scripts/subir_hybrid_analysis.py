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

# Entorno de analisis: 330 = Linux (Ubuntu 24.04, 64 bit) - confirmado via
# GET /system/environments contra la API key real (ids anteriores como 300/310
# ya no son validos, la lista de entornos se actualizo)
ENVIRONMENT_ID = 330

HEADERS = {
    "api-key": API_KEY,
    "user-agent": "Falcon Sandbox",
    "accept": "application/json",
}


def buscar_por_hash(sha256):
    """Busca si el hash ya fue analizado antes por la comunidad (no gasta cuota).
    Usa GET /search/hash (el metodo POST esta deprecado)."""
    url = f"{BASE_URL}/search/hash"
    headers_get = {**HEADERS}
    resp = requests.get(url, headers=headers_get, params={"hash": sha256}, timeout=20)
    if resp.status_code >= 400:
        print(f"    Respuesta cruda del servidor: {resp.text[:500]}")
    resp.raise_for_status()
    resultados = resp.json()
    return resultados


def listar_entornos():
    """Consulta los entornos de analisis disponibles (GET /system/environments)."""
    url = f"{BASE_URL}/system/environments"
    resp = requests.get(url, headers=HEADERS, timeout=20)
    resp.raise_for_status()
    return resp.json()


def subir_archivo(filepath):
    """Sube el archivo para analisis dinamico. Devuelve el job_id/sha256."""
    url = f"{BASE_URL}/submit/file"
    with open(filepath, "rb") as f:
        files = {"file": (os.path.basename(filepath), f)}
        data = {"environment_id": ENVIRONMENT_ID}
        headers_con_accept = {**HEADERS, "accept": "application/json"}
        resp = requests.post(
            url,
            headers=headers_con_accept,
            files=files,
            data=data,
            timeout=60,
            allow_redirects=False,  # evitar el redirect www <-> sin-www que rompe el POST
        )
    if resp.status_code in (301, 302, 307, 308):
        # Si redirige, seguimos manualmente a la URL indicada, preservando metodo y body
        nueva_url = resp.headers.get("Location")
        print(f"    (siguiendo redirect a: {nueva_url})")
        with open(filepath, "rb") as f:
            files = {"file": (os.path.basename(filepath), f)}
            resp = requests.post(
                nueva_url, headers=headers_con_accept, files=files, data=data, timeout=60
            )
    if resp.status_code >= 400:
        print(f"    Respuesta cruda del servidor: {resp.text[:500]}")
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
