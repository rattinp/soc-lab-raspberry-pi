#!/usr/bin/env python3
"""
Enriquece las IPs atacantes ya capturadas en incidentes.json con:
- Reputacion / reportes de abuso (AbuseIPDB)
- Geolocalizacion: pais, ciudad, lat/lon (ip-api.com, gratis, sin API key)

Guarda todo en ips_enriquecidas.json, indexado por IP, para no volver a
consultar la misma IP dos veces (evita gastar cuota de la API de gracia).
"""

import json
import os
import time
import requests

INCIDENTES_PATH = os.path.expanduser("~/incidentes.json")
SALIDA_PATH = os.path.expanduser("~/ips_enriquecidas.json")

ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY")
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
IPAPI_URL = "http://ip-api.com/json/{ip}"


def cargar_ips_unicas():
    """Lee incidentes.json y devuelve el set de IPs unicas (excluyendo 'desconocida')."""
    with open(INCIDENTES_PATH, "r") as f:
        datos = json.load(f)

    ips = set()
    for incidente in datos:
        ip = incidente.get("ip_origen", "").strip()
        if ip and ip.lower() != "desconocida":
            ips.add(ip)
    return ips


def cargar_registro_existente():
    if os.path.exists(SALIDA_PATH):
        try:
            with open(SALIDA_PATH, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {}
    return {}


def guardar_registro(registro):
    with open(SALIDA_PATH, "w") as f:
        json.dump(registro, f, indent=2, ensure_ascii=False)


def consultar_abuseipdb(ip):
    """Consulta reputacion de la IP en AbuseIPDB. Devuelve dict con los datos relevantes."""
    if not ABUSEIPDB_API_KEY:
        return {"error": "ABUSEIPDB_API_KEY no configurada"}

    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    try:
        resp = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=10)
        resp.raise_for_status()
        data = resp.json().get("data", {})
        return {
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "usage_type": data.get("usageType"),
            "is_tor": data.get("isTor"),
        }
    except Exception as e:
        return {"error": str(e)}


def consultar_geolocalizacion(ip):
    """Consulta geolocalizacion via ip-api.com (gratis, sin key, limite ~45 req/min)."""
    try:
        resp = requests.get(IPAPI_URL.format(ip=ip), timeout=10)
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") == "success":
            return {
                "pais": data.get("country"),
                "region": data.get("regionName"),
                "ciudad": data.get("city"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "org": data.get("org"),
            }
        else:
            return {"error": data.get("message", "consulta fallida")}
    except Exception as e:
        return {"error": str(e)}


def main():
    ips = cargar_ips_unicas()
    print(f"=== Encontradas {len(ips)} IPs unicas en incidentes.json ===\n")

    registro = cargar_registro_existente()

    for i, ip in enumerate(ips, 1):
        if ip in registro:
            print(f"[{i}/{len(ips)}] {ip} -> ya en registro, se omite")
            continue

        print(f"[{i}/{len(ips)}] Consultando {ip} ...")

        abuse_info = consultar_abuseipdb(ip)
        time.sleep(1.5)  # respetar rate limit de AbuseIPDB (free tier)

        geo_info = consultar_geolocalizacion(ip)
        time.sleep(1.5)  # respetar rate limit de ip-api.com

        registro[ip] = {
            "abuseipdb": abuse_info,
            "geolocalizacion": geo_info,
        }

        guardar_registro(registro)

        score = abuse_info.get("abuse_confidence_score", "N/A")
        pais = geo_info.get("pais", "N/A")
        ciudad = geo_info.get("ciudad", "N/A")
        print(f"    Pais: {pais} | Ciudad: {ciudad} | Score de abuso: {score}%")
        print("-" * 60)

    print(f"\n=== Listo. Datos guardados en {SALIDA_PATH} ===")


if __name__ == "__main__":
    main()
