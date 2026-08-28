#!/usr/bin/env python3
"""
Comparador de modelos: corre los comandos unicos ya capturados por el honeypot
contra dos modelos de Ollama (uno generico, uno especializado en ciberseguridad)
y guarda ambos analisis lado a lado para comparar calidad.
"""

import json
import os
import time
from datetime import datetime

import ollama

# ============== CONFIGURACION ==============
INCIDENTES_PATH = os.path.expanduser("~/incidentes.json")
COMPARACION_PATH = os.path.expanduser("~/comparacion_modelos.json")

MODELO_GENERICO = "llama3.2:3b"
MODELO_ESPECIALIZADO = "ALIENTELLIGENCE/cybersecuritythreatanalysisv2"

PROMPT_TEMPLATE = (
    "Actua como un analista experto en ciberseguridad. Analiza este comando "
    "capturado en un honeypot: {comando}. "
    "Responde estrictamente en un parrafo corto de maximo 3 lineas en espanol."
)


def cargar_comandos_unicos():
    """Lee incidentes.json y devuelve la lista de comandos unicos (sin duplicados)."""
    with open(INCIDENTES_PATH, "r") as f:
        datos = json.load(f)

    vistos = set()
    unicos = []
    for incidente in datos:
        comando = incidente.get("comando", "").strip()
        if comando and comando not in vistos:
            vistos.add(comando)
            unicos.append(comando)

    return unicos


def consultar_modelo(modelo, comando):
    """Envia el prompt a un modelo de Ollama y devuelve la respuesta y el tiempo que tardo."""
    prompt = PROMPT_TEMPLATE.format(comando=comando)
    inicio = time.time()
    try:
        respuesta = ollama.generate(model=modelo, prompt=prompt)
        texto = respuesta["response"].strip()
        duracion = round(time.time() - inicio, 1)
        return texto, duracion
    except Exception as e:
        duracion = round(time.time() - inicio, 1)
        return f"[ERROR: {e}]", duracion


def main():
    comandos = cargar_comandos_unicos()
    print(f"=== Encontrados {len(comandos)} comandos unicos en incidentes.json ===\n")

    resultados = []

    for i, comando in enumerate(comandos, 1):
        print(f"[{i}/{len(comandos)}] Comando: {comando[:80]}")

        print(f"    -> Consultando {MODELO_GENERICO} ...")
        analisis_generico, tiempo_generico = consultar_modelo(MODELO_GENERICO, comando)

        print(f"    -> Consultando {MODELO_ESPECIALIZADO} ...")
        analisis_especializado, tiempo_especializado = consultar_modelo(MODELO_ESPECIALIZADO, comando)

        resultado = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "comando": comando,
            "modelo_generico": {
                "nombre": MODELO_GENERICO,
                "analisis": analisis_generico,
                "tiempo_segundos": tiempo_generico,
            },
            "modelo_especializado": {
                "nombre": MODELO_ESPECIALIZADO,
                "analisis": analisis_especializado,
                "tiempo_segundos": tiempo_especializado,
            },
        }
        resultados.append(resultado)

        print(f"    Generico ({tiempo_generico}s): {analisis_generico[:100]}...")
        print(f"    Especializado ({tiempo_especializado}s): {analisis_especializado[:100]}...")
        print("-" * 70)

        # Guardar progresivamente por si se corta a mitad de camino
        with open(COMPARACION_PATH, "w") as f:
            json.dump(resultados, f, indent=2, ensure_ascii=False)

    print(f"\n=== Listo. Comparacion completa guardada en {COMPARACION_PATH} ===")


if __name__ == "__main__":
    main()
