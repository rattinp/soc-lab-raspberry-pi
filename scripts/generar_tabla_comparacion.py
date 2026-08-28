#!/usr/bin/env python3
"""
Genera una tabla en Markdown comparando el analisis de ambos modelos
(generico vs especializado en ciberseguridad), lista para pegar en el
articulo del Capitulo 2.
"""

import json
import os

COMPARACION_PATH = os.path.expanduser("~/comparacion_modelos.json")
SALIDA_PATH = os.path.expanduser("~/tabla_comparacion.md")


def truncar(texto, max_chars=180):
    """Corta el texto a un largo razonable para que la tabla no sea gigante."""
    texto = texto.replace("\n", " ").strip()
    if len(texto) > max_chars:
        return texto[:max_chars].rstrip() + "..."
    return texto


def main():
    with open(COMPARACION_PATH, "r") as f:
        resultados = json.load(f)

    lineas = []
    lineas.append("| Comando | Llama 3.2 (genérico) | Modelo especializado en ciberseguridad |")
    lineas.append("|---|---|---|")

    tiempo_generico_total = 0
    tiempo_especializado_total = 0

    for r in resultados:
        comando = truncar(r["comando"], 60)
        analisis_generico = truncar(r["modelo_generico"]["analisis"])
        analisis_especializado = truncar(r["modelo_especializado"]["analisis"])

        tiempo_generico_total += r["modelo_generico"]["tiempo_segundos"]
        tiempo_especializado_total += r["modelo_especializado"]["tiempo_segundos"]

        # Escapar pipes dentro del texto para no romper la tabla markdown
        comando = comando.replace("|", "\\|")
        analisis_generico = analisis_generico.replace("|", "\\|")
        analisis_especializado = analisis_especializado.replace("|", "\\|")

        lineas.append(f"| `{comando}` | {analisis_generico} | {analisis_especializado} |")

    n = len(resultados)
    promedio_generico = round(tiempo_generico_total / n, 1) if n else 0
    promedio_especializado = round(tiempo_especializado_total / n, 1) if n else 0

    lineas.append("")
    lineas.append(f"**Comandos únicos comparados:** {n}")
    lineas.append(f"**Tiempo promedio por consulta — Llama 3.2 genérico:** {promedio_generico}s")
    lineas.append(f"**Tiempo promedio por consulta — Modelo especializado:** {promedio_especializado}s")

    contenido = "\n".join(lineas)

    with open(SALIDA_PATH, "w") as f:
        f.write(contenido)

    print(f"=== Tabla generada en {SALIDA_PATH} ===")
    print(f"Comandos comparados: {n}")
    print(f"Tiempo promedio genérico: {promedio_generico}s | especializado: {promedio_especializado}s")


if __name__ == "__main__":
    main()
