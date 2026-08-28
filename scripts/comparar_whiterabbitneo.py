#!/usr/bin/env python3
"""
Prueba rapida de UN solo comando contra WhiteRabbitNeo, con num_predict y
num_ctx limitados, para tener un ejemplo real de calidad sin esperar 20+ min.
"""

import time
import ollama

MODELO = "monotykamary/whiterabbitneo-v1.5a:7b_q4_K_M"

# Usamos el comando mas representativo del patron de fingerprinting:
# el script "filter" que crea/ejecuta/autodestruye un archivo.
COMANDO = '/usr/bin/bash -c printf "#!/bin/bash\\necho \\"xxxxxx\\"\\n" > filter && chmod +x filter && ./filter && rm -rf filter'

PROMPT = (
    f"Actua como un analista experto en ciberseguridad. Analiza este comando "
    f"capturado en un honeypot: {COMANDO}. "
    f"Responde estrictamente en un parrafo corto de maximo 3 lineas en espanol."
)

print(f"=== Probando UN comando contra {MODELO} ===")
print(f"Comando: {COMANDO}\n")
print("Esperando respuesta (puede tardar 1-3 minutos)...\n")

inicio = time.time()

respuesta = ollama.generate(
    model=MODELO,
    prompt=PROMPT,
    options={
        "num_predict": 150,
        "num_ctx": 1024,
    },
)

duracion = round(time.time() - inicio, 1)

print(f"=== Respuesta ({duracion}s) ===")
print(respuesta["response"].strip())
