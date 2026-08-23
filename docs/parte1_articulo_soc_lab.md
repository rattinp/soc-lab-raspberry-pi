# Construyendo un SOC casero con IA local — Parte 1: la arquitectura y los primeros ataques

*Esta es la primera entrega de una serie sobre cómo armé, desde cero, un laboratorio de ciberseguridad defensiva con IA 100% local en una Raspberry Pi 5. En esta parte cubro la arquitectura completa y los resultados de las primeras horas de exposición real a internet. Las próximas entregas van a cubrir captura de payloads reales, comparación de modelos de IA, y hardening adicional.*

---

## Introducción

Con más de 20 años en IT y trabajando actualmente como Jefe de Sector Infraestructura en una organización binacional, quise llevar la ciberseguridad defensiva a un terreno práctico: montar un laboratorio real, expuesto a internet, que capture ataques reales y los analice con inteligencia artificial corriendo 100% local — sin depender de servicios en la nube, sin enviar un solo byte de los logs a terceros.

La pregunta que quería responder: **¿cuánto tarda internet en atacar un dispositivo nuevo, y qué tan sofisticados son esos ataques automatizados?**

---

## Objetivo del experimento

- Medir cuánto tarda un dispositivo recién expuesto a internet en recibir su primer ataque.
- Capturar comandos reales de atacantes/bots (SSH y Telnet) en un entorno seguro y aislado.
- Usar un modelo de lenguaje local (sin nube) para generar un diagnóstico automático de cada intento.
- Hacerlo todo sobre hardware accesible: una Raspberry Pi 5.

---

## 1. Hardware y sistema base

- **Raspberry Pi 5**, montada en carcasa **Argon ONE V3** (aluminio, con ventilación PWM activa).
- **Raspberry Pi OS Lite (64-bit)**, instalación headless (sin monitor ni periféricos), administrada 100% por SSH.
- Control térmico configurado con el script oficial de Argon40 (`argon1.sh`), con curva de ventilador ajustada de forma agresiva (arrancando en 45°C) para sostener la carga sumada de Ollama + honeypot 24/7.

---

## 2. Hardening de acceso

Antes de exponer nada a internet, se aseguró el acceso administrativo:

- El SSH real de administración se movió del puerto 22 al **puerto 2222**, para separarlo completamente del honeypot.
- **UFW** configurado con política `deny incoming` por defecto, permitiendo únicamente el acceso administrativo por 2222.
- Los puertos 22 (SSH honeypot) y 23 (Telnet honeypot) quedaron reservados exclusivamente para el tráfico dirigido al contenedor de Cowrie.

Un detalle técnico no menor: **Docker gestiona sus propias reglas de `iptables`** para los puertos que publica, y en la práctica puede saltear el filtrado de UFW para esos puertos específicos. Esto no es un problema en este caso —es justamente el comportamiento deseado para exponer el honeypot— pero vale la pena saberlo: la exposición real a internet la define el *port forwarding del router*, no UFW.

---

## 3. El honeypot: Cowrie sobre Docker

Se desplegó el contenedor oficial de **Cowrie** (`cowrie/cowrie:latest`), un honeypot SSH/Telnet interactivo de mediana interacción, que simula un servidor Linux vulnerable y registra cada comando que un atacante intenta ejecutar.

```bash
docker run -d \
  --name cowrie \
  --restart always \
  -p 22:2222 \
  -p 23:2223 \
  -v <volumen_config>:/cowrie/cowrie-git/etc \
  -v /home/usuario/cowrie_logs:/cowrie/cowrie-git/var \
  cowrie/cowrie:latest
```

Ambos protocolos —SSH y Telnet— se habilitaron explícitamente vía `cowrie.cfg`, ya que Telnet viene deshabilitado por defecto (es el vector clásico de botnets IoT como Mirai).

---

## 4. Exposición controlada a internet

En el router doméstico se configuraron reglas de **Port Forwarding**:

- Puerto público 22 → Pi:22 (honeypot SSH)
- Puerto público 23 → Pi:23 (honeypot Telnet)

Ningún otro puerto quedó expuesto. El SSH real de administración (2222) permanece accesible solo dentro de la LAN.

---

## 5. Motor de IA local: Ollama + Llama 3.2

Se instaló **Ollama** de forma nativa (script oficial ARM64), corriendo como servicio `systemd` en el puerto `11434`, con el modelo **Llama 3.2 (3B)** descargado localmente. Toda la inferencia ocurre en la propia Pi — cero llamadas a APIs externas, cero costo por token, cero exposición de datos.

---

## 6. El script analista: uniendo honeypot + IA

Un script en Python (`analista_ia.py`) escucha en tiempo real la salida de Docker (`docker logs -f`) del contenedor Cowrie, y por cada línea que Cowrie marca como comando real del atacante (`CMD:` / `Command found:`):

1. Extrae la IP de origen y el protocolo (SSH/Telnet).
2. Arma un prompt y se lo envía a Ollama, pidiendo un diagnóstico breve en español.
3. Registra la temperatura de la CPU y el estado de throttling (telemetría de hardware en el momento exacto del ataque).
4. Guarda todo estructurado en `incidentes.json`.

Todo el pipeline corre de forma autónoma como servicio `systemd` (`analista.service`), con reinicio automático ante fallas.

---

## 7. Dashboard de monitoreo

Se construyó un dashboard con **Streamlit** que expone en la LAN:

- Temperatura de CPU y estado de throttling en tiempo real.
- Métricas agregadas: total de eventos, IPs únicas, protocolo más atacado.
- Gráficos de las IPs y comandos más frecuentes.
- Historial completo de incidentes con el análisis de la IA para cada uno.

También corre como servicio `systemd` (`dashboard.service`), accesible vía `http://<IP_de_la_Pi>:8501`.

---

## 8. Resultados de las primeras horas

**Ventana de observación:** 23 de agosto de 2026, 02:53 a 11:50 (8h56min).

| Métrica | Valor |
|---|---|
| Total de eventos capturados | **334** |
| IPs únicas atacantes | **4** |
| Protocolo atacado | **100% SSH** (Telnet aún sin tráfico real) |
| Temperatura CPU (rango) | 29°C – 62°C (promedio 52.6°C) |
| Eventos de throttling | **0** (ni uno solo en 334 corridas de inferencia) |

### Las IPs atacantes

| IP (enmascarada) | Eventos | % del total |
|---|---|---|
| `80.94.92.xxx` (host A) | 192 | 57% |
| `2.57.122.xxx` (host B) | 70 | 21% |
| `2.57.122.xxx` (host C, primer ataque registrado) | 48 | 14% |
| `80.94.92.xxx` (host D) | 24 | 7% |

Dato interesante: las IPs se agrupan en dos bloques /24 distintos, y dentro de cada bloque el comportamiento es **idéntico letra por letra** — fuerte indicio de que se trata del mismo actor (o la misma botnet) operando desde varios hosts de un mismo proveedor, en vez de atacantes independientes.

### El patrón de ataque: un script de fingerprinting automatizado

Lo más revelador del dataset no fue la cantidad de IPs, sino que **las 4 ejecutaron exactamente la misma secuencia de comandos**, en el mismo orden, sin variación:

1. `uname -s -v -n -r -m` — identificación básica del sistema.
2. Dos variantes de `export PATH=...` — asegurar que sus binarios puedan ejecutarse.
3. Una batería de `echo CLAVE:` (`UNAME`, `ARCH`, `UPTIME`, `CPUS`, `CPU_MODEL`, `GPU`, `LAST`, `FILTER`) — recolección de huella del sistema en formato fácil de parsear, típica de malware que reporta esta info a su servidor de comando y control.
4. El comando más revelador de todos:

```bash
/usr/bin/bash -c printf "#!/bin/bash\necho \"xxxxxx\"\n" > filter && chmod +x filter && ./filter && rm -rf filter
```

Este último paso crea un script, lo hace ejecutable, lo corre, y se **borra a sí mismo** — es una prueba clásica de *"¿puedo escribir y ejecutar en este filesystem?"*, un chequeo de sandbox/honeypot que suele preceder a la descarga del payload real. El nombre `filter` coincide con el `echo FILTER:` del paso anterior, lo que sugiere que todo el bloque es un único módulo de reconocimiento reutilizado por el atacante en cada host.

Esto no es un humano tipeando — es un script, corriendo de forma idéntica en 4 máquinas distintas, en cuestión de horas desde que el honeypot quedó expuesto.

---

## 9. Lo que la IA local detectó bien (y lo que no)

Llama 3.2 (3B), corriendo enteramente en la Pi, generó un análisis en español para cada uno de los 334 eventos, en tiempo real, sin costo y sin salir de la red local. Para un modelo de este tamaño, el resultado es sorprendentemente útil como primera pasada.

Pero también se le notan las costuras: el mismo comando `echo FILTER:` recibió interpretaciones distintas cada vez que apareció — "inyección de código" una vez, "trampa de captura" otra, "filtro no válido" en otra — sin reconocer que era **la misma técnica repetida**. Un modelo más grande (o uno especializado en seguridad) probablemente hubiera detectado el patrón y lo hubiera señalado como parte de una secuencia conocida, en vez de narrar cada línea de forma aislada.

Esto abre la puerta a la próxima entrega de esta serie: comparar Llama 3.2 3B contra modelos más grandes y contra modelos específicamente afinados para ciberseguridad, usando este mismo dataset de 334 eventos reales como benchmark.

---

## 10. Próximos pasos (Parte 2 en camino)

- **Captura de payloads reales**: habilitar que Cowrie descargue de verdad los binarios que los atacantes intentan bajar (hoy la salida a internet está bloqueada/simulada), analizarlos por hash contra VirusTotal, sin ejecutarlos jamás.
- **Comparación de modelos de IA**: correr este mismo dataset contra modelos especializados en ciberseguridad disponibles en Ollama, y contra un LLM de frontera en la nube, para medir la brecha de calidad de análisis.
- **Enriquecimiento con threat intelligence**: chequeo automático de las IPs atacantes contra AbuseIPDB.
- **Exposición de Telnet**: ya habilitado a nivel de infraestructura, pendiente de tráfico real para analizar el perfil de ataques IoT/Mirai.
- **Alertas en tiempo real**: notificación (Telegram) cuando entra un ataque nuevo, sin depender de mirar el dashboard.

---

## Reproducí este laboratorio vos mismo

Todo el código —el script analista, el dashboard, y la configuración de servicios— está disponible en GitHub: **[link al repo]**

## Stack utilizado

`Raspberry Pi 5` · `Argon ONE V3` · `Raspberry Pi OS Lite 64-bit` · `Docker` · `Cowrie` · `Ollama` · `Llama 3.2 (3B)` · `Python` · `Streamlit` · `systemd` · `UFW`

---

*Este proyecto fue desarrollado de forma independiente como laboratorio personal de ciberseguridad defensiva. Parte 2 próximamente.*
