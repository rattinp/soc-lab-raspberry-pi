HoneyPI: un SOC casero con IA local — Capítulo 1

Esta es la descripción sobre como armar, desde cero, un laboratorio de ciberseguridad defensiva con IA 100% local en una Raspberry Pi 5 — el "HoneyPI". En esta parte cubro la arquitectura completa y los resultados de las primeras 15 horas de exposición real a internet. Los próximos capítulos van a cubrir captura de payloads reales y comparación de modelos de IA.

________________________________________

Introducción

La idea básica era montar un laboratorio real, expuesto a internet, que capture ataques reales y los analice con IA corriendo 100% local — sin depender de servicios en la nube y sin enviar un solo byte de los logs a terceros.

Las preguntas que quería responder: ¿cuánto tarda hoy en día un servicio publicado en internet en ser escaneado o atacado? ¿Qué tan sofisticados son esos ataques automatizados? ¿Y qué tan bien puede una IA local, corriendo en una placa de menos de 100 dólares, interpretar todo ese flujo sin depender de la nube?

________________________________________

Objetivo del experimento

•	Medir cuánto tarda un dispositivo recién expuesto a internet en recibir su primer ataque, si bien para esto necesitaríamos contar con una muestra de cientos de dispositivos, considero que esta información, sobre todo en una IP del rango residencial siempre es de valor.
•	Capturar comandos reales de atacantes/bots (SSH y Telnet) en un entorno seguro y aislado (Al final utilice solamente SSH)
•	Usar un modelo de lenguaje local (sin nube) para generar un diagnóstico automático de cada intento.
•	Hacerlo todo sobre hardware accesible: una Raspberry Pi 5.

________________________________________

1. Hardware y sistema base

•	Raspberry Pi 5, montada en carcasa Argon ONE V3 (aluminio, con ventilación PWM activa). Es indispensable una refrigeración adecuada para evitar el sobrecalentamiento.
•	Raspberry Pi OS Lite (64-bit), instalación headless (sin monitor ni periféricos), administrada 100% por SSH.
•	Control térmico configurado con el script oficial de Argon40 (argon1.sh), con curva de ventilador ajustada de forma agresiva (arrancando en 45°C) para sostener la carga sumada de Ollama + honeypot 24/7.

________________________________________

2. Hardening de acceso

Antes de exponer nada a internet, se aseguró el acceso administrativo:

•	El SSH real de administración se movió del puerto 22 al puerto 2222, para separarlo completamente del honeypot.
•	UFW configurado con política deny incoming por defecto, permitiendo únicamente el acceso administrativo por 2222.
•	Los puertos 22 (SSH honeypot) y 23 (Telnet honeypot) quedaron reservados exclusivamente para el tráfico dirigido al contenedor de Cowrie.

Un detalle técnico no menor: Docker gestiona sus propias reglas de iptables para los puertos que publica, y en la práctica puede saltear el filtrado de UFW para esos puertos específicos. Esto no es un problema en este caso —es justamente el comportamiento deseado para exponer el honeypot— pero vale la pena saberlo: la exposición real a internet la define el port forwarding del router, no UFW.

________________________________________

3. El honeypot: Cowrie sobre Docker

Se desplegó el contenedor oficial de Cowrie (cowrie/cowrie:latest), un honeypot SSH/Telnet interactivo de mediana interacción, que simula un servidor Linux vulnerable y registra cada comando que un atacante intenta ejecutar.

docker run -d \
  --name cowrie \
  --restart always \
  -p 22:2222 \
  -p 23:2223 \
  -v <volumen_config>:/cowrie/cowrie-git/etc \
  -v /home/usuario/cowrie_logs:/cowrie/cowrie-git/var \
  cowrie/cowrie:latest

Ambos protocolos —SSH y Telnet— se habilitaron explícitamente vía cowrie.cfg, ya que Telnet viene deshabilitado por defecto (es el vector clásico de botnets IoT como Mirai). Hasta el cierre de este capítulo, todo el tráfico real recibido fue por SSH; Telnet permanece habilitado a la espera de su primer visitante.

________________________________________

4. Exposición controlada a internet

En el router doméstico se configuraron reglas de Port Forwarding:

•	Puerto público 22 → Pi:22 (honeypot SSH)
•	Puerto público 23 → Pi:23 (honeypot Telnet)

Ningún otro puerto quedó expuesto. El SSH real de administración (2222) permanece accesible solo dentro de la LAN.

________________________________________

5. Motor de IA local: Ollama + Llama 3.2

Se instaló Ollama de forma nativa (script oficial ARM64), corriendo como servicio systemd en el puerto 11434, con el modelo Llama 3.2 (3B) descargado localmente. Toda la inferencia ocurre en la propia Pi — cero llamadas a APIs externas, cero costo por token, cero exposición de datos. Cada análisis demora unos 10 segundos en generarse. No funciona del todo bien y está pendiente utilizar modelos orientados a ciberseguridad y análisis con modelos de Claude y GPT.

________________________________________

6. El script analista: uniendo honeypot + IA

Un script en Python (analista_ia.py) escucha en tiempo real la salida de Docker (docker logs -f) del contenedor Cowrie, y por cada línea que Cowrie marca como comando real del atacante (CMD: / Command found:):

1.	Extrae la IP de origen y el protocolo (SSH/Telnet).
2.	Arma un prompt y se lo envía a Ollama, pidiendo un diagnóstico breve en español.
3.	Registra la temperatura de la CPU y el estado de throttling (telemetría de hardware en el momento exacto del ataque).
4.	Guarda todo estructurado en incidentes.json.

Todo el pipeline corre de forma autónoma como servicio systemd (analista.service), con reinicio automático ante fallas.

________________________________________

7. Dashboard de monitoreo

Se construyó un dashboard con Streamlit que expone en la LAN:

•	Temperatura de CPU y estado de throttling en tiempo real.
•	Métricas agregadas: total de eventos, IPs únicas, protocolo más atacado.
•	Gráficos de las IPs y comandos más frecuentes.
•	Historial completo de incidentes con el análisis de la IA para cada uno.

También corre como servicio systemd (dashboard.service), accesible vía http://<IP_de_la_Pi>:8501.

________________________________________

8. Resultados de las primeras 15 horas

A los 38 minutos de quedar expuesto, un bot de escaneo ya había encontrado el honeypot por SSH y estaba intentando confirmar si había caído en una shell real.

Métrica	Valor
Total de eventos capturados	833
IPs únicas atacantes	8
Protocolo atacado	100% SSH (No se publicó Telnet)
Temperatura CPU (rango)	29°C – 62°C
Eventos de throttling	0

Dos patrones de ataque bien diferenciados

Patrón 1 — Fingerprinting automatizado. Un grupo de IPs, agrupadas en dos bloques /24 distintos, ejecutó exactamente la misma secuencia de comandos, letra por letra: identificación del sistema (uname), variables de entorno, una batería de echo CLAVE: recolectando huella del hardware, y el dato más revelador — un mini-script que se crea, se ejecuta y se autodestruye para comprobar si puede escribir y correr código en el filesystem. No es una persona tipeando: es un script de reconocimiento, corriendo idéntico en varias máquinas, probablemente parte de la misma botnet.

Patrón 2 — Verificación de shell por fuerza bruta. Un segundo actor, mucho más agresivo en volumen, repitió un único comando (echo xsec) cientos de veces en sesiones separadas, con reconexiones cada 10-15 segundos — un patrón típico de bot que confirma si logró un shell interactivo real antes de continuar, probablemente en el marco de un scanning masivo más que de una sesión interactiva sostenida. Esta actividad tiende a generar más temperatura en la Pi debido al uso intensivo del procesador para generar los análisis de IA.

Entre ambos patrones, quedó claro que no hay tiempo de gracia para un servicio recién expuesto a internet: la primera visita llegó en minutos.

________________________________________

9. Lo que la IA local detectó bien (y lo que no)

Llama 3.2 (3B), corriendo enteramente en la Pi, generó un análisis en español para cada uno de los 833 eventos, en tiempo real, sin costo y sin salir de la red local. Para un modelo de este tamaño, el resultado es sorprendentemente útil como algo de primera línea.

Pero también tuvo algunas inconsistencias: el mismo comando repetido cientos de veces recibió interpretaciones distintas cada vez — sin reconocer que era la misma técnica repetida. Un modelo más grande (o uno especializado en seguridad), o simplemente uno con memoria de los eventos anteriores, probablemente hubiera detectado el patrón y lo hubiera señalado como parte de una campaña conocida, en vez de analizar cada línea de forma aislada.

Esto abre la puerta a mejoras: comparar Llama 3.2 3B contra modelos más grandes y contra modelos específicamente afinados para ciberseguridad, usando este mismo dataset como benchmark.

________________________________________

10. Próximos pasos

•	Captura de payloads reales: habilitar que Cowrie descargue de verdad los binarios que los atacantes intentan bajar (hoy la salida a internet está bloqueada/simulada), analizarlos por hash contra VirusTotal, sin ejecutarlos jamás.
•	Comparación de modelos de IA: correr este mismo dataset contra modelos especializados en ciberseguridad disponibles en Ollama, y contra un LLM de frontera en la nube, para medir la brecha de calidad de análisis.
•	Enriquecimiento con threat intelligence: chequeo automático de las IPs atacantes contra AbuseIPDB.
•	Perfil de ataques Telnet: publicar Telnet para analizar el perfil de bots estilo IoT/Mirai.
•	Alertas en tiempo real: notificación (Telegram) cuando entra un ataque nuevo, sin depender de mirar el dashboard.
•	Agregar Geolocalización a las IPs atacantes.

________________________________________

Para reproducir este laboratorio:

Todo el código —el script de python, dashboard, la configuración de servicios, etc.— está disponible en GitHub:
https://github.com/rattinp/soc-lab-raspberry-pi

El espacio a la colaboración está más que abierto — issues, pull requests, y sugerencias son bienvenidas.

Stack utilizado
Raspberry Pi 5 · Argon ONE V3 · Raspberry Pi OS Lite 64-bit · Docker · Cowrie · Ollama · Llama 3.2 (3B) · Python · Streamlit · systemd · UFW

________________________________________

Este proyecto fue desarrollado de forma independiente como laboratorio personal de ciberseguridad defensiva. Capítulo 2 próximamente.
