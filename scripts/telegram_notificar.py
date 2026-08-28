#!/usr/bin/env python3
"""
Modulo reusable para enviar alertas por Telegram.
Se importa desde otros scripts (analista_ia.py, vigilar_payloads.py) para
notificar eventos en tiempo real sin tener que mirar el dashboard.
"""

import os
import requests

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")


def enviar_alerta(mensaje):
    """Envia un mensaje de texto por Telegram. Falla en silencio si algo sale mal
    (nunca queremos que un problema de notificacion tumbe el script principal)."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("[-] Telegram no configurado (faltan variables de entorno), se omite alerta")
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": mensaje,
        "parse_mode": "HTML",
    }

    try:
        resp = requests.post(url, data=payload, timeout=10)
        resp.raise_for_status()
    except Exception as e:
        print(f"[-] Error enviando alerta por Telegram: {e}")


if __name__ == "__main__":
    # Permite probar el modulo directamente: python3 telegram_notificar.py
    enviar_alerta("🛡️ Prueba de notificacion desde HoneyPI")
    print("Alerta de prueba enviada (revisa Telegram).")
