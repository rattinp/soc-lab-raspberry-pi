import streamlit as st
import json
import pandas as pd
import os
import time

st.set_page_config(page_title="HoneyPI SOC Lab - Publico", page_icon="🛡️", layout="wide")
st.title("🛡️ HoneyPI - SOC Lab Público")
st.subheader("Datos actualizados cada hora desde una Raspberry Pi 5")
st.caption("⚠️ Este es un espejo público de solo lectura. Se actualiza automáticamente vía GitHub.")

# --- Rutas relativas al repo (Streamlit Cloud clona el repo completo) ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")

HISTORIAL_PATH = os.path.join(DATA_DIR, "incidentes.json")
IPS_ENRIQUECIDAS_PATH = os.path.join(DATA_DIR, "ips_enriquecidas.json")
PAYLOADS_PATH = os.path.join(DATA_DIR, "payloads_capturados.json")
ESTADO_HW_PATH = os.path.join(DATA_DIR, "estado_hardware.json")

# --- Estado del hardware (guardado por el script de sincronizacion) ---
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
            st.metric("🕒 Última actualización", estado.get("actualizado", "N/A"))
    except Exception:
        st.info("Estado de hardware no disponible todavía.")
else:
    st.info("Estado de hardware no disponible todavía.")

st.markdown("---")

# --- Incidentes ---
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
                st.metric("🚨 Total de Eventos", len(df))
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
                if "servicio" in df.columns:
                    st.write("**Ataques por Protocolo**")
                    st.bar_chart(df["servicio"].value_counts())
            with e2:
                if "ip_origen" in df.columns:
                    st.write("**Top 10 IPs Atacantes**")
                    st.bar_chart(df["ip_origen"].value_counts().head(10))
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
                })
                lat, lon = geo.get("lat"), geo.get("lon")
                if lat is not None and lon is not None:
                    mapa_puntos.append({"lat": lat, "lon": lon})

            df_ips = pd.DataFrame(filas)
            g1, g2 = st.columns([2, 1])
            with g1:
                st.dataframe(df_ips, width='stretch')
            with g2:
                if mapa_puntos:
                    st.map(pd.DataFrame(mapa_puntos), zoom=1)
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
            st.dataframe(
                df_payloads[["timestamp", "nombre_archivo", "tamano_bytes", "VirusTotal"]],
                width='stretch',
                column_config={"VirusTotal": st.column_config.LinkColumn("VirusTotal", display_text="Ver análisis")},
            )
        else:
            st.info("Todavía no se capturó ningún payload real.")
    except Exception as e:
        st.error(f"Error al procesar payloads: {e}")
else:
    st.info("⌛ Sin datos de payloads todavía.")

st.markdown("---")
st.caption("Proyecto HoneyPI — honeypot + IA local en Raspberry Pi 5. Código completo en GitHub.")
