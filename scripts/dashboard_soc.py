import streamlit as st
import json
import pandas as pd
import subprocess
import os
import time

st.set_page_config(page_title="SOC Lab - Raspberry Pi 5", page_icon="🛡️", layout="wide")
st.title("🛡️ Cyber Security SOC Lab - Monitoreo de IA")
st.subheader("Análisis de incidentes en tiempo real procesados localmente con Llama 3.2")

# --- Auto-refresh opcional ---
auto_refresh = st.sidebar.checkbox("🔄 Auto-actualizar cada 10s", value=False)
st.sidebar.caption("Si está activo, la página se recarga sola.")

# --- Sección de Hardware (Métricas arriba en tiempo real) ---
col1, col2, col3, col4 = st.columns(4)

try:
    temp_raw = subprocess.check_output(["vcgencmd", "measure_temp"], text=True)
    temp = temp_raw.strip().split("=")[1]
except Exception:
    temp = "N/A"

try:
    throttled_raw = subprocess.check_output(["vcgencmd", "get_throttled"], text=True)
    throttled_hex = throttled_raw.strip().split("=")[1]
    throttled_val = int(throttled_hex, 16)
    if throttled_val == 0:
        throttled_status = "✅ OK"
    else:
        throttled_status = f"⚠️ {throttled_hex}"
except Exception:
    throttled_status = "N/A"

with col1:
    st.metric(label="🌡️ Temperatura CPU (Argon V3)", value=temp)
with col2:
    st.metric(label="⚡ Estado Throttling", value=throttled_status)
with col3:
    st.metric(label="🔒 Estado del Firewall UFW", value="Activo")
with col4:
    st.metric(label="📡 Red de Acceso", value="Solo Interna (LAN)")

st.markdown("---")

# --- Cargar base de datos de incidentes ---
HISTORIAL_PATH = os.path.expanduser("~/incidentes.json")

if os.path.exists(HISTORIAL_PATH):
    try:
        with open(HISTORIAL_PATH, "r") as f:
            datos = json.load(f)
        df = pd.DataFrame(datos)

        if not df.empty:
            # Reversar para ver los ataques más recientes primero
            df = df.iloc[::-1].reset_index(drop=True)

            # --- Métricas rápidas de ataques ---
            c1, c2, c3 = st.columns(3)
            with c1:
                st.metric(label="🚨 Total de Eventos Capturados", value=len(df))
            with c2:
                if "ip_origen" in df.columns:
                    st.metric(label="🌍 IPs Únicas", value=df["ip_origen"].nunique())
            with c3:
                if "servicio" in df.columns:
                    servicio_top = df["servicio"].value_counts().idxmax()
                    st.metric(label="🎯 Protocolo Más Atacado", value=servicio_top)

            st.markdown("---")

            # --- Estadísticas agregadas ---
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

            st.markdown("---")

            # --- Historial en vivo ---
            st.write("### 🕒 Historial Reciente de Ataques")
            st.dataframe(df, use_container_width=True)

            # --- Último análisis IA ---
            st.write("### 🔍 Detalle del Último Análisis de la IA")
            ultimo = df.iloc[0]
            comando_txt = ultimo.get("comando", "N/A")
            analisis_txt = ultimo.get("analisis", "N/A")
            ip_txt = ultimo.get("ip_origen", "N/A")
            st.info(
                f"**IP de origen:** `{ip_txt}`\n\n"
                f"**Comando ejecutado:** `{comando_txt}`\n\n"
                f"**Diagnóstico de Llama 3.2:** {analisis_txt}"
            )
        else:
            st.info("⌛ El archivo de incidentes existe pero está vacío. Esperando el primer ataque...")

    except Exception as e:
        st.error(f"Error al procesar los datos: {e}")
else:
    st.info("⌛ Esperando el primer ataque para poblar el mapa de datos...")

# Botón manual de actualización
if st.button("🔄 Actualizar Panel"):
    st.rerun()

# Auto-refresh (si está activado)
if auto_refresh:
    time.sleep(10)
    st.rerun()
