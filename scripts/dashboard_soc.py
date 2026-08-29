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

# --- Sección de Hardware ---
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
    throttled_status = "✅ OK" if throttled_val == 0 else f"⚠️ {throttled_hex}"
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

# --- Cargar incidentes ---
HISTORIAL_PATH = os.path.expanduser("~/incidentes.json")
IPS_ENRIQUECIDAS_PATH = os.path.expanduser("~/ips_enriquecidas.json")
PAYLOADS_PATH = os.path.expanduser("~/payloads_capturados.json")

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
                st.metric(label="🚨 Total de Eventos Capturados", value=len(df))
            with c2:
                if "ip_origen" in df.columns:
                    st.metric(label="🌍 IPs Únicas", value=df["ip_origen"].nunique())
            with c3:
                if "servicio" in df.columns:
                    servicio_top = df["servicio"].value_counts().idxmax()
                    st.metric(label="🎯 Protocolo Más Atacado", value=servicio_top)

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

            # --- NUEVO: MITRE ATT&CK + Severidad ---
            if "mitre_tactic" in df.columns:
                st.markdown("---")
                st.write("### 🗺️ Clasificación MITRE ATT&CK")
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
                    st.info("Todavía no hay eventos con clasificación MITRE (se completa con la versión actualizada del analista).")

    except Exception as e:
        st.error(f"Error al procesar incidentes: {e}")
else:
    st.info("⌛ Esperando el primer ataque para poblar el mapa de datos...")

st.markdown("---")

# --- NUEVO: Geolocalización y reputación de IPs (AbuseIPDB) ---
st.write("### 🌎 Geolocalización y Reputación de IPs Atacantes")

if os.path.exists(IPS_ENRIQUECIDAS_PATH):
    try:
        with open(IPS_ENRIQUECIDAS_PATH, "r") as f:
            ips_data = json.load(f)

        if ips_data:
            filas = []
            mapa_puntos = []

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

                lat = geo.get("lat")
                lon = geo.get("lon")
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
        st.error(f"Error al procesar ips_enriquecidas.json: {e}")
else:
    st.info("⌛ Todavía no se corrió el enriquecimiento de IPs (enriquecer_ips.py).")

st.markdown("---")

# --- NUEVO: Payloads capturados ---
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

            df_payloads["Veredicto VirusTotal"] = payloads[::-1]
            df_payloads["Veredicto VirusTotal"] = [
                _veredicto_vt(p) for p in payloads[::-1]
            ]

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

            st.dataframe(
                df_payloads[["timestamp", "nombre_archivo", "tamano_bytes", "YARA", "Veredicto VirusTotal", "VirusTotal", "Hybrid Analysis"]],
                width='stretch',
                column_config={
                    "VirusTotal": st.column_config.LinkColumn("VirusTotal", display_text="Ver análisis"),
                    "Hybrid Analysis": st.column_config.LinkColumn("Hybrid Analysis", display_text="Ver análisis"),
                },
            )
        else:
            st.info("Todavía no se capturó ningún payload real. La vigilancia sigue activa.")
    except Exception as e:
        st.error(f"Error al procesar payloads_capturados.json: {e}")
else:
    st.info("⌛ Esperando el primer payload real capturado por el honeypot...")

st.markdown("---")

# --- Último análisis IA (si hay incidentes) ---
if not df.empty:
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

    st.write("### 🕒 Historial Reciente de Ataques")
    st.dataframe(df, width='stretch')

# Botón manual de actualización
if st.button("🔄 Actualizar Panel"):
    st.rerun()

if auto_refresh:
    time.sleep(10)
    st.rerun()
