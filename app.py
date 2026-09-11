import os
import subprocess
import threading
import streamlit as st
import sqlite3
import pandas as pd
import plotly.express as px
from streamlit_autorefresh import st_autorefresh
from google import genai

from init_db import init_db


def start_background_engine():
    if not os.path.exists("run_engine.py"):
        return

    try:
        subprocess.Popen(
            ["python", "run_engine.py"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except Exception:
        pass


if "engine_started" not in st.session_state:
    st.session_state["engine_started"] = True
    thread = threading.Thread(target=start_background_engine, daemon=True)
    thread.start()


def seed_sample_telemetry():
    conn = sqlite3.connect("netpulse.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS traffic_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        bytes_captured INTEGER,
        packet_count INTEGER
    )
    """)

    sample_rows = [
        (45000, 150),
        (62000, 180),
        (81000, 210),
        (91000, 260),
        (3500000, 2800),
        (4200000, 3100),
    ]
    cursor.executemany(
        "INSERT INTO traffic_logs (bytes_captured, packet_count) VALUES (?, ?)",
        sample_rows,
    )
    conn.commit()
    conn.close()


st.set_page_config(page_title="NetPulse | AI Network Security", layout="wide")
init_db()
st_autorefresh(interval=2000, key="netpulse_heartbeat")

st.title("🌐 NetPulse: Real-Time Network Threat Analyzer")
st.caption("Low-Level Ingestion Engine + Gemini API Threat Summarization")

api_key = st.secrets.get("GEMINI_API_KEY") or os.environ.get("GEMINI_API_KEY")

with st.sidebar:
    user_key = st.text_input("Gemini API Key (Optional)", value=api_key or "", type="password")
    if user_key:
        api_key = user_key
    elif not api_key:
        st.warning("⚠️ No Gemini API key detected. Add it in Streamlit Secrets.")

if st.sidebar.button("⚠️ Trigger DDoS Traffic Spike"):
    try:
        subprocess.Popen(
            ["python", "traffic_gen.py"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        st.sidebar.warning("DDoS Spike Injected! Graph updated.")
        st.rerun()
    except Exception as e:
        st.sidebar.error(f"Failed to trigger spike: {e}")

if st.sidebar.button("⚡ Generate Sample Telemetry / DDoS Spike"):
    seed_sample_telemetry()
    st.sidebar.success("Sample telemetry injected! Refreshing...")
    st.rerun()


def fetch_latest_logs():
    conn = sqlite3.connect("netpulse.db", timeout=10)
    try:
        df = pd.read_sql_query("SELECT * FROM traffic_logs ORDER BY id DESC LIMIT 20", conn)
    finally:
        conn.close()
    return df

df = fetch_latest_logs()

if not df.empty:
    df_sorted = df.sort_values(by="id")

    c1, c2, c3 = st.columns(3)
    latest_pkt = df_sorted.iloc[-1]["packet_count"]
    latest_bytes = df_sorted.iloc[-1]["bytes_captured"]

    c1.metric("Latest Packet Count", f"{latest_pkt} pkts")
    c2.metric("Latest Volume", f"{latest_bytes / 1024:.2f} KB")
    c3.metric("Total Snapshots Captured", f"{len(df_sorted)}")

    st.subheader("📊 Live Traffic Volume (Bytes Captured)")
    fig = px.line(df_sorted, x="timestamp", y="bytes_captured", markers=True, title="Network Throughput Timeline")
    st.plotly_chart(fig, use_container_width=True)

    st.markdown("---")
    st.subheader("🤖 Gemini AI Threat Analysis")
    has_anomaly = (df_sorted["bytes_captured"] > 1000000).any()

    if has_anomaly:
        st.error("🚨 ANOMALOUS TRAFFIC SPIKE DETECTED!")

        if st.button("Generate Gemini Threat Report"):
            if not api_key:
                st.warning("Please add a Gemini API key in Streamlit Secrets or enter one in the sidebar.")
            else:
                try:
                    client = genai.Client(api_key=api_key)
                    metrics_payload = df_sorted.tail(5).to_dict(orient="records")

                    prompt = f"""
                    You are a Security Operations Center (SOC) Specialist. Analyze these recent network telemetry logs:
                    {metrics_payload}

                    Provide a brief threat report (3 bullet points max):
                    1. Attack Classification & Threat Level (e.g., High - Volumetric DDoS).
                    2. Explanation of telemetry anomaly.
                    3. Recommended SOC mitigation steps.
                    """

                    with st.spinner("Analyzing threat telemetry with Gemini..."):
                        response = client.models.generate_content(
                            model="gemini-2.5-flash",
                            contents=prompt
                        )
                        st.success("Analysis Complete")
                        st.markdown(response.text)
                except Exception as e:
                    st.error(f"Gemini API Call Failed: {e}")
    else:
        st.success("🟢 Network metrics nominal. No active threats detected.")
else:
    st.info("No network telemetry found. Generate sample telemetry from the sidebar or run run_engine.py to start logging.")
