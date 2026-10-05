import os
import subprocess
import threading
import time
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
if "gemini_report" not in st.session_state:
    st.session_state.gemini_report = None
if "gemini_report_is_local" not in st.session_state:
    st.session_state.gemini_report_is_local = False
if "gemini_last_call" not in st.session_state:
    st.session_state.gemini_last_call = 0.0

init_db()

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

def fetch_recent_anomalies():
    conn = sqlite3.connect("netpulse.db", timeout=10)
    try:
        anomalies = pd.read_sql_query(
            "SELECT * FROM traffic_logs "
            "WHERE bytes_captured > 1000000 "
            "AND timestamp >= datetime('now', '-15 seconds') "
            "ORDER BY id DESC LIMIT 20",
            conn,
        )
    finally:
        conn.close()
    return anomalies

df = fetch_latest_logs()
recent_anomalies = fetch_recent_anomalies()

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
    has_anomaly = not recent_anomalies.empty

    if has_anomaly:
        st.error("🚨 ANOMALOUS TRAFFIC SPIKE DETECTED!")

        if st.button("Generate Gemini Threat Report"):
            if not api_key:
                st.warning("Please add a Gemini API key in Streamlit Secrets or enter one in the sidebar.")
            else:
                elapsed = time.monotonic() - st.session_state.gemini_last_call
                if elapsed < 10:
                    st.warning(f"Please wait {10 - int(elapsed)} seconds before requesting another report.")
                else:
                    st.session_state.gemini_last_call = time.monotonic()
                    try:
                        client = genai.Client(api_key=api_key)
                        metrics_payload = (
                            recent_anomalies.sort_values(by="id")
                            .tail(5)
                            .to_dict(orient="records")
                        )

                        prompt = f"""
                        You are a Security Operations Center (SOC) Specialist. Analyze these recent network telemetry logs:
                        {metrics_payload}

                        Provide a brief threat report (3 bullet points max):
                        1. Attack Classification & Threat Level (e.g., High - Volumetric DDoS).
                        2. Explanation of telemetry anomaly.
                        3. Recommended SOC mitigation steps.
                        """

                        with st.spinner("Analyzing threat telemetry with Gemini..."):
                            for attempt in range(3):
                                try:
                                    response = client.models.generate_content(
                                        model="gemini-3.8-flash",
                                        contents=prompt
                                    )
                                    st.session_state.gemini_report = response.text
                                    st.session_state.gemini_report_is_local = False
                                    break
                                except Exception as e:
                                    if getattr(e, "code", None) != 503 or attempt == 2:
                                        raise
                                    time.sleep(2 ** (attempt + 1))
                    except Exception as e:
                        error_status = str(getattr(e, "status", ""))
                        if getattr(e, "code", None) == 503:
                            st.error("Gemini is still experiencing high demand after 3 attempts. Please try again shortly.")
                        elif getattr(e, "code", None) == 429 or "RESOURCE_EXHAUSTED" in error_status or "RESOURCE_EXHAUSTED" in str(e):
                            peak_row = recent_anomalies.loc[recent_anomalies["bytes_captured"].idxmax()]
                            latest_row = df_sorted.iloc[-1]
                            st.session_state.gemini_report = (
                                "**Classification:** Possible volumetric traffic spike; investigate as a potential DDoS.\n\n"
                                f"**Evidence:** Peak observed volume was {int(peak_row['bytes_captured']):,} bytes "
                                f"with {int(peak_row['packet_count']):,} packets. Latest sample: "
                                f"{int(latest_row['bytes_captured']):,} bytes and "
                                f"{int(latest_row['packet_count']):,} packets.\n\n"
                                "**Recommended actions:** Review source IPs and traffic distribution, apply rate limits "
                                "or upstream DDoS protection if confirmed, and monitor subsequent samples. The current "
                                "telemetry does not include source addresses, so it cannot confirm attack attribution."
                            )
                            st.session_state.gemini_report_is_local = True
                            st.warning("Gemini quota is exhausted. Showing a local telemetry triage instead; check your Gemini usage and wait for quota reset before requesting AI analysis.")
                        else:
                            st.error(f"Gemini API Call Failed: {e}")
    else:
        st.success("🟢 Network metrics nominal. No active threats detected.")
else:
    st.info("No network telemetry found. Generate sample telemetry from the sidebar or run run_engine.py to start logging.")

if st.session_state.gemini_report:
    if st.session_state.gemini_report_is_local:
        st.info("Local triage (Gemini unavailable)")
    else:
        st.success("Analysis Complete")
    st.markdown("### 🤖 SOC Threat Triage")
    st.markdown(st.session_state.gemini_report)

    if st.button("Clear Report"):
        st.session_state.gemini_report = None
        st.session_state.gemini_report_is_local = False
        st.rerun()

if not st.session_state.gemini_report:
    st_autorefresh(interval=2000, key="netpulse_heartbeat")
