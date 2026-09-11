import streamlit as st
import sqlite3
import pandas as pd
import plotly.express as px
from streamlit_autorefresh import st_autorefresh
from google import genai

from init_db import init_db

st.set_page_config(page_title="NetPulse | AI Network Security", layout="wide")
init_db()
st_autorefresh(interval=2000, key="netpulse_heartbeat")

st.title("🌐 NetPulse: Real-Time Network Threat Analyzer")
st.caption("Low-Level Ingestion Engine + Gemini API Threat Summarization")

api_key = st.sidebar.text_input("Google Gemini API Key", type="password")

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
                st.warning("Please enter your Gemini API Key in the sidebar.")
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
    st.info("No network telemetry found. Run run_engine.py to start logging.")
