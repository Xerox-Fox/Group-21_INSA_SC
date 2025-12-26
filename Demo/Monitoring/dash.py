import sqlite3
import pandas as pd
import streamlit as st
import time
import json
from colorama import init, Fore, Style

# Initialize colorama for cross-platform color support
init()

DB_FILE = "anomalies.db"

st.set_page_config(page_title="Live Anomaly Dashboard", layout="wide")

st.title("Live Log Anomaly Detection Dashboard")
st.markdown("**Real-time anomaly monitoring for Server logs. Updates every 60 seconds.**")

# Function to load data from SQLite
def load_data():
    try:
        conn = sqlite3.connect(DB_FILE)
        df = pd.read_sql_query("SELECT * FROM anomalies ORDER BY timestamp DESC LIMIT 1000", conn)
        conn.close()
        if not df.empty:
            df["timestamp"] = pd.to_datetime(df["timestamp"], format="%Y-%m-%d %H:%M:%S", errors="coerce")
            df = df.dropna(subset=["timestamp"])
        return df
    except sqlite3.Error as e:
        st.error(f"Error connecting to database: {e}")
        return pd.DataFrame()

# Placeholder for auto-refresh
placeholder = st.empty()

# Main loop for auto-refresh
while True:
    with placeholder.container():
        df = load_data()

        if df.empty:
            st.info("No anomalies detected yet...")
        else:
            # Recent anomalies
            st.subheader("⚠️ Recent Anomalies")
            # Style anomalies with red text
            styled_df = df.tail(10).style.apply(
                lambda x: ["color: red" for _ in x], axis=1
            )
            st.dataframe(styled_df, use_container_width=True)

            # Trend per minute (Line Chart)
            df["minute"] = df["timestamp"].dt.floor("T")
            trend = df.groupby("minute").size().reset_index(name="count")
            
            st.subheader("Anomaly Trend (per minute)")
            if not trend.empty:
                trend["minute_str"] = trend["minute"].dt.strftime("%Y-%m-%d %H:%M")
                chart_data = {
                    "labels": trend["minute_str"].tolist(),
                    "datasets": [{
                        "label": "Anomalies per Minute",
                        "data": trend["count"].tolist(),
                        "borderColor": "rgba(75, 192, 192, 1)",
                        "backgroundColor": "rgba(75, 192, 192, 0.2)",
                        "fill": True,
                        "tension": 0.4,
                        "pointBackgroundColor": "rgba(255, 99, 132, 1)",
                        "pointBorderColor": "#fff",
                        "pointHoverBackgroundColor": "#fff",
                        "pointHoverBorderColor": "rgba(255, 99, 132, 1)"
                    }]
                }
                chart_config = {
                    "type": "line",
                    "data": chart_data,
                    "options": {
                        "responsive": True,
                        "plugins": {
                            "title": {"display": True, "text": "Anomaly Trend Over Time"},
                            "tooltip": {"enabled": True},
                            "legend": {"display": True}
                        },
                        "scales": {
                            "x": {"title": {"display": True, "text": "Time"}},
                            "y": {
                                "title": {"display": True, "text": "Anomaly Count"},
                                "beginAtZero": True
                            }
                        }
                    }
                }
                st.markdown("**Modern Line Chart**")
                st.components.v1.html(
                    f"""
                    <div style='background: #1e1e1e; padding: 20px; border-radius: 10px;'>
                        <canvas id='lineChart'></canvas>
                        <script src='https://cdn.jsdelivr.net/npm/chart.js'></script>
                        <script>
                            const ctx = document.getElementById('lineChart').getContext('2d');
                            new Chart(ctx, {json.dumps(chart_config)});
                        </script>
                    </div>
                    """,
                    height=400
                )
            else:
                st.info("No trend data available yet.")

            # Doughnut Chart for Anomaly Severity
            st.subheader("Anomaly Severity Distribution")
            if not df.empty:
                df["severity"] = pd.cut(
                    df["error_rate"],
                    bins=[0, 0.3, 0.7, 1.0],
                    labels=["Low", "Medium", "High"],
                    include_lowest=True
                )
                severity_counts = df["severity"].value_counts().reindex(["Low", "Medium", "High"], fill_value=0)
                chart_data = {
                    "labels": severity_counts.index.tolist(),
                    "datasets": [{
                        "data": severity_counts.values.tolist(),
                        "backgroundColor": [
                            "rgba(54, 162, 235, 0.8)",  # Blue for Low
                            "rgba(255, 206, 86, 0.8)",  # Yellow for Medium
                            "rgba(255, 99, 132, 0.8)"   # Red for High
                        ],
                        "borderColor": ["#1e1e1e"] * 3,
                        "borderWidth": 2
                    }]
                }
                chart_config = {
                    "type": "doughnut",
                    "data": chart_data,
                    "options": {
                        "responsive": True,
                        "plugins": {
                            "title": {"display": True, "text": "Anomaly Severity Distribution"},
                            "legend": {"position": "top"}
                        }
                    }
                }
                st.markdown("**Severity Breakdown**")
                st.components.v1.html(
                    f"""
                    <div style='background: #1e1e1e; padding: 20px; border-radius: 10px;'>
                        <canvas id='doughnutChart'></canvas>
                        <script src='https://cdn.jsdelivr.net/npm/chart.js'></script>
                        <script>
                            const ctx = document.getElementById('doughnutChart').getContext('2d');
                            new Chart(ctx, {json.dumps(chart_config)});
                        </script>
                    </div>
                    """,
                    height=400
                )
            else:
                st.info("No severity data available yet.")

    # Wait 60 seconds before refreshing
    time.sleep(60)