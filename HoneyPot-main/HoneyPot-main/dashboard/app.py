"""Live Streamlit dashboard for the SSH honeypot.

Reads the JSON session logs written by `src/session_recorder.py` (and the
JSONL malware-capture / fingerprint logs) off disk — it never talks to the
honeypot process directly, so it can run on a different box for safety.

Run with:
    streamlit run dashboard/app.py
"""
from __future__ import annotations

import glob
import json
import os
import sys
import time
from collections import Counter
from datetime import datetime

import pandas as pd
import plotly.express as px
import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import yaml
    with open("config/config.yaml") as fh:
        _CFG = yaml.safe_load(fh)
except Exception:
    _CFG = {}

LOGS_GLOB = (_CFG.get("dashboard") or {}).get("logs_glob", "logs/session_*.json")
REFRESH_SECONDS = (_CFG.get("dashboard") or {}).get("refresh_seconds", 5)

st.set_page_config(page_title="SSH Honeypot Dashboard", layout="wide", page_icon="🛡️")


@st.cache_data(ttl=REFRESH_SECONDS, show_spinner=False)
def load_sessions() -> pd.DataFrame:
    rows = []
    for path in glob.glob(LOGS_GLOB):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                rows.append(json.load(fh))
        except Exception:
            continue
    if not rows:
        return pd.DataFrame()
    return pd.json_normalize(rows)


def load_malware_captures():
    path = (_CFG.get("malware_capture") or {}).get("capture_log", "logs/malware_capture.jsonl")
    records = []
    if os.path.exists(path):
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except Exception:
                        pass
    return records


def parse_ts(value):
    if not value:
        return None
    try:
        return datetime.strptime(value.replace("Z", ""), "%Y-%m-%dT%H:%M:%S")
    except Exception:
        return None


st.title("🛡️ SSH Honeypot — Live Attack Dashboard")
st.caption(f"Auto-refreshing every {REFRESH_SECONDS}s · reading `{LOGS_GLOB}`")

df = load_sessions()

if df.empty:
    st.info("No session logs found yet. Once attackers connect, sessions will appear here.")
    time.sleep(REFRESH_SECONDS)
    st.rerun()

# ---------------------------------------------------------------------- #
# Top-line metrics
# ---------------------------------------------------------------------- #
now = datetime.utcnow()
df["start_dt"] = df["start_time"].apply(parse_ts)
active_mask = df["end_time"].isna() if "end_time" in df else pd.Series([False] * len(df))

col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Total sessions", len(df))
col2.metric("Active sessions", int(active_mask.sum()))
col3.metric("Unique source IPs", df["src_ip"].nunique() if "src_ip" in df else 0)
col4.metric("Likely scanners", int(df.get("likely_scanner", pd.Series(dtype=bool)).sum()))
avg_dur = df["duration_seconds"].dropna().mean() if "duration_seconds" in df else None
col5.metric("Avg. session (s)", f"{avg_dur:.1f}" if avg_dur else "—")

st.divider()

# ---------------------------------------------------------------------- #
# Live sessions table
# ---------------------------------------------------------------------- #
st.subheader("Live / recent sessions")
display_cols = [c for c in [
    "session_id", "src_ip", "geo_country", "geo_city", "accepted_username",
    "accepted_password", "fingerprint_label", "likely_scanner", "start_time",
    "duration_seconds", "disconnect_reason",
] if c in df.columns]
st.dataframe(
    df[display_cols].sort_values("start_time", ascending=False),
    use_container_width=True, height=320,
)

st.divider()

left, right = st.columns(2)

# ---------------------------------------------------------------------- #
# Countries + world map
# ---------------------------------------------------------------------- #
with left:
    st.subheader("Attacks by country")
    if "geo_country" in df.columns:
        country_counts = df["geo_country"].value_counts().reset_index()
        country_counts.columns = ["country", "count"]
        fig = px.bar(country_counts.head(15), x="country", y="count")
        st.plotly_chart(fig, use_container_width=True)

with right:
    st.subheader("World map of source IPs")
    if {"geo_latitude", "geo_longitude"}.issubset(df.columns):
        geo_df = df.dropna(subset=["geo_latitude", "geo_longitude"])
        if not geo_df.empty:
            fig = px.scatter_geo(
                geo_df, lat="geo_latitude", lon="geo_longitude",
                hover_name="src_ip", hover_data=["geo_country", "geo_city"],
                projection="natural earth",
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No geolocated sessions yet (GeoIP DB missing or all-local traffic).")
    else:
        st.info("GeoIP coordinates not present in logs — configure `geoip` in config.yaml.")

st.divider()

left2, right2 = st.columns(2)

with left2:
    st.subheader("Top source IPs")
    if "src_ip" in df.columns:
        top_ips = df["src_ip"].value_counts().reset_index()
        top_ips.columns = ["ip", "count"]
        st.bar_chart(top_ips.set_index("ip").head(15))

with right2:
    st.subheader("Top usernames / passwords tried")
    all_attempts = []
    if "auth_attempts" in df.columns:
        for attempts in df["auth_attempts"].dropna():
            all_attempts.extend(attempts)
    if all_attempts:
        users = Counter(a["username"] for a in all_attempts)
        pwds = Counter(a["password"] for a in all_attempts)
        tab1, tab2 = st.tabs(["Usernames", "Passwords"])
        with tab1:
            st.bar_chart(pd.Series(dict(users.most_common(15))))
        with tab2:
            st.bar_chart(pd.Series(dict(pwds.most_common(15))))
    else:
        st.info("No auth attempts logged yet.")

st.divider()

# ---------------------------------------------------------------------- #
# Commands + heatmap + timeline
# ---------------------------------------------------------------------- #
st.subheader("Top commands executed")
all_commands = []
if "commands" in df.columns:
    for cmds in df["commands"].dropna():
        all_commands.extend(c["command"].split()[0] for c in cmds if c.get("command"))
if all_commands:
    cmd_counts = Counter(all_commands)
    st.bar_chart(pd.Series(dict(cmd_counts.most_common(20))))
else:
    st.info("No commands logged yet.")

col_heat, col_timeline = st.columns(2)

with col_heat:
    st.subheader("Activity heatmap (hour × weekday)")
    valid = df.dropna(subset=["start_dt"])
    if not valid.empty:
        valid = valid.copy()
        valid["hour"] = valid["start_dt"].dt.hour
        valid["weekday"] = valid["start_dt"].dt.day_name()
        pivot = valid.pivot_table(index="weekday", columns="hour", values="session_id", aggfunc="count", fill_value=0)
        order = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
        pivot = pivot.reindex([d for d in order if d in pivot.index])
        fig = px.imshow(pivot, aspect="auto", labels=dict(x="Hour of day", y="Weekday", color="Sessions"))
        st.plotly_chart(fig, use_container_width=True)

with col_timeline:
    st.subheader("Sessions over time")
    valid = df.dropna(subset=["start_dt"])
    if not valid.empty:
        ts = valid.set_index("start_dt").resample("1H").size()
        st.line_chart(ts)

st.divider()

# ---------------------------------------------------------------------- #
# Attack graph: session -> commands (bipartite, sampled)
# ---------------------------------------------------------------------- #
st.subheader("Attack graph — sessions → commands")
try:
    import networkx as nx
    import plotly.graph_objects as go

    G = nx.Graph()
    sample = df.tail(30)
    for _, row in sample.iterrows():
        sid = row.get("session_id", "?")
        G.add_node(f"S:{sid}", kind="session")
        for c in (row.get("commands") or [])[:15]:
            cmd_name = (c.get("command") or "").split()[0]
            if not cmd_name:
                continue
            node = f"C:{cmd_name}"
            G.add_node(node, kind="command")
            G.add_edge(f"S:{sid}", node)

    if G.number_of_nodes() > 0:
        pos = nx.spring_layout(G, seed=42, k=0.6)
        edge_x, edge_y = [], []
        for u, v in G.edges():
            edge_x += [pos[u][0], pos[v][0], None]
            edge_y += [pos[u][1], pos[v][1], None]
        edge_trace = go.Scatter(x=edge_x, y=edge_y, mode="lines",
                                 line=dict(width=0.5, color="#888"), hoverinfo="none")

        node_x, node_y, node_text, node_color = [], [], [], []
        for n, attrs in G.nodes(data=True):
            node_x.append(pos[n][0]); node_y.append(pos[n][1])
            node_text.append(n)
            node_color.append("#e74c3c" if attrs.get("kind") == "session" else "#3498db")

        node_trace = go.Scatter(
            x=node_x, y=node_y, mode="markers+text", text=node_text,
            textposition="top center", hoverinfo="text",
            marker=dict(size=12, color=node_color),
        )
        fig = go.Figure(data=[edge_trace, node_trace])
        fig.update_layout(showlegend=False, margin=dict(l=10, r=10, t=10, b=10),
                           xaxis=dict(visible=False), yaxis=dict(visible=False))
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Not enough data yet to render an attack graph.")
except ImportError:
    st.info("Install `networkx` to enable the attack graph view.")

st.divider()

# ---------------------------------------------------------------------- #
# Malware capture
# ---------------------------------------------------------------------- #
st.subheader("Malware staging attempts (wget/curl — never downloaded)")
captures = load_malware_captures()
if captures:
    st.dataframe(pd.DataFrame(captures), use_container_width=True)
else:
    st.info("No wget/curl attempts captured yet.")

# ---------------------------------------------------------------------- #
# Auto-refresh
# ---------------------------------------------------------------------- #
time.sleep(REFRESH_SECONDS)
st.rerun()
