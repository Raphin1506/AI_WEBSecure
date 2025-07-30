#!/usr/bin/env python3
"""CyberSentinel AI – Streamlit dashboard (rev. 2025‑07‑30)

Principais mudanças nesta revisão
--------------------------------
* **Thread resiliente** – checa `is_alive()` e reinicia se necessário.
* **Erros visíveis** – exceções no worker vão para `st.session_state['capture_error']`.
* **Stop limpa tudo** – encerra `LiveCapture.close()` e `join()` da thread.
* **Diagnóstico na UI** – mostra status da thread, tamanho da fila e última falha.
"""

from __future__ import annotations

import asyncio
import datetime as _dt
import queue
import threading
import sys
from collections import deque
from pathlib import Path

import pandas as pd
import streamlit as st
from sklearn.ensemble import IsolationForest

###########################################################################
# Compat / setup                                                          #
###########################################################################

if sys.platform.startswith("win"):
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    except AttributeError:
        pass

try:
    from streamlit_autorefresh import st_autorefresh  # type: ignore
except ModuleNotFoundError:  # graceful fallback
    def st_autorefresh(*_, **__):
        pass

# Monkey‑patch: make asyncio.all_tasks safe when no loop is running (Py3.11+)
_original_all_tasks = asyncio.all_tasks  # type: ignore

def _safe_all_tasks(loop=None):  # type: ignore
    try:
        return _original_all_tasks(loop)
    except RuntimeError:
        return set()

asyncio.all_tasks = _safe_all_tasks  # type: ignore

try:
    import pyshark  # needs Wireshark/tshark + Npcap
except ModuleNotFoundError:
    pyshark = None  # type: ignore

###########################################################################
# Live‑capture backend                                                    #
###########################################################################

PACKET_QUEUE: "queue.Queue[dict]" = queue.Queue(maxsize=5_000)


def _packet_to_row(pkt: "pyshark.packet.packet.Packet") -> dict:
    """Extract minimal fields needed for anomaly detection."""
    try:
        proto = pkt.transport_layer or "N/A"
    except AttributeError:
        proto = "N/A"
    try:
        length = int(getattr(pkt, "length", 0))
    except Exception:
        length = 0
    row = {
        "timestamp": _dt.datetime.now(),
        "ip_src": getattr(pkt, "ip", {}).src if hasattr(pkt, "ip") else "?",
        "ip_dst": getattr(pkt, "ip", {}).dst if hasattr(pkt, "ip") else "?",
        "proto": proto,
        "src_port": getattr(pkt[proto], "srcport", None) if proto != "N/A" else None,
        "dst_port": getattr(pkt[proto], "dstport", None) if proto != "N/A" else None,
        "size": length,
    }
    return row


def start_live_capture(interface: str = "1", bpf: str = "ip or ip6") -> None:
    """Spin up / restart a background PyShark capture thread."""
    if pyshark is None:
        st.error("PyShark/Wireshark não instalado – não é possível capturar pacotes.")
        return

    # If an old thread exists but is dead → clean reference so we can restart
    t = st.session_state.get("capture_thread")
    if t is not None and t.is_alive():
        return  # already running
    st.session_state["capture_thread"] = None  # drop stale
    st.session_state["capture_error"] = ""

    def _worker() -> None:
        asyncio.set_event_loop(asyncio.new_event_loop())
        try:
            cap = pyshark.LiveCapture(interface=interface, bpf_filter=bpf)
            st.session_state["live_cap"] = cap  # store to allow close()
            for pkt in cap.sniff_continuously():
                try:
                    PACKET_QUEUE.put_nowait(_packet_to_row(pkt))
                except queue.Full:
                    try:
                        PACKET_QUEUE.get_nowait()  # drop oldest
                    except queue.Empty:
                        pass
                    PACKET_QUEUE.put_nowait(_packet_to_row(pkt))
        except Exception as e:  # noqa: BLE001 – surface any error
            st.session_state["capture_error"] = f"{type(e).__name__}: {e}"
        finally:
            st.session_state.pop("live_cap", None)

    t = threading.Thread(target=_worker, daemon=True, name="LiveCaptureThread")
    t.start()
    st.session_state["capture_thread"] = t


def stop_live_capture():
    """Terminate capture: close tshark and join thread."""
    # Close LiveCapture (kills tshark subprocess)
    cap = st.session_state.pop("live_cap", None)
    if cap is not None:
        try:
            cap.close()
        except Exception:
            pass

    # Join worker thread
    t = st.session_state.pop("capture_thread", None)
    if t is not None and t.is_alive():
        t.join(timeout=1.0)

###########################################################################
# Anomaly detection                                                       #
###########################################################################

def detectar_anomalias(df: pd.DataFrame, features: list[str]) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame()

    work = df.copy()
    work[features] = work[features].fillna(0).astype(float)

    iso = IsolationForest(n_estimators=150, contamination=0.05, random_state=42)
    iso.fit(work[features])
    preds = iso.predict(work[features])  # 1 = normal, ‑1 = anomaly
    df = df.assign(
        risco=["ALTO" if p == -1 else "BAIXO" for p in preds],
        acao_recomendada=["Investigar" if p == -1 else "Monitorar" for p in preds],
    )
    return df[df["risco"] == "ALTO"]

###########################################################################
# Streamlit UI                                                            #
###########################################################################

st.set_page_config(page_title="CyberSentinel AI", layout="wide")
st.title("🛡️ CyberSentinel AI — Network Threat Monitor")

st.sidebar.header("🎛️ Controles")

interface_input = st.sidebar.text_input(
    "Interface",
    value="1",
    help="Use o NÚMERO mostrado por 'tshark -D' ou o GUID completo.",
)
bpf_filter = st.sidebar.text_input("BPF filter", value="ip or ip6")

t = st.session_state.get("capture_thread")
is_running = t is not None and t.is_alive()

col_start, col_stop = st.sidebar.columns(2)
if col_start.button("▶️ Start", disabled=is_running):
    start_live_capture(interface_input, bpf_filter)

if col_stop.button("⏹️ Stop", disabled=not is_running):
    stop_live_capture()

st.sidebar.markdown("---")
st.sidebar.info("Upload um CSV (exportado do Suricata, Zeek etc.) para análise batch.")
upload_file = st.sidebar.file_uploader("📂 Upload CSV", type="csv")

###########################################################################
# Auto‑refresh every 2 s                                                  #
###########################################################################
st_autorefresh(interval=2_000, key="live_refresh")

###########################################################################
# Main layout                                                             #
###########################################################################

left, right = st.columns((2, 1))

# -------- Live traffic ---------
with left:
    st.subheader("📡 Live traffic")

    # Diagnostics
    diag_thread = st.session_state.get("capture_thread")
    st.caption(
        f"Thread alive: {diag_thread.is_alive() if diag_thread else False} | "
        f"Queue: {PACKET_QUEUE.qsize()} | "
        f"Erro: {st.session_state.get('capture_error', '')}"
    )

    rows: list[dict] = []
    while not PACKET_QUEUE.empty():
        rows.append(PACKET_QUEUE.get())
    df_live = pd.DataFrame(rows)

    if not df_live.empty:
        anomalies_live = detectar_anomalias(df_live, ["src_port", "dst_port", "size"])
        st.dataframe(df_live.tail(100), use_container_width=True)
        if not anomalies_live.empty:
            st.error(f"🚨 {len(anomalies_live)} ameaças detectadas em tempo real!")
            st.dataframe(anomalies_live, use_container_width=True)
    else:
        st.info("Nenhum pacote capturado ainda…")

# -------- Batch CSV analysis ---------
with right:
    st.subheader("📑 Batch analysis")
    if upload_file is not None:
        try:
            df_csv = pd.read_csv(upload_file)
        except Exception as e:
            st.error(f"Falha ao ler CSV: {e}")
            df_csv = pd.DataFrame()

        if not df_csv.empty:
            missing = {"src_port", "dst_port", "size"} - set(df_csv.columns)
            if missing:
                st.warning(f"CSV faltando colunas {missing}. Tente mapear ou renomear antes de enviar.")
            else:
                anomalies_csv = detectar_anomalias(df_csv, ["src_port", "dst_port", "size"])
                st.write("Amostra dos dados:")
                st.dataframe(df_csv.head(20), use_container_width=True)
                if not anomalies_csv.empty:
                    st.error(f"🚨 {len(anomalies_csv)} ameaças encontradas no arquivo!")
                    st.dataframe(anomalies_csv, use_container_width=True)
                else:
                    st.success("Nenhuma anomalia encontrada no arquivo enviado.")
    else:
        st.info("Carregue um CSV para análise off‑line.")
