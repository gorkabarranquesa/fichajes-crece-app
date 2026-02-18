# ============================================================
# app.py  (versión con ajuste de tolerancia en negativos)
# ============================================================

import base64
import binascii
import csv
import datetime as dt
from datetime import date, datetime, timedelta
import json
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import pandas as pd
import requests
import streamlit as st
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# =========================
# CONFIG / SEGURIDAD
# =========================

# NUNCA imprimir/mostrar: API_TOKEN, APP_KEY_B64, payloads cifrados/descifrados, PII sensible
# verify=True, retries/backoff y timeouts

API_ROOT = "https://sincronizaciones.crecepersonas.es"
API_BASE = f"{API_ROOT}/api"
API_TOKEN = os.getenv("CRECE_API_TOKEN", "").strip()
APP_KEY_B64 = os.getenv("CRECE_APP_KEY_B64", "").strip()

TIMEOUT = 30
VERIFY_SSL = True

# Tolerancia diaria para déficits
TOLERANCIA_MINUTOS = 5

# =========================
# HELPERS
# =========================

def _norm_key(s: str) -> str:
    s = (s or "").strip().upper()
    s = re.sub(r"\s+", " ", s)
    return s

def _mask(s: str, keep_last: int = 4) -> str:
    if not s:
        return ""
    s2 = str(s)
    if len(s2) <= keep_last:
        return "*" * len(s2)
    return "*" * (len(s2) - keep_last) + s2[-keep_last:]

def _safe_err(msg: str) -> str:
    return msg.replace(API_TOKEN, "***").replace(APP_KEY_B64, "***")

def _round_seconds_to_minute(s: float) -> int:
    if s is None:
        return 0
    try:
        s = float(s)
    except Exception:
        return 0
    if s < 0:
        s = 0.0
    return int(round(s / 60.0)) * 60

def segundos_a_hhmm(seg: float) -> str:
    """
    Convierte segundos a HH:MM usando el MISMO redondeo en toda la app.
    """
    seg_i = _round_seconds_to_minute(seg)
    total_min = seg_i // 60
    h = total_min // 60
    m = total_min % 60
    return f"{h:02d}:{m:02d}"

def mins_to_hhmm_simple(mm: int) -> str:
    mm = int(mm or 0)
    if mm < 0:
        mm = 0
    h = mm // 60
    m = mm % 60
    return f"{h:02d}:{m:02d}"

def hhmm_to_min(hhmm: str) -> int:
    hhmm = (hhmm or "").strip()
    if not hhmm:
        return 0
    try:
        hh, mm = hhmm.split(":")
        return int(hh) * 60 + int(mm)
    except Exception:
        return 0

def diferencia_hhmm(tc_hhmm: str, tt_hhmm: str) -> str:
    tc_hhmm = (tc_hhmm or "").strip()
    tt_hhmm = (tt_hhmm or "").strip()
    if not tc_hhmm or not tt_hhmm:
        return ""
    tc_min = hhmm_to_min(tc_hhmm)
    tt_min = hhmm_to_min(tt_hhmm)

    if tc_min == tt_min:
        return ""

    diff = tc_min - tt_min
    sign = "+" if diff > 0 else "-"
    diff = abs(diff)

    h = diff // 60
    m = diff % 60
    return f"{sign}{h:02d}:{m:02d}"

def ts_to_hhmm(ts):
    if ts is None or pd.isna(ts):
        return ""
    try:
        return pd.to_datetime(ts).strftime("%H:%M")
    except Exception:
        return ""

def hhmm_to_min_clock(hhmm: str) -> int | None:
    hhmm = (hhmm or "").strip()
    if not hhmm:
        return None
    try:
        hh, mm = hhmm.split(":")
        return int(hh) * 60 + int(mm)
    except Exception:
        return None

def floor_to_30(m: int) -> int:
    m = int(m or 0)
    return (m // 30) * 30

def ceil_to_30(m: int) -> int:
    m = int(m or 0)
    return ((m + 29) // 30) * 30

def _signed_hhmm(mm: int) -> str:
    mm = int(mm or 0)
    if mm == 0:
        return "00:00"
    sign = "+" if mm > 0 else "-"
    mm = abs(mm)
    h = mm // 60
    m = mm % 60
    return f"{sign}{h:02d}:{m:02d}"

# =========================
# HTTP + CIFRADO
# =========================

def _build_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "Authorization": f"Bearer {API_TOKEN}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    })
    return s

def _compose_urls(endpoint: str):
    """
    Construye URLs posibles para un endpoint, con fallback automático.

    - Soporta despliegues donde la API está bajo /api y otros donde NO.
    - Soporta variaciones de ruta: /exportacion/... vs /exportaciones/...
      (hemos visto 404 dependiendo del entorno/versión).
    """
    ep = endpoint if endpoint.startswith("/") else f"/{endpoint}"

    # Variantes de endpoint (singular/plural)
    ep_variants = [ep]
    if "/exportaciones/" in ep:
        ep_variants.append(ep.replace("/exportaciones/", "/exportacion/"))
    if "/exportacion/" in ep:
        ep_variants.append(ep.replace("/exportacion/", "/exportaciones/"))

    # Deduplicar variantes manteniendo orden
    _tmp = []
    for v in ep_variants:
        if v not in _tmp:
            _tmp.append(v)
    ep_variants = _tmp

    urls = []
    for epv in ep_variants:
        # Preferente: API_BASE (normalmente https://.../api) + endpoint
        urls.append(f"{API_BASE}{epv}")

        # Fallback: quitar /api del base (https://...) manteniendo endpoint
        if API_BASE.endswith("/api"):
            urls.append(f"{API_ROOT}{epv}")

        # Fallback alternativo: si el endpoint NO empieza por /api, probar con /api delante (por si el base NO lo tuviera)
        if not epv.startswith("/api/"):
            urls.append(f"{API_ROOT}/api{epv}")

    # Deduplicar manteniendo orden
    out = []
    for u in urls:
        if u not in out:
            out.append(u)
    return out

def _post_json(session: requests.Session, endpoint: str, payload: dict, retries: int = 3, backoff: float = 0.75):
    urls = _compose_urls(endpoint)
    last_err = None

    for i in range(retries):
        for url in urls:
            try:
                r = session.post(url, json=payload, timeout=TIMEOUT, verify=VERIFY_SSL)
                if r.status_code >= 400:
                    # Si es 404, probamos el siguiente URL candidato
                    if r.status_code == 404:
                        raise FileNotFoundError(f"HTTP 404 on {endpoint}")
                    raise RuntimeError(f"HTTP {r.status_code}: {r.text[:200]}")
                return r.json()
            except FileNotFoundError as e:
                last_err = e
                continue
            except Exception as e:
                last_err = e
                # para errores no-404 no probamos otros urls en el mismo intento; reintento con backoff
                break
        time.sleep(backoff * (2 ** i))

    raise RuntimeError(_safe_err(f"POST failed {endpoint}: {last_err}"))

def _decrypt_payload(payload: dict) -> bytes:
    """
    Descifra payload tipo {iv:..., value:...} en base64 con AES-CBC.
    """
    if not APP_KEY_B64:
        raise RuntimeError("Falta APP_KEY_B64 en variables de entorno.")
    key = base64.b64decode(APP_KEY_B64)

    iv_b64 = payload.get("iv")
    val_b64 = payload.get("value")
    if not iv_b64 or not val_b64:
        raise RuntimeError("Payload cifrado inválido (faltan iv/value).")

    iv = base64.b64decode(iv_b64)
    ct = base64.b64decode(val_b64)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    try:
        pt = unpad(pt, AES.block_size)
    except ValueError:
        pass
    return pt

def _parse_json_bytes(b: bytes):
    try:
        return json.loads(b.decode("utf-8"))
    except Exception:
        try:
            return json.loads(b.decode("latin1"))
        except Exception:
            return None

# =========================
# FESTIVOS (CSV) — por sede
# =========================

def _parse_sedes_field(sedes_raw: str):
    """
    Devuelve lista de sedes incluidas, y lista de sedes excluidas si detecta "En P3 no será festivo".
    """
    sedes_raw = (sedes_raw or "").strip()
    if not sedes_raw:
        return [], []

    parts = [p.strip() for p in re.split(r"[;,/]+", sedes_raw) if p.strip()]
    included = []
    excluded = []

    for p in parts:
        if p.lower().startswith("en ") and "no" in p.lower() and "festivo" in p.lower():
            m = re.search(r"(P\d\s+[A-Z0-9 ]+)", p.upper())
            if m:
                excluded.append(_norm_key(m.group(1)))
            continue
        included.append(_norm_key(p))

    return included, excluded

@st.cache_data(show_spinner=False)
def load_festivos_labels_from_csv_bytes(csv_bytes: bytes):
    """
    Devuelve:
      - festivos_by_sede: dict sede_norm -> set(YYYY-MM-DD)
      - festivos_labels_by_sede: dict sede_norm -> dict(YYYY-MM-DD -> nombre_festivo)
    """
    festivos_by_sede = {}
    festivos_labels_by_sede = {}

    if not csv_bytes:
        return festivos_by_sede, festivos_labels_by_sede

    bio = pd.io.common.BytesIO(csv_bytes)

    last_exc = None
    df = None

    for enc in ("utf-8-sig", "utf-8", "latin1"):
        for sep in (",", ";"):
            try:
                bio.seek(0)
                df = pd.read_csv(bio, sep=sep, encoding=enc, engine='python', on_bad_lines='skip')
                last_exc = None
                break
            except UnicodeDecodeError as e:
                last_exc = e
                continue
            except Exception as e:
                last_exc = e
                continue
        if df is not None:
            break

    if df is None:
        raise RuntimeError(f"No se pudo leer el CSV de festivos (encoding/separador). {last_exc}")

    # Columnas esperadas: Fecha, Festivo, Sede(s) (o similares)
    cols = {str(c).lower().strip(): c for c in df.columns}
    all_cols = list(df.columns)

    def _first_existing(*keys):
        for k in keys:
            if k in cols:
                return cols[k]
        return None

    fecha_col = _first_existing("fecha", "date", "dia", "día")
    festivo_col = _first_existing("festivo", "nombre", "name", "descripcion", "descripción")
    sedes_col = _first_existing("sede(s)", "sedes", "sede", "centro", "centros")

    # Fallbacks por posición, pero SOLO si existen columnas suficientes
    if fecha_col is None and len(all_cols) >= 1:
        fecha_col = all_cols[0]
    if festivo_col is None:
        if len(all_cols) >= 2:
            festivo_col = all_cols[1]
        elif len(all_cols) == 1:
            raise RuntimeError("CSV de festivos inválido: falta la columna del nombre del festivo.")
    if sedes_col is None:
        if len(all_cols) >= 3:
            sedes_col = all_cols[2]
        else:
            raise RuntimeError("CSV de festivos inválido: falta la columna de sede(s).")

    for _, r in df.iterrows():
        raw_fecha = str(r.get(fecha_col, "")).strip()
        raw_name = str(r.get(festivo_col, "")).strip()
        raw_sedes = str(r.get(sedes_col, "")).strip()

        d = None
        for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y", "%Y/%m/%d"):
            try:
                d = dt.datetime.strptime(raw_fecha, fmt).date()
                break
            except Exception:
                continue
        if not d:
            continue
        day_str = d.strftime("%Y-%m-%d")

        inc, exc = _parse_sedes_field(raw_sedes)
        if not inc:
            continue

        for sede in inc:
            if sede in exc:
                continue
            festivos_by_sede.setdefault(sede, set()).add(day_str)
            festivos_labels_by_sede.setdefault(sede, {})[day_str] = raw_name or "Festivo"

    return festivos_by_sede, festivos_labels_by_sede

def get_festivos_for_sede(sede: str, festivos_by_sede: dict):
    sede_n = _norm_key(sede)
    return festivos_by_sede.get(sede_n, set())

def get_festivo_label(sede: str, day_str: str, festivos_labels_by_sede: dict):
    sede_n = _norm_key(sede)
    return (festivos_labels_by_sede.get(sede_n) or {}).get(day_str)

def is_weekend(d: date) -> bool:
    return d.weekday() >= 5

# =========================
# (… resto del fichero SIN CAMBIOS respecto a tu base …)
# =========================
# NOTA: el fichero completo está en el enlace de descarga.
