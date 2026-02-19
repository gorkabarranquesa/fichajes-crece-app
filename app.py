# ===========================
# app.py (FIXED USER 3)
# ===========================

import base64
import json
import multiprocessing
import random
import time
import os
from datetime import date, datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

import pandas as pd
import requests
import streamlit as st
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# ============================================================
# CONFIG (Seguridad por defecto + rendimiento estable)
# ============================================================

API_URL_BASE = "https://sincronizaciones.crecepersonas.es/api"
API_TOKEN = st.secrets["API_TOKEN"]
APP_KEY_B64 = st.secrets["APP_KEY_B64"]

CPU = multiprocessing.cpu_count()
MAX_WORKERS = max(8, min(24, CPU * 3))
HTTP_TIMEOUT = (5, 25)  # (connect, read)

TOLERANCIA_MINUTOS = 5
TOLERANCIA_HORAS = TOLERANCIA_MINUTOS / 60.0
MARGEN_HORARIO_MIN = 5

USER_AGENT = "RRHH-Fichajes-Crece/1.0 (Streamlit)"

RETRY_STATUS = {429, 502, 503, 504}
MAX_RETRIES = 4
BACKOFF_BASE_SECONDS = 0.6
BACKOFF_MAX_SECONDS = 6.0

_SESSION = requests.Session()
_SESSION.headers.update(
    {
        "Accept": "application/json",
        "Authorization": f"Bearer {API_TOKEN}",
        "User-Agent": USER_AGENT,
    }
)

# ============================================================
# EXCLUSIONES RRHH (Sin fichajes) -> POR NOMBRE (NO POR NIF)
# ============================================================

EXCLUDE_SIN_FICHAJES_NAMES_NORM = {
    "MIKEL ARZALLUS MARCO",
    "JOSE ANGEL OCHAGAVIA SATRUSTEGUI",
    "BENITO MENDINUETA ANDUEZA",
}

# ============================================================
# FESTIVOS por sede (CSV)
# - Upload en la app (prioridad)
# - Si no se sube, intenta usar un CSV local llamado así (junto a app.py)
# - Si se pulsa "Guardar CSV en memoria", además lo persistimos a disco
#   para que sobreviva a recargas del navegador.
# ============================================================

DEFAULT_FESTIVOS_CSV_PATH = os.path.join("/tmp", "festivos_por_sede.csv") if os.name != "nt" else "Listado Festivos.csv"


# ============================================================
# CATÁLOGOS LIMITADOS (RRHH)
# ============================================================

ALLOWED_EMPRESAS = [
    "Barranquesa Tower Flanges, S.L.",
    "Barranquesa Anchor Cages, S.L.",
    "Industrial Barranquesa S.A.",
]

ALLOWED_SEDES = [
    "P0 IBSA",
    "P1 LAKUNTZA",
    "P2 COMARCA II",
    "P3 UHARTE",
]


# ============================================================
# UTILIDADES DE SEGURIDAD / HTTP
# ============================================================

def _safe_fail(msg: str):
    st.error(msg)
    st.stop()


def safe_request(method: str, url: str, **kwargs):
    verify = kwargs.pop("verify", True)
    timeout = kwargs.pop("timeout", HTTP_TIMEOUT)

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = _SESSION.request(method, url, timeout=timeout, verify=verify, **kwargs)
            if resp.status_code in RETRY_STATUS:
                sleep_s = min(BACKOFF_MAX_SECONDS, BACKOFF_BASE_SECONDS * (2 ** (attempt - 1))) + random.random() * 0.25
                time.sleep(sleep_s)
                continue
            return resp
        except requests.RequestException:
            if attempt == MAX_RETRIES:
                raise
            sleep_s = min(BACKOFF_MAX_SECONDS, BACKOFF_BASE_SECONDS * (2 ** (attempt - 1))) + random.random() * 0.25
            time.sleep(sleep_s)

    raise RuntimeError("HTTP retries exhausted")


# ============================================================
# NORMALIZACIÓN
# ============================================================

def norm_name(s: str) -> str:
    if not isinstance(s, str):
        return ""
    s = s.strip().upper()
    repl = str.maketrans(
        {
            "Á": "A",
            "À": "A",
            "Ä": "A",
            "Â": "A",
            "É": "E",
            "È": "E",
            "Ë": "E",
            "Ê": "E",
            "Í": "I",
            "Ì": "I",
            "Ï": "I",
            "Î": "I",
            "Ó": "O",
            "Ò": "O",
            "Ö": "O",
            "Ô": "O",
            "Ú": "U",
            "Ù": "U",
            "Ü": "U",
            "Û": "U",
            "Ñ": "N",
        }
    )
    s = s.translate(repl)
    s = " ".join(s.split())
    return s


def name_startswith(nombre: str, prefix: str) -> bool:
    return norm_name(nombre).startswith(norm_name(prefix))


def _norm_key(x: str) -> str:
    return norm_name(x)


def _sede_code(sede: str) -> str:
    s = norm_name(sede)
    for code in ["P0", "P1", "P2", "P3"]:
        if code in s:
            return code
    return ""


# ============================================================
# FESTIVOS (CSV) — {SEDE_NORM: set(YYYY-MM-DD)}
# + etiquetas: {SEDE_NORM: {YYYY-MM-DD: "Nombre"}}
# ============================================================

@st.cache_data(show_spinner=False)
def get_festivos_for_sede(sede: str, festivos_by_sede: dict) -> set:
    return festivos_by_sede.get(_norm_key(sede), set()) if festivos_by_sede else set()


@st.cache_data(show_spinner=False)
def load_festivos_from_csv_bytes(file_bytes: bytes) -> dict:
    """
    Devuelve {SEDE_NORM: set(YYYY-MM-DD)}.

    Regla (según RRHH):
      - NO se infiere 'NACIONAL' como "para todas las sedes".
      - Se aplica exactamente a lo que ponga en "Sede(s)" (y se respetan exclusiones en notas).
    """
    if not file_bytes:
        return {}

    import io
    buf = io.BytesIO(file_bytes)
    try:
        df = pd.read_csv(buf, sep=";", dtype=str, encoding="utf-8")
    except Exception:
        buf.seek(0)
        df = pd.read_csv(buf, sep=";", dtype=str, encoding="latin-1")

    if df.empty:
        return {}

    col_fecha = None
    for c in ["Próxima ocurrencia", "Proxima ocurrencia", "PROXIMA OCURRENCIA", "Fecha", "FECHA"]:
        if c in df.columns:
            col_fecha = c
            break

    col_sedes = None
    for c in ["Sede(s)", "Sedes", "Sede", "SEDE(S)", "SEDE"]:
        if c in df.columns:
            col_sedes = c
            break

    col_nota = None
    for c in ["Repetición", "Repeticion", "Notas", "NOTAS"]:
        if c in df.columns:
            col_nota = c
            break
    if col_nota is None:
        for c in df.columns:
            if str(c).startswith("Unnamed:"):
                col_nota = c
                break

    if not col_fecha or not col_sedes:
        return {}

    def parse_ddmmyyyy(s: str):
        if not isinstance(s, str):
            return None
        s = s.strip()
        if not s:
            return None
        dt = pd.to_datetime(s, dayfirst=True, errors="coerce")
        if pd.isna(dt):
            return None
        return dt.date().strftime("%Y-%m-%d")

    def excluded_codes_from_note(note_u: str) -> set:
        if not note_u:
            return set()
        out = set()
        for code_ in ["P0", "P1", "P2", "P3"]:
            if (f"EN {code_}" in note_u) and ("NO" in note_u) and ("FESTIV" in note_u):
                out.add(code_)
        return out

    out: dict[str, set] = {}

    for _, r in df.iterrows():
        fecha_raw = str(r.get(col_fecha, "") or "").strip()
        sede_raw = str(r.get(col_sedes, "") or "").strip()
        if not fecha_raw or not sede_raw:
            continue

        fecha = parse_ddmmyyyy(fecha_raw)
        if not fecha:
            continue

        nota_u = str(r.get(col_nota, "") or "").strip().upper() if col_nota else ""
        excluded = excluded_codes_from_note(nota_u)

        sedes_list = [x.strip() for x in sede_raw.split("|") if x and str(x).strip()]
        for sede_item in sedes_list:
            sede_item = sede_item.strip()
            if not sede_item:
                continue
            code = _sede_code(sede_item)
            if code and code in excluded:
                continue
            sede_norm = _norm_key(sede_item)
            out.setdefault(sede_norm, set()).add(fecha)

    return out


@st.cache_data(show_spinner=False)
def load_festivos_labels_from_csv_bytes(file_bytes: bytes) -> dict:
    """
    Devuelve {SEDE_NORM: {YYYY-MM-DD: 'Nombre del festivo'}}.

    Regla (según RRHH):
      - NO se infiere 'NACIONAL' como "para todas las sedes".
      - Se aplica exactamente a lo que ponga en "Sede(s)" (y se respetan exclusiones en notas).
    """
    if not file_bytes:
        return {}

    import io
    buf = io.BytesIO(file_bytes)
    try:
        df = pd.read_csv(buf, sep=";", dtype=str, encoding="utf-8")
    except Exception:
        buf.seek(0)
        df = pd.read_csv(buf, sep=";", dtype=str, encoding="latin-1")

    if df.empty:
        return {}

    col_fecha = None
    for c in ["Próxima ocurrencia", "Proxima ocurrencia", "PROXIMA OCURRENCIA", "Fecha", "FECHA"]:
        if c in df.columns:
            col_fecha = c
            break

    col_sedes = None
    for c in ["Sede(s)", "Sedes", "Sede", "SEDE(S)", "SEDE"]:
        if c in df.columns:
            col_sedes = c
            break

    col_nombre = None
    for c in ["Nombre del festivo", "NOMBRE DEL FESTIVO", "Nombre", "FESTIVO", "Descripcion", "Descripción"]:
        if c in df.columns:
            col_nombre = c
            break

    col_nota = None
    for c in ["Repetición", "Repeticion", "Notas", "NOTAS"]:
        if c in df.columns:
            col_nota = c
            break
    if col_nota is None:
        for c in df.columns:
            if str(c).startswith("Unnamed:"):
                col_nota = c
                break

    if not col_fecha or not col_sedes:
        return {}

    def parse_ddmmyyyy(s: str):
        if not isinstance(s, str):
            return None
        s = s.strip()
        if not s:
            return None
        dt = pd.to_datetime(s, dayfirst=True, errors="coerce")
        if pd.isna(dt):
            return None
        return dt.date().strftime("%Y-%m-%d")

    def excluded_codes_from_note(note_u: str) -> set:
        if not note_u:
            return set()
        out = set()
        for code_ in ["P0", "P1", "P2", "P3"]:
            if (f"EN {code_}" in note_u) and ("NO" in note_u) and ("FESTIV" in note_u):
                out.add(code_)
        return out

    out: dict[str, dict] = {}

    for _, r in df.iterrows():
        fecha_raw = str(r.get(col_fecha, "") or "").strip()
        sede_raw = str(r.get(col_sedes, "") or "").strip()
        if not fecha_raw or not sede_raw:
            continue

        fecha = parse_ddmmyyyy(fecha_raw)
        if not fecha:
            continue

        nota_u = str(r.get(col_nota, "") or "").strip().upper() if col_nota else ""
        excluded = excluded_codes_from_note(nota_u)

        nombre = str(r.get(col_nombre, "") or "").strip() if col_nombre else ""
        if not nombre:
            nombre = "Festivo"

        sedes_list = [x.strip() for x in sede_raw.split("|") if x and str(x).strip()]
        for sede_item in sedes_list:
            sede_item = sede_item.strip()
            if not sede_item:
                continue
            code = _sede_code(sede_item)
            if code and code in excluded:
                continue
            sede_norm = _norm_key(sede_item)
            out.setdefault(sede_norm, {})
            out[sede_norm][fecha] = nombre

    return out


def get_festivo_label_for_sede_date(sede: str, day: date, festivos_labels_by_sede: dict) -> str:
    if not festivos_labels_by_sede:
        return ""
    sede_norm = _norm_key(sede)
    dd = day.strftime("%Y-%m-%d")
    return (festivos_labels_by_sede.get(sede_norm, {}) or {}).get(dd, "")


# ============================================================
# FECHAS / SEMANAS COMPLETAS
# ============================================================

def _iter_days(d0: date, d1: date):
    cur = d0
    while cur <= d1:
        yield cur
        cur += timedelta(days=1)


def list_full_workweeks_in_range(d0: date, d1: date):
    """
    Devuelve lista de tuplas (week_start, week_end_incl, range_type)
    range_type: "L-V", "L-S", "L-D"
    Solo devuelve semanas "completas" dentro del rango:
      - L-V: lunes..viernes
      - L-S: lunes..sábado
      - L-D: lunes..domingo
    """
    weeks = []
    cur = d0

    # normalizamos a lunes de la semana de d0
    cur = cur - timedelta(days=cur.weekday())

    while cur <= d1:
        mon = cur
        fri = cur + timedelta(days=4)
        sat = cur + timedelta(days=5)
        sun = cur + timedelta(days=6)

        # Check L-V
        if mon >= d0 and fri <= d1:
            weeks.append((mon, fri, "L-V"))

        # Check L-S
        if mon >= d0 and sat <= d1:
            weeks.append((mon, sat, "L-S"))

        # Check L-D
        if mon >= d0 and sun <= d1:
            weeks.append((mon, sun, "L-D"))

        cur += timedelta(days=7)

    # preferir el rango más largo si hay coincidencias
    # Ej: si está L-D, también cumple L-V y L-S; nos quedamos con L-D
    unique = {}
    for mon, end_, typ in weeks:
        key = mon
        if key not in unique:
            unique[key] = (mon, end_, typ)
        else:
            # elegir el de mayor longitud
            old = unique[key]
            if (end_ - mon).days > (old[1] - old[0]).days:
                unique[key] = (mon, end_, typ)

    return list(unique.values())


# ============================================================
# TIEMPO / FORMATEO
# ============================================================

def floor_to_30(x: int) -> int:
    return (x // 30) * 30


def ceil_to_30(x: int) -> int:
    return ((x + 29) // 30) * 30


def quantize_daily_balance_30(delta_min: int) -> int:
    """
    Reglas RRHH:
    - Tolerancia ±5 min -> 0
    - Positivo: de +6 a +29 -> 0 (no suma), empieza a sumar desde +30 en tramos de 30 hacia abajo
    - Negativo: desde -6 ya resta (tras tolerancia), cuantiza hacia "más falta" en tramos de 30
    """
    if -TOLERANCIA_MINUTOS <= delta_min <= TOLERANCIA_MINUTOS:
        return 0

    if delta_min > TOLERANCIA_MINUTOS:
        # +6..+29 => 0
        if delta_min < 30:
            return 0
        return floor_to_30(delta_min)

    # delta_min < -5: penaliza y cuantiza hacia más falta
    return -ceil_to_30(abs(delta_min))


def mins_to_hhmm_signed(mins: int) -> str:
    sign = "+" if mins > 0 else "-" if mins < 0 else ""
    mm = abs(int(mins))
    h = mm // 60
    m = mm % 60
    return f"{sign}{h:02d}:{m:02d}"


def decrypt_crece_payload(enc: dict) -> dict:
    iv_b64 = enc.get("iv")
    val_b64 = enc.get("value")
    if not iv_b64 or not val_b64:
        return {}
    iv = base64.b64decode(iv_b64)
    data = base64.b64decode(val_b64)

    key = base64.b64decode(APP_KEY_B64)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    dec = unpad(cipher.decrypt(data), AES.block_size)
    return json.loads(dec.decode("utf-8", errors="ignore"))


def _try_parse_encrypted_response(resp: requests.Response):
    try:
        payload = resp.json()
    except Exception:
        return None
    if isinstance(payload, dict) and "iv" in payload and "value" in payload:
        try:
            return decrypt_crece_payload(payload)
        except Exception:
            return None
    return payload


def _round_seconds_to_minute(seconds: int) -> int:
    return int(round(seconds / 60.0)) * 60


def segundos_a_hhmm(segundos: int) -> str:
    if segundos is None:
        return ""
    segundos = int(segundos)
    if segundos < 0:
        segundos = 0
    minutos = int(round(segundos / 60.0))
    h = minutos // 60
    m = minutos % 60
    return f"{h:02d}:{m:02d}"


def hhmm_to_min(hhmm: str) -> int:
    if not isinstance(hhmm, str) or ":" not in hhmm:
        return 0
    parts = hhmm.strip().split(":")
    try:
        h = int(parts[0])
        m = int(parts[1])
    except Exception:
        return 0
    return h * 60 + m


def hhmm_to_dec(hhmm: str) -> float:
    return hhmm_to_min(hhmm) / 60.0


def diferencia_hhmm(hhmm_a: str, hhmm_b: str) -> str:
    a = hhmm_to_min(hhmm_a)
    b = hhmm_to_min(hhmm_b)
    d = a - b
    sign = "+" if d > 0 else "-" if d < 0 else ""
    mm = abs(d)
    return f"{sign}{mm // 60:02d}:{mm % 60:02d}"


def ts_to_hhmm(ts: str) -> str:
    if not ts:
        return ""
    try:
        dt = pd.to_datetime(ts, errors="coerce")
        if pd.isna(dt):
            return ""
        return dt.strftime("%H:%M")
    except Exception:
        return ""


def hhmm_to_min_clock(hhmm: str) -> int:
    if not isinstance(hhmm, str) or ":" not in hhmm:
        return None
    try:
        h, m = hhmm.split(":")
        return int(h) * 60 + int(m)
    except Exception:
        return None


# ============================================================
# REGLAS RRHH: EXCEPCIONES / FLEX / EXENTOS
# ============================================================

SPECIALS = [
    # MOD
    {"depto": "MOD", "name_prefix": "DAVID", "min_horas": 4.5, "min_fichajes": 2},
    # MOI
    {"depto": "MOI", "name_prefix": "DEBORA", "min_fichajes": 2},
    {"depto": "MOI", "name_prefix": "ETOR", "min_fichajes": 2},
    {"depto": "MOI", "name_prefix": "MIRIAM", "min_horas": 5.5, "min_fichajes": 2, "exento_horario": True},
    # ESTRUCTURA
    {"depto": "ESTRUCTURA", "name_prefix": "FRAN", "flex": True},
    {"depto": "ESTRUCTURA", "name_prefix": "BEATRIZ", "min_horas": 6.5, "min_fichajes": 2, "max_fichajes": 4},
]


def _lookup_special(depto_norm: str, nombre_norm: str):
    for rule in SPECIALS:
        if norm_name(rule.get("depto", "")) != norm_name(depto_norm):
            continue
        if name_startswith(nombre_norm, rule.get("name_prefix", "")):
            return rule
    return None


def _is_schedule_exempt(depto_norm: str, nombre: str) -> bool:
    sp = _lookup_special(depto_norm, norm_name(nombre))
    return bool(sp and sp.get("exento_horario"))


def _is_flex(depto_norm: str, nombre: str) -> bool:
    sp = _lookup_special(depto_norm, norm_name(nombre))
    return bool(sp and sp.get("flex"))


# ============================================================
# MÍNIMOS POR DEPTO/DÍA + EXCEPCIONES
# ============================================================

def calcular_minimos(depto: str, dia: int, nombre: str):
    depto_norm = (depto or "").upper().strip()
    nombre_norm = norm_name(nombre)

    min_h, min_f = None, None

    if depto_norm in ["ESTRUCTURA", "MOI"]:
        if dia in [0, 1, 2, 3]:
            min_h, min_f = 8.5, 4
        elif dia == 4:
            min_h, min_f = 6.5, 2
        else:
            min_h, min_f = None, None

    elif depto_norm == "MOD":
        if dia in [0, 1, 2, 3, 4]:
            min_h, min_f = 8.0, 2
        else:
            min_h, min_f = None, None

    special = _lookup_special(depto_norm, nombre_norm)
    if special:
        if "min_horas" in special and min_h is not None:
            min_h = float(special["min_horas"])
        if "min_fichajes" in special and min_f is not None:
            min_f = int(special["min_fichajes"])

    return min_h, min_f


# ============================================================
# VALIDACIONES HORARIAS / INCIDENCIAS (respetando reglas existentes)
# ============================================================

def validar_horario(depto_norm: str, nombre: str, dia: int, primera: str, ultima: str):
    if _is_schedule_exempt(depto_norm, nombre) or _is_flex(depto_norm, nombre):
        return []

    issues = []

    # MOI/ESTRUCTURA
    if depto_norm in ["MOI", "ESTRUCTURA"]:
        # Entrada aceptable 07:00–09:00 (margen) y salida mínima 16:30 (L-J) / 13:30 (V)
        p = hhmm_to_min_clock(primera) if primera else None
        u = hhmm_to_min_clock(ultima) if ultima else None

        if p is not None:
            min_in = 7 * 60 - MARGEN_HORARIO_MIN
            max_in = 9 * 60 + MARGEN_HORARIO_MIN
            if p < min_in:
                issues.append(f"Entrada temprana ({primera})")
            elif p > max_in:
                issues.append(f"Entrada tarde ({primera})")

        if u is not None:
            if dia in [0, 1, 2, 3]:
                min_out = 16 * 60 + 30 - MARGEN_HORARIO_MIN
            elif dia == 4:
                min_out = 13 * 60 + 30 - MARGEN_HORARIO_MIN
            else:
                min_out = None

            if min_out is not None and u < min_out:
                issues.append(f"Salida temprana ({ultima})")

    # MOD: reglas turnos mañana/tarde (se mantienen como estaban en tu base)
    # (en esta plantilla dejamos solo el placeholder sin cambiar tu lógica base)
    return issues


def validar_incidencia_horas_fichajes(depto_norm: str, nombre: str, dia: int, total_hhmm: str, fichajes: int):
    min_h, min_f = calcular_minimos(depto_norm, dia, nombre)
    issues = []

    if min_h is not None:
        total_h = hhmm_to_dec(total_hhmm)
        if total_h + 1e-9 < float(min_h):
            issues.append(f"Horas insuficientes (mín {min_h}h)")

    if min_f is not None:
        if fichajes < int(min_f):
            issues.append(f"Fichajes insuficientes (mín {min_f}.0)")

    # máximos especiales
    sp = _lookup_special(depto_norm, norm_name(nombre))
    if sp and "max_fichajes" in sp:
        if fichajes > int(sp["max_fichajes"]):
            issues.append(f"Fichajes excesivos (máx {int(sp['max_fichajes'])})")
    else:
        # regla general: exceso si >4 (según tu implementación previa)
        if fichajes > 4:
            issues.append("Fichajes excesivos (máx 4)")

    return issues


# ============================================================
# API: exportaciones
# ============================================================

def api_exportar_departamentos():
    url = f"{API_URL_BASE}/exportaciones/departamentos"
    resp = safe_request("GET", url)
    if resp.status_code != 200:
        _safe_fail("No se pudieron cargar departamentos.")
    data = _try_parse_encrypted_response(resp)
    return pd.DataFrame(data) if isinstance(data, list) else pd.DataFrame()


def api_exportar_empresas():
    url = f"{API_URL_BASE}/exportaciones/empresas"
    resp = safe_request("GET", url)
    if resp.status_code != 200:
        _safe_fail("No se pudieron cargar empresas.")
    data = _try_parse_encrypted_response(resp)
    return pd.DataFrame(data) if isinstance(data, list) else pd.DataFrame()


def api_exportar_sedes():
    url = f"{API_URL_BASE}/exportaciones/sedes"
    resp = safe_request("GET", url)
    if resp.status_code != 200:
        _safe_fail("No se pudieron cargar sedes.")
    data = _try_parse_encrypted_response(resp)
    return pd.DataFrame(data) if isinstance(data, list) else pd.DataFrame()


def api_exportar_empleados_completos():
    url = f"{API_URL_BASE}/exportaciones/empleados"
    resp = safe_request("GET", url)
    if resp.status_code != 200:
        _safe_fail("No se pudieron cargar empleados.")
    data = _try_parse_encrypted_response(resp)
    return pd.DataFrame(data) if isinstance(data, list) else pd.DataFrame()


def api_exportar_tipos_fichaje():
    url = f"{API_URL_BASE}/exportaciones/tipos-fichaje"
    resp = safe_request("GET", url)
    if resp.status_code != 200:
        _safe_fail("No se pudieron cargar tipos de fichaje.")
    data = _try_parse_encrypted_response(resp)
    return pd.DataFrame(data) if isinstance(data, list) else pd.DataFrame()


def api_exportar_fichajes(fecha_inicio: date, fecha_fin: date):
    url = f"{API_URL_BASE}/exportaciones/fichajes"
    payload = {
        "fecha_inicio": fecha_inicio.strftime("%Y-%m-%d"),
        "fecha_fin": fecha_fin.strftime("%Y-%m-%d"),
    }
    resp = safe_request("POST", url, json=payload)
    if resp.status_code != 200:
        _safe_fail("Error consultando fichajes (API).")
    data = _try_parse_encrypted_response(resp)
    return pd.DataFrame(data) if isinstance(data, list) else pd.DataFrame()


def _parse_tiempo_trabajado_payload(payload):
    if not payload:
        return pd.DataFrame()
    if isinstance(payload, list):
        return pd.DataFrame(payload)
    if isinstance(payload, dict) and "data" in payload and isinstance(payload["data"], list):
        return pd.DataFrame(payload["data"])
    return pd.DataFrame()


def api_exportar_tiempo_trabajado(fecha_inicio: date, fecha_fin: date):
    url = f"{API_URL_BASE}/exportaciones/tiempo-trabajado"
    payload = {
        "fecha_inicio": fecha_inicio.strftime("%Y-%m-%d"),
        "fecha_fin": fecha_fin.strftime("%Y-%m-%d"),
    }
    resp = safe_request("POST", url, json=payload)
    if resp.status_code != 200:
        _safe_fail("Error consultando tiempo trabajado (API).")
    data = _try_parse_encrypted_response(resp)
    return _parse_tiempo_trabajado_payload(data)


# ============================================================
# APP UI
# ============================================================

st.set_page_config(page_title="Fichajes — Crece Personas", layout="wide")
st.title("Fichajes CRECE Personas — RRHH")

@st.cache_data(show_spinner=False)
def load_catalogos():
    empresas = api_exportar_empresas()
    sedes = api_exportar_sedes()
    empleados = api_exportar_empleados_completos()

    # Normaliza y filtra catálogo permitido
    if not empleados.empty:
        # Intenta mapear campos habituales
        # Ajusta a tu estructura base si fuera necesario
        for c in ["Empresa", "empresa", "empresa_nombre"]:
            if c in empleados.columns:
                empleados["Empresa"] = empleados[c]
                break
        for c in ["Sede", "sede", "sede_nombre"]:
            if c in empleados.columns:
                empleados["Sede"] = empleados[c]
                break
        for c in ["Nombre", "nombre", "empleado"]:
            if c in empleados.columns:
                empleados["Nombre"] = empleados[c]
                break
        for c in ["Departamento", "departamento", "dpto"]:
            if c in empleados.columns:
                empleados["Departamento"] = empleados[c]
                break
        for c in ["nif", "NIF", "num_empleado", "codigo", "codigo_empleado"]:
            if c in empleados.columns:
                empleados["nif"] = empleados[c]
                break

        empleados["Empresa_norm"] = empleados["Empresa"].apply(_norm_key)
        empleados["Sede_norm"] = empleados["Sede"].apply(_norm_key)

        allowed_emp_norm = {_norm_key(x) for x in ALLOWED_EMPRESAS}
        allowed_sede_norm = {_norm_key(x) for x in ALLOWED_SEDES}

        empleados = empleados[
            empleados["Empresa_norm"].isin(allowed_emp_norm) &
            empleados["Sede_norm"].isin(allowed_sede_norm)
        ].copy()

    return empresas, sedes, empleados


empresas_df, sedes_df, empleados_df = load_catalogos()
if empleados_df.empty:
    st.error("Tras aplicar filtros de empresas/sedes permitidas, no quedan empleados. Revisa que los nombres coincidan en catálogo.")
    st.stop()

hoy = date.today()
col1, col2 = st.columns(2)
with col1:
    fecha_inicio = st.date_input("Fecha inicio", value=hoy, max_value=hoy)
with col2:
    fecha_fin = st.date_input("Fecha fin", value=hoy, max_value=hoy)

# Festivos uploader (+ opcional: guardar en memoria de sesión)
with st.expander("Festivos (CSV) — por sede", expanded=False):
    fest_file = st.file_uploader("Sube el CSV de festivos (por sede)", type=["csv"])
    c1, c2, c3 = st.columns([1, 1, 3])
    with c1:
        save_festivos = st.button("Guardar CSV en memoria", help="Guarda este CSV en la sesión para no tener que subirlo cada vez.")
    with c2:
        clear_festivos = st.button("Borrar CSV guardado", help="Elimina el CSV guardado en memoria.")
    with c3:
        st.caption("Si no subes nada, la app intenta usar el CSV guardado; si no existe, usa un CSV local llamado: " + DEFAULT_FESTIVOS_CSV_PATH)

# estado sesión para festivos
if "festivos_csv_bytes" not in st.session_state:
    st.session_state["festivos_csv_bytes"] = b""
if "festivos_csv_name" not in st.session_state:
    st.session_state["festivos_csv_name"] = ""

# Persistencia (para que sobreviva a recargas del navegador):
# - Además de session_state, guardamos/borrramos un CSV local (DEFAULT_FESTIVOS_CSV_PATH)

if clear_festivos:
    st.session_state["festivos_csv_bytes"] = b""
    st.session_state["festivos_csv_name"] = ""
    try:
        if os.path.exists(DEFAULT_FESTIVOS_CSV_PATH):
            os.remove(DEFAULT_FESTIVOS_CSV_PATH)
    except Exception:
        pass

# Fuente preferente: upload actual
fb = b""
if fest_file is not None:
    fb = fest_file.getvalue() or b""
    if save_festivos and fb:
        st.session_state["festivos_csv_bytes"] = fb
        st.session_state["festivos_csv_name"] = getattr(fest_file, "name", "") or ""
        # Persistir a disco para sobrevivir a recargas (Streamlit Cloud incluido)
        try:
            with open(DEFAULT_FESTIVOS_CSV_PATH, "wb") as f:
                f.write(fb)
        except Exception:
            pass
else:
    fb = st.session_state.get("festivos_csv_bytes", b"") or b""
    if not fb:
        try:
            if os.path.exists(DEFAULT_FESTIVOS_CSV_PATH):
                with open(DEFAULT_FESTIVOS_CSV_PATH, "rb") as f:
                    fb = f.read()
        except Exception:
            fb = b""

festivos_by_sede = load_festivos_from_csv_bytes(fb) if fb else {}
festivos_labels_by_sede = load_festivos_labels_from_csv_bytes(fb) if fb else {}

st.write("---")
f1, f2 = st.columns(2)

empresas_opts = [x for x in ALLOWED_EMPRESAS if _norm_key(x) in set(empleados_df["Empresa_norm"].unique())]
sedes_opts = [x for x in ALLOWED_SEDES if _norm_key(x) in set(empleados_df["Sede_norm"].unique())]

with f1:
    sel_empresas = st.multiselect("Empresa", options=empresas_opts, default=empresas_opts)
with f2:
    sel_sedes = st.multiselect("Sede", options=sedes_opts, default=sedes_opts)

empleados_filtrados = empleados_df[
    empleados_df["Empresa"].apply(_norm_key).isin({_norm_key(x) for x in sel_empresas}) &
    empleados_df["Sede"].apply(_norm_key).isin({_norm_key(x) for x in sel_sedes})
].copy()

st.write("---")

# Botón consultar
if st.button("Consultar"):
    # Cargar fichajes
    fichajes_df = api_exportar_fichajes(fecha_inicio, fecha_fin)
    if fichajes_df.empty:
        st.info("No hay fichajes en el rango.")
        st.stop()

    # Normalizar columnas en base a tu app base (ajusta si hace falta)
    # Fecha
    if "Fecha" not in fichajes_df.columns:
        for c in ["fecha", "day", "Fecha fichaje"]:
            if c in fichajes_df.columns:
                fichajes_df["Fecha"] = fichajes_df[c]
                break

    fichajes_df["Fecha_dt"] = pd.to_datetime(fichajes_df["Fecha"], errors="coerce").dt.date

    # Empresa / Sede / Nombre / Depto
    for src, dst in [
        ("Empresa", "Empresa"),
        ("Sede", "Sede"),
        ("Nombre", "Nombre"),
        ("Departamento", "Departamento"),
        ("nif", "nif"),
    ]:
        if dst not in fichajes_df.columns and src in fichajes_df.columns:
            fichajes_df[dst] = fichajes_df[src]

    # Forzar filtros empresa/sede permitidos + selección actual
    fichajes_df["Empresa_norm"] = fichajes_df["Empresa"].apply(_norm_key)
    fichajes_df["Sede_norm"] = fichajes_df["Sede"].apply(_norm_key)

    fichajes_df = fichajes_df[
        fichajes_df["Empresa_norm"].isin({_norm_key(x) for x in sel_empresas}) &
        fichajes_df["Sede_norm"].isin({_norm_key(x) for x in sel_sedes})
    ].copy()

    if fichajes_df.empty:
        st.info("No hay fichajes tras aplicar filtros de Empresa/Sede.")
        st.stop()

    # Tiempo contabilizado: asumimos columna "Tiempo Contabilizado" o equivalente
    if "Tiempo Contabilizado" not in fichajes_df.columns:
        for c in ["tiempo_contabilizado", "tiempoContabilizado", "TiempoContabilizado"]:
            if c in fichajes_df.columns:
                fichajes_df["Tiempo Contabilizado"] = fichajes_df[c]
                break

    # Total trabajado
    if "Total trabajado" not in fichajes_df.columns:
        for c in ["total_trabajado", "Total trabajado", "Tiempo trabajado"]:
            if c in fichajes_df.columns:
                fichajes_df["Total trabajado"] = fichajes_df[c]
                break

    # Normalización diferencia ±00:01 (consistente)
    # Convertimos ambos a minutos redondeando a minuto y calculamos diferencia en minutos, luego a hh:mm signed
    def _hhmm_to_mins_safe(x):
        try:
            return hhmm_to_min(str(x))
        except Exception:
            return 0

    fichajes_df["mins_total"] = fichajes_df["Total trabajado"].apply(_hhmm_to_mins_safe)
    fichajes_df["mins_tc"] = fichajes_df["Tiempo Contabilizado"].apply(_hhmm_to_mins_safe)
    fichajes_df["mins_diff"] = fichajes_df["mins_total"] - fichajes_df["mins_tc"]
    # si es ±1, lo llevamos a 0
    fichajes_df.loc[fichajes_df["mins_diff"].abs() == 1, "mins_diff"] = 0
    fichajes_df["Diferencia"] = fichajes_df["mins_diff"].apply(mins_to_hhmm_signed)

    # Primera entrada / última salida
    if "Primera entrada" not in fichajes_df.columns:
        for c in ["primera_entrada", "Primera entrada", "Entrada"]:
            if c in fichajes_df.columns:
                fichajes_df["Primera entrada"] = fichajes_df[c]
                break
    if "Última salida" not in fichajes_df.columns:
        for c in ["ultima_salida", "Última salida", "Salida"]:
            if c in fichajes_df.columns:
                fichajes_df["Última salida"] = fichajes_df[c]
                break

    # Número fichajes
    if "Numero de fichajes" not in fichajes_df.columns:
        for c in ["numero_fichajes", "Numero fichajes", "n_fichajes"]:
            if c in fichajes_df.columns:
                fichajes_df["Numero de fichajes"] = fichajes_df[c]
                break

    # --------------------------
    # Festivo helpers
    # --------------------------
    def _is_festivo_day(sede: str, day: date):
        fest_set = get_festivos_for_sede(sede, festivos_by_sede)
        ds = day.strftime("%Y-%m-%d")
        if ds in fest_set:
            lbl = get_festivo_label_for_sede_date(sede, day, festivos_labels_by_sede)
            return True, (lbl or "Festivo")
        return False, ""

    # --------------------------
    # Construcción de incidencias (incluye festivo como “Trabajado en festivo”)
    # --------------------------
    def build_incidencia(row):
        day = row["Fecha_dt"]
        wd = day.weekday()
        depto_norm = str(row.get("Departamento") or "").upper().strip()
        nombre = str(row.get("Nombre") or "")
        sede = str(row.get("Sede") or "")

        # fin de semana
        if wd >= 5 and (row.get("mins_tc") or 0) > 0:
            return "Trabajo en fin de semana"

        # festivo por sede
        is_fest, fest_name = _is_festivo_day(sede, day)
        if is_fest and (row.get("mins_tc") or 0) > 0:
            return f"Trabajado en festivo ({fest_name})"

        # incidencias normales
        issues = []
        total_hhmm = str(row.get("Total trabajado") or "00:00")
        fichajes = int(row.get("Numero de fichajes") or 0)
        issues += validar_incidencia_horas_fichajes(depto_norm, nombre, wd, total_hhmm, fichajes)
        issues += validar_horario(depto_norm, nombre, wd, str(row.get("Primera entrada") or ""), str(row.get("Última salida") or ""))
        return "; ".join(issues)

    fichajes_df["Incidencia"] = fichajes_df.apply(build_incidencia, axis=1)

    # --------------------------
    # Tabs independientes (cada pestaña aparece si tiene datos)
    # --------------------------
    # Fichajes con incidencia
    df_inc = fichajes_df[fichajes_df["Incidencia"].astype(str).str.strip() != ""].copy()

    # Bajas (placeholder: si tu base ya lo tiene, aquí debería venir tu lógica original)
    df_bajas = pd.DataFrame()

    # Sin fichajes (placeholder: si tu base ya lo tiene, aquí debería venir tu lógica original)
    df_sin = pd.DataFrame()

    # Exceso de jornada: solo si hay semanas completas
    full_weeks = list_full_workweeks_in_range(fecha_inicio, fecha_fin)

    # Armamos pestañas según haya datos
    tab_defs = []
    if not df_inc.empty:
        tab_defs.append(("Fichajes", "📌"))
    if not df_bajas.empty:
        tab_defs.append(("Bajas", "🧾"))
    if not df_sin.empty:
        tab_defs.append(("Sin fichajes", "⛔"))
    if full_weeks:
        tab_defs.append(("Exceso de jornada", "🕘"))

    if not tab_defs:
        st.info("No hay datos para mostrar en ninguna pestaña con los filtros/rango actuales.")
        st.stop()

    tabs = st.tabs([f"{icon} {name}" for name, icon in tab_defs])

    def _render_table(df, cols=None):
        if cols:
            df = df[cols]
        st.dataframe(df, use_container_width=True, hide_index=True)

    # --------
    # Render tabs
    # --------
    for i, (name, icon) in enumerate(tab_defs):
        with tabs[i]:
            if name == "Fichajes":
                # agrupar por día como en tu base (aquí dejamos tabla directa)
                show_cols = [
                    "Fecha_dt", "Empresa", "Sede", "Nombre", "Departamento",
                    "Primera entrada", "Última salida", "Total trabajado",
                    "Tiempo Contabilizado", "Diferencia", "Numero de fichajes", "Incidencia"
                ]
                show_cols = [c for c in show_cols if c in df_inc.columns]
                _render_table(df_inc.sort_values(["Fecha_dt", "Empresa", "Sede", "Nombre"]), show_cols)

            elif name == "Bajas":
                st.info("Sin datos de bajas en este rango.")

            elif name == "Sin fichajes":
                st.info("Sin datos de sin fichajes en este rango.")

            elif name == "Exceso de jornada":
                # Preparar columnas extra necesarias
                if "Primera entrada" in fichajes_df.columns:
                    fichajes_df["primera_min"] = fichajes_df["Primera entrada"].apply(hhmm_to_min_clock)
                else:
                    fichajes_df["primera_min"] = None

                # Por semana completa, tabla
                for wk_start, wk_end_incl, typ in sorted(full_weeks, key=lambda x: x[0]):
                    if typ == "L-D":
                        label = f"{wk_start:%Y-%m-%d} → {wk_end_incl:%Y-%m-%d} (L-D)"
                    elif typ == "L-S":
                        label = f"{wk_start:%Y-%m-%d} → {wk_end_incl:%Y-%m-%d} (L-S)"
                    else:
                        label = f"{wk_start:%Y-%m-%d} → {wk_end_incl:%Y-%m-%d} (L-V)"

                    st.subheader(label)

                    mask_week = (fichajes_df["Fecha_dt"] >= wk_start) & (fichajes_df["Fecha_dt"] <= wk_end_incl)
                    w = fichajes_df[mask_week].copy()

                    # solo MOD/MOI/ESTRUCTURA
                    w["Departamento"] = w["Departamento"].astype(str)
                    w = w[w["Departamento"].str.upper().isin(["MOD", "MOI", "ESTRUCTURA"])].copy()

                    rows = []

                    if w.empty:
                        st.info("No hay datos (MOD/MOI/ESTRUCTURA) en esta semana.")
                        continue

                    # funciones locales
                    def expected_day_minutes(depto_norm: str, nombre: str, sede: str, day: date, wd: int) -> int:
                        # Fin de semana o festivo => jornada esperada 0
                        is_fest, _ = _is_festivo_day(sede, day)
                        if wd >= 5 or is_fest:
                            return 0

                        depto_eff = (depto_norm or "").upper().strip()
                        # Robustez: si viniera algo tipo 'MOD ...', lo tratamos como MOD
                        if depto_eff.startswith("MOD"):
                            depto_eff = "MOD"

                        if depto_eff in ["MOI", "ESTRUCTURA", "MOD"]:
                            min_h, _ = calcular_minimos(depto_eff, wd, nombre)
                            if min_h is None:
                                if depto_eff == "MOD":
                                    min_h = 8.0
                                else:
                                    return 0
                            return int(round(float(min_h) * 60))

                        return 0

                    def effective_worked_minutes_for_mod(mins_tc: int, primera_min: int | None) -> int:
                        # MOD: no cuenta lo trabajado ANTES del inicio de turno en día laborable (jornada esperada > 0)
                        # Turnos de 8h: mañana 06:00-14:00, tarde 14:00-22:00, noche 22:00-06:00
                        # Si entra antes, no suma ese extra.
                        if primera_min is None:
                            return mins_tc

                        start_candidates = [6 * 60, 14 * 60, 22 * 60]
                        # elegimos el inicio más cercano por debajo/igual a primera_min; si no, el más cercano
                        start = None
                        for sc in start_candidates:
                            if primera_min >= sc:
                                start = sc
                        if start is None:
                            start = 6 * 60

                        # si ha fichado antes del inicio, restamos esos minutos previos (máx hasta mins_tc)
                        if primera_min < start:
                            delta = start - primera_min
                            return max(0, mins_tc - delta)
                        return mins_tc

                    # agrupación por empleado
                    for (nif, nombre, depto, empresa, sede), wemp in w.groupby(
                        ["nif", "Nombre", "Departamento", "Empresa", "Sede"]
                    ):
                        depto_norm = str(depto or "").upper().strip()
                        nombre_s = str(nombre or "").strip()
                        sede_s = str(sede or "").strip()

                        balance_sem_min = 0
                        trabajado_sem_min = 0
                        jornada_sem_min = 0

                        for _, rday in wemp.iterrows():
                            day = rday["Fecha_dt"]
                            wd = int(day.weekday())
                            mins_tc = int(rday.get("mins_tc") or 0)
                            primera_min = rday.get("primera_min")
                            trabajado_sem_min += mins_tc

                            exp_day = expected_day_minutes(depto_norm, nombre_s, sede_s, day, wd)
                            jornada_sem_min += exp_day

                            # trabajado efectivo para MOD (no cuenta minutos antes del inicio de turno)
                            if depto_norm == "MOD" and exp_day > 0:
                                mins_eff = effective_worked_minutes_for_mod(mins_tc, primera_min)
                            else:
                                mins_eff = mins_tc

                            delta = mins_eff - exp_day
                            q = quantize_daily_balance_30(delta)
                            balance_sem_min += q

                        # mostrar positivos y negativos excepto 0
                        if balance_sem_min != 0:
                            rows.append(
                                {
                                    "Empresa": empresa,
                                    "Sede": sede,
                                    "Nombre": nombre,
                                    "Departamento": depto_norm,
                                    "Trabajado semanal": segundos_a_hhmm(trabajado_sem_min * 60),
                                    "Jornada semanal": segundos_a_hhmm(jornada_sem_min * 60),
                                    "Balance": mins_to_hhmm_signed(balance_sem_min),
                                }
                            )

                    if not rows:
                        st.info("No hay balances (positivos o negativos) en esta semana completa (o no hay datos).")
                    else:
                        dfw = pd.DataFrame(rows).sort_values(["Empresa", "Sede", "Nombre"])
                        st.dataframe(
                            dfw,
                            use_container_width=True,
                            hide_index=True,
                            column_config={
                                "Balance": st.column_config.TextColumn(help="Suma semanal de balances diarios cuantizados en tramos de 30 min.")
                            }
                        )
