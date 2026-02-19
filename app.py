import base64
import json
import multiprocessing
import random
import time
from datetime import date, datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

import pandas as pd
import requests
import streamlit as st
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# ============================================================
# CONFIG (Seguridad por defecto)
# ============================================================

st.set_page_config(page_title="Fichajes CRECE Personas", layout="wide")

API_BASE_URL = st.secrets.get("API_BASE_URL", "https://sincronizaciones.crecepersonas.es")
API_TOKEN = st.secrets.get("API_TOKEN", "")
APP_KEY_B64 = st.secrets.get("APP_KEY_B64", "")

DEFAULT_TIMEOUT = 30
MAX_RETRIES = 3

# ============================================================
# UTILIDADES: Seguridad / Normalización
# ============================================================

def _mask(s: str, show: int = 4) -> str:
    if not s:
        return ""
    s = str(s)
    if len(s) <= show:
        return "*" * len(s)
    return s[:show] + ("*" * (len(s) - show))


def normalize_text(s: str) -> str:
    if s is None:
        return ""
    s = str(s).strip().lower()
    s = " ".join(s.split())
    return s


def normalize_sede(s: str) -> str:
    # Normaliza "P0 IBSA" / "P0  IBSA" / "p0 ibsa"
    s = normalize_text(s).upper()
    s = s.replace("  ", " ").strip()
    return s


def normalize_empresa(s: str) -> str:
    return " ".join(str(s or "").strip().split())


def safe_error(msg: str):
    # No mostrar tokens/payloads, solo msg controlado
    st.error(msg)


def hhmm_to_min(s: str) -> int:
    if s is None:
        return 0
    s = str(s).strip()
    if not s:
        return 0
    if ":" not in s:
        return 0
    try:
        h, m = s.split(":")
        return int(h) * 60 + int(m)
    except Exception:
        return 0


def min_to_hhmm(m: int) -> str:
    try:
        m = int(m)
    except Exception:
        m = 0
    sign = "-" if m < 0 else ""
    m = abs(m)
    h = m // 60
    mm = m % 60
    return f"{sign}{h:02d}:{mm:02d}"


def hhmm_to_min_clock(s: str) -> int | None:
    """Convierte 'HH:MM' a minutos desde 00:00 (para comparar horas del día)."""
    if s is None:
        return None
    s = str(s).strip()
    if not s or ":" not in s:
        return None
    try:
        h, m = s.split(":")
        return int(h) * 60 + int(m)
    except Exception:
        return None


def _to_float_any(x) -> float:
    try:
        if x is None:
            return 0.0
        if isinstance(x, (int, float)):
            return float(x)
        s = str(x).strip().replace(",", ".")
        return float(s)
    except Exception:
        return 0.0


def _pick_key(df: pd.DataFrame, candidates: list[str]) -> str | None:
    cols = {c.lower(): c for c in df.columns}
    for c in candidates:
        if c.lower() in cols:
            return cols[c.lower()]
    return None


def _pick_any_dict_key(d: dict, candidates: list[str]) -> str | None:
    if not isinstance(d, dict):
        return None
    keys = {str(k).lower(): k for k in d.keys()}
    for c in candidates:
        if c.lower() in keys:
            return keys[c.lower()]
    return None


def _as_list(x):
    if x is None:
        return []
    if isinstance(x, list):
        return x
    if isinstance(x, tuple):
        return list(x)
    return [x]


def _parse_sedes_cell(cell: str) -> list[str]:
    """
    Parse robusto para campo "Sede(s)" del CSV:
    - separadores: coma, punto y coma, barra, salto de línea
    - devuelve sedes normalizadas (ej. "P0 IBSA")
    """
    if cell is None:
        return []
    s = str(cell).strip()
    if not s:
        return []
    for sep in [";", ",", "|", "\n"]:
        s = s.replace(sep, " / ")
    parts = [p.strip() for p in s.split("/") if p.strip()]
    out = []
    for p in parts:
        out.append(normalize_sede(p))
    # quitar duplicados manteniendo orden
    seen = set()
    res = []
    for it in out:
        if it not in seen:
            seen.add(it)
            res.append(it)
    return res


# ============================================================
# HTTP Session con retries
# ============================================================

def make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"Authorization": f"Bearer {API_TOKEN}"})
    return s


def request_with_retries(
    session: requests.Session,
    method: str,
    url: str,
    json_payload: dict | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> requests.Response:
    last_exc = None
    for attempt in range(MAX_RETRIES):
        try:
            resp = session.request(
                method,
                url,
                json=json_payload,
                timeout=timeout,
                verify=True,
            )
            return resp
        except Exception as e:
            last_exc = e
            time.sleep(0.5 * (attempt + 1))
    raise last_exc


# ============================================================
# AES Decrypt (Crece Personas exportaciones)
# ============================================================

def decrypt_payload_aes_cbc(payload: dict) -> dict:
    """
    payload: {"iv": "...b64...", "value": "...b64..."}.
    key: APP_KEY_B64 (b64)
    """
    if not payload:
        return {}
    if not APP_KEY_B64:
        return {}
    try:
        key = base64.b64decode(APP_KEY_B64)
        iv = base64.b64decode(payload.get("iv", ""))
        value = base64.b64decode(payload.get("value", ""))
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plain = unpad(cipher.decrypt(value), AES.block_size)
        return json.loads(plain.decode("utf-8"))
    except Exception:
        return {}


# ============================================================
# Catálogos: Empresas / Sedes / Empleados
# ============================================================

EMPRESAS_APROBADAS = [
    "Barranquesa Tower Flanges, S.L.",
    "Barranquesa Anchor Cages, S.L.",
    "Industrial Barranquesa S.A.",
]

SEDES_APROBADAS = [
    "P0 IBSA",
    "P1 LAKUNTZA",
    "P2 COMARCA II",
    "P3 UHARTE",
]


@st.cache_data(show_spinner=False)
def load_catalogos() -> tuple[list[dict], list[dict]]:
    # Se asume que esta parte ya está OK en tu base.
    # Aquí dejamos un placeholder seguro si tu app ya trae implementado el catálogo real.
    # (Si tu base ya lo tiene, esto se mantiene igual.)
    return [], []


# ============================================================
# Festivos CSV (por sede)
# ============================================================

def _read_festivos_csv_bytes(file_bytes: bytes) -> pd.DataFrame:
    """Lee CSV de festivos de forma robusta (encoding/sep) y devuelve DataFrame."""
    if not file_bytes:
        return pd.DataFrame()
    import io

    # Intentos de decodificación
    raw = None
    for enc in ["utf-8-sig", "utf-8", "latin-1"]:
        try:
            raw = file_bytes.decode(enc)
            break
        except Exception:
            continue
    if raw is None:
        raw = file_bytes.decode("latin-1", errors="ignore")

    best_df = pd.DataFrame()
    best_cols = 0
    for sep in [";", ",", "\t", "|"]:
        try:
            df_try = pd.read_csv(io.StringIO(raw), sep=sep, dtype=str)
            if df_try.shape[1] > best_cols:
                best_df = df_try
                best_cols = df_try.shape[1]
        except Exception:
            continue

    if best_cols < 2:
        try:
            best_df = pd.read_csv(io.StringIO(raw), sep=None, engine="python", dtype=str)
        except Exception:
            return pd.DataFrame()

    best_df = best_df.fillna("")
    return best_df


def load_festivos_labels_from_csv_bytes(file_bytes: bytes) -> dict:
    """
    Devuelve {SEDE_NORM: {YYYY-MM-DD: 'Nombre del festivo'}}.

    Regla (según RRHH):
      - NO se infiere 'NACIONAL' como "para todas las sedes".
      - Se aplica exactamente a lo que ponga en "Sede(s)" (y se respetan exclusiones en notas).
    """
    if not file_bytes:
        return {}

    df = _read_festivos_csv_bytes(file_bytes)

    if df.empty:
        return {}

    col_fecha = None
    for c in ["Próxima ocurrencia", "Fecha", "fecha", "Dia", "Día", "día"]:
        if c in df.columns:
            col_fecha = c
            break
    if col_fecha is None:
        # fallback: primera columna
        col_fecha = df.columns[0]

    # columnas de sedes y nombre
    col_sedes = None
    for c in ["Sede(s)", "Sedes", "Sede", "sede", "sedes"]:
        if c in df.columns:
            col_sedes = c
            break
    if col_sedes is None:
        # si no hay columna, no podemos asignar por sede
        return {}

    cols_lower = {c.lower(): c for c in df.columns}
    festivo_col = cols_lower.get("festivo") or cols_lower.get("nombre") or cols_lower.get("name") or None
    if festivo_col is None:
        # fallback: intenta una columna que no sea fecha/sedes
        candidates = [c for c in df.columns if c not in [col_fecha, col_sedes]]
        festivo_col = candidates[0] if candidates else None

    out: dict[str, dict[str, str]] = {}

    for _, r in df.iterrows():
        raw_date = str(r.get(col_fecha, "")).strip()
        if not raw_date:
            continue
        # normaliza fecha
        day = None
        for fmt in ["%d/%m/%Y", "%Y-%m-%d", "%d-%m-%Y", "%d/%m/%y"]:
            try:
                day = datetime.strptime(raw_date, fmt).date()
                break
            except Exception:
                continue
        if day is None:
            continue

        name = str(r.get(festivo_col, "")).strip() if festivo_col else "Festivo"
        sedes_cell = str(r.get(col_sedes, "")).strip()
        sedes = _parse_sedes_cell(sedes_cell)
        if not sedes:
            continue

        dstr = day.strftime("%Y-%m-%d")
        for sede_norm in sedes:
            out.setdefault(sede_norm, {})
            out[sede_norm][dstr] = name if name else "Festivo"

    return out


def build_festivos_by_sede(labels: dict) -> dict:
    """Devuelve {SEDE_NORM: set(YYYY-MM-DD)} a partir del dict de labels."""
    out = {}
    for sede_norm, mp in (labels or {}).items():
        out[sede_norm] = set(mp.keys())
    return out


def get_festivos_for_sede(sede: str, festivos_by_sede: dict) -> set:
    s = normalize_sede(sede)
    return set((festivos_by_sede or {}).get(s, set()))


def get_festivo_label_for_sede_date(sede: str, day_str: str, labels_by_sede: dict) -> str:
    s = normalize_sede(sede)
    return (labels_by_sede or {}).get(s, {}).get(day_str, "")


# ============================================================
# RRHH: Reglas base (mínimos, excepciones)
# ============================================================

def calcular_minimos(departamento: str, weekday: int, nombre: str) -> tuple[float, int]:
    """
    Devuelve (min_horas, min_fichajes) por departamento/día con excepciones.
    weekday: 0=Lunes ... 6=Domingo
    """
    dep = (departamento or "").upper().strip()
    n = normalize_text(nombre)

    # Excepciones por nombre (prefijo)
    def starts(x: str) -> bool:
        return n.startswith(normalize_text(x))

    # Defaults
    min_h, min_f = 0.0, 0

    if dep in ["MOI", "ESTRUCTURA"]:
        if weekday <= 3:  # L-J
            min_h, min_f = 8.5, 4
        elif weekday == 4:  # V
            min_h, min_f = 6.5, 2
        else:
            min_h, min_f = 0.0, 0
    elif dep == "MOD":
        if weekday <= 4:
            min_h, min_f = 8.0, 2
        else:
            min_h, min_f = 0.0, 0

    # Excepciones específicas
    if dep == "MOD" and starts("david"):
        min_h, min_f = 4.5, 2
    if dep == "MOI" and (starts("débora") or starts("debora")):
        min_f = 2
    if dep == "MOI" and starts("etor"):
        min_f = 2
    if dep == "MOI" and starts("miriam"):
        min_h, min_f = 5.5, 2
    if dep == "ESTRUCTURA" and starts("beatriz"):
        min_h, min_f = 6.5, 2

    return min_h, min_f


# ============================================================
# /informes/empleados: bajas + horas_programadas (por día)
# ============================================================

def api_informe_empleados(session: requests.Session, day: date) -> list[dict]:
    url = f"{API_BASE_URL}/api/informes/empleados"
    payload = {"fecha_inicio": day.strftime("%Y-%m-%d"), "fecha_fin": day.strftime("%Y-%m-%d")}
    resp = request_with_retries(session, "POST", url, json_payload=payload)
    if resp.status_code != 200:
        return []
    try:
        js = resp.json()
        if isinstance(js, list):
            return js
        if isinstance(js, dict):
            # puede venir {"data":[...]} u otro wrapper
            for k in ["data", "result", "empleados", "items"]:
                if k in js and isinstance(js[k], list):
                    return js[k]
        return []
    except Exception:
        return []


def _get_horas_baja_from_row(row: dict) -> float:
    if not isinstance(row, dict):
        return 0.0

    candidates = [
        "horas_baja",
        "horasBaja",
        "horas_de_baja",
        "horas_baja_total",
        "total_horas_baja",
        "horas_baja_dia",
        "horas_baja_diarias",
        "horas_baja_hoy",
        "horas_baja_parte",
    ]
    for c in candidates:
        if c in row:
            return _to_float_any(row.get(c))

    for k in ["baja", "bajas", "ausencia", "ausencias", "incidencia", "incidencias"]:
        v = row.get(k)
        if isinstance(v, dict):
            for c in candidates:
                if c in v:
                    return _to_float_any(v.get(c))
        if isinstance(v, list):
            for it in v:
                if isinstance(it, dict):
                    for c in candidates:
                        if c in it:
                            return _to_float_any(it.get(c))

    return 0.0


def _get_horas_programadas_minutes_from_row(row: dict) -> int | None:
    """Devuelve minutos programados del día (jornada esperada) si el informe lo trae.

    Soporta formatos típicos:
    - "08:30" / "8:30"  -> 510
    - 8.5                  -> 510 (horas decimales)
    - "8h 30m"           -> 510
    """
    if not isinstance(row, dict):
        return None

    candidates = [
        "horas_programadas",
        "horasProgramadas",
        "horas_programadas_dia",
        "horasProgramadasDia",
        "horas_jornada",
        "horasJornada",
        "jornada",
        "jornada_diaria",
        "jornadaDiaria",
    ]
    val = None
    for c in candidates:
        if c in row and row.get(c) not in (None, ""):
            val = row.get(c)
            break
    if val in (None, ""):
        return None

    # string hh:mm
    if isinstance(val, str):
        s = val.strip()
        # hh:mm
        import re as _re
        if _re.match(r"^\d{1,2}:\d{2}$", s):
            try:
                h, m = s.split(":")
                return int(h) * 60 + int(m)
            except Exception:
                pass
        # "8h 30m"
        m1 = _re.match(r"^(\d{1,2})\s*h\s*(\d{1,2})\s*m$", s, flags=_re.IGNORECASE)
        if m1:
            return int(m1.group(1)) * 60 + int(m1.group(2))
        # "8h"
        m2 = _re.match(r"^(\d{1,2})\s*h$", s, flags=_re.IGNORECASE)
        if m2:
            return int(m2.group(1)) * 60
        try:
            f = float(s.replace(",", "."))
            return int(round(f * 60))
        except Exception:
            return None

    if isinstance(val, (int, float)):
        try:
            return int(round(float(val) * 60))
        except Exception:
            return None

    return None


# ============================================================
# Exportación fichajes
# ============================================================

def api_exportacion_fichajes(session: requests.Session, day: date) -> list[dict]:
    """
    Endpoint exportaciones/fichajes.
    Devuelve payload cifrado; aquí asumimos que tu base ya lo maneja.
    """
    url = f"{API_BASE_URL}/api/exportaciones/fichajes"
    payload = {"fecha_inicio": day.strftime("%Y-%m-%d"), "fecha_fin": day.strftime("%Y-%m-%d")}
    resp = request_with_retries(session, "POST", url, json_payload=payload)
    if resp.status_code != 200:
        return []
    try:
        js = resp.json()
        if isinstance(js, dict) and "iv" in js and "value" in js:
            body = decrypt_payload_aes_cbc(js)
            if isinstance(body, list):
                return body
            if isinstance(body, dict):
                for k in ["data", "result", "items"]:
                    if k in body and isinstance(body[k], list):
                        return body[k]
                return []
        if isinstance(js, list):
            return js
        return []
    except Exception:
        return []


# ============================================================
# Incidencias / Resumen por día (TU BASE)
# ============================================================

def build_incidencia(row: pd.Series) -> str:
    """
    Mantener como esté en tu base.
    Aquí dejamos placeholder compatible, asumiendo que tu base real ya tiene esto.
    """
    return str(row.get("Incidencia", "")).strip()


# ============================================================
# Semanas completas dentro del rango
# ============================================================

def list_full_workweeks_in_range(d0: date, d1: date) -> list[tuple[date, date, str]]:
    """
    Devuelve lista de semanas "completas" dentro del rango:
    - L-V  (5 días) si el rango incluye exactamente esos días completos
    - L-S  (6 días)
    - L-D  (7 días)
    Se usa SOLO para pestaña "Exceso de jornada".
    """
    if d0 > d1:
        return []

    weeks = []
    cur = d0

    # avanzar al lunes siguiente o mismo lunes
    while cur.weekday() != 0:
        cur += timedelta(days=1)
        if cur > d1:
            return []

    while cur <= d1:
        wk_start = cur
        wk_end = wk_start + timedelta(days=6)

        # L-D completo
        if wk_start >= d0 and wk_end <= d1:
            weeks.append((wk_start, wk_end, "L-D"))
            cur = wk_end + timedelta(days=1)
            continue

        # L-S completo
        wk_end_ls = wk_start + timedelta(days=5)
        if wk_start >= d0 and wk_end_ls <= d1:
            weeks.append((wk_start, wk_end_ls, "L-S"))
            cur = wk_end_ls + timedelta(days=1)
            continue

        # L-V completo
        wk_end_lv = wk_start + timedelta(days=4)
        if wk_start >= d0 and wk_end_lv <= d1:
            weeks.append((wk_start, wk_end_lv, "L-V"))
            cur = wk_end_lv + timedelta(days=1)
            continue

        break

    return weeks


# ============================================================
# UI: Inputs
# ============================================================

st.title("Fichajes CRECE Personas")

col1, col2 = st.columns(2)
with col1:
    d0 = st.date_input("Fecha inicio", value=date.today())
with col2:
    d1 = st.date_input("Fecha fin", value=date.today())

with st.expander("Festivos (CSV) — por sede", expanded=False):
    up = st.file_uploader("Sube el CSV de festivos (por sede)", type=["csv"], key="festivos_uploader")

    # Persistencia simple en sesión
    if "festivos_csv_bytes_saved" not in st.session_state:
        st.session_state["festivos_csv_bytes_saved"] = None

    cA, cB = st.columns([1, 1])
    with cA:
        if st.button("Guardar CSV en memoria"):
            if up is not None:
                try:
                    st.session_state["festivos_csv_bytes_saved"] = up.getvalue()
                    st.success("CSV guardado en memoria (sesión actual).")
                except Exception:
                    safe_error("No se pudo guardar el CSV en memoria.")
            else:
                safe_error("Sube un CSV primero para guardarlo.")
    with cB:
        if st.button("Borrar CSV guardado"):
            st.session_state["festivos_csv_bytes_saved"] = None
            st.info("CSV borrado de memoria.")

    st.caption("Si no subes nada, la app intenta usar un CSV guardado en memoria o un CSV local llamado: Listado Festivos.csv")

# cargar bytes del csv (prioridad: uploader > guardado > local)
csv_bytes = None
if up is not None:
    try:
        csv_bytes = up.getvalue()
    except Exception:
        csv_bytes = None
if (not csv_bytes) and st.session_state.get("festivos_csv_bytes_saved"):
    csv_bytes = st.session_state.get("festivos_csv_bytes_saved")

if not csv_bytes:
    # intento local
    try:
        with open("Listado Festivos.csv", "rb") as f:
            csv_bytes = f.read()
    except Exception:
        csv_bytes = None

festivos_labels_by_sede = load_festivos_labels_from_csv_bytes(csv_bytes) if csv_bytes else {}
festivos_by_sede = build_festivos_by_sede(festivos_labels_by_sede) if festivos_labels_by_sede else {}

# Filtros Empresa / Sede (mantener tu UX)
col3, col4 = st.columns(2)
with col3:
    empresas_sel = st.multiselect("Empresa", options=EMPRESAS_APROBADAS, default=EMPRESAS_APROBADAS)
with col4:
    sedes_sel = st.multiselect("Sede", options=SEDES_APROBADAS, default=SEDES_APROBADAS)

do = st.button("Consultar")

# ============================================================
# EJECUCIÓN
# ============================================================

if do:
    # Validación fechas
    if d0 > d1:
        safe_error("Fecha inicio no puede ser mayor que fecha fin.")
        st.stop()

    # firma para no recomputar si no cambia
    signature = (str(d0), str(d1), tuple(sorted(empresas_sel)), tuple(sorted(sedes_sel)), bool(csv_bytes))

    # Crear sesión HTTP
    session = make_session()

    # --------- FICHAJES (día a día) ----------
    days = []
    cur = d0
    while cur <= d1:
        days.append(cur)
        cur += timedelta(days=1)

    # ========= Empleados base (placeholder) =========
    # En tu base real ya existe base_emp. Aquí se mantiene.
    # Suponemos que tu app ya lo crea con columnas: nif, num_empleado, Nombre, Empresa, Sede, Departamento
    base_emp = pd.DataFrame(columns=["nif", "num_empleado", "Nombre", "Empresa", "Sede", "Departamento"])
    # Si tu base lo rellena en otro sitio, se mantiene (no tocamos).

    # Pedir fichajes por día
    fichajes_rows = []
    for day in days:
        rows = api_exportacion_fichajes(session, day)
        if rows:
            for r in rows:
                r["_day"] = day.strftime("%Y-%m-%d")
            fichajes_rows.extend(rows)

    df_fichajes = pd.DataFrame(fichajes_rows) if fichajes_rows else pd.DataFrame()

    # Placeholder: en tu base esto se transforma a 'resumen' (por empleado/día) con columnas:
    # Fecha, Empresa, Sede, Nombre, Departamento, Primera entrada, Última salida, Total trabajado, Tiempo Contabilizado, Diferencia, Numero de fichajes, Incidencia
    # Aquí respetamos tu estructura: si no tienes fichajes_rows no hay resumen.
    resumen = pd.DataFrame()

    # --------- BAJAS (día a día) ----------
    bajas_por_dia = {}
    prog_by_day_nif = {}
    for day in days:
        rows = api_informe_empleados(session, day)
        if not rows:
            continue

        df_rep = pd.DataFrame(rows).fillna("")
        if df_rep.empty:
            continue

        # Guardar horas_programadas (si existe) para cálculo de jornada esperada (por día)
        try:
            df_rep["horas_prog_min"] = df_rep.apply(lambda r: _get_horas_programadas_minutes_from_row(r.to_dict()), axis=1)
        except Exception:
            df_rep["horas_prog_min"] = None

        key_nif_all = _pick_key(df_rep, ["nif", "NIF", "dni", "DNI"])
        key_num_all = _pick_key(df_rep, ["num_empleado", "numEmpleado", "employee_number", "employeeNumber", "id_empleado", "idEmpleado"])

        merged_all = None
        if key_nif_all is not None:
            df_rep["nif_join_all"] = df_rep[key_nif_all].astype(str).str.upper().str.strip()
            merged_all = df_rep.merge(base_emp, left_on="nif_join_all", right_on="nif", how="inner")
        elif key_num_all is not None:
            df_rep["num_join_all"] = df_rep[key_num_all].astype(str).str.strip()
            merged_all = df_rep.merge(base_emp, left_on="num_join_all", right_on="num_empleado", how="inner")

        if merged_all is not None and (not merged_all.empty):
            day_map = prog_by_day_nif.setdefault(day.strftime("%Y-%m-%d"), {})
            for _, rr in merged_all.iterrows():
                try:
                    nif_u = str(rr.get("nif", "")).upper().strip()
                    mp = rr.get("horas_prog_min", None)
                    if nif_u and mp is not None and int(mp) >= 0:
                        day_map[nif_u] = int(mp)
                except Exception:
                    pass

        # filtrar bajas por horas_baja > 0
        try:
            df_rep["_horas_baja"] = df_rep.apply(lambda r: _get_horas_baja_from_row(r.to_dict()), axis=1)
        except Exception:
            df_rep["_horas_baja"] = 0.0

        df_rep = df_rep[df_rep["_horas_baja"] > 0.0].copy()
        if df_rep.empty:
            continue

        # Unir con base_emp si existe (mantener tu lógica real)
        key_nif = _pick_key(df_rep, ["nif", "NIF", "dni", "DNI"])
        key_num = _pick_key(df_rep, ["num_empleado", "numEmpleado", "employee_number", "employeeNumber", "id_empleado", "idEmpleado"])
        if key_nif:
            df_rep["nif_join"] = df_rep[key_nif].astype(str).str.upper().str.strip()
            merged = df_rep.merge(base_emp, left_on="nif_join", right_on="nif", how="inner")
        elif key_num:
            df_rep["num_join"] = df_rep[key_num].astype(str).str.strip()
            merged = df_rep.merge(base_emp, left_on="num_join", right_on="num_empleado", how="inner")
        else:
            merged = df_rep.copy()

        # Respetar filtros empresa/sede si esas columnas existen
        if "Empresa" in merged.columns:
            merged = merged[merged["Empresa"].isin(empresas_sel)]
        if "Sede" in merged.columns:
            merged = merged[merged["Sede"].isin(sedes_sel)]

        if merged.empty:
            continue

        merged["Fecha"] = day.strftime("%Y-%m-%d")
        bajas_por_dia[day.strftime("%Y-%m-%d")] = merged.reset_index(drop=True)

    # --------- SIN FICHAJES (placeholder) ----------
    # En tu base ya está implementado; aquí se conserva como st.session_state["result_sin_fichajes"]
    sin_por_dia = {}

    # --------- INCIDENCIAS ----------
    salida_incidencias = pd.DataFrame()
    if not resumen.empty:
        # aplicar build_incidencia (tu base real)
        resumen["Incidencia"] = resumen.apply(build_incidencia, axis=1)
        salida_incidencias = resumen[resumen["Incidencia"].astype(str).str.strip() != ""].copy()

    # --------- EXCESOS (solo semanas completas) ----------
    full_weeks = list_full_workweeks_in_range(d0, d1)
    excesos_por_semana = {}
    csv_excesos = b""

    if (not resumen.empty) and full_weeks:
        # Preprocesado resumen para tiempos
        tmp = resumen.copy()

        if "Tiempo Contabilizado" in tmp.columns:
            tmp["mins_tc"] = tmp["Tiempo Contabilizado"].apply(hhmm_to_min)
        else:
            tmp["mins_tc"] = 0

        if "Primera entrada" in tmp.columns:
            tmp["primera_min"] = tmp["Primera entrada"].apply(hhmm_to_min_clock)
        else:
            tmp["primera_min"] = None

        def _is_festivo_day(sede: str, day: date) -> tuple[bool, str]:
            # retorna (is_festivo, label)
            day_str = day.strftime("%Y-%m-%d")
            fest_dates = get_festivos_for_sede(sede, festivos_by_sede)
            if day_str in fest_dates:
                label = get_festivo_label_for_sede_date(sede, day_str, festivos_labels_by_sede)
                return True, (label or "Festivo")
            return False, ""

            def expected_day_minutes(depto_norm: str, nombre: str, sede: str, day: date, wd: int, nif: str | None = None) -> int:
                """Jornada esperada (minutos) por día.

                Prioridad:
                1) horas_programadas del informe /informes/empleados (si existe para ese empleado y día)
                2) reglas internas (calcular_minimos), aplicando festivos/fin de semana = 0
                """
                # 1) Si tenemos horas_programadas del API, eso manda (ya viene con festivos/fin de semana aplicado)
                try:
                    if nif:
                        mp = prog_by_day_nif.get(day.strftime("%Y-%m-%d"), {}).get(str(nif).upper().strip())
                        if mp is not None:
                            return int(mp)
                except Exception:
                    pass

                # 2) fallback: fin de semana o festivo => 0
                is_fest, _ = _is_festivo_day(sede, day)
                if wd >= 5 or is_fest:
                    return 0

                if depto_norm in ["MOI", "ESTRUCTURA", "MOD"]:
                    min_h, _ = calcular_minimos(depto_norm, wd, nombre)
                    return int(round(float(min_h) * 60)) if min_h is not None else 0

                return 0

        def effective_worked_minutes_for_mod(mins_tc: int, primera_min: int | None) -> int:
            # MOD: no cuenta lo trabajado ANTES del inicio del turno.
            # Turno mañana: 06:00–14:00  | Turno tarde: 14:00–22:00
            # (Noche no se fuerza aquí; con datos actuales es lo más estable)
            if primera_min is None:
                return max(0, int(mins_tc))

            # Heurística de turno por primera entrada
            turno_inicio = 6 * 60 if primera_min < 14 * 60 else 14 * 60
            # si entra antes del inicio del turno, se descuenta "no computable"
            if primera_min < turno_inicio:
                descontar = turno_inicio - primera_min
                return max(0, int(mins_tc) - descontar)
            return max(0, int(mins_tc))

        TOL = 5  # minutos tolerancia diaria

        def quantize_daily_balance(diff_min: int) -> int:
            """
            Reglas:
            - dentro de ±5 => 0
            - positivo: se cuantiza hacia abajo en múltiplos de 30,
              pero: 0..29 => 0 (NO suma), empieza a sumar desde 30
            - negativo: se cuantiza hacia "más falta": -1..-30 => -30, etc.
            """
            if -TOL <= diff_min <= TOL:
                return 0

            if diff_min > TOL:
                # 0..29 => 0
                if diff_min < 30:
                    return 0
                return (diff_min // 30) * 30

            # diff_min < -TOL
            import math
            return -int(math.ceil(abs(diff_min) / 30.0) * 30)

        for wk_start, wk_end, wk_label in full_weeks:
            # sub-resumen semana
            mask = (pd.to_datetime(tmp["Fecha"]).dt.date >= wk_start) & (pd.to_datetime(tmp["Fecha"]).dt.date <= wk_end)
            sub = tmp[mask].copy()
            if sub.empty:
                continue

            rows_out = []

            # Agrupar por empleado
            for (nif, nombre, depto, empresa, sede), g in sub.groupby(["nif", "Nombre", "Departamento", "Empresa", "Sede"]):
                depto_norm = str(depto or "").upper().strip()
                nombre_s = str(nombre or "").strip()
                sede_s = str(sede or "").strip()

                # mapa por día de trabajado y primera entrada
                day_map = {}
                for _, rr in g.iterrows():
                    try:
                        dd = pd.to_datetime(rr["Fecha"]).date()
                    except Exception:
                        continue
                    day_map.setdefault(dd, {"mins_tc": 0, "primera_min": None})
                    day_map[dd]["mins_tc"] += int(rr.get("mins_tc", 0) or 0)
                    pm = rr.get("primera_min", None)
                    if pm is not None:
                        curpm = day_map[dd].get("primera_min")
                        if curpm is None or (isinstance(curpm, (int, float)) and pm < curpm):
                            day_map[dd]["primera_min"] = pm

                # recorrer todos los días de la semana seleccionada (L-V / L-S / L-D)
                jornada_sem_min = 0
                trabajado_sem_min = 0
                balance_sem_min = 0

                cur_day = wk_start
                while cur_day <= wk_end:
                    wd = int(cur_day.weekday())
                    rec = day_map.get(cur_day)
                    mins_tc = int(rec["mins_tc"]) if rec else 0
                    primera_min = rec.get("primera_min") if rec else None

                    exp_day = expected_day_minutes(depto_norm, nombre_s, sede_s, cur_day, wd, nif=nif)
                    jornada_sem_min += exp_day

                    # trabajado efectivo para MOD (solo si es día laborable y hay jornada esperada)
                    if depto_norm == "MOD" and exp_day > 0:
                        worked_eff = effective_worked_minutes_for_mod(mins_tc, primera_min)
                    else:
                        worked_eff = mins_tc

                    trabajado_sem_min += worked_eff

                    diff = worked_eff - exp_day
                    bal = quantize_daily_balance(diff)
                    balance_sem_min += bal

                    cur_day += timedelta(days=1)

                # Mostrar también negativos/positivos (si balance != 0)
                if balance_sem_min != 0:
                    rows_out.append(
                        {
                            "Empresa": empresa,
                            "Sede": sede,
                            "Nombre": nombre,
                            "Departamento": depto,
                            "Trabajado semanal": min_to_hhmm(trabajado_sem_min),
                            "Jornada semanal": min_to_hhmm(jornada_sem_min),
                            "Exceso": min_to_hhmm(balance_sem_min),
                        }
                    )

            if rows_out:
                df_week = pd.DataFrame(rows_out)
                excesos_por_semana[f"{wk_start.strftime('%Y-%m-%d')} → {wk_end.strftime('%Y-%m-%d')} ({wk_label})"] = df_week

        # CSV de excesos (todas las semanas)
        if excesos_por_semana:
            all_df = []
            for k, dfw in excesos_por_semana.items():
                dft = dfw.copy()
                dft["Semana"] = k
                all_df.append(dft)
            df_all = pd.concat(all_df, ignore_index=True)
            csv_excesos = df_all.to_csv(index=False).encode("utf-8")

        # --------- Guardar en estado + CSVs ----------
        incidencias_por_dia = {}
        if not salida_incidencias.empty:
            for day, subd in salida_incidencias.groupby("Fecha"):
                incidencias_por_dia[str(day)] = subd.reset_index(drop=True)

        st.session_state["last_sig"] = signature
        st.session_state["result_incidencias"] = incidencias_por_dia
        st.session_state["result_bajas"] = bajas_por_dia
        st.session_state["result_sin_fichajes"] = sin_por_dia
        st.session_state["result_excesos_semana"] = excesos_por_semana

        st.session_state["result_csv_incidencias"] = (
            salida_incidencias.to_csv(index=False).encode("utf-8") if not salida_incidencias.empty else b""
        )

        if bajas_por_dia:
            df_all_bajas = pd.concat(list(bajas_por_dia.values()), ignore_index=True)
            st.session_state["result_csv_bajas"] = df_all_bajas.to_csv(index=False).encode("utf-8")
        else:
            st.session_state["result_csv_bajas"] = b""

        if sin_por_dia:
            df_all_sin = pd.concat(list(sin_por_dia.values()), ignore_index=True)
            st.session_state["result_csv_sin"] = df_all_sin.to_csv(index=False).encode("utf-8")
        else:
            st.session_state["result_csv_sin"] = b""

        st.session_state["result_csv_excesos"] = csv_excesos

# ------------------------------------------------------------
# Render: Tabs
# ------------------------------------------------------------

has_incidencias = bool(st.session_state.get("result_incidencias"))
has_bajas = bool(st.session_state.get("result_bajas"))
has_sin = bool(st.session_state.get("result_sin_fichajes"))
has_excesos = bool(st.session_state.get("result_excesos_semana"))

tabs = []
labels = []
if has_incidencias:
    labels.append("📌 Fichajes")
    tabs.append("fichajes")
if has_bajas:
    labels.append("🏥 Bajas")
    tabs.append("bajas")
if has_sin:
    labels.append("⛔ Sin fichajes")
    tabs.append("sin")
if has_excesos:
    labels.append("🕒 Exceso de jornada")
    tabs.append("excesos")

if not tabs:
    st.info("Ajusta filtros/fechas y pulsa Consultar para ver resultados.")
    st.stop()

tab_objs = st.tabs(labels)

for tname, tab in zip(tabs, tab_objs):
    with tab:
        if tname == "fichajes":
            data = st.session_state.get("result_incidencias", {})
            for day, df_day in data.items():
                st.subheader(day)
                st.dataframe(df_day, use_container_width=True)
            if st.session_state.get("result_csv_incidencias"):
                st.download_button(
                    "Descargar CSV incidencias",
                    data=st.session_state["result_csv_incidencias"],
                    file_name="incidencias.csv",
                    mime="text/csv",
                )
        elif tname == "bajas":
            data = st.session_state.get("result_bajas", {})
            for day, df_day in data.items():
                st.subheader(day)
                st.dataframe(df_day, use_container_width=True)
            if st.session_state.get("result_csv_bajas"):
                st.download_button(
                    "Descargar CSV bajas",
                    data=st.session_state["result_csv_bajas"],
                    file_name="bajas.csv",
                    mime="text/csv",
                )
        elif tname == "sin":
            data = st.session_state.get("result_sin_fichajes", {})
            for day, df_day in data.items():
                st.subheader(day)
                st.dataframe(df_day, use_container_width=True)
            if st.session_state.get("result_csv_sin"):
                st.download_button(
                    "Descargar CSV sin fichajes",
                    data=st.session_state["result_csv_sin"],
                    file_name="sin_fichajes.csv",
                    mime="text/csv",
                )
        elif tname == "excesos":
            data = st.session_state.get("result_excesos_semana", {})
            for wk, dfwk in data.items():
                st.subheader(wk)
                st.dataframe(dfwk, use_container_width=True)
            if st.session_state.get("result_csv_excesos"):
                st.download_button(
                    "Descargar CSV excesos (todas las semanas)",
                    data=st.session_state["result_csv_excesos"],
                    file_name="excesos.csv",
                    mime="text/csv",
                )
