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
# ============================================================

DEFAULT_FESTIVOS_CSV_PATH = "Listado Festivos.csv"


def _safe_fail(_exc: Exception) -> None:
    return None


def safe_request(method: str, url: str, *, data=None, params=None, json_body=None, timeout=HTTP_TIMEOUT):
    method = (method or "").upper().strip()
    if method not in {"GET", "POST"}:
        return None

    last_exc = None
    for attempt in range(MAX_RETRIES + 1):
        try:
            resp = _SESSION.request(
                method,
                url,
                data=data,
                params=params,
                json=json_body,
                timeout=timeout,
                verify=True,
            )

            if resp.status_code in RETRY_STATUS:
                if attempt < MAX_RETRIES:
                    wait = min(BACKOFF_MAX_SECONDS, BACKOFF_BASE_SECONDS * (2 ** attempt))
                    wait += random.uniform(0, 0.25)
                    time.sleep(wait)
                    continue
                return resp

            return resp

        except requests.RequestException as e:
            last_exc = e
            if attempt < MAX_RETRIES:
                wait = min(BACKOFF_MAX_SECONDS, BACKOFF_BASE_SECONDS * (2 ** attempt))
                wait += random.uniform(0, 0.25)
                time.sleep(wait)
                continue
            _safe_fail(last_exc)
            return None

    _safe_fail(last_exc if last_exc else Exception("Unknown request error"))
    return None


# ============================================================
# NORMALIZACIÓN
# ============================================================

def norm_name(s: str) -> str:
    if s is None:
        return ""
    return " ".join(str(s).upper().strip().split())


def name_startswith(nombre_norm: str, prefix_norm: str) -> bool:
    return bool(nombre_norm) and bool(prefix_norm) and nombre_norm.startswith(prefix_norm)


def _norm_key(s: str) -> str:
    return " ".join((s or "").strip().upper().split())



# --- sede code helper (needed for festivos) ---
def _sede_code(sede: str) -> str:
    """Devuelve el código P0/P1/P2/P3 a partir del nombre de sede normalizado."""
    s = _norm_key(sede)
    if not s:
        return ""
    tok = s.split()[0]
    if tok in {"P0", "P1", "P2", "P3"}:
        return tok
    for c in ["P0", "P1", "P2", "P3"]:
        if s.startswith(c):
            return c
    return ""


# ============================================================
# FESTIVOS CSV -> {SEDE_NORM: set(YYYY-MM-DD)}
# ============================================================

@st.cache_data(show_spinner=False, ttl=3600)


def get_festivos_for_sede(sede: str, festivos_by_sede: dict) -> set:
    """Devuelve set de fechas 'YYYY-MM-DD' festivas para esa sede, con matching robusto."""
    if not festivos_by_sede:
        return set()

    sede_norm = _norm_key(sede)
    if sede_norm in festivos_by_sede:
        return set(festivos_by_sede.get(sede_norm, set()) or set())

    code = _sede_code(sede_norm)
    if not code:
        return set()

    out = set()

    # Caso: CSV con clave "P1"
    if code in festivos_by_sede:
        out |= set(festivos_by_sede.get(code, set()) or set())

    # Caso: CSV con clave "P1 LAKUNTZA" (o variantes)
    for k, v in festivos_by_sede.items():
        k_norm = _norm_key(k)
        if k_norm.startswith(code):
            out |= set(v or set())

    return out
def load_festivos_from_csv_bytes(file_bytes: bytes) -> dict:
    """
    Devuelve {SEDE_NORM: set({YYYY-MM-DD,...})}.
    CSV esperado: separador ';' con columnas tipo:
      - "Próxima ocurrencia" (dd/mm/yyyy)
      - "Sede(s)" (con sedes separadas por '|')
      - opcional "Repetición" / nota (p.ej. "En P3 no será festivo")
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

    # columnas
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

    if not col_fecha or not col_sedes:
        return {}

    def parse_ddmmyyyy(s: str):
        if not isinstance(s, str):
            return None
        s = s.strip()
        if not s:
            return None
        try:
            dt = pd.to_datetime(s, dayfirst=True, errors="coerce")
            if pd.isna(dt):
                return None
            return dt.date().strftime("%Y-%m-%d")
        except Exception:
            return None

    out = {}
    for _, r in df.iterrows():
        fecha_raw = str(r.get(col_fecha, "") or "").strip()
        sede_raw = str(r.get(col_sedes, "") or "").strip()
        if not fecha_raw or not sede_raw:
            continue

        fecha = parse_ddmmyyyy(fecha_raw)
        if not fecha:
            continue

        nota = str(r.get(col_nota, "") or "").strip().upper() if col_nota else ""
        exclude_p3 = ("P3" in nota and "NO" in nota and "FESTIV" in nota)

        sedes = [x.strip() for x in sede_raw.split("|") if x.strip()]
        for s in sedes:
            s_norm = _norm_key(s)
            if exclude_p3 and s_norm.startswith("P3"):
                continue
            out.setdefault(s_norm, set()).add(fecha)

    return out


@st.cache_data(show_spinner=False, ttl=3600)
def load_festivos_labels_from_csv_bytes(file_bytes: bytes) -> dict:
    """
    Devuelve {SEDE_NORM: {YYYY-MM-DD: 'Nombre del festivo'}} usando el mismo CSV.

    - Para festivos tipo NACIONAL: se aplica a todas las sedes (salvo exclusión explícita en notas).
    - Si falta el nombre, se devuelve 'Festivo'.
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

    col_tipo = None
    for c in ["Tipo", "TIPO"]:
        if c in df.columns:
            col_tipo = c
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
        try:
            dt = pd.to_datetime(s, dayfirst=True, errors="coerce")
            if pd.isna(dt):
                return None
            return dt.date().strftime("%Y-%m-%d")
        except Exception:
            return None

    def excluded_codes_from_note(note_u: str) -> set:
        if not note_u:
            return set()
        out = set()
        for code in ["P0", "P1", "P2", "P3"]:
            if (f"EN {code}" in note_u) and ("NO" in note_u) and ("FESTIV" in note_u):
                out.add(code)
        return out

    allowed_sedes_local = ["P0 IBSA", "P1 LAKUNTZA", "P2 COMARCA II", "P3 UHARTE"]

    out = {}
    for _, r in df.iterrows():
        fecha_raw = str(r.get(col_fecha, "") or "").strip()
        sede_raw = str(r.get(col_sedes, "") or "").strip()
        if not fecha_raw:
            continue

        fecha = parse_ddmmyyyy(fecha_raw)
        if not fecha:
            continue

        tipo_u = str(r.get(col_tipo, "") or "").strip().upper() if col_tipo else ""
        nota_u = str(r.get(col_nota, "") or "").strip().upper() if col_nota else ""
        excluded = excluded_codes_from_note(nota_u)

        nombre = str(r.get(col_nombre, "") or "").strip() if col_nombre else ""
        if not nombre:
            nombre = "Festivo"

        if "NACIONAL" in tipo_u:
            sedes_list = allowed_sedes_local
        else:
            if not sede_raw:
                continue
            sedes_list = [x.strip() for x in sede_raw.split("|") if x.strip()]

        for s in sedes_list:
            s_norm = _norm_key(s)
            code = _sede_code(s_norm)
            if code in excluded:
                continue
            out.setdefault(s_norm, {})[fecha] = nombre

    return out


def get_festivo_label_for_sede_date(sede: str, day_yyyy_mm_dd: str, festivos_labels_by_sede: dict) -> str:
    """Devuelve el nombre del festivo (si lo hay) para esa sede y fecha (matching robusto)."""
    if not festivos_labels_by_sede:
        return ""
    sede_norm = _norm_key(sede)
    if sede_norm in festivos_labels_by_sede:
        return str((festivos_labels_by_sede.get(sede_norm, {}) or {}).get(day_yyyy_mm_dd, "") or "")

    code = _sede_code(sede_norm)
    if not code:
        return ""

    if code in festivos_labels_by_sede:
        return str((festivos_labels_by_sede.get(code, {}) or {}).get(day_yyyy_mm_dd, "") or "")

    for k, v in festivos_labels_by_sede.items():
        k_norm = _norm_key(k)
        if k_norm.startswith(code):
            val = (v or {}).get(day_yyyy_mm_dd)
            if val:
                return str(val)

    return ""

def _iter_days(d0: date, d1: date):
    cur = d0
    while cur <= d1:
        yield cur
        cur += timedelta(days=1)


def list_full_workweeks_in_range(fi: date, ff: date):
    """
    Semanas completas contenidas dentro del rango.

    - Si el rango cubre L-V (lunes a viernes) -> se incluye semana L-V
    - Si además cubre sábado+domingo -> se devuelve esa semana como L-D

    Devuelve lista de tuplas: (week_start_monday, week_end_inclusive, include_weekend_bool)
    """

    def monday_of(d: date) -> date:
        return d - timedelta(days=d.weekday())

    weeks = []
    cur = monday_of(fi)
    end_limit = monday_of(ff)

    while cur <= end_limit:
        mon = cur
        fri = cur + timedelta(days=4)
        sat = cur + timedelta(days=5)
        sun = cur + timedelta(days=6)

        if (fi <= mon) and (ff >= fri):
            include_weekend = (fi <= sat) and (ff >= sun)
            end_incl = sun if include_weekend else fri
            weeks.append((mon, end_incl, include_weekend))

        cur += timedelta(days=7)

    return weeks



def floor_to_30(mins: int) -> int:
    if mins <= 0:
        return 0
    return (mins // 30) * 30


def mins_to_hhmm_signed(mins: int) -> str:
    sign = "+" if mins >= 0 else "-"
    a = abs(int(mins))
    h = a // 60
    m = a % 60
    return f"{sign}{h:02d}:{m:02d}"


# ============================================================
# RESTRICCIONES (solo estas empresas y sedes)
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

ALLOWED_EMPRESAS_N = {_norm_key(x) for x in ALLOWED_EMPRESAS}
ALLOWED_SEDES_N = {_norm_key(x) for x in ALLOWED_SEDES}


# ============================================================
# DESCIFRADO CRECE (AES-CBC)
# ============================================================

def decrypt_crece_payload(payload_b64: str, app_key_b64: str) -> str:
    json_raw = base64.b64decode(payload_b64).decode("utf-8")
    payload = json.loads(json_raw)

    iv = base64.b64decode(payload["iv"])
    ct = base64.b64decode(payload["value"])
    key = base64.b64decode(app_key_b64)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ct), AES.block_size)
    return decrypted.decode("utf-8")


def _try_parse_encrypted_response(resp: requests.Response):
    if resp is None:
        return None

    raw_text = (resp.text or "").strip()
    candidates = []

    try:
        candidates.append(resp.json())
    except Exception:
        pass

    candidates.append(raw_text)

    for c in candidates:
        try:
            if isinstance(c, dict) and "iv" in c and "value" in c:
                payload_obj = {"iv": c["iv"], "value": c["value"]}
                payload_b64 = base64.b64encode(json.dumps(payload_obj).encode("utf-8")).decode("utf-8")
                dec = decrypt_crece_payload(payload_b64, APP_KEY_B64)
                return json.loads(dec)

            if isinstance(c, str):
                s = c.strip().strip('"').strip()

                if s.startswith("{") and s.endswith("}"):
                    obj = json.loads(s)
                    if isinstance(obj, dict) and "iv" in obj and "value" in obj:
                        payload_b64 = base64.b64encode(json.dumps(obj).encode("utf-8")).decode("utf-8")
                        dec = decrypt_crece_payload(payload_b64, APP_KEY_B64)
                        return json.loads(dec)

                try:
                    dec_json_raw = base64.b64decode(s).decode("utf-8")
                    obj = json.loads(dec_json_raw)
                    if isinstance(obj, dict) and "iv" in obj and "value" in obj:
                        dec = decrypt_crece_payload(s, APP_KEY_B64)
                        return json.loads(dec)
                except Exception:
                    pass

        except Exception:
            continue

    return None


# ============================================================
# TIEMPOS (con redondeo consistente)
# ============================================================

def _round_seconds_to_minute(seg: float) -> int:
    if seg is None or (isinstance(seg, float) and pd.isna(seg)):
        return 0
    try:
        s = float(seg)
    except Exception:
        return 0
    if s < 0:
        s = 0.0
    return int(round(s / 60.0)) * 60


def segundos_a_hhmm(seg: float) -> str:
    seg_i = _round_seconds_to_minute(seg)
    total_min = seg_i // 60
    h = total_min // 60
    m = total_min % 60
    return f"{h:02d}:{m:02d}"


def hhmm_to_min(hhmm: str) -> int:
    if not isinstance(hhmm, str) or ":" not in hhmm:
        return 0
    try:
        h, m = map(int, hhmm.split(":"))
        return max(0, h * 60 + m)
    except Exception:
        return 0


def hhmm_to_dec(hhmm: str) -> float:
    return hhmm_to_min(hhmm) / 60.0


def diferencia_hhmm(tc_hhmm: str, tt_hhmm: str) -> str:
    tc_hhmm = (tc_hhmm or "").strip()
    tt_hhmm = (tt_hhmm or "").strip()
    if not tc_hhmm or not tt_hhmm:
        return ""

    tc_min = hhmm_to_min(tc_hhmm)
    tt_min = hhmm_to_min(tt_hhmm)

    # ✅ tolerancia de 1 minuto para eliminar +00:01 / -00:01 por redondeos
    if abs(tc_min - tt_min) <= 1:
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


def hhmm_to_min_clock(hhmm: str):
    if not isinstance(hhmm, str) or ":" not in hhmm:
        return None
    try:
        h, m = map(int, hhmm.split(":"))
        return h * 60 + m
    except Exception:
        return None


# ============================================================
# REGLAS ESPECIALES (las tuyas)
# ============================================================

N_DAVID = norm_name("David Rodriguez Vazquez")
N_DEBORA = norm_name("Debora Luis Soto")
N_ETOR = norm_name("Etor Alegria Reparaz")
N_FRAN = norm_name("Francisco Javier Diaz Arozarena")
N_MIRIAM = norm_name("Miriam Martin Muñoz")
N_BEATRIZ = norm_name("Beatriz Andueza Roncal")

SPECIAL_RULES_PREFIX = [
    ("MOD", N_DAVID, {"min_horas": 4.5, "min_fichajes": 2}),
    ("MOI", N_DEBORA, {"min_fichajes": 2}),
    ("MOI", N_ETOR, {"min_fichajes": 2}),
    ("MOI", N_MIRIAM, {"min_horas": 5.5, "min_fichajes": 2}),
    ("ESTRUCTURA", N_BEATRIZ, {"min_horas": 6.5, "min_fichajes": 2, "max_fichajes_ok": 4}),
]

SCHEDULE_EXEMPT_PREFIX = [
    ("MOD", N_DAVID),
    ("MOI", N_MIRIAM),
]

FLEX_BY_DEPTO = {
    "ESTRUCTURA": [N_FRAN],
    "MOI": [N_DEBORA, N_ETOR],
}


def _lookup_special(depto_norm: str, nombre_norm: str):
    for d, pref, rules in SPECIAL_RULES_PREFIX:
        if depto_norm == d and name_startswith(nombre_norm, pref):
            return rules
    return None


def _is_schedule_exempt(depto_norm: str, nombre_norm: str) -> bool:
    for d, pref in SCHEDULE_EXEMPT_PREFIX:
        if depto_norm == d and name_startswith(nombre_norm, pref):
            return True
    return False


def _is_flex(depto_norm: str, nombre_norm: str) -> bool:
    for pref in FLEX_BY_DEPTO.get(depto_norm, []):
        if name_startswith(nombre_norm, pref):
            return True
    return False


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


def expected_week_minutes_for_employee(depto: str, nombre: str, sede: str, week_mon: date, week_fri: date, festivos_by_sede: dict) -> int:
    """
    Jornada esperada semanal por empleado:
    - suma jornada diaria esperada (calcular_minimos) de L-V
    - si un día es festivo en ESA sede -> no suma jornada ese día
    - así los de jornada especial quedan automáticamente bien
    """
    sede_norm = _norm_key(sede)
    festivos = festivos_by_sede.get(sede_norm, set())

    total = 0
    cur = week_mon
    while cur <= week_fri:
        wd = cur.weekday()
        if wd <= 4:
            day_str = cur.strftime("%Y-%m-%d")
            if day_str not in festivos:
                min_h, _ = calcular_minimos(depto, wd, nombre)
                if min_h is not None:
                    total += int(round(float(min_h) * 60))
        cur += timedelta(days=1)

    return max(0, total)


def validar_horario(depto: str, nombre: str, dia: int, primera_entrada_hhmm: str, ultima_salida_hhmm: str) -> list[str]:
    depto_norm = (depto or "").upper().strip()
    nombre_norm = norm_name(nombre)

    if dia not in [0, 1, 2, 3, 4]:
        return []

    if _is_schedule_exempt(depto_norm, nombre_norm):
        return []

    incid = []
    e_min = hhmm_to_min_clock(primera_entrada_hhmm)
    s_min = hhmm_to_min_clock(ultima_salida_hhmm)

    if e_min is None:
        return incid

    if depto_norm == "MOD":
        turno = "manana" if e_min < (12 * 60) else "tarde"

        if turno == "manana":
            ini_ok, fin_ok = 5 * 60 + 30, 6 * 60
            fin_turno = 14 * 60
            if e_min < ini_ok:
                incid.append(f"Entrada temprana ({primera_entrada_hhmm})")
            elif ini_ok <= e_min <= fin_ok:
                pass
            elif e_min <= fin_turno:
                incid.append(f"Entrada fuera de rango ({primera_entrada_hhmm})")
            else:
                incid.append(f"Entrada tarde ({primera_entrada_hhmm})")
        else:
            ini_ok, fin_ok = 13 * 60, 14 * 60
            fin_turno = 22 * 60
            if e_min < ini_ok:
                incid.append(f"Entrada temprana ({primera_entrada_hhmm})")
            elif ini_ok <= e_min <= fin_ok:
                pass
            elif e_min <= fin_turno:
                incid.append(f"Entrada fuera de rango ({primera_entrada_hhmm})")
            else:
                incid.append(f"Entrada tarde ({primera_entrada_hhmm})")
        return incid

    if depto_norm in ["MOI", "ESTRUCTURA"]:
        flex = _is_flex(depto_norm, nombre_norm)

        if not flex:
            ini, fin = 7 * 60, 9 * 60
            salida_min = (13 * 60 + 30) if dia == 4 else (16 * 60 + 30)

            if e_min < (ini - MARGEN_HORARIO_MIN):
                incid.append(f"Entrada temprana ({primera_entrada_hhmm})")
            elif e_min > fin:
                incid.append(f"Entrada tarde ({primera_entrada_hhmm})")

            if s_min is not None and s_min < (salida_min - MARGEN_HORARIO_MIN):
                incid.append(f"Salida temprana ({ultima_salida_hhmm})")
        return incid

    return incid


def validar_incidencia_horas_fichajes(r) -> list[str]:
    min_h = r.get("min_horas")
    min_f = r.get("min_fichajes")
    if pd.isna(min_h) or pd.isna(min_f):
        return []

    try:
        num_fich = int(r.get("Numero de fichajes", 0) or 0)
    except Exception:
        num_fich = 0

    try:
        horas_val = float(r.get("horas_dec_validacion", 0.0) or 0.0)
    except Exception:
        horas_val = 0.0

    motivos = []

    umbral_inferior = float(min_h) - TOLERANCIA_HORAS
    if horas_val < umbral_inferior:
        motivos.append(f"Horas insuficientes (mín {min_h}h)")

    if num_fich < int(min_f):
        motivos.append(f"Fichajes insuficientes (mín {min_f})")

    max_ok = r.get("max_fichajes_ok")
    if pd.notna(max_ok):
        try:
            max_ok_i = int(max_ok)
        except Exception:
            max_ok_i = None
        if max_ok_i is not None and horas_val >= umbral_inferior and num_fich > max_ok_i:
            motivos.append(f"Fichajes excesivos (máx {max_ok_i})")
    else:
        if horas_val >= umbral_inferior and num_fich > int(min_f):
            motivos.append(f"Fichajes excesivos (mín {min_f})")

    return motivos


# ============================================================
# API EXPORTACIÓN / INFORMES
# ============================================================

@st.cache_data(show_spinner=False, ttl=3600)
def api_exportar_departamentos() -> pd.DataFrame:
    url = f"{API_URL_BASE}/exportacion/departamentos"
    resp = safe_request("GET", url)
    if resp is None:
        return pd.DataFrame(columns=["departamento_id", "departamento_nombre"])
    resp.raise_for_status()
    data = _try_parse_encrypted_response(resp)
    if not isinstance(data, list):
        return pd.DataFrame(columns=["departamento_id", "departamento_nombre"])
    return pd.DataFrame(
        [{"departamento_id": d.get("id"), "departamento_nombre": d.get("nombre")}
         for d in (data or [])]
    )


@st.cache_data(show_spinner=False, ttl=3600)
def api_exportar_empresas() -> pd.DataFrame:
    url = f"{API_URL_BASE}/exportacion/empresas"
    resp = safe_request("GET", url)
    if resp is None:
        return pd.DataFrame(columns=["empresa_id", "empresa_nombre"])
    try:
        resp.raise_for_status()
    except Exception:
        return pd.DataFrame(columns=["empresa_id", "empresa_nombre"])
    data = _try_parse_encrypted_response(resp)
    if not isinstance(data, list):
        return pd.DataFrame(columns=["empresa_id", "empresa_nombre"])
    return pd.DataFrame(
        [{"empresa_id": e.get("id"), "empresa_nombre": e.get("nombre")}
         for e in (data or [])]
    )


@st.cache_data(show_spinner=False, ttl=3600)
def api_exportar_sedes() -> pd.DataFrame:
    url1 = f"{API_URL_BASE}/exportacion/sedes"
    resp = safe_request("GET", url1)
    if resp is not None and resp.status_code == 200:
        data = _try_parse_encrypted_response(resp)
        if isinstance(data, list):
            return pd.DataFrame(
                [{"sede_id": s.get("id"), "sede_nombre": s.get("nombre")}
                 for s in (data or [])]
            )

    url2 = f"{API_URL_BASE}/exportacion/centros"
    resp2 = safe_request("GET", url2)
    if resp2 is None:
        return pd.DataFrame(columns=["sede_id", "sede_nombre"])
    try:
        resp2.raise_for_status()
    except Exception:
        return pd.DataFrame(columns=["sede_id", "sede_nombre"])

    data2 = _try_parse_encrypted_response(resp2)
    if not isinstance(data2, list):
        return pd.DataFrame(columns=["sede_id", "sede_nombre"])
    return pd.DataFrame(
        [{"sede_id": s.get("id"), "sede_nombre": s.get("nombre")}
         for s in (data2 or [])]
    )


def api_exportar_empleados_completos() -> pd.DataFrame:
    url = f"{API_URL_BASE}/exportacion/empleados"
    data = {"solo_nif": 0}

    resp = safe_request("POST", url, data=data)
    if resp is None:
        return pd.DataFrame(columns=["nif", "nombre_completo", "departamento_id", "empresa_id", "sede_id", "num_empleado"])
    resp.raise_for_status()

    data_dec = _try_parse_encrypted_response(resp)
    if not isinstance(data_dec, list):
        return pd.DataFrame(columns=["nif", "nombre_completo", "departamento_id", "empresa_id", "sede_id", "num_empleado"])

    empleados = data_dec
    lista = []

    for e in (empleados or []):
        nombre = e.get("name") or e.get("nombre") or ""
        primer_apellido = e.get("primer_apellido") or ""
        segundo_apellido = e.get("segundo_apellido") or ""

        if not (primer_apellido or segundo_apellido) and e.get("apellidos"):
            partes = str(e["apellidos"]).split()
            primer_apellido = partes[0] if len(partes) > 0 else ""
            segundo_apellido = " ".join(partes[1:]) if len(partes) > 1 else ""

        nombre_completo = f"{nombre} {primer_apellido} {segundo_apellido}".strip()

        empresa_id = e.get("empresa") or e.get("empresa_id") or e.get("cod_empresa") or e.get("company_id")
        sede_id = e.get("sede") or e.get("sede_id") or e.get("centro") or e.get("centro_id")
        num_empleado = e.get("num_empleado") or e.get("employee_number") or e.get("id_empleado") or e.get("id")

        row = {
            "nif": e.get("nif"),
            "nombre_completo": nombre_completo,
            "departamento_id": e.get("departamento"),
            "empresa_id": empresa_id,
            "sede_id": sede_id,
            "num_empleado": str(num_empleado).strip() if num_empleado is not None else "",
        }

        for k in [
            "deleted_at",
            "activo",
            "estado",
            "situacion",
            "fecha_baja",
            "fecha_fin_contrato",
            "fin_contrato",
            "contrato_activo",
            "en_activo",
        ]:
            if k in e:
                row[k] = e.get(k)

        lista.append(row)

    df = pd.DataFrame(lista)
    if not df.empty:
        df["nif"] = df["nif"].astype(str).str.upper().str.strip()
        df["num_empleado"] = df["num_empleado"].astype(str).str.strip()
    return df


@st.cache_data(show_spinner=False, ttl=3600)
def api_exportar_tipos_fichaje() -> dict:
    url = f"{API_URL_BASE}/exportacion/tipos-fichaje"
    try:
        resp = safe_request("POST", url)
        if resp is None:
            return {}
        resp.raise_for_status()

        data_dec = _try_parse_encrypted_response(resp)
        if not isinstance(data_dec, list):
            return {}

        out = {}
        for t in data_dec:
            tid = t.get("id")
            if tid is None:
                continue
            out[int(tid)] = {
                "descuenta_tiempo": int(t.get("descuenta_tiempo") or 0),
                "turno_nocturno": int(t.get("turno_nocturno") or 0),
            }
        return out
    except Exception as e:
        _safe_fail(e)
        return {}


def api_exportar_fichajes(nif: str, fi: str, ff: str) -> list:
    url = f"{API_URL_BASE}/exportacion/fichajes"
    data = {"fecha_inicio": fi, "fecha_fin": ff, "nif": nif, "order": "asc"}

    try:
        resp = safe_request("POST", url, data=data)
        if resp is None:
            return []
        resp.raise_for_status()

        data_dec = _try_parse_encrypted_response(resp)
        return data_dec if isinstance(data_dec, list) else []
    except Exception as e:
        _safe_fail(e)
        return []


def _parse_tiempo_trabajado_payload(parsed) -> pd.DataFrame:
    filas = []

    def add_row(key: str, val):
        k = (str(key) or "").upper().strip()
        if not k:
            return

        if isinstance(val, dict):
            filas.append(
                {
                    "nif": str(val.get("nif") or k).upper().strip(),
                    "tiempoEfectivo_seg": val.get("tiempoEfectivo"),
                    "tiempoContabilizado_seg": val.get("tiempoContabilizado"),
                }
            )
            return

        if isinstance(val, list) and len(val) >= 4:
            filas.append(
                {"nif": k, "tiempoEfectivo_seg": val[-2], "tiempoContabilizado_seg": val[-1]}
            )
            return

        filas.append({"nif": k, "tiempoEfectivo_seg": None, "tiempoContabilizado_seg": None})

    if isinstance(parsed, dict):
        for k, v in parsed.items():
            add_row(k, v)

    df = pd.DataFrame(filas)
    if df.empty:
        return pd.DataFrame(columns=["nif", "tiempoEfectivo_seg", "tiempoContabilizado_seg"])
    df["nif"] = df["nif"].astype(str).str.upper().str.strip()
    return df


def api_exportar_tiempo_trabajado(desde: str, hasta: str, nifs=None) -> pd.DataFrame:
    url = f"{API_URL_BASE}/exportacion/tiempo-trabajado"
    payload = [("desde", desde), ("hasta", hasta)]

    if nifs:
        for v in nifs:
            s = str(v).strip() if v is not None else ""
            if s:
                payload.append(("nif[]", s))

    try:
        resp = safe_request("POST", url, data=payload)
        if resp is None:
            return pd.DataFrame(columns=["nif", "tiempoEfectivo_seg", "tiempoContabilizado_seg"])
        resp.raise_for_status()

        data_dec = _try_parse_encrypted_response(resp)
        if data_dec is None:
            return pd.DataFrame(columns=["nif", "tiempoEfectivo_seg", "tiempoContabilizado_seg"])

        return _parse_tiempo_trabajado_payload(data_dec)

    except Exception as e:
        _safe_fail(e)
        return pd.DataFrame(columns=["nif", "tiempoEfectivo_seg", "tiempoContabilizado_seg"])


def api_informe_empleados(fecha_desde: str, fecha_hasta: str):
    url = f"{API_URL_BASE}/informes/empleados"
    body = {"fecha_desde": fecha_desde, "fecha_hasta": fecha_hasta}
    try:
        resp = safe_request("POST", url, json_body=body)
        if resp is None:
            return None
        resp.raise_for_status()
        return _try_parse_encrypted_response(resp)
    except Exception as e:
        _safe_fail(e)
        return None


# ============================================================
# HELPERS BAJAS (ROBUSTO)
# ============================================================

def _to_float_any(x) -> float:
    if x is None or (isinstance(x, float) and pd.isna(x)):
        return 0.0
    try:
        if isinstance(x, str):
            s = x.strip().replace(",", ".")
            return float(s) if s else 0.0
        return float(x)
    except Exception:
        return 0.0


def _extract_rows_from_informe(rep):
    if rep is None:
        return []

    if isinstance(rep, list):
        return [r for r in rep if isinstance(r, dict)]

    if isinstance(rep, dict):
        for k in ["data", "empleados", "results", "resultado", "items"]:
            v = rep.get(k)
            if isinstance(v, list):
                return [r for r in v if isinstance(r, dict)]

        vals = list(rep.values())
        if vals and all(isinstance(v, dict) for v in vals):
            return vals

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
            if "horas" in v:
                return _to_float_any(v.get("horas"))
        elif isinstance(v, list):
            best = 0.0
            for it in v:
                if isinstance(it, dict):
                    h = _get_horas_baja_from_row(it)
                    if h > best:
                        best = h
            if best > 0:
                return best

    return 0.0


def _pick_key(df: pd.DataFrame, names: list[str]):
    for n in names:
        if n in df.columns:
            return n
    return None


# ============================================================
# DÍA (turno nocturno) + tiempos netos
# ============================================================

def ajustar_fecha_dia(fecha_dt: pd.Timestamp, turno_nocturno: int) -> str:
    if turno_nocturno == 1 and fecha_dt.hour < 6:
        return (fecha_dt.date() - timedelta(days=1)).strftime("%Y-%m-%d")
    return fecha_dt.date().strftime("%Y-%m-%d")


def calcular_tiempos_neto(df: pd.DataFrame, tipos_map: dict) -> pd.DataFrame:
    rows_out = []
    if df.empty:
        return pd.DataFrame(columns=["nif", "Fecha", "segundos_neto"])

    for nif in df["nif"].unique():
        sub_emp = df[df["nif"] == nif].copy()
        for fecha_dia in sub_emp["fecha_dia"].unique():
            sub = sub_emp[sub_emp["fecha_dia"] == fecha_dia].copy()
            sub = sub.sort_values("fecha_dt")

            sumados = 0
            descontados = 0

            i = 0
            n = len(sub)
            while i < n - 1:
                a = sub.iloc[i]
                b = sub.iloc[i + 1]
                if a.get("direccion") == "entrada" and b.get("direccion") == "salida":
                    delta = (b["fecha_dt"] - a["fecha_dt"]).total_seconds()
                    if delta >= 0:
                        delta_i = int(round(delta))
                        props = tipos_map.get(int(a.get("tipo")), {}) if a.get("tipo") is not None else {}
                        if int(props.get("descuenta_tiempo", 0)) == 1:
                            descontados += delta_i
                        else:
                            sumados += delta_i
                    i += 2
                else:
                    i += 1

            rows_out.append({"nif": nif, "Fecha": fecha_dia, "segundos_neto": max(0, sumados - descontados)})

    return pd.DataFrame(rows_out)


def calcular_primera_ultima(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame(columns=["nif", "Fecha", "primera_entrada_dt", "ultima_salida_dt"])

    entradas = df[df["direccion"] == "entrada"].groupby(["nif", "fecha_dia"], as_index=False)["fecha_dt"].min()
    entradas = entradas.rename(columns={"fecha_dia": "Fecha", "fecha_dt": "primera_entrada_dt"})

    salidas = df[df["direccion"] == "salida"].groupby(["nif", "fecha_dia"], as_index=False)["fecha_dt"].max()
    salidas = salidas.rename(columns={"fecha_dia": "Fecha", "fecha_dt": "ultima_salida_dt"})

    return entradas.merge(salidas, on=["nif", "Fecha"], how="outer")


# ============================================================
# FILTRO "ACTIVO / CONTRATO" (robusto)
# ============================================================

def _parse_date_any(x):
    if x is None or (isinstance(x, float) and pd.isna(x)):
        return None
    s = str(x).strip()
    if not s:
        return None
    for fmt in ("%Y-%m-%d", "%d-%m-%Y", "%Y/%m/%d", "%d/%m/%Y", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).date()
        except Exception:
            pass
    try:
        return pd.to_datetime(s, errors="coerce").date()
    except Exception:
        return None


def empleado_activo_o_contrato(df_emp: pd.DataFrame) -> pd.Series:
    if df_emp.empty:
        return pd.Series([], dtype=bool)

    if "deleted_at" in df_emp.columns:
        deleted = df_emp["deleted_at"].notna() & df_emp["deleted_at"].astype(str).str.strip().ne("") & df_emp["deleted_at"].astype(str).str.lower().ne("null")
    else:
        deleted = pd.Series([False] * len(df_emp))

    flags_true = pd.Series([False] * len(df_emp))
    for col in ["activo", "en_activo", "contrato_activo"]:
        if col in df_emp.columns:
            s = df_emp[col]
            flags_true = flags_true | s.astype(str).str.strip().str.lower().isin(["1", "true", "t", "si", "sí", "yes", "y"])

    estado_ok = pd.Series([False] * len(df_emp))
    for col in ["estado", "situacion"]:
        if col in df_emp.columns:
            s = df_emp[col].astype(str).str.strip().str.upper()
            estado_ok = estado_ok | s.isin(["ACTIVO", "ALTA", "EN ALTA", "EN_ALTA", "ACTIVE"])

    if "fecha_baja" in df_emp.columns:
        fb = df_emp["fecha_baja"].apply(_parse_date_any)
        fb_has = fb.notna()
        fb_past = fb_has & (fb <= date.today())
        baja = fb_past
    else:
        baja = pd.Series([False] * len(df_emp))

    fin_ok = pd.Series([False] * len(df_emp))
    for col in ["fecha_fin_contrato", "fin_contrato"]:
        if col in df_emp.columns:
            fc = df_emp[col].apply(_parse_date_any)
            fin_ok = fin_ok | (fc.notna() & (fc >= date.today()))

    any_signal_cols = any(c in df_emp.columns for c in ["activo", "en_activo", "contrato_activo", "estado", "situacion", "fecha_fin_contrato", "fin_contrato"])
    if any_signal_cols:
        active = (flags_true | estado_ok | fin_ok) & (~deleted) & (~baja)
    else:
        active = (~deleted) & (~baja)

    return active.fillna(False)


# ============================================================
# UI
# ============================================================

st.set_page_config(page_title="Fichajes CRECE Personas", layout="wide")

with st.spinner("Cargando catálogos…"):
    departamentos_df = api_exportar_departamentos()
    empresas_df = api_exportar_empresas()
    sedes_df = api_exportar_sedes()
    empleados_df = api_exportar_empleados_completos()

if empleados_df.empty:
    st.error("No hay empleados disponibles.")
    st.stop()

empleados_df = empleados_df.merge(departamentos_df, on="departamento_id", how="left")

empleados_df["empresa_id"] = empleados_df.get("empresa_id", pd.Series([""] * len(empleados_df))).astype(str).str.strip()
empleados_df["sede_id"] = empleados_df.get("sede_id", pd.Series([""] * len(empleados_df))).astype(str).str.strip()

emp_map = {}
if not empresas_df.empty and "empresa_id" in empresas_df.columns:
    empresas_df["empresa_id"] = empresas_df["empresa_id"].astype(str).str.strip()
    emp_map = dict(zip(empresas_df["empresa_id"], empresas_df["empresa_nombre"].fillna("").astype(str)))

sede_map = {}
if not sedes_df.empty and "sede_id" in sedes_df.columns:
    sedes_df["sede_id"] = sedes_df["sede_id"].astype(str).str.strip()
    sede_map = dict(zip(sedes_df["sede_id"], sedes_df["sede_nombre"].fillna("").astype(str)))

empleados_df["Empresa"] = empleados_df["empresa_id"].map(emp_map).fillna("").astype(str)
empleados_df["Sede"] = empleados_df["sede_id"].map(sede_map).fillna("").astype(str)

empleados_df.loc[empleados_df["Empresa"].str.strip().eq(""), "Empresa"] = empleados_df["empresa_id"]
empleados_df.loc[empleados_df["Sede"].str.strip().eq(""), "Sede"] = empleados_df["sede_id"]

empleados_df["Empresa_norm"] = empleados_df["Empresa"].apply(_norm_key)
empleados_df["Sede_norm"] = empleados_df["Sede"].apply(_norm_key)

empleados_df = empleados_df[
    empleados_df["Empresa_norm"].isin(ALLOWED_EMPRESAS_N) &
    empleados_df["Sede_norm"].isin(ALLOWED_SEDES_N)
].copy()

if empleados_df.empty:
    st.error("Tras aplicar filtros de empresas/sedes permitidas, no quedan empleados. Revisa que los nombres coincidan en catálogo.")
    st.stop()

hoy = date.today()
col1, col2 = st.columns(2)
with col1:
    fecha_inicio = st.date_input("Fecha inicio", value=hoy, max_value=hoy)
with col2:
    fecha_fin = st.date_input("Fecha fin", value=hoy, max_value=hoy)

# Festivos uploader
with st.expander("Festivos (CSV) — por sede", expanded=False):
    fest_file = st.file_uploader("Sube el CSV de festivos (por sede)", type=["csv"])
    st.caption("Si no subes nada, la app intenta usar un CSV local llamado: " + DEFAULT_FESTIVOS_CSV_PATH)

festivos_by_sede = {}
festivos_labels_by_sede = {}

if fest_file is not None:
    fb = fest_file.getvalue()
    festivos_by_sede = load_festivos_from_csv_bytes(fb)
    festivos_labels_by_sede = load_festivos_labels_from_csv_bytes(fb)
else:
    try:
        import os
        if os.path.exists(DEFAULT_FESTIVOS_CSV_PATH):
            with open(DEFAULT_FESTIVOS_CSV_PATH, "rb") as f:
                fb = f.read()
                festivos_by_sede = load_festivos_from_csv_bytes(fb)
                festivos_labels_by_sede = load_festivos_labels_from_csv_bytes(fb)
    except Exception:
        festivos_by_sede = {}
        festivos_labels_by_sede = {}


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


def _sig(fi: str, ff: str, empresas_sel: list, sedes_sel: list) -> str:
    return f"{fi}|{ff}|E:{','.join(sorted(map(str, empresas_sel)))}|S:{','.join(sorted(map(str, sedes_sel)))}"


for k, v in [
    ("last_sig", ""),
    ("result_incidencias", {}),
    ("result_bajas", {}),
    ("result_sin_fichajes", {}),
    ("result_excesos_semana", {}),
    ("result_csv_incidencias", b""),
    ("result_csv_bajas", b""),
    ("result_csv_sin", b""),
    ("result_csv_excesos", b""),
]:
    if k not in st.session_state:
        st.session_state[k] = v

consultar = st.button("Consultar")

if consultar:
    if fecha_inicio > fecha_fin:
        st.error("❌ La fecha inicio no puede ser posterior a la fecha fin.")
        st.stop()
    if fecha_fin > hoy:
        st.error("❌ La fecha fin no puede ser mayor que hoy.")
        st.stop()
    if empleados_filtrados.empty:
        st.warning("No hay empleados con los filtros seleccionados.")
        st.stop()

    fi = fecha_inicio.strftime("%Y-%m-%d")
    ff = fecha_fin.strftime("%Y-%m-%d")
    signature = _sig(fi, ff, sel_empresas, sel_sedes)

    with st.spinner("Procesando…"):
        tipos_map = api_exportar_tipos_fichaje()

        # --------- FICHAJES ----------
        fichajes_rows = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as exe:
            futures = {exe.submit(api_exportar_fichajes, r["nif"], fi, ff): r for _, r in empleados_filtrados.iterrows()}
            for fut in as_completed(futures):
                emp = futures[fut]
                for x in (fut.result() or []):
                    fichajes_rows.append(
                        {
                            "nif": emp["nif"],
                            "Nombre": emp["nombre_completo"],
                            "Departamento": emp.get("departamento_nombre"),
                            "Empresa": emp.get("Empresa"),
                            "Sede": emp.get("Sede"),
                            "id": x.get("id"),
                            "tipo": x.get("tipo"),
                            "direccion": x.get("direccion"),
                            "fecha": x.get("fecha"),
                        }
                    )

        if not fichajes_rows:
            df_fich = pd.DataFrame(columns=["nif", "Nombre", "Departamento", "Empresa", "Sede", "id", "tipo", "direccion", "fecha", "fecha_dt", "fecha_dia"])
        else:
            df_fich = pd.DataFrame(fichajes_rows)
            df_fich["nif"] = df_fich["nif"].astype(str).str.upper().str.strip()
            df_fich["fecha_dt"] = pd.to_datetime(df_fich["fecha"], errors="coerce")
            df_fich = df_fich.dropna(subset=["fecha_dt"])

            def _dia_row(r):
                props = tipos_map.get(int(r["tipo"]), {}) if pd.notna(r.get("tipo")) else {}
                return ajustar_fecha_dia(r["fecha_dt"], int(props.get("turno_nocturno", 0)))

            df_fich["fecha_dia"] = df_fich.apply(_dia_row, axis=1)

        # --------- INCIDENCIAS ----------
        if df_fich.empty:
            salida_incidencias = pd.DataFrame(columns=[
                "Fecha", "Empresa", "Sede", "Nombre", "Departamento",
                "Primera entrada", "Última salida", "Total trabajado",
                "Tiempo Contabilizado", "Diferencia", "Numero de fichajes", "Incidencia"
            ])
            resumen = pd.DataFrame()
        else:
            df_fich["Numero"] = df_fich.groupby(["nif", "fecha_dia"])["id"].transform("count")
            conteo = (
                df_fich.groupby(["nif", "Nombre", "Departamento", "Empresa", "Sede", "fecha_dia"], as_index=False)
                .agg(Numero=("Numero", "max"))
                .rename(columns={"fecha_dia": "Fecha", "Numero": "Numero de fichajes"})
            )

            neto = calcular_tiempos_neto(df_fich, tipos_map)
            resumen = conteo.merge(neto, on=["nif", "Fecha"], how="left")
            resumen["segundos_neto"] = resumen["segundos_neto"].fillna(0)

            resumen["Total trabajado"] = resumen["segundos_neto"].apply(segundos_a_hhmm)

            io = calcular_primera_ultima(df_fich)
            resumen = resumen.merge(io, on=["nif", "Fecha"], how="left")
            resumen["Primera entrada"] = resumen["primera_entrada_dt"].apply(ts_to_hhmm)
            resumen["Última salida"] = resumen["ultima_salida_dt"].apply(ts_to_hhmm)

            nifs = resumen["nif"].dropna().astype(str).str.upper().str.strip().unique().tolist()

            tc_rows = []
            d0 = datetime.strptime(fi, "%Y-%m-%d").date()
            d1 = datetime.strptime(ff, "%Y-%m-%d").date()

            for cur in _iter_days(d0, d1):
                desde = cur.strftime("%Y-%m-%d")
                df_tc = api_exportar_tiempo_trabajado(desde, desde, nifs=nifs)
                if df_tc.empty or df_tc["tiempoContabilizado_seg"].isna().all():
                    hasta = (cur + timedelta(days=1)).strftime("%Y-%m-%d")
                    df_tc = api_exportar_tiempo_trabajado(desde, hasta, nifs=nifs)
                if not df_tc.empty:
                    df_tc["Fecha"] = desde
                    tc_rows.append(df_tc)

            if tc_rows:
                tc = pd.concat(tc_rows, ignore_index=True)
                tc["Tiempo Contabilizado"] = tc["tiempoContabilizado_seg"].apply(segundos_a_hhmm)
                tc = tc[["nif", "Fecha", "Tiempo Contabilizado"]]
            else:
                tc = pd.DataFrame(columns=["nif", "Fecha", "Tiempo Contabilizado"])

            resumen = resumen.merge(tc, on=["nif", "Fecha"], how="left")
            resumen["Tiempo Contabilizado"] = resumen["Tiempo Contabilizado"].fillna("")

            resumen["Diferencia"] = resumen.apply(
                lambda r: diferencia_hhmm(r.get("Tiempo Contabilizado", ""), r.get("Total trabajado", "")),
                axis=1
            )

            resumen["horas_dec_marcajes"] = resumen["Total trabajado"].apply(hhmm_to_dec)
            resumen["horas_dec_contabilizado"] = resumen["Tiempo Contabilizado"].apply(hhmm_to_dec)

            resumen["horas_dec_validacion"] = resumen["horas_dec_marcajes"]
            mask_tc = resumen["Tiempo Contabilizado"].astype(str).str.strip().ne("")
            resumen.loc[mask_tc, "horas_dec_validacion"] = resumen.loc[mask_tc, "horas_dec_contabilizado"]

            resumen["dia"] = pd.to_datetime(resumen["Fecha"]).dt.weekday

            def _max_ok(r):
                sp = _lookup_special((r.get("Departamento") or "").upper().strip(), norm_name(r.get("Nombre")))
                if sp and "max_fichajes_ok" in sp:
                    return sp["max_fichajes_ok"]
                return pd.NA

            resumen["max_fichajes_ok"] = resumen.apply(_max_ok, axis=1)

            resumen[["min_horas", "min_fichajes"]] = resumen.apply(
                lambda r: pd.Series(calcular_minimos(r.get("Departamento"), int(r["dia"]), r.get("Nombre"))),
                axis=1,
            )

            def build_incidencia(r) -> str:
                motivos = []

                # ✅ Festivo: si hay trabajo, se marca como "Trabajado en festivo" y NO se aplican incidencias habituales
                day_str = str(r.get("Fecha", "") or "")
                sede_str = str(r.get("Sede", "") or "")
                fest_set = get_festivos_for_sede(sede_str, festivos_by_sede)
                if day_str and (day_str in fest_set):
                    worked = (float(r.get("horas_dec_validacion", 0.0) or 0.0) > 0.0) or (
                        int(r.get("Numero de fichajes", 0) or 0) > 0
                    )
                    if worked:
                        return "Trabajado en festivo"

                if int(r.get("dia", 0)) in [5, 6]:
                    worked = (float(r.get("horas_dec_validacion", 0.0) or 0.0) > 0.0) or (
                        int(r.get("Numero de fichajes", 0) or 0) > 0
                    )
                    if worked:
                        motivos.append("Trabajo en fin de semana")
                    return "; ".join(motivos)

                motivos += validar_incidencia_horas_fichajes(r)
                motivos += validar_horario(
                    r.get("Departamento"),
                    r.get("Nombre"),
                    int(r.get("dia", 0)),
                    r.get("Primera entrada", ""),
                    r.get("Última salida", ""),
                )
                return "; ".join(motivos)

            resumen["Incidencia"] = resumen.apply(build_incidencia, axis=1)

            salida_incidencias = resumen[resumen["Incidencia"].astype(str).str.strip().ne("")].copy()

            if not salida_incidencias.empty:
                salida_incidencias = salida_incidencias[
                    [
                        "Fecha",
                        "Empresa",
                        "Sede",
                        "Nombre",
                        "Departamento",
                        "Primera entrada",
                        "Última salida",
                        "Total trabajado",
                        "Tiempo Contabilizado",
                        "Diferencia",
                        "Numero de fichajes",
                        "Incidencia",
                    ]
                ].sort_values(["Fecha", "Nombre"], kind="mergesort")
            else:
                salida_incidencias = pd.DataFrame(columns=[
                    "Fecha", "Empresa", "Sede", "Nombre", "Departamento", "Primera entrada", "Última salida",
                    "Total trabajado", "Tiempo Contabilizado", "Diferencia", "Numero de fichajes", "Incidencia"
                ])

        # --------- BAJAS (día a día) ----------
        bajas_por_dia = {}
        d0 = datetime.strptime(fi, "%Y-%m-%d").date()
        d1 = datetime.strptime(ff, "%Y-%m-%d").date()

        base_emp = empleados_filtrados.copy()
        base_emp["nif"] = base_emp["nif"].astype(str).str.upper().str.strip()
        base_emp["num_empleado"] = base_emp.get("num_empleado", pd.Series([""] * len(base_emp))).astype(str).str.strip()

        for cur in _iter_days(d0, d1):
            day = cur.strftime("%Y-%m-%d")
            rep = api_informe_empleados(day, day)
            rows = _extract_rows_from_informe(rep)
            if not rows:
                continue

            df_rep = pd.DataFrame(rows)
            if df_rep.empty:
                continue

            df_rep["horas_baja"] = df_rep.apply(lambda r: _get_horas_baja_from_row(r.to_dict()), axis=1)
            df_rep = df_rep[df_rep["horas_baja"] > 0.0].copy()
            if df_rep.empty:
                continue

            key_nif = _pick_key(df_rep, ["nif", "NIF", "dni", "DNI"])
            key_num = _pick_key(df_rep, ["num_empleado", "numEmpleado", "employee_number", "employeeNumber", "id_empleado", "idEmpleado"])

            merged = None
            if key_nif is not None:
                df_rep["nif_join"] = df_rep[key_nif].astype(str).str.upper().str.strip()
                merged = df_rep.merge(base_emp, left_on="nif_join", right_on="nif", how="inner")
            elif key_num is not None:
                df_rep["num_join"] = df_rep[key_num].astype(str).str.strip()
                merged = df_rep.merge(base_emp, left_on="num_join", right_on="num_empleado", how="inner")

            if merged is None or merged.empty:
                continue

            out = pd.DataFrame({
                "Fecha": day,
                "Empresa": merged["Empresa"].fillna("").astype(str),
                "Sede": merged["Sede"].fillna("").astype(str),
                "Nombre": merged["nombre_completo"].fillna("").astype(str),
                "Departamento": merged.get("departamento_nombre", "").fillna("").astype(str),
                "Horas baja": merged["horas_baja"].round(2),
            })

            out = out[out["Nombre"].astype(str).str.strip().ne("")]
            if not out.empty:
                bajas_por_dia[day] = out.sort_values(["Nombre"], kind="mergesort").reset_index(drop=True)

        # --------- SIN FICHAJES ----------
        sin_por_dia = {}

        base_emp_sin = base_emp.copy()
        mask_activo = empleado_activo_o_contrato(base_emp_sin)
        base_emp_sin = base_emp_sin[mask_activo].copy()

        # ✅ Excluir por NOMBRE (no por NIF)
        base_emp_sin["nombre_excl_norm"] = base_emp_sin["nombre_completo"].apply(norm_name)
        base_emp_sin = base_emp_sin[~base_emp_sin["nombre_excl_norm"].isin(EXCLUDE_SIN_FICHAJES_NAMES_NORM)].copy()

        empleados_nifs = base_emp_sin["nif"].dropna().astype(str).str.upper().str.strip().unique().tolist()

        presentes = {}
        if not df_fich.empty:
            for day, sub in df_fich.groupby("fecha_dia"):
                presentes[str(day)] = set(sub["nif"].dropna().astype(str).str.upper().str.strip().tolist())

        for cur in _iter_days(d0, d1):
            day = cur.strftime("%Y-%m-%d")
            present_set = presentes.get(day, set())
            missing = [n for n in empleados_nifs if n not in present_set]
            if not missing:
                continue

            miss_df = base_emp_sin[base_emp_sin["nif"].isin(missing)].copy()
            if miss_df.empty:
                continue

            out = miss_df[["Empresa", "Sede", "nombre_completo", "departamento_nombre"]].copy()
            out = out.rename(columns={"nombre_completo": "Nombre", "departamento_nombre": "Departamento"})
            out.insert(0, "Fecha", day)
            out = out.sort_values(["Nombre"], kind="mergesort").reset_index(drop=True)
            sin_por_dia[day] = out

        # --------- EXCESO SEMANAL (MOI + ESTRUCTURA + MOD) — usando Tiempo Contabilizado ----------
        # ✅ Reglas:
        #   - Se calcula por semanas completas dentro del rango:
        #       * si el rango cubre L-V => semana L-V
        #       * si además cubre S-D => semana L-D (y esas horas también suman)
        #   - Festivos (por sede): si alguien trabaja en festivo, ESAS horas cuentan como exceso.
        #   - MOI/ESTRUCTURA:
        #       * Jornada semanal esperada = suma de min_horas diarios (L-V) excluyendo festivos.
        #       * Exceso = (mins en festivo + mins en finde si aplica) + max(mins L-V no festivo - jornada, 0)
        #   - MOD:
        #       * Jornada base 8h/día (L-V), excluyendo festivos.
        #       * Exceso por turno (8h):
        #           - NO cuenta el adelanto antes del inicio del turno (p.ej. 05:30 no suma hasta 06:00).
        #           - El exceso se mide por día: max((TC - adelanto) - 480, 0).
        excesos_por_semana = {}
        csv_excesos = b""

        full_weeks = list_full_workweeks_in_range(d0, d1)

        if (not resumen.empty) and full_weeks:
            sub = resumen.copy()
            sub["Departamento_norm"] = sub["Departamento"].astype(str).str.upper().str.strip()
            sub = sub[sub["Departamento_norm"].isin(["MOI", "ESTRUCTURA", "MOD"])].copy()

            if not sub.empty:
                sub["Fecha_dt"] = pd.to_datetime(sub["Fecha"], errors="coerce").dt.date
                sub = sub.dropna(subset=["Fecha_dt"]).copy()

                sub["mins_tc"] = sub["Tiempo Contabilizado"].apply(hhmm_to_min).astype(int)

                all_rows = []

                for wk_start, wk_end_incl, include_weekend in full_weeks:
                    wk_fri = wk_start + timedelta(days=4)
                    wk_sat = wk_start + timedelta(days=5)
                    wk_sun = wk_start + timedelta(days=6)

                    label = f"{wk_start:%Y-%m-%d} → {wk_end_incl:%Y-%m-%d} (" + ("L-D" if include_weekend else "L-V") + ")"

                    mask_week = (sub["Fecha_dt"] >= wk_start) & (sub["Fecha_dt"] <= wk_end_incl)
                    w = sub[mask_week].copy()

                    rows = []
                    for (nif, nombre, depto, empresa, sede), wemp in w.groupby(["nif", "Nombre", "Departamento", "Empresa", "Sede"]):
                        depto_s = str(depto or "").strip()
                        nombre_s = str(nombre or "").strip()
                        sede_s = str(sede or "").strip()

                        # festivos sede (robusto)
                        fest_set_str = get_festivos_for_sede(sede_s, festivos_by_sede)
                        fest_set_date = set()
                        for ds in fest_set_str:
                            try:
                                fest_set_date.add(datetime.strptime(ds, "%Y-%m-%d").date())
                            except Exception:
                                pass

                        weekend_set = {wk_sat, wk_sun} if include_weekend else set()

                        # minutos trabajados en festivo / fin de semana
                        mins_fest = int(wemp[wemp["Fecha_dt"].isin(fest_set_date)]["mins_tc"].sum()) if fest_set_date else 0
                        mins_weekend = int(wemp[wemp["Fecha_dt"].isin(weekend_set)]["mins_tc"].sum()) if weekend_set else 0

                        # Mon-Fri no festivo (base para comparar)
                        mask_monfri = (wemp["Fecha_dt"] >= wk_start) & (wemp["Fecha_dt"] <= wk_fri)
                        if fest_set_date:
                            mask_monfri = mask_monfri & (~wemp["Fecha_dt"].isin(fest_set_date))

                        mins_nonfest_monfri = int(wemp[mask_monfri]["mins_tc"].sum())

                        exp_min = expected_week_minutes_for_employee(depto_s, nombre_s, sede_s, wk_start, wk_fri, festivos_by_sede)

                        # Exceso Mon-Fri no festivo
                        if str(depto_s or "").upper().strip() == "MOD":
                            # Por día: no cuenta adelanto antes del inicio de turno
                            daily_excess = 0
                            w_mod = wemp[mask_monfri].copy()
                            for _, rr in w_mod.iterrows():
                                mins_tc_day = int(rr.get("mins_tc", 0) or 0)
                                e_hhmm = str(rr.get("Primera entrada", "") or "")
                                e_min = hhmm_to_min_clock(e_hhmm)

                                # Heurística de turno según hora de entrada
                                if e_min is None:
                                    shift_start = 6 * 60
                                elif e_min < 12 * 60:
                                    shift_start = 6 * 60
                                elif e_min < 21 * 60:
                                    shift_start = 14 * 60
                                else:
                                    shift_start = 22 * 60

                                early = max(0, shift_start - (e_min or shift_start))
                                eff = max(0, mins_tc_day - early)
                                daily_excess += max(eff - 480, 0)

                            extra_nonfest = daily_excess
                        else:
                            extra_nonfest = max(mins_nonfest_monfri - exp_min, 0)

                        # Exceso total
                        exceso_total = mins_fest + mins_weekend + extra_nonfest
                        exceso_min = floor_to_30(exceso_total) if exceso_total >= 30 else 0
                        if exceso_min <= 0:
                            continue

                        # Trabajado semanal mostrado (TC total en el tramo)
                        trabajado_total = int(wemp["mins_tc"].sum())

                        row = {
                            "Empresa": str(empresa or ""),
                            "Sede": sede_s,
                            "Nombre": nombre_s,
                            "Departamento": depto_s,
                            "Trabajado semanal": segundos_a_hhmm(trabajado_total * 60),
                            "Jornada semanal": segundos_a_hhmm(exp_min * 60),
                            "Exceso": mins_to_hhmm_signed(exceso_min),
                        }
                        rows.append(row)
                        all_rows.append({"Semana": label, **row})

                    if rows:
                        dfw = pd.DataFrame(rows).sort_values(["Empresa", "Sede", "Departamento", "Nombre"], kind="mergesort").reset_index(drop=True)
                    else:
                        dfw = pd.DataFrame(columns=["Empresa", "Sede", "Nombre", "Departamento", "Trabajado semanal", "Jornada semanal", "Exceso"])
                    excesos_por_semana[label] = dfw

                if all_rows:
                    df_all = pd.DataFrame(all_rows).sort_values(["Semana", "Empresa", "Sede", "Departamento", "Nombre"], kind="mergesort").reset_index(drop=True)
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
fi_sig = fecha_inicio.strftime("%Y-%m-%d")
ff_sig = fecha_fin.strftime("%Y-%m-%d")
current_sig = _sig(fi_sig, ff_sig, sel_empresas, sel_sedes)

if st.session_state["last_sig"] != current_sig:
    st.info("Ajusta filtros/fechas y pulsa **Consultar** para ver resultados.")
    st.stop()

weeks_ui = list_full_workweeks_in_range(fecha_inicio, fecha_fin)
show_week_tab = bool(weeks_ui)

if show_week_tab:
    tab1, tab2, tab3, tab4 = st.tabs(["📌 Fichajes", "🏥 Bajas", "⛔ Sin fichajes", "🕒 Exceso de jornada"])
else:
    tab1, tab2, tab3 = st.tabs(["📌 Fichajes", "🏥 Bajas", "⛔ Sin fichajes"])

with tab1:
    incid = st.session_state.get("result_incidencias", {}) or {}
    if not incid:
        st.success("🎉 No hay incidencias en el rango seleccionado.")
    else:
        for day in sorted(incid.keys()):
            # Etiqueta de festivo (si aplica a alguna fila del día)
            fest_names = set()
            try:
                df_day = incid[day]
                if isinstance(df_day, pd.DataFrame) and (not df_day.empty):
                    for _, rr in df_day.iterrows():
                        sede_rr = str(rr.get("Sede", "") or "")
                        if str(day) in get_festivos_for_sede(sede_rr, festivos_by_sede):
                            nm = get_festivo_label_for_sede_date(sede_rr, str(day), festivos_labels_by_sede)
                            fest_names.add(nm or "Festivo")
            except Exception:
                fest_names = set()

            if len(fest_names) == 1:
                fest_label = next(iter(fest_names))
                st.markdown(f"### 📅 {day} ({fest_label})")
            elif len(fest_names) > 1:
                st.markdown(f"### 📅 {day} (Festivo)")
            else:
                st.markdown(f"### 📅 {day}")
            st.data_editor(incid[day], use_container_width=True, hide_index=True, disabled=True, num_rows="fixed")
        csv_i = st.session_state.get("result_csv_incidencias", b"") or b""
        if csv_i:
            st.download_button("⬇ Descargar CSV incidencias", csv_i, "fichajes_incidencias.csv", "text/csv")

with tab2:
    bajas = st.session_state.get("result_bajas", {}) or {}
    if not bajas:
        st.info("No hay empleados de baja en el rango seleccionado.")
    else:
        for day in sorted(bajas.keys()):
            st.markdown(f"### 🏥 Empleados de baja — {day}")
            st.data_editor(bajas[day], use_container_width=True, hide_index=True, disabled=True, num_rows="fixed")
        csv_b = st.session_state.get("result_csv_bajas", b"") or b""
        if csv_b:
            st.download_button("⬇ Descargar CSV bajas", csv_b, "empleados_baja.csv", "text/csv")

with tab3:
    sinf = st.session_state.get("result_sin_fichajes", {}) or {}
    if not sinf:
        st.info("No hay empleados sin fichajes (activos/contrato) en el rango seleccionado.")
    else:
        for day in sorted(sinf.keys()):
            st.markdown(f"### ⛔ Empleados sin fichajes (activos/contrato) — {day}")
            st.data_editor(sinf[day], use_container_width=True, hide_index=True, disabled=True, num_rows="fixed")
        csv_s = st.session_state.get("result_csv_sin", b"") or b""
        if csv_s:
            st.download_button("⬇ Descargar CSV sin fichajes", csv_s, "empleados_sin_fichajes.csv", "text/csv")

if show_week_tab:
    with tab4:
        excesos = st.session_state.get("result_excesos_semana", {}) or {}

        for wk_start, wk_end_incl, include_weekend in weeks_ui:
            label = f"{wk_start:%Y-%m-%d} → {wk_end_incl:%Y-%m-%d} (" + ("L-D" if include_weekend else "L-V") + ")"
            st.markdown(f"### 🗓 {label}")
            dfw = excesos.get(label)
            if dfw is None or dfw.empty:
                st.info("No hay excesos (MOI/ESTRUCTURA/MOD) en esta semana completa (o no hay datos).")
            else:
                st.data_editor(dfw, use_container_width=True, hide_index=True, disabled=True, num_rows="fixed")

        csv_w = st.session_state.get("result_csv_excesos", b"") or b""
        if csv_w:
            st.download_button("⬇ Descargar CSV excesos (todas las semanas)", csv_w, "excesos_jornada_semanal.csv", "text/csv")
