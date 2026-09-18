import base64
import hashlib
import hmac
import json
import unicodedata
import multiprocessing
import threading
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

# ---- Hardened cache: no NIF en claro en claves/valores persistidos ----
def _cache_hmac(value: str, context: str) -> str:
    try:
        key = base64.b64decode(APP_KEY_B64)
    except Exception:
        key = str(APP_KEY_B64).encode("utf-8")
    msg = f"{context}|{value or ''}".encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()[:24]


def _hash_nif(nif: str) -> str:
    return _cache_hmac((nif or "").upper().strip(), "NIF")


def _hash_emp_code(code: str) -> str:
    return _cache_hmac(_canonical_emp_code(code), "EMP") if str(code or "").strip() else ""


def _fingerprint_nifs(nifs: tuple[str, ...]) -> str:
    joined = "|".join(sorted(nifs))
    return _cache_hmac(joined, "NIFSET")

CPU = multiprocessing.cpu_count()
MAX_WORKERS = max(8, min(24, CPU * 3))
HTTP_TIMEOUT = (5, 25)  # (connect, read)

def _max_workers_days(n_days: int) -> int:
    # Endpoint diarios de CRECE: concurrencia deliberadamente conservadora.
    n = max(1, int(n_days or 0))
    if n <= 4:
        return n
    if n <= 31:
        return 4
    return 3

def _max_workers_emps(n_emps: int) -> int:
    # Límite conservador para llamadas por empleado
    n = int(n_emps or 0)
    base = min(12, max(4, (CPU * 2)))
    if n >= 200:
        return min(8, base)
    if n >= 80:
        return min(10, base)
    return base


TOLERANCIA_MINUTOS = 5
MARGEN_HORARIO_MIN = 5

USER_AGENT = "RRHH-Fichajes-Crece/1.0 (Streamlit)"

RETRY_STATUS = {429, 500, 502, 503, 504}
MAX_RETRIES = 4
BACKOFF_BASE_SECONDS = 0.6
BACKOFF_MAX_SECONDS = 6.0

_SESSION_LOCAL = threading.local()

def _get_http_session() -> requests.Session:
    """Una Session por hilo: pooling sin compartir estado entre workers."""
    sess = getattr(_SESSION_LOCAL, "session", None)
    if sess is None:
        sess = requests.Session()
        sess.headers.update(
            {
                "Accept": "application/json",
                "Authorization": f"Bearer {API_TOKEN}",
                "User-Agent": USER_AGENT,
            }
        )
        _SESSION_LOCAL.session = sess
    return sess


# ============================================================
# SIN FICHAJES: sin exclusiones nominales hardcodeadas
# ============================================================

def _safe_fail(_exc: Exception) -> None:
    return None


def safe_request(method: str, url: str, *, data=None, params=None, json_body=None, timeout=HTTP_TIMEOUT):
    method = (method or "").upper().strip()
    if method not in {"GET", "POST"}:
        return None

    last_exc = None
    for attempt in range(MAX_RETRIES + 1):
        try:
            resp = _get_http_session().request(
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

def _text(value) -> str:
    """Convierte valores API/DataFrame a texto de forma segura.

    Evita que None/NaN rompan comparaciones y, sobre todo, centraliza la
    normalización usada por los mapas de Horas programadas/Bajas.
    """
    if value is None:
        return ""
    try:
        if pd.isna(value):
            return ""
    except Exception:
        pass
    return str(value).strip()

def norm_name(s: str) -> str:
    """Normaliza nombres ignorando tildes, mayúsculas y espacios."""
    raw = unicodedata.normalize("NFKD", str(s or "").strip())
    raw = "".join(ch for ch in raw if not unicodedata.combining(ch))
    return " ".join(raw.upper().split())


def name_startswith(nombre_norm: str, prefix_norm: str) -> bool:
    return bool(nombre_norm) and bool(prefix_norm) and nombre_norm.startswith(prefix_norm)


def _norm_key(s: str) -> str:
    raw = unicodedata.normalize("NFKD", str(s or "").strip())
    raw = "".join(ch for ch in raw if not unicodedata.combining(ch))
    return " ".join(raw.upper().split())


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
# ============================================================

def _iter_days(d0: date, d1: date):
    """Itera fechas (inclusive) sin cache (evita objetos no serializables)."""
    cur = d0
    while cur <= d1:
        yield cur
        cur += timedelta(days=1)



def list_full_workweeks_in_range(fi: date, ff: date):
    """
    Semanas completas contenidas dentro del rango.

    Reglas:
    - Para incluir una semana, el rango debe cubrir como mínimo L-V.
    - Si además cubre sábado -> se devuelve como L-S.
    - Si además cubre sábado+domingo -> se devuelve como L-D.

    Devuelve lista de tuplas: (week_start_monday, week_end_inclusive, weekend_mode)
      weekend_mode: "LV" | "LS" | "LD"
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

        # Semana base L-V completa
        if (fi <= mon) and (ff >= fri):
            include_sat = (fi <= sat) and (ff >= sat)
            include_sun = (fi <= sun) and (ff >= sun)

            if include_sun and include_sat:
                end_incl = sun
                mode = "LD"
            elif include_sat:
                end_incl = sat
                mode = "LS"
            else:
                end_incl = fri
                mode = "LV"

            weeks.append((mon, end_incl, mode))

        cur += timedelta(days=7)

    return weeks



def floor_to_30(mins: int) -> int:
    if mins <= 0:
        return 0
    return (mins // 30) * 30


def ceil_to_30(mins: int) -> int:
    if mins <= 0:
        return 0
    return ((mins + 29) // 30) * 30


def quantize_daily_balance_30(diff_mins: int, tol: int = 5) -> int:
    """Cuantiza un balance diario en tramos de 30 min con tolerancia.
    - |diff| <= tol => 0
    - diff > tol: no suma nada si diff < 30; si diff >= 30 => floor a múltiplos de 30
    - diff < -tol: resta hacia 'más falta' => -ceil(|diff|/30)*30
    """
    d = int(diff_mins)
    if abs(d) <= int(tol):
        return 0
    if d > 0:
        return floor_to_30(d) if d >= 30 else 0
    return -ceil_to_30(abs(d))



def effective_worked_minutes_for_mod(mins_tc: int, primera_min: int | None) -> int:
    """Para MOD: en día laborable (horas_programadas>0), NO cuenta el tiempo antes del inicio de turno.
    Heurística:
      - Primera entrada < 12:00  -> turno mañana empieza 06:00
      - Primera entrada >= 12:00 -> turno tarde empieza 14:00
    Si primera_entrada < inicio_turno: restamos (inicio_turno - primera_entrada) del total contabilizado.
    """
    try:
        total = int(mins_tc or 0)
    except Exception:
        total = 0
    if total <= 0:
        return 0
    if primera_min is None:
        return total
    try:
        pe = int(primera_min)
    except Exception:
        return total

    shift_start = 6 * 60 if pe < (12 * 60) else 14 * 60
    if pe >= shift_start:
        return total
    exclude = shift_start - pe
    return max(0, total - exclude)


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
            # Compatibilidad con proxies/versiones que ya materializan el JSON.
            if isinstance(c, list):
                return c
            if isinstance(c, dict) and not ("iv" in c and "value" in c):
                return c

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



def _df_view(df):
    """Return a dataframe ready for UI display (hide internal helper columns)."""
    try:
        cols_hide = {"nif","empresa_norm","sede_norm","Empresa_norm","Sede_norm","EMPRESA_NORM","SEDE_NORM"}
        return df.drop(columns=[c for c in cols_hide if c in df.columns], errors="ignore")
    except Exception:
        return df

def _make_editor_key(prefix: str, *parts) -> str:
    raw = prefix + "|" + "|".join(str(p) for p in parts)
    return prefix + "_" + hashlib.md5(raw.encode("utf-8")).hexdigest()[:10]


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
    ("MOD", N_DAVID, {"min_fichajes": 2}),
    ("MOI", N_DEBORA, {"min_fichajes": 2}),
    ("MOI", N_ETOR, {"min_fichajes": 2}),
    ("MOI", N_MIRIAM, {"min_fichajes": 2}),
    ("ESTRUCTURA", N_BEATRIZ, {"min_fichajes": 2, "max_fichajes_ok": 4}),
]

SCHEDULE_EXEMPT_PREFIX = [
    ("MOD", N_DAVID),
    ("MOI", N_MIRIAM),
]

FLEX_BY_DEPTO = {
    "ESTRUCTURA": [N_FRAN],
    "MOI": [N_DEBORA, N_ETOR],
}

BTF_EMPRESA_N = _norm_key("Barranquesa Tower Flanges, S.L.")


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


def _is_flex(depto_norm: str, nombre_norm: str, sede: str = "") -> bool:
    # Regla RRHH: todos los empleados MOI de P1 LAKUNTZA tienen entrada/salida flexible.
    if depto_norm == "MOI" and _sede_code(sede) == "P1":
        return True

    for pref in FLEX_BY_DEPTO.get(depto_norm, []):
        if name_startswith(nombre_norm, pref):
            return True
    return False


def validar_horario(
    depto: str,
    nombre: str,
    dia: int,
    primera_entrada_hhmm: str,
    ultima_salida_hhmm: str,
    expected_minutes=None,
    sede: str = "",
    empresa: str = "",
) -> list[str]:
    depto_norm = (depto or "").upper().strip()
    nombre_norm = norm_name(nombre)

    if dia not in [0, 1, 2, 3, 4]:
        return []

    if _is_schedule_exempt(depto_norm, nombre_norm):
        return []

    # Tower Flanges: no validar entrada/salida, pero sí horas y nº de fichajes.
    if _norm_key(empresa) == BTF_EMPRESA_N:
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
        flex = _is_flex(depto_norm, nombre_norm, sede)

        if not flex:
            ini, fin = 7 * 60, 9 * 60

            try:
                exp_m = int(expected_minutes) if expected_minutes is not None else None
            except Exception:
                exp_m = None

            # La jornada reducida/completa la determina CRECE mediante Horas programadas.
            salida_min = None
            if exp_m is not None and exp_m > 0:
                salida_min = (13 * 60 + 30) if exp_m <= (6 * 60 + 35) else (16 * 60 + 30)

            if e_min < (ini - MARGEN_HORARIO_MIN):
                incid.append(f"Entrada temprana ({primera_entrada_hhmm})")
            elif e_min > fin:
                incid.append(f"Entrada tarde ({primera_entrada_hhmm})")

            if salida_min is not None and s_min is not None and s_min < (salida_min - MARGEN_HORARIO_MIN):
                incid.append(f"Salida temprana ({ultima_salida_hhmm})")
        return incid

    return incid


# ============================================================
# API EXPORTACIÓN / INFORMES
# ============================================================

@st.cache_data(show_spinner=False, ttl=3600)
def api_exportar_departamentos() -> pd.DataFrame:
    url = f"{API_URL_BASE}/exportacion/departamentos"
    resp = safe_request("GET", url)
    if resp is None:
        return pd.DataFrame(columns=["departamento_id", "departamento_nombre"])
    try:
        resp.raise_for_status()
    except Exception:
        _safe_fail(Exception(f"HTTP {getattr(resp,'status_code', 'ERR')} exportacion/departamentos"))
        return pd.DataFrame(columns=["departamento_id", "departamento_nombre"])
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


@st.cache_data(show_spinner=False, ttl=300)
def api_exportar_empleados_completos() -> pd.DataFrame:
    url = f"{API_URL_BASE}/exportacion/empleados"
    data = {"solo_nif": 0}

    resp = safe_request("POST", url, data=data)
    if resp is None:
        return pd.DataFrame(columns=["nif", "nombre_completo", "departamento_id", "empresa_id", "sede_id", "num_empleado"])
    try:
        resp.raise_for_status()
    except Exception:
        _safe_fail(Exception(f"HTTP {getattr(resp,'status_code', 'ERR')} exportacion/empleados"))
        return pd.DataFrame(columns=["nif", "nombre_completo", "departamento_id", "empresa_id", "sede_id", "num_empleado"])

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
        # Nº empleado y ID interno de CRECE NO son lo mismo. /informes/empleados
        # enlaza por "Nº empleado", por lo que nunca usamos e["id"] como sustituto.
        num_empleado = (
            e.get("num_empleado")
            or e.get("Num_empleado")
            or e.get("numEmpleado")
            or e.get("numero_empleado")
            or e.get("Numero_empleado")
            or e.get("numeroEmpleado")
            or e.get("employee_number")
            or e.get("employeeNumber")
            or e.get("id_empleado")
            or e.get("idEmpleado")
        )

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
        df["nif"] = df["nif"].fillna("").astype(str).str.upper().str.strip()
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




@st.cache_data(show_spinner=False, ttl=300)
def _cached_tiempo_contabilizado_map(d0_iso: str, d1_iso: str, nifs_fingerprint: str, _nifs: tuple[str, ...]) -> dict:
    """Cache seguro (TTL corto): devuelve {(NIF, YYYY-MM-DD): minutos_contabilizados}.
    Solo cachea minutos (int), no payloads ni datos sensibles extra.
    """
    try:
        d0 = datetime.strptime(d0_iso, "%Y-%m-%d").date()
        d1 = datetime.strptime(d1_iso, "%Y-%m-%d").date()
    except Exception:
        return {}

    nifs = [str(x).upper().strip() for x in (_nifs or ()) if str(x).strip()]
    if not nifs:
        return {}

    days = [d.strftime("%Y-%m-%d") for d in _iter_days(d0, d1)]
    if not days:
        return {}

    max_workers = _max_workers_days(len(days))
    out: dict[tuple[str, str], int] = {}  # {(hash_nif, YYYY-MM-DD): minutes_programadas}  # {(hash_nif, YYYY-MM-DD): minutes}

    def _fetch_day(day: str):
        df_tc = api_exportar_tiempo_trabajado(day, day, nifs=nifs)
        return day, df_tc

    with ThreadPoolExecutor(max_workers=max_workers) as exe:
        futs = [exe.submit(_fetch_day, day) for day in days]
        for fut in as_completed(futs):
            day, df_tc = fut.result()
            if df_tc is None or df_tc.empty:
                continue
            for _, rr in df_tc.iterrows():
                nif_tc = str(rr.get("nif") or "").upper().strip()
                if not nif_tc:
                    continue
                seg = rr.get("tiempoContabilizado_seg")
                try:
                    mins = int(round(float(seg or 0) / 60.0))
                except Exception:
                    mins = 0
                out[(_hash_nif(nif_tc), day)] = max(0, mins)

    return out


def build_tiempo_contabilizado_map(d0: date, d1: date, nifs: list[str]) -> dict:
    """Devuelve {(NIF, YYYY-MM-DD): minutos_contabilizados} para rango [d0,d1].

    Regla: SIEMPRE se usa tiempoContabilizado de /exportacion/tiempo-trabajado, haya fichaje o no.
    Optimización: consulta día a día en paralelo + cache TTL corto (solo ints).
    """
    nifs_norm = tuple(sorted({str(x).upper().strip() for x in (nifs or []) if str(x).strip()}))
    if not nifs_norm:
        return {}
    fp = _fingerprint_nifs(nifs_norm)
    hashed = _cached_tiempo_contabilizado_map(d0.strftime("%Y-%m-%d"), d1.strftime("%Y-%m-%d"), fp, nifs_norm)
    if not hashed:
        return {}
    hash_to_nif = {_hash_nif(n): n for n in nifs_norm}
    out: dict[tuple[str, str], int] = {}  # {(hash_nif, YYYY-MM-DD): minutes_programadas}
    for (hn, day), mins in hashed.items():
        nif = hash_to_nif.get(hn)
        if not nif:
            continue
        out[(nif, day)] = int(mins)
    return out


def api_informe_empleados(fecha_desde: str, fecha_hasta: str):
    """Consulta /informes/empleados como informe POR PERIODO.

    El manual documenta fecha_desde/fecha_hasta como parámetros POST. Probamos
    primero form-urlencoded (forma habitual del API CRECE) y dejamos JSON como
    compatibilidad. Solo aceptamos una respuesta si contiene filas de informe;
    un HTTP 200 con wrapper/error no se considera una lectura válida.
    """
    url = f"{API_URL_BASE}/informes/empleados"
    body = {"fecha_desde": fecha_desde, "fecha_hasta": fecha_hasta}

    for mode in ("form", "json"):
        try:
            resp = safe_request(
                "POST",
                url,
                data=body if mode == "form" else None,
                json_body=body if mode == "json" else None,
                timeout=(5, 60),
            )
            if resp is None:
                continue
            resp.raise_for_status()
            parsed = _try_parse_encrypted_response(resp)
            if parsed is None:
                continue
            # Evita aceptar como éxito un objeto de error/wrapper sin empleados.
            if _extract_rows_from_informe(parsed):
                return parsed
        except Exception as e:
            _safe_fail(e)
            continue

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


def _field_key_norm(value) -> str:
    """Normaliza nombres de campos del informe CRECE.

    El API de informes documenta etiquetas legibles (p. ej. "Nº empleado",
    "Horas programadas"), mientras que algunas instalaciones/versiones pueden
    devolver snake_case/camelCase. Esta normalización permite soportar ambos
    formatos sin depender de una etiqueta exacta.
    """
    s = unicodedata.normalize("NFKD", str(value or ""))
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    s = s.lower().replace("º", "o").replace("°", "o")
    return "".join(ch for ch in s if ch.isalnum())


def _row_get_alias(row: dict, aliases: list[str]):
    """Devuelve (encontrado, valor) buscando por alias normalizados."""
    if not isinstance(row, dict):
        return False, None
    wanted = {_field_key_norm(a) for a in aliases}
    for key, value in row.items():
        if _field_key_norm(key) in wanted:
            return True, value
    return False, None


def _canonical_emp_code(value) -> str:
    """Código de empleado estable.

    Normaliza 00055, 55 y 55.0 al mismo valor para poder enlazar de forma
    fiable exportación de empleados con Nº empleado del informe.
    """
    s = _text(value)
    if not s:
        return ""
    if s.isdigit():
        return s.lstrip("0") or "0"
    try:
        num = float(s.replace(",", "."))
        if num >= 0 and num.is_integer():
            return str(int(num))
    except Exception:
        pass
    return s.upper()


def _get_employee_number_from_row(row: dict) -> str:
    found, value = _row_get_alias(
        row,
        [
            "Nº empleado", "N° empleado", "N. empleado", "N empleado",
            "Numero empleado", "Número empleado", "num_empleado", "numEmpleado",
            "employee_number", "employeeNumber", "id_empleado", "idEmpleado",
        ],
    )
    return _canonical_emp_code(value) if found else ""


def _duration_value_to_minutes(value):
    """Convierte una duración diaria del informe a minutos.

    Soporta horas decimales (8 / 8,5), HH:MM[:SS], minutos y, como último
    recurso, segundos. Devuelve None si no puede interpretarse.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return None

    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return None
        if ":" in raw:
            parts = raw.split(":")
            try:
                if len(parts) == 2:
                    h, m = int(parts[0]), int(parts[1])
                    return max(0, h * 60 + m)
                if len(parts) == 3:
                    h, m, sec = int(parts[0]), int(parts[1]), float(parts[2].replace(",", "."))
                    return max(0, int(round(h * 60 + m + sec / 60.0)))
            except Exception:
                return None
        raw = raw.replace(",", ".")
        try:
            num = float(raw)
        except Exception:
            return None
    else:
        try:
            num = float(value)
        except Exception:
            return None

    if pd.isna(num) or num < 0:
        return None
    # En consultas de un día: <=24 suele ser horas decimales; <=1440 minutos;
    # valores superiores se interpretan como segundos.
    if num <= 24:
        return int(round(num * 60))
    if num <= 24 * 60:
        return int(round(num))
    return int(round(num / 60.0))


def _report_hours_to_minutes(value):
    """Convierte campos de informe expresados en horas a minutos.

    En /informes/empleados los campos se llaman explícitamente "Horas ...".
    Los valores numéricos se interpretan siempre como horas decimales, también
    cuando un periodo agregado supera 24 horas.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return None
        if ":" in raw:
            parts = raw.split(":")
            try:
                if len(parts) == 2:
                    h, m = int(parts[0]), int(parts[1])
                    return max(0, h * 60 + m)
                if len(parts) == 3:
                    h, m = int(parts[0]), int(parts[1])
                    sec = float(parts[2].replace(",", "."))
                    return max(0, int(round(h * 60 + m + sec / 60.0)))
            except Exception:
                return None
        raw = raw.replace(",", ".")
        try:
            num = float(raw)
        except Exception:
            return None
    else:
        try:
            num = float(value)
        except Exception:
            return None

    if pd.isna(num) or num < 0:
        return None
    return int(round(num * 60.0))


_INFORME_EMP_IDX_NUM = 0
_INFORME_EMP_IDX_HORAS_PROGRAMADAS = 25
_INFORME_EMP_IDX_HORAS_BAJA = 33


def _normalize_informe_employee_row(item):
    if isinstance(item, dict):
        return item
    if isinstance(item, (list, tuple)):
        row = {}
        if len(item) > _INFORME_EMP_IDX_NUM:
            row["Nº empleado"] = item[_INFORME_EMP_IDX_NUM]
        if len(item) > _INFORME_EMP_IDX_HORAS_PROGRAMADAS:
            row["Horas programadas"] = item[_INFORME_EMP_IDX_HORAS_PROGRAMADAS]
        if len(item) > _INFORME_EMP_IDX_HORAS_BAJA:
            row["Horas de baja laboral (laborables, no naturales)"] = item[_INFORME_EMP_IDX_HORAS_BAJA]
        return row if row else None
    return None


def _extract_rows_from_informe(rep):
    if rep is None:
        return []

    raw_rows = None
    if isinstance(rep, list):
        raw_rows = rep
    elif isinstance(rep, dict):
        for k in ["data", "empleados", "results", "resultado", "items"]:
            v = rep.get(k)
            if isinstance(v, list):
                raw_rows = v
                break

        if raw_rows is None:
            if _get_employee_number_from_row(rep):
                raw_rows = [rep]
            else:
                vals = list(rep.values())
                if vals and all(isinstance(v, (dict, list, tuple)) for v in vals):
                    raw_rows = vals

    if not isinstance(raw_rows, list):
        return []

    out = []
    for item in raw_rows:
        row = _normalize_informe_employee_row(item)
        if isinstance(row, dict):
            out.append(row)
    return out


def _get_horas_baja_from_row(row: dict) -> float:
    if not isinstance(row, dict):
        return 0.0

    aliases = [
        "Horas de baja laboral (laborables, no naturales)",
        "horas_baja", "horasBaja", "horas_de_baja", "horas_baja_total",
        "total_horas_baja", "horas_baja_dia", "horas_baja_diarias",
        "horas_baja_hoy", "horas_baja_parte",
    ]
    found, value = _row_get_alias(row, aliases)
    if found:
        return _to_float_any(value)

    for k in ["baja", "bajas", "ausencia", "ausencias", "incidencia", "incidencias"]:
        v = row.get(k)
        if isinstance(v, dict):
            found, value = _row_get_alias(v, aliases + ["horas"])
            if found:
                return _to_float_any(value)
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
    wanted = {_field_key_norm(n) for n in names}
    for col in df.columns:
        if _field_key_norm(col) in wanted:
            return col
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
        dt = pd.to_datetime(s, errors="coerce")
        if pd.isna(dt):
            return None
        return dt.date()
    except Exception:
        return None




def _normalize_emp_code(x: str, pad: int = 10) -> str:
    s = str(x or '').strip()
    if not s:
        return ''
    if s.isdigit():
        return s.zfill(pad)
    return s


def _get_horas_programadas_minutes_from_row(row: dict):
    """Devuelve (campo_encontrado, minutos_programados).

    Según el manual del informe de empleados, el campo se denomina
    "Horas programadas". También se admiten variantes históricas.
    Es importante distinguir un 0 real (día no laborable) de un campo ausente.
    """
    if not isinstance(row, dict):
        return False, None

    aliases = [
        "Horas programadas",
        "horas_programadas", "horasProgramadas",
        "horas_programadas_dia", "horasProgramadasDia",
        "horas_programadas_hoy", "horasProgramadasHoy",
    ]
    found, value = _row_get_alias(row, aliases)
    if found:
        mins = _report_hours_to_minutes(value)
        return (mins is not None), mins

    for nested_key in ["contrato", "jornada", "horario", "turno"]:
        nested = row.get(nested_key)
        if isinstance(nested, dict):
            found, value = _row_get_alias(nested, aliases)
            if found:
                mins = _report_hours_to_minutes(value)
                return (mins is not None), mins

    return False, None



def _metrics_from_informe_payload(rep) -> dict:
    """Extrae solo HP y baja por Nº empleado pseudonimizado.

    La caché nunca conserva el payload completo del informe ni datos personales:
    únicamente hash de Nº empleado -> minutos programados / minutos de baja.
    """
    hp_by_emp: dict[str, int] = {}
    baja_by_emp: dict[str, int] = {}

    for row in _extract_rows_from_informe(rep):
        code = _get_employee_number_from_row(row)
        if not code:
            continue
        he = _hash_emp_code(code)
        if not he:
            continue

        found_hp, hp_mins = _get_horas_programadas_minutes_from_row(row)
        if found_hp and hp_mins is not None:
            hp_by_emp[he] = max(0, int(hp_mins))

        baja_h = _get_horas_baja_from_row(row)
        if baja_h > 0:
            baja_by_emp[he] = max(0, int(round(float(baja_h) * 60.0)))

    return {"hp": hp_by_emp, "baja": baja_by_emp}


@st.cache_data(show_spinner=False, ttl=900)
def _cached_informe_period_metrics(fecha_desde: str, fecha_hasta: str) -> dict:
    """Métricas agregadas de /informes/empleados para un periodo.

    El manual define este endpoint como un INFORME POR PERIODO. Por tanto,
    no lo tratamos como un endpoint diario. Cacheamos únicamente métricas
    pseudonimizadas (hash de Nº empleado -> minutos), nunca el payload ni PII.
    """
    rep = api_informe_empleados(fecha_desde, fecha_hasta)
    if rep is None:
        raise RuntimeError(
            f"Informe de empleados no disponible para {fecha_desde}..{fecha_hasta}"
        )
    rows = _extract_rows_from_informe(rep)
    if not rows:
        raise RuntimeError(
            f"Informe de empleados vacío/no interpretable para {fecha_desde}..{fecha_hasta}"
        )
    return _metrics_from_informe_payload(rep)


def _chunk_date_ranges(d0: date, d1: date, chunk_days: int = 31):
    """Divide un rango en bloques pequeños para evitar informes acumulados enormes."""
    cur = d0
    while cur <= d1:
        end = min(d1, cur + timedelta(days=max(1, int(chunk_days)) - 1))
        yield cur, end
        cur = end + timedelta(days=1)


def build_informe_diario_maps_resilient(
    d0: date,
    d1: date,
    base_emp: pd.DataFrame,
) -> tuple[dict, dict, list[str]]:
    """Reconstruye Horas programadas y Bajas DIARIAS desde el informe por periodo.

    Motivo:
    /api/informes/empleados devuelve métricas agregadas DEL PERIODO. Consultarlo
    con fecha_desde == fecha_hasta ha demostrado no ser fiable en esta intranet.

    Estrategia:
    - Para cada bloque de hasta 31 días usamos un ancla dos días anterior.
    - Consultamos acumulados [ancla..fin] para cada fecha de corte.
    - El valor del día D es la diferencia:
          acumulado(ancla..D) - acumulado(ancla..D-1)
    - Ambas consultas abarcan al menos 2 días, por lo que no dependemos de la
      consulta "mismo día -> mismo día".
    - La misma reconstrucción obtiene Horas programadas y Horas de baja.
    - Un 0 derivado es un cero real; un fallo de API NO se transforma en 0.

    La caché conserva únicamente hashes de Nº empleado y minutos.
    """
    if base_emp is None or base_emp.empty or d0 > d1:
        return {}, {}, []

    be = base_emp.copy()
    be["nif"] = be["nif"].fillna("").astype(str).str.upper().str.strip()
    if "num_empleado" not in be.columns:
        be["num_empleado"] = ""
    be["num_empleado_code"] = be["num_empleado"].apply(_canonical_emp_code)

    emp_hash_to_nif: dict[str, str] = {}
    for _, row in be.iterrows():
        code = _text(row.get("num_empleado_code"))
        nif = _text(row.get("nif")).upper()
        if code and nif:
            emp_hash_to_nif[_hash_emp_code(code)] = nif

    if not emp_hash_to_nif:
        # Sin Nº empleado no se puede enlazar de forma fiable con el informe.
        return {}, {}, [
            d.strftime("%Y-%m-%d") for d in _iter_days(d0, d1)
        ]

    # Preparamos todas las consultas acumuladas necesarias.
    # key=(anchor_iso,end_iso) -> métricas
    request_pairs: set[tuple[str, str]] = set()
    chunks: list[tuple[date, date, date]] = []
    for c0, c1 in _chunk_date_ranges(d0, d1, 31):
        anchor = c0 - timedelta(days=2)
        chunks.append((c0, c1, anchor))

        # Corte previo al primer día del bloque y cada día del bloque.
        first_cut = c0 - timedelta(days=1)
        cuts = [first_cut] + list(_iter_days(c0, c1))
        for cut in cuts:
            request_pairs.add(
                (anchor.strftime("%Y-%m-%d"), cut.strftime("%Y-%m-%d"))
            )

    metrics_by_pair: dict[tuple[str, str], dict] = {}
    failed_pairs: list[tuple[str, str]] = []

    def _fetch(pair: tuple[str, str]):
        a, b = pair
        return pair, _cached_informe_period_metrics(a, b)

    # Concurrencia baja: el informe es pesado.
    workers = max(1, min(3, len(request_pairs)))
    with ThreadPoolExecutor(max_workers=workers) as exe:
        futs = {exe.submit(_fetch, pair): pair for pair in request_pairs}
        for fut in as_completed(futs):
            pair = futs[fut]
            try:
                pair_r, metrics = fut.result()
                metrics_by_pair[pair_r] = metrics
            except Exception as exc:
                _safe_fail(exc)
                failed_pairs.append(pair)

    # Reintento secuencial de pares fallidos.
    unresolved_pairs: set[tuple[str, str]] = set()
    for pair in sorted(set(failed_pairs)):
        ok = False
        for attempt in range(2):
            if attempt:
                time.sleep(0.8)
            try:
                _, metrics = _fetch(pair)
                metrics_by_pair[pair] = metrics
                ok = True
                break
            except Exception as exc:
                _safe_fail(exc)
        if not ok:
            unresolved_pairs.add(pair)

    hp_out: dict[tuple[str, str], int] = {}
    baja_out: dict[tuple[str, str], int] = {}
    unresolved_days: set[str] = set()

    def _delta(curr: dict, prev: dict, section: str, he: str):
        c = int((((curr or {}).get(section, {}) or {}).get(he, 0)) or 0)
        p = int((((prev or {}).get(section, {}) or {}).get(he, 0)) or 0)
        return c - p

    for c0, c1, anchor in chunks:
        anchor_iso = anchor.strftime("%Y-%m-%d")
        prev_cut = c0 - timedelta(days=1)

        for day in _iter_days(c0, c1):
            day_iso = day.strftime("%Y-%m-%d")
            prev_iso = prev_cut.strftime("%Y-%m-%d")
            pair_prev = (anchor_iso, prev_iso)
            pair_curr = (anchor_iso, day_iso)

            if (
                pair_prev in unresolved_pairs
                or pair_curr in unresolved_pairs
                or pair_prev not in metrics_by_pair
                or pair_curr not in metrics_by_pair
            ):
                unresolved_days.add(day_iso)
                prev_cut = day
                continue

            prev_metrics = metrics_by_pair[pair_prev]
            curr_metrics = metrics_by_pair[pair_curr]

            day_bad = False
            for he, nif in emp_hash_to_nif.items():
                hp_delta = _delta(curr_metrics, prev_metrics, "hp", he)
                baja_delta = _delta(curr_metrics, prev_metrics, "baja", he)

                # Pequeños negativos pueden venir de redondeo decimal del informe.
                # Negativos materiales indican que no podemos reconstruir ese día.
                if hp_delta < -5 or baja_delta < -5:
                    day_bad = True
                    continue

                hp_out[(nif, day_iso)] = max(0, hp_delta)
                if baja_delta > 0:
                    baja_out[(nif, day_iso)] = max(0, baja_delta)

            if day_bad:
                unresolved_days.add(day_iso)

            prev_cut = day

    # Si una fecha quedó dudosa, eliminamos todas sus HP derivadas para no mezclar
    # datos fiables con parciales.
    if unresolved_days:
        hp_out = {
            k: v for k, v in hp_out.items()
            if k[1] not in unresolved_days
        }
        baja_out = {
            k: v for k, v in baja_out.items()
            if k[1] not in unresolved_days
        }

    return hp_out, baja_out, sorted(unresolved_days)




def empleado_activo_o_contrato(df_emp: pd.DataFrame) -> pd.Series:
    if df_emp.empty:
        return pd.Series([], dtype=bool)

    if "deleted_at" in df_emp.columns:
        deleted = df_emp["deleted_at"].notna() & df_emp["deleted_at"].astype(str).str.strip().ne("") & df_emp["deleted_at"].astype(str).str.lower().ne("null")
    else:
        deleted = pd.Series(False, index=df_emp.index, dtype=bool)

    flags_true = pd.Series(False, index=df_emp.index, dtype=bool)
    for col in ["activo", "en_activo", "contrato_activo"]:
        if col in df_emp.columns:
            s = df_emp[col]
            flags_true = flags_true | s.astype(str).str.strip().str.lower().isin(["1", "true", "t", "si", "sí", "yes", "y"])

    estado_ok = pd.Series(False, index=df_emp.index, dtype=bool)
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
        baja = pd.Series(False, index=df_emp.index, dtype=bool)

    fin_ok = pd.Series(False, index=df_emp.index, dtype=bool)
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


st.write("---")
f1, f2 = st.columns(2)

empresas_opts = [x for x in ALLOWED_EMPRESAS if _norm_key(x) in set(empleados_df["Empresa_norm"].unique())]
sedes_opts = [x for x in ALLOWED_SEDES if _norm_key(x) in set(empleados_df["Sede_norm"].unique())]

with f1:
    sel_empresas = st.multiselect("Empresa", options=empresas_opts, default=empresas_opts)
with f2:
    sel_sedes = st.multiselect("Sede", options=sedes_opts, default=sedes_opts)

empleados_filtrados_emp_sede = empleados_df[
    empleados_df["Empresa"].apply(_norm_key).isin({_norm_key(x) for x in sel_empresas}) &
    empleados_df["Sede"].apply(_norm_key).isin({_norm_key(x) for x in sel_sedes})
].copy()

# Opciones del selector de empleados: todos los activos del universo permitido
# (si eliges empleados concretos, su filtro manda por encima de Empresa/Sede)
empleados_activos_opts_df = empleados_df[empleado_activo_o_contrato(empleados_df)].copy()
empleados_activos_opts_df = empleados_activos_opts_df.sort_values(["nombre_completo"], kind="mergesort")
_nombre_series = empleados_activos_opts_df["nombre_completo"].fillna("").astype(str).str.strip()
_nombre_counts = _nombre_series.value_counts()
emp_opts_map = {}
for _, _erow in empleados_activos_opts_df.iterrows():
    _nombre = str(_erow.get("nombre_completo") or "").strip()
    _nif = str(_erow.get("nif") or "").upper().strip()
    if not _nombre or not _nif:
        continue
    _label = _nombre
    if int(_nombre_counts.get(_nombre, 0)) > 1:
        _num = str(_erow.get("num_empleado") or "").strip()
        _suffix = _num if _num else _nif[-4:]
        _label = f"{_nombre} ({_suffix})"
    emp_opts_map[_label] = _nif
emp_opts_names = list(emp_opts_map.keys())
sel_empleados = st.multiselect(
    "Empleados activos",
    options=emp_opts_names,
    default=[],
    help="Si no seleccionas ninguno, se filtra por Empresa/Sede. Si seleccionas empleados, ese filtro tiene prioridad.",
)
sel_empleados_nifs = {
    emp_opts_map[n]
    for n in sel_empleados
    if n in emp_opts_map and str(emp_opts_map[n]).strip()
}

if sel_empleados_nifs:
    empleados_filtrados = empleados_df[
        empleados_df["nif"].astype(str).str.upper().str.strip().isin(sel_empleados_nifs)
    ].copy()
else:
    empleados_filtrados = empleados_filtrados_emp_sede.copy()

st.write("---")


def _sig(fi: str, ff: str, empresas_sel: list, sedes_sel: list, empleados_sel_nifs: set[str] | None = None) -> str:
    empleados_sel_nifs = empleados_sel_nifs or set()
    emp_part = ','.join(sorted(map(str, empleados_sel_nifs)))
    if empleados_sel_nifs:
        empresas_part = '*'
        sedes_part = '*'
    else:
        empresas_part = ','.join(sorted(map(str, empresas_sel)))
        sedes_part = ','.join(sorted(map(str, sedes_sel)))
    return f"{fi}|{ff}|E:{empresas_part}|S:{sedes_part}|EMP:{emp_part}"


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
    ("scope_fi", ""),
    ("scope_ff", ""),
    ("scope_empresas_norm", set()),
    ("scope_sedes_norm", set()),
    ("scope_empleados_nif", set()),
    ("scope_used_employee_filter", False),
    ("result_informe_missing_days", []),
]:
    if k not in st.session_state:
        st.session_state[k] = v


# --- Safe defaults to avoid NameError on first load / when no results ---
salida_incidencias = pd.DataFrame()
incidencias_por_dia = {}
bajas_por_dia = {}
sin_por_dia = {}
weeks_ui = []

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
    signature = _sig(fi, ff, sel_empresas, sel_sedes, sel_empleados_nifs)

    with st.spinner("Procesando…"):
        tipos_map = api_exportar_tipos_fichaje()

        # --------- FICHAJES ----------
        fichajes_rows = []
        with ThreadPoolExecutor(max_workers=_max_workers_emps(len(empleados_filtrados))) as exe:
            futures = {exe.submit(api_exportar_fichajes, r["nif"], fi, ff): r for _, r in empleados_filtrados.iterrows()}
            for fut in as_completed(futures):
                emp = futures[fut]
                try:
                    rows_fich = fut.result() or []
                except Exception as _e:
                    _safe_fail(_e)
                    rows_fich = []
                for x in rows_fich:
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

        # --------- MAPAS DIARIOS COMPARTIDOS ----------
        # Se consultan una sola vez por rango y se reutilizan en todas las pestañas.
        d0 = datetime.strptime(fi, "%Y-%m-%d").date()
        d1 = datetime.strptime(ff, "%Y-%m-%d").date()

        base_emp = empleados_filtrados.copy()
        base_emp["nif"] = base_emp["nif"].fillna("").astype(str).str.upper().str.strip()
        base_emp["num_empleado"] = base_emp.get(
            "num_empleado", pd.Series("", index=base_emp.index)
        ).fillna("").astype(str).str.strip()

        try:
            horas_prog_map_query, bajas_min_map_query, informe_missing_days = build_informe_diario_maps_resilient(
                d0, d1, base_emp
            )
        except Exception as _e:
            _safe_fail(_e)
            horas_prog_map_query, bajas_min_map_query, informe_missing_days = {}, {}, []

        nifs_all_query = [
            n for n in base_emp["nif"].dropna().astype(str).str.upper().str.strip().unique().tolist()
            if n
        ]
        try:
            tc_map_query = build_tiempo_contabilizado_map(d0, d1, nifs_all_query)
        except Exception as _e:
            _safe_fail(_e)
            tc_map_query = {}

        # --------- INCIDENCIAS ----------
        if df_fich.empty:
            salida_incidencias = pd.DataFrame(columns=[
                "Fecha", "Empresa", "Sede", "Nombre", "Departamento",
                "Primera entrada", "Última salida", "Total trabajado",
                "Tiempo Contabilizado", "Diferencia", "Numero de fichajes", "Incidencia"
            ])
            resumen = pd.DataFrame()
        else:
            df_fich["Numero"] = df_fich.groupby(["nif", "fecha_dia"])["nif"].transform("size")
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

            horas_prog_map_incid = horas_prog_map_query
            tc_map_incid = tc_map_query

            if tc_map_incid:
                tc = pd.DataFrame(
                    [
                        {
                            "nif": nif_k,
                            "Fecha": day_k,
                            "Tiempo Contabilizado": segundos_a_hhmm(int(mins_k) * 60),
                        }
                        for (nif_k, day_k), mins_k in tc_map_incid.items()
                    ]
                )
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

            def build_incidencia(r) -> str:
                motivos = []

                day_str = str(r.get("Fecha", "") or "")
                nif_str = str(r.get("nif", "") or "").upper().strip()

                exp_key = (nif_str, day_str)
                exp_known = exp_key in (horas_prog_map_incid or {})
                exp_min = None
                if exp_known:
                    try:
                        exp_min = int(horas_prog_map_incid[exp_key])
                    except Exception:
                        exp_known = False
                        exp_min = None

                worked_minutes = int(round(float(r.get("horas_dec_validacion", 0.0) or 0.0) * 60))
                num_fich = int(r.get("Numero de fichajes", 0) or 0)
                worked = worked_minutes > 0 or num_fich > 0

                # Solo un cero explícito de CRECE significa día no laborable.
                if exp_known and exp_min == 0 and worked:
                    return "Trabajado en día no laborable"

                if int(r.get("dia", 0)) in [5, 6]:
                    if worked:
                        motivos.append("Trabajo en fin de semana")
                    return "; ".join(motivos)

                # Horas insuficientes: siempre contra Horas programadas de CRECE.
                if exp_known and exp_min is not None and exp_min > 0 and worked_minutes < (exp_min - TOLERANCIA_MINUTOS):
                    motivos.append(f"Horas insuficientes (mín {segundos_a_hhmm(exp_min * 60)})")

                depto_norm = str(r.get("Departamento") or "").upper().strip()

                # Cantidad de fichajes: para MOI/ESTRUCTURA depende de la jornada
                # programada real; para MOD el mínimo general es 2.
                min_f = None
                if depto_norm in ["MOI", "ESTRUCTURA"]:
                    if exp_known and exp_min is not None and exp_min > 0:
                        min_f = 2 if exp_min <= (6 * 60 + 35) else 4
                elif depto_norm == "MOD":
                    min_f = 2

                sp = _lookup_special(depto_norm, norm_name(r.get("Nombre")))
                if sp and "min_fichajes" in sp:
                    min_f = int(sp["min_fichajes"])

                hours_ok = bool(
                    exp_known
                    and exp_min is not None
                    and exp_min > 0
                    and worked_minutes >= max(0, exp_min - TOLERANCIA_MINUTOS)
                )

                if min_f is not None:
                    try:
                        min_f_i = int(min_f)
                        if num_fich < min_f_i:
                            motivos.append(f"Fichajes insuficientes (mín {min_f_i})")

                        max_ok = r.get("max_fichajes_ok")
                        if pd.notna(max_ok):
                            max_ok_i = int(max_ok)
                            if hours_ok and num_fich > max_ok_i:
                                motivos.append(f"Fichajes excesivos (máx {max_ok_i})")
                        elif hours_ok and num_fich > min_f_i:
                            motivos.append(f"Fichajes excesivos (mín {min_f_i})")
                    except Exception:
                        pass

                motivos += validar_horario(
                    r.get("Departamento"),
                    r.get("Nombre"),
                    int(r.get("dia", 0)),
                    r.get("Primera entrada", ""),
                    r.get("Última salida", ""),
                    expected_minutes=(exp_min if exp_known else None),
                    sede=r.get("Sede", ""),
                    empresa=r.get("Empresa", ""),
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
                        "nif",
                    ]
                ].sort_values(["Fecha", "Nombre"], kind="mergesort")
            else:
                salida_incidencias = pd.DataFrame(columns=[
                    "Fecha", "Empresa", "Sede", "Nombre", "Departamento", "Primera entrada", "Última salida",
                    "Total trabajado", "Tiempo Contabilizado", "Diferencia", "Numero de fichajes", "Incidencia", "nif"
                ])

        # --------- BAJAS ----------
        # Se reutiliza la MISMA lectura diaria de /informes/empleados utilizada
        # para Horas programadas. No se vuelve a golpear el endpoint.
        bajas_por_dia = {}
        if bajas_min_map_query:
            base_by_nif = (
                base_emp[base_emp["nif"].astype(str).str.strip().ne("")]
                .drop_duplicates(subset=["nif"])
                .set_index("nif", drop=False)
            )
            rows_by_day: dict[str, list[dict]] = {}
            for (nif_b, day_b), baja_mins in bajas_min_map_query.items():
                if int(baja_mins or 0) <= 0 or nif_b not in base_by_nif.index:
                    continue
                emp = base_by_nif.loc[nif_b]
                rows_by_day.setdefault(day_b, []).append(
                    {
                        "Fecha": day_b,
                        "Empresa": _text(emp.get("Empresa")),
                        "Sede": _text(emp.get("Sede")),
                        "Nombre": _text(emp.get("nombre_completo")),
                        "Departamento": _text(emp.get("departamento_nombre")),
                        "Horas baja": round(int(baja_mins) / 60.0, 2),
                        "nif": nif_b,
                    }
                )

            for day_b, rows_b in rows_by_day.items():
                out = pd.DataFrame(rows_b)
                out = out[out["Nombre"].astype(str).str.strip().ne("")]
                if not out.empty:
                    bajas_por_dia[day_b] = (
                        out.sort_values(["Nombre"], kind="mergesort").reset_index(drop=True)
                    )

        # --------- SIN FICHAJES ----------
        sin_por_dia = {}

        base_emp_sin = base_emp.copy()
        mask_activo = empleado_activo_o_contrato(base_emp_sin)
        base_emp_sin = base_emp_sin[mask_activo].copy()

        empleados_nifs = [
            n for n in base_emp_sin["nif"].dropna().astype(str).str.upper().str.strip().unique().tolist()
            if n
        ]

        presentes = {}
        if not df_fich.empty:
            for day, sub in df_fich.groupby("fecha_dia"):
                presentes[str(day)] = set(
                    sub["nif"].dropna().astype(str).str.upper().str.strip().tolist()
                )

        bajas_nifs_by_day: dict[str, set[str]] = {}
        for (nif_b, day_b), baja_mins in (bajas_min_map_query or {}).items():
            if int(baja_mins or 0) > 0:
                bajas_nifs_by_day.setdefault(str(day_b), set()).add(str(nif_b).upper().strip())

        for cur in _iter_days(d0, d1):
            day = cur.strftime("%Y-%m-%d")
            present_set = presentes.get(day, set())

            # Solo puede faltar fichaje si CRECE programa jornada > 0.
            expected_to_work = {
                n for n in empleados_nifs
                if int(horas_prog_map_query.get((n, day), 0) or 0) > 0
            }
            on_sick_leave = bajas_nifs_by_day.get(day, set())
            fully_accounted = {
                n for n in expected_to_work
                if int(tc_map_query.get((n, day), 0) or 0)
                >= max(0, int(horas_prog_map_query.get((n, day), 0) or 0) - TOLERANCIA_MINUTOS)
            }

            missing = sorted(expected_to_work - present_set - on_sick_leave - fully_accounted)
            if not missing:
                continue

            miss_df = base_emp_sin[base_emp_sin["nif"].isin(missing)].copy()
            if miss_df.empty:
                continue

            out = miss_df[["Empresa", "Sede", "nombre_completo", "departamento_nombre", "nif"]].copy()
            out = out.rename(columns={"nombre_completo": "Nombre", "departamento_nombre": "Departamento"})
            out.insert(0, "Fecha", day)
            out = out.sort_values(["Nombre"], kind="mergesort").reset_index(drop=True)
            sin_por_dia[day] = out


        # --------- EXCESO SEMANAL (MOI + ESTRUCTURA + MOD) ----------
        # ✅ Criterio (RRHH):
        #   - Trabajado diario SIEMPRE = tiempoContabilizado (exportacion/tiempo-trabajado), haya fichaje o no.
        #   - Esperado diario SIEMPRE = horas_programadas (informes/empleados).
        #   - Balance diario = trabajado - esperado, con tolerancia ±5 y cuantización a 30 min.
        #   - Exceso semanal = suma de balances diarios cuantizados (con signo, puede ser + o -).
        #   - Exceso no tiene incidencias, solo cálculo de balance.

        # Semanas completas disponibles dentro del rango (L-V, L-S, L-D)
        try:
            full_weeks = list_full_workweeks_in_range(d0, d1)  # [(mon, end_incl, mode), ...]
        except Exception:
            full_weeks = []

        excesos_por_semana = {}
        csv_excesos = b""

        if full_weeks:
            # Reutilizamos exactamente los mismos mapas usados por Fichajes/Sin fichajes.
            horas_prog_map = horas_prog_map_query
            tc_map = tc_map_query

            def expected_day_minutes(nif: str, day: date):
                key = (str(nif).upper().strip(), day.strftime("%Y-%m-%d"))
                if key not in horas_prog_map:
                    return None
                return int(horas_prog_map[key])

            def worked_day_minutes(nif: str, day: date) -> int:
                return int(tc_map.get((str(nif).upper().strip(), day.strftime("%Y-%m-%d")), 0) or 0)

            # Primera entrada por día: solo se usa para el matiz MOD del balance.
            # La columna "Trabajado semanal" sigue sumando TODO tiempoContabilizado.
            primera_entrada_map: dict[tuple[str, str], int] = {}
            if not df_fich.empty:
                _entradas_exc = df_fich[df_fich["direccion"] == "entrada"].copy()
                if not _entradas_exc.empty:
                    _grp_exc = (
                        _entradas_exc.groupby(["nif", "fecha_dia"], as_index=False)["fecha_dt"]
                        .min()
                    )
                    for _, _rr in _grp_exc.iterrows():
                        _nif_e = str(_rr.get("nif") or "").upper().strip()
                        _day_e = str(_rr.get("fecha_dia") or "")
                        _ts_e = _rr.get("fecha_dt")
                        if _nif_e and _day_e and pd.notna(_ts_e):
                            _dt_e = pd.to_datetime(_ts_e)
                            primera_entrada_map[(_nif_e, _day_e)] = int(_dt_e.hour * 60 + _dt_e.minute)

            # 3) Cálculo por semana y empleado (NO depende de que haya fichajes)
            base_exc = base_emp.copy()
            base_exc["Departamento_norm"] = base_exc.get("departamento_nombre", base_exc.get("Departamento", "")).astype(str).str.upper().str.strip()
            base_exc = base_exc[base_exc["Departamento_norm"].isin(["MOI", "ESTRUCTURA", "MOD"])].copy()

            all_rows = []

            for wk_start, wk_end_incl, mode in full_weeks:
                # Etiqueta UI
                if mode == "LD":
                    label = f"{wk_start:%Y-%m-%d} → {wk_end_incl:%Y-%m-%d} (L-D)"
                elif mode == "LS":
                    label = f"{wk_start:%Y-%m-%d} → {wk_end_incl:%Y-%m-%d} (L-S)"
                else:
                    label = f"{wk_start:%Y-%m-%d} → {wk_end_incl:%Y-%m-%d} (L-V)"

                rows = []
                if not base_exc.empty:
                    for _, emp in base_exc.iterrows():
                        nif = str(emp.get("nif") or "").upper().strip()
                        if not nif:
                            continue

                        nombre = str(emp.get("nombre_completo") or emp.get("Nombre") or "").strip()
                        depto = str(emp.get("departamento_nombre") or emp.get("Departamento") or "").strip()
                        empresa = str(emp.get("Empresa") or "").strip()
                        sede = str(emp.get("Sede") or "").strip()

                        exceso_sem_min = 0
                        trabajado_sem_min = 0
                        jornada_sem_min = 0

                        cur_day = wk_start
                        expected_complete = True
                        while cur_day <= wk_end_incl:
                            mins_tc = worked_day_minutes(nif, cur_day)
                            exp_day = expected_day_minutes(nif, cur_day)
                            if exp_day is None:
                                expected_complete = False
                                break

                            # La columna semanal muestra siempre el tiempoContabilizado
                            # completo de CRECE, tal como pidió RRHH.
                            trabajado_sem_min += int(mins_tc)
                            jornada_sem_min += int(exp_day)

                            # Matiz MOD: en días laborables el tiempo anterior al inicio
                            # de turno no suma al BALANCE diario. No se modifica el total
                            # mostrado en "Trabajado semanal".
                            mins_balance = int(mins_tc)
                            if str(depto).upper().strip() == "MOD" and int(exp_day) > 0:
                                pe = primera_entrada_map.get(
                                    (nif, cur_day.strftime("%Y-%m-%d"))
                                )
                                mins_balance = effective_worked_minutes_for_mod(mins_tc, pe)

                            diff_day = int(mins_balance) - int(exp_day)
                            bal_day_q = quantize_daily_balance_30(diff_day, tol=5)
                            exceso_sem_min += int(bal_day_q)
                            cur_day += timedelta(days=1)

                        # No fabricamos un esperado=0 si el informe no devuelve Horas programadas.
                        # Es más seguro omitir ese empleado/semana que calcular un exceso falso.
                        if not expected_complete:
                            continue

                        # Mostrar solo si hay exceso semanal != 0
                        if exceso_sem_min == 0:
                            continue

                        row = {
                            "Empresa": empresa,
                            "Sede": sede,
                            "Nombre": nombre,
                            "Departamento": depto,
                            "Trabajado semanal": segundos_a_hhmm(trabajado_sem_min * 60),
                            "Jornada semanal": segundos_a_hhmm(jornada_sem_min * 60),
                            "Exceso": mins_to_hhmm_signed(exceso_sem_min),
                            "nif": nif,
                        }
                        rows.append(row)
                        all_rows.append({"Semana": label, **{k: v for k, v in row.items() if k != "nif"}})

                if rows:
                    dfw = (
                        pd.DataFrame(rows)
                        .sort_values(["Empresa", "Sede", "Departamento", "Nombre"], kind="mergesort")
                        .reset_index(drop=True)
                    )
                else:
                    dfw = pd.DataFrame(columns=["Empresa", "Sede", "Nombre", "Departamento", "Trabajado semanal", "Jornada semanal", "Exceso", "nif"])

                excesos_por_semana[label] = dfw

            if all_rows:
                df_all = (
                    pd.DataFrame(all_rows)
                    .sort_values(["Semana", "Empresa", "Sede", "Departamento", "Nombre"], kind="mergesort")
                    .reset_index(drop=True)
                )
                csv_excesos = df_all.to_csv(index=False).encode("utf-8")
if consultar:
    # --------- Guardar en estado + CSVs ----------
    incidencias_por_dia = {}
    if not salida_incidencias.empty:
        for day, subd in salida_incidencias.groupby("Fecha"):
            incidencias_por_dia[str(day)] = subd.reset_index(drop=True)

    st.session_state["last_sig"] = signature

    # Alcance (scope) de la última consulta: permite re-filtrar en memoria al reducir Empresa/Sede
    st.session_state["scope_fi"] = fecha_inicio.isoformat()
    st.session_state["scope_ff"] = fecha_fin.isoformat()
    st.session_state["scope_empresas_norm"] = {_norm_key(x) for x in sel_empresas}
    st.session_state["scope_sedes_norm"] = {_norm_key(x) for x in sel_sedes}
    st.session_state["scope_empleados_nif"] = set(empleados_filtrados["nif"].astype(str).str.upper().str.strip().tolist())
    st.session_state["scope_used_employee_filter"] = bool(sel_empleados_nifs)
    st.session_state["result_incidencias"] = incidencias_por_dia
    st.session_state["result_bajas"] = bajas_por_dia
    st.session_state["result_sin_fichajes"] = sin_por_dia
    st.session_state["result_excesos_semana"] = excesos_por_semana
    st.session_state["result_informe_missing_days"] = list(informe_missing_days or [])

    st.session_state["result_csv_incidencias"] = (
        _df_view(salida_incidencias).to_csv(index=False).encode("utf-8") if not salida_incidencias.empty else b""
    )

    if bajas_por_dia:
        df_all_bajas = pd.concat(list(bajas_por_dia.values()), ignore_index=True)
        st.session_state["result_csv_bajas"] = _df_view(df_all_bajas).to_csv(index=False).encode("utf-8")
    else:
        st.session_state["result_csv_bajas"] = b""

    if sin_por_dia:
        df_all_sin = pd.concat(list(sin_por_dia.values()), ignore_index=True)
        st.session_state["result_csv_sin"] = _df_view(df_all_sin).to_csv(index=False).encode("utf-8")
    else:
        st.session_state["result_csv_sin"] = b""

    st.session_state["result_csv_excesos"] = csv_excesos


# ------------------------------------------------------------
# Render: Tabs
# ------------------------------------------------------------
fi_sig = fecha_inicio.strftime("%Y-%m-%d")
ff_sig = fecha_fin.strftime("%Y-%m-%d")
current_sig = _sig(fi_sig, ff_sig, sel_empresas, sel_sedes, sel_empleados_nifs)

last_sig = st.session_state.get("last_sig", "")
results_match = (last_sig == current_sig)
if not last_sig:
    # En el arranque (sin haber pulsado Consultar) NO mostramos nada más que los filtros.
    # Importante: sin mensajes ni pestañas.
    st.stop()
elif not results_match:
    pass


try:
    weeks_ui = list_full_workweeks_in_range(fecha_inicio, fecha_fin)
except Exception:
    weeks_ui = []

# Pestañas (siempre visibles)
# Solo mostramos resultados si corresponden a los filtros actuales (firma coincide)
res_incid = st.session_state.get("result_incidencias", {}) or {}
res_bajas = st.session_state.get("result_bajas", {}) or {}
res_sin = st.session_state.get("result_sin_fichajes", {}) or {}
res_exc = st.session_state.get("result_excesos_semana", {}) or {}

# --- Re-filtrado local (sin recargar) cuando el usuario REDUCE Empresa/Sede tras una consulta ---
active_emp_norm = {_norm_key(x) for x in sel_empresas}
active_sed_norm = {_norm_key(x) for x in sel_sedes}

scope_fi = st.session_state.get("scope_fi", "")
scope_ff = st.session_state.get("scope_ff", "")
scope_emp_norm = set(st.session_state.get("scope_empresas_norm", set()) or set())
scope_sed_norm = set(st.session_state.get("scope_sedes_norm", set()) or set())
scope_emp_nifs = set(st.session_state.get("scope_empleados_nif", set()) or set())
active_emp_nifs = set(sel_empleados_nifs or set())

scope_used_employee_filter = bool(st.session_state.get("scope_used_employee_filter", False))
same_dates_as_scope = (scope_fi == fecha_inicio.isoformat()) and (scope_ff == fecha_fin.isoformat())

if active_emp_nifs:
    # Con empleados seleccionados, ese filtro manda sobre Empresa/Sede.
    can_filter_locally = same_dates_as_scope and active_emp_nifs.issubset(scope_emp_nifs)
else:
    # Quitar un filtro de empleados de una consulta originalmente limitada amplía
    # el universo y exige volver a consultar.
    can_filter_locally = (
        same_dates_as_scope
        and not scope_used_employee_filter
        and active_emp_norm.issubset(scope_emp_norm)
        and active_sed_norm.issubset(scope_sed_norm)
    )

def _ensure_norm_cols(df: pd.DataFrame) -> pd.DataFrame:
    if df is None or df.empty:
        return df
    if "Empresa_norm" not in df.columns:
        if "Empresa" in df.columns:
            df = df.copy()
            df["Empresa_norm"] = df["Empresa"].apply(_norm_key)
    if "Sede_norm" not in df.columns:
        if "Sede" in df.columns:
            df = df.copy()
            df["Sede_norm"] = df["Sede"].apply(_norm_key)
    return df

def _filter_df_by_active(df: pd.DataFrame) -> pd.DataFrame:
    if df is None or df.empty:
        return df
    df = _ensure_norm_cols(df)
    if active_emp_nifs:
        if "nif" in df.columns:
            df = df[df["nif"].astype(str).str.upper().str.strip().isin(active_emp_nifs)]
        return df
    if "Empresa_norm" in df.columns:
        df = df[df["Empresa_norm"].isin(active_emp_norm)]
    if "Sede_norm" in df.columns:
        df = df[df["Sede_norm"].isin(active_sed_norm)]
    return df

def _filter_day_dict(d: dict) -> dict:
    if not isinstance(d, dict) or not d:
        return d or {}
    out = {}
    for k, v in d.items():
        if isinstance(v, pd.DataFrame):
            filtered = _filter_df_by_active(v)
            if filtered is not None and not filtered.empty:
                out[k] = filtered
        else:
            out[k] = v
    return out

# Si podemos filtrar localmente, aplicamos el filtro a los resultados cacheados para render
if can_filter_locally:
    res_incid = _filter_day_dict(res_incid)
    res_bajas = _filter_day_dict(res_bajas)
    res_sin = _filter_day_dict(res_sin)
    res_exc = _filter_day_dict(res_exc)
else:
    # Si el alcance visible ya no está contenido en la última consulta, no se
    # muestran resultados antiguos bajo filtros nuevos.
    if st.session_state.get("last_sig", ""):
        if not same_dates_as_scope:
            st.info("ℹ️ Has cambiado el rango de fechas respecto a la última consulta. Pulsa **Consultar** para recargar datos.")
        elif active_emp_nifs and not active_emp_nifs.issubset(scope_emp_nifs):
            st.info("ℹ️ Has ampliado Empleados respecto a la última consulta. Pulsa **Consultar** para recargar datos.")
        elif scope_used_employee_filter and not active_emp_nifs:
            st.info("ℹ️ Has quitado el filtro de empleados de una consulta limitada. Pulsa **Consultar** para cargar el universo completo.")
        elif (not active_emp_norm.issubset(scope_emp_norm)) or (not active_sed_norm.issubset(scope_sed_norm)):
            st.info("ℹ️ Has ampliado Empresa/Sede respecto a la última consulta. Pulsa **Consultar** para recargar datos.")
        st.stop()


def _csv_from_result_dict(result_dict: dict, *, week_mode: bool = False) -> bytes:
    """CSV de lo que realmente se está mostrando tras el re-filtrado local."""
    parts = []
    for key, df in (result_dict or {}).items():
        if not isinstance(df, pd.DataFrame) or df.empty:
            continue
        tmp = _df_view(df).copy()
        if week_mode:
            tmp.insert(0, "Semana", str(key))
        parts.append(tmp)
    if not parts:
        return b""
    return pd.concat(parts, ignore_index=True).to_csv(index=False).encode("utf-8")


# Aviso no bloqueante únicamente si CRECE ha dejado alguna fecha sin informe.
_missing_days_ui = list(st.session_state.get("result_informe_missing_days", []) or [])
if _missing_days_ui:
    st.warning(
        f"No se ha podido reconstruir de forma fiable la jornada programada para "
        f"{len(_missing_days_ui)} fecha(s). La consulta continúa sin inventar datos; "
        "esas fechas se omiten únicamente de las validaciones que necesitan Horas programadas."
    )


# Tabs: en rangos cortos (menos de 7 días) solo mostramos Fichajes/Bajas/Sin fichajes
range_days = (fecha_fin - fecha_inicio).days + 1 if fecha_fin >= fecha_inicio else 0
tab_labels = ["📌 Fichajes", "🏥 Bajas", "⛔ Sin fichajes"]
show_exceso_tab = bool(weeks_ui)
if show_exceso_tab:
    tab_labels.append("🕒 Exceso de jornada")

_tabs = st.tabs(tab_labels)
_tab_fich, _tab_bajas, _tab_sin = _tabs[0], _tabs[1], _tabs[2]
_tab_exc = _tabs[3] if show_exceso_tab else None


tab_map = {
    "tab_fich": _tab_fich,
    "tab_bajas": _tab_bajas,
    "tab_sin": _tab_sin,
}
if _tab_exc is not None:
    tab_map["tab_exc"] = _tab_exc


if "tab_fich" in tab_map:
    with tab_map["tab_fich"]:
        incid = res_incid
        if not incid:
            if _missing_days_ui:
                st.warning(
                    "No hay incidencias mostrables, pero faltan datos de jornada programada "
                    "para parte del rango y no se pueden validar todas las reglas dependientes de Horas programadas."
                )
            else:
                st.success("🎉 No hay incidencias en el rango seleccionado.")
        else:
            for day in sorted(incid.keys()):
                view_df = _df_view(incid[day])
                if view_df is None or (hasattr(view_df, "empty") and view_df.empty):
                    continue
                st.markdown(f"### 📅 {day}")
                st.data_editor(view_df, use_container_width=True, hide_index=True, disabled=True, num_rows="fixed", key=_make_editor_key('incid', day, current_sig))
            csv_i = _csv_from_result_dict(res_incid)
            if csv_i:
                st.download_button("⬇ Descargar CSV incidencias", csv_i, "fichajes_incidencias.csv", "text/csv")

if "tab_bajas" in tab_map:
    with tab_map["tab_bajas"]:
        bajas = res_bajas
        if not bajas:
            if _missing_days_ui:
                st.warning(
                    "No se puede confirmar que no haya bajas en todo el rango porque faltan "
                    "datos del informe de empleados para algunas fechas."
                )
            else:
                st.info("No hay empleados de baja en el rango seleccionado.")
        else:
            for day in sorted(bajas.keys()):
                view_df = _df_view(bajas.get(day))
                if view_df is None or (hasattr(view_df, 'empty') and view_df.empty):
                    continue
                st.markdown(f"### 🏥 Empleados de baja — {day}")
                st.data_editor(view_df, use_container_width=True, hide_index=True, disabled=True, num_rows="fixed", key=_make_editor_key('bajas', day, current_sig))
            csv_b = _csv_from_result_dict(res_bajas)
            if csv_b:
                st.download_button("⬇ Descargar CSV bajas", csv_b, "empleados_baja.csv", "text/csv")

if "tab_sin" in tab_map:
    with tab_map["tab_sin"]:
        sinf = res_sin
        if not sinf:
            if _missing_days_ui:
                st.warning(
                    "No se puede confirmar que no haya empleados sin fichajes en todo el rango "
                    "porque faltan Horas programadas para algunas fechas."
                )
            else:
                st.info("No hay empleados sin fichajes (activos/contrato) en el rango seleccionado.")
        else:
            for day in sorted(sinf.keys()):
                view_df = _df_view(sinf.get(day))
                if view_df is None or (hasattr(view_df, 'empty') and view_df.empty):
                    continue
                st.markdown(f"### ⛔ Empleados sin fichajes (activos/contrato) — {day}")
                st.data_editor(view_df, use_container_width=True, hide_index=True, disabled=True, num_rows="fixed", key=_make_editor_key('sinf', day, current_sig))
            csv_s = _csv_from_result_dict(res_sin)
            if csv_s:
                st.download_button("⬇ Descargar CSV sin fichajes", csv_s, "empleados_sin_fichajes.csv", "text/csv")

if "tab_exc" in tab_map:
    with tab_map["tab_exc"]:
        excesos = res_exc
        shown_any_week = False

        for wk_start, wk_end_incl, wk_mode in weeks_ui:
            label = f"{wk_start:%Y-%m-%d} → {wk_end_incl:%Y-%m-%d} (" + ("L-D" if wk_mode=="LD" else ("L-S" if wk_mode=="LS" else "L-V")) + ")"
            dfw = excesos.get(label)
            if dfw is None or dfw.empty:
                continue

            shown_any_week = True
            st.markdown(f"### 🗓 {label}")
            st.data_editor(_df_view(dfw), use_container_width=True, hide_index=True, disabled=True, num_rows="fixed", key=_make_editor_key('exceso', label, current_sig))

        if not shown_any_week:
            if _missing_days_ui:
                st.warning(
                    "No se puede confirmar que no haya excesos de jornada: faltan Horas programadas "
                    "para parte del rango."
                )
            else:
                st.info("No hay excesos de jornada en el rango seleccionado.")

        csv_w = _csv_from_result_dict(res_exc, week_mode=True)
        if csv_w:
            st.download_button("⬇ Descargar CSV excesos (todas las semanas)", csv_w, "excesos_jornada_semanal.csv", "text/csv")
