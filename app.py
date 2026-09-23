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
from email.utils import parsedate_to_datetime
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


def _canonical_crece_id(value) -> str:
    if value is None:
        return ""
    try:
        if pd.isna(value):
            return ""
    except Exception:
        pass
    s = str(value).strip()
    if not s:
        return ""
    try:
        f = float(s.replace(",", "."))
        if f.is_integer():
            return str(int(f))
    except Exception:
        pass
    return s


def _hash_crece_employee_id(value) -> str:
    cid = _canonical_crece_id(value)
    return _cache_hmac(cid, "CRECE_EMP_ID") if cid else ""


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
RETRY_AFTER_MAX_SECONDS = 90.0

# CRECE limita /api/informes/* a 1 petición por minuto. La aplicación usa
# /informes/turnos como única fuente de jornada diaria y serializa estas llamadas.
INFORME_MIN_INTERVAL_SECONDS = 61.0
_INFORME_GATE_LOCK = threading.Lock()
_INFORME_LAST_FINISH_MONO = 0.0

# Diagnóstico técnico temporal de /informes/empleados. Solo guarda metadatos
# no sensibles: fecha/rango, modo, intento, estado HTTP, tiempos, bytes y etapa.
_INFORME_DIAG_LOCK = threading.Lock()
_INFORME_DIAG_EVENTS: list[dict] = []

def _diag_informe_event(**event) -> None:
    clean = {}
    for k, v in event.items():
        if v is None:
            clean[k] = None
        elif isinstance(v, (int, float, bool)):
            clean[k] = v
        else:
            clean[k] = str(v)[:160]
    with _INFORME_DIAG_LOCK:
        _INFORME_DIAG_EVENTS.append(clean)

def _reset_informe_diag() -> None:
    with _INFORME_DIAG_LOCK:
        _INFORME_DIAG_EVENTS.clear()

def _snapshot_informe_diag() -> list[dict]:
    with _INFORME_DIAG_LOCK:
        return [dict(x) for x in _INFORME_DIAG_EVENTS]

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


def _retry_after_seconds(resp: requests.Response) -> float | None:
    """Interpreta Retry-After sin registrar cabeceras ni payloads."""
    try:
        raw = (resp.headers.get("Retry-After") or "").strip()
    except Exception:
        raw = ""
    if not raw:
        return None
    try:
        return max(0.0, min(RETRY_AFTER_MAX_SECONDS, float(raw)))
    except Exception:
        pass
    try:
        dt = parsedate_to_datetime(raw)
        seconds = dt.timestamp() - time.time()
        return max(0.0, min(RETRY_AFTER_MAX_SECONDS, seconds))
    except Exception:
        return None


def safe_request(method: str, url: str, *, data=None, params=None, json_body=None, timeout=HTTP_TIMEOUT, trace_label: str | None = None):
    method = (method or "").upper().strip()
    if method not in {"GET", "POST"}:
        return None

    last_exc = None
    for attempt in range(MAX_RETRIES + 1):
        try:
            _t0 = time.monotonic()
            resp = _get_http_session().request(
                method,
                url,
                data=data,
                params=params,
                json=json_body,
                timeout=timeout,
                verify=True,
            )
            _elapsed_ms = int(round((time.monotonic() - _t0) * 1000.0))
            if trace_label:
                _diag_informe_event(
                    kind="http", label=trace_label, attempt=attempt + 1,
                    status=int(resp.status_code), elapsed_ms=_elapsed_ms,
                    bytes=len(resp.content or b""),
                    retry_after=_retry_after_seconds(resp),
                    content_type=(resp.headers.get("Content-Type") or "").split(";")[0],
                )

            if resp.status_code in RETRY_STATUS:
                if attempt < MAX_RETRIES:
                    wait = min(BACKOFF_MAX_SECONDS, BACKOFF_BASE_SECONDS * (2 ** attempt))
                    retry_after = _retry_after_seconds(resp)
                    if retry_after is not None:
                        wait = max(wait, retry_after)
                    wait += random.uniform(0, 0.20)
                    time.sleep(wait)
                    continue
                return resp

            return resp

        except requests.RequestException as e:
            last_exc = e
            if trace_label:
                _diag_informe_event(
                    kind="transport_error", label=trace_label, attempt=attempt + 1,
                    error=type(e).__name__,
                )
            if attempt < MAX_RETRIES:
                wait = min(BACKOFF_MAX_SECONDS, BACKOFF_BASE_SECONDS * (2 ** attempt))
                wait += random.uniform(0, 0.20)
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




def effective_worked_minutes_for_mod(mins_tc: int, pre_shift_work_minutes: int = 0) -> int:
    """Tiempo válido para el balance MOD.

    La columna visual conserva todo ``tiempoContabilizado``. Para el balance de
    un día MOD se descuenta únicamente el trabajo REAL que los intervalos
    entrada/salida sitúan antes del inicio oficial del turno (06:00 mañana,
    14:00 tarde o 22:00 noche), también si ese día figura L/libre. Nunca se
    descuenta un hueco sin fichajes.
    """
    try:
        total = max(0, int(mins_tc))
    except Exception:
        total = 0
    try:
        pre = max(0, int(pre_shift_work_minutes))
    except Exception:
        pre = 0
    return max(0, total - pre)



def normalize_midnight_continuations(df_fich: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    """Agrupa continuaciones reales de turno partidas por CRECE a las 00:00.

    CRECE puede materializar un turno que cruza medianoche como::

        ... entrada -> salida 23:59   /   entrada 00:00 -> salida 06:xx ...

    El segundo par sigue perteneciendo al turno iniciado el día anterior. Esta
    función reasigna *solo* ese par inequívoco al día de inicio y devuelve un
    mapa de minutos de trabajo que deben trasladarse, únicamente para el
    cálculo por turno, desde el día civil siguiente al anterior.

    No se inventa tiempo: el traslado se basa exclusivamente en intervalos de
    fichajes reales. ``tiempoContabilizado`` bruto se conserva intacto para la
    columna semanal; el mapa de traslado se utiliza después solo para alinear
    el balance diario con el turno.
    """
    if df_fich is None or df_fich.empty:
        return (df_fich.copy() if isinstance(df_fich, pd.DataFrame) else pd.DataFrame()), {}

    required = {"nif", "fecha_dt", "direccion", "fecha_dia"}
    if not required.issubset(set(df_fich.columns)):
        return df_fich.copy(), {}

    out = df_fich.copy()
    out["nif"] = out["nif"].fillna("").astype(str).str.upper().str.strip()
    out["fecha_dt"] = pd.to_datetime(out["fecha_dt"], errors="coerce")
    transfers: dict[tuple[str, str, str], int] = {}

    for nif, sub in out.dropna(subset=["fecha_dt"]).groupby("nif", sort=False):
        if not nif:
            continue
        sub = sub.sort_values("fecha_dt", kind="mergesort")
        idxs = list(sub.index)
        # Buscamos la secuencia salida 23:5x -> entrada 00:0x -> salida matinal.
        for j in range(len(idxs) - 2):
            ia, ib, ic = idxs[j], idxs[j + 1], idxs[j + 2]
            a, b, c = out.loc[ia], out.loc[ib], out.loc[ic]
            if str(a.get("direccion") or "").lower().strip() != "salida":
                continue
            if str(b.get("direccion") or "").lower().strip() != "entrada":
                continue
            if str(c.get("direccion") or "").lower().strip() != "salida":
                continue

            a_dt = pd.to_datetime(a.get("fecha_dt"), errors="coerce")
            b_dt = pd.to_datetime(b.get("fecha_dt"), errors="coerce")
            c_dt = pd.to_datetime(c.get("fecha_dt"), errors="coerce")
            if pd.isna(a_dt) or pd.isna(b_dt) or pd.isna(c_dt):
                continue

            if b_dt.date() != c_dt.date() or b_dt.date() != (a_dt.date() + timedelta(days=1)):
                continue

            a_min = int(a_dt.hour) * 60 + int(a_dt.minute)
            b_min = int(b_dt.hour) * 60 + int(b_dt.minute)
            c_min = int(c_dt.hour) * 60 + int(c_dt.minute)

            # La firma 23:55+ / 00:05- evita reclasificar fichajes nocturnos
            # normales que no sean un corte artificial de medianoche.
            if a_min < 23 * 60 + 55 or b_min > 5:
                continue
            # Una continuación de turno industrial debe terminar en la mañana.
            # Permitimos hasta mediodía para no perder horas extra del mismo turno.
            if c_min > 12 * 60 or c_dt <= b_dt:
                continue
            if (b_dt - a_dt).total_seconds() > 10 * 60:
                continue

            prev_day = a_dt.date().strftime("%Y-%m-%d")
            civil_day = b_dt.date().strftime("%Y-%m-%d")
            out.at[ib, "fecha_dia"] = prev_day
            out.at[ic, "fecha_dia"] = prev_day

            worked_mins = max(0, int(round((c_dt - b_dt).total_seconds() / 60.0)))
            if worked_mins > 0:
                k = (str(nif).upper().strip(), civil_day, prev_day)
                transfers[k] = int(transfers.get(k, 0)) + worked_mins

    return out, transfers


def apply_midnight_tc_transfers(tc_map: dict, transfers: dict) -> dict:
    """Alinea TC para balances por turno sin modificar el TC bruto original.

    Cada traslado mueve como máximo los minutos de trabajo REAL detectados y
    nunca crea minutos nuevos. Solo se aplica si CRECE devolvió TC para ambos
    días implicados, de modo que dato ausente nunca se convierte en cero.
    """
    adjusted = dict(tc_map or {})
    for (nif, from_day, to_day), requested in (transfers or {}).items():
        src = (str(nif).upper().strip(), str(from_day))
        dst = (str(nif).upper().strip(), str(to_day))
        if src not in adjusted or dst not in adjusted:
            continue
        try:
            available = max(0, int(adjusted[src]))
            amount = min(available, max(0, int(requested)))
        except Exception:
            continue
        if amount <= 0:
            continue
        adjusted[src] = available - amount
        adjusted[dst] = max(0, int(adjusted[dst])) + amount
    return adjusted


def build_mod_pre_shift_work_map(
    df_fich: pd.DataFrame,
    tipos_map: dict,
    shift_start_map: dict | None = None,
) -> dict:
    """Devuelve {(NIF, fecha): minutos_trabajados antes del inicio real del turno MOD}.

    Prioriza la hora de inicio del horario asignado en CRECE. Para MOD, la regla
    operativa confirmada es 06:00/14:00/22:00; si CRECE no expone el inicio, se
    usa ese patrón como fallback. Solo descuenta trabajo REAL contenido en pares
    entrada->salida.
    """
    if df_fich is None or df_fich.empty:
        return {}

    required = {"nif", "fecha_dia", "fecha_dt", "direccion", "tipo"}
    if not required.issubset(set(df_fich.columns)):
        return {}

    out: dict[tuple[str, str], int] = {}
    for (nif, day_iso), sub in df_fich.groupby(["nif", "fecha_dia"]):
        nif_s = str(nif or "").upper().strip()
        day_s = str(day_iso or "")
        if not nif_s or not day_s:
            continue

        sub = sub.sort_values("fecha_dt").reset_index(drop=True)
        entradas = sub[sub["direccion"] == "entrada"]
        if entradas.empty:
            continue

        # CRECE puede partir un turno nocturno en el cambio de día y devolver
        # dentro del mismo día civil una cola 00:00-06:xx del turno anterior y
        # un nuevo tramo nocturno 21/22:xx-23:59. Ese patrón NO puede tratarse
        # como trabajo previo a un turno de mañana: provocaría descuentos de
        # ~6 h/día y déficits semanales artificiales.
        entrada_dts = pd.to_datetime(entradas["fecha_dt"], errors="coerce").dropna()
        split_night_group = bool(
            (not entrada_dts.empty)
            and any(int(ts.hour) < 6 for ts in entrada_dts)
            and any(int(ts.hour) >= 18 for ts in entrada_dts)
        )

        first_ts = pd.to_datetime(entradas.iloc[0]["fecha_dt"], errors="coerce")
        if pd.isna(first_ts):
            continue
        shift_start_map = shift_start_map or {}
        shift_start_min = shift_start_map.get((nif_s, day_s))

        # Regla RRHH confirmada para MOD: los tres turnos estándar son
        # 06:00-14:00, 14:00-22:00 y 22:00-06:00. La hora de entrada puede
        # adelantarse (p. ej. 21:30 para el turno de noche), pero ese tiempo
        # anterior al inicio oficial NO suma al balance de exceso.
        #
        # Si los marcajes muestran inequívocamente un turno partido por
        # medianoche, ese turno es el de noche y su inicio oficial es 22:00.
        # Esto evita depender de que /exportacion/horarios exponga bien la
        # hora de inicio para poder descontar, por ejemplo, 21:30-22:00.
        if split_night_group:
            shift_start_min = 22 * 60

        if shift_start_min is None:
            first_clock_min = int(first_ts.hour) * 60 + int(first_ts.minute)
            if first_clock_min >= 18 * 60:
                shift_start_min = 22 * 60
            elif first_clock_min >= 12 * 60:
                shift_start_min = 14 * 60
            else:
                shift_start_min = 6 * 60
        try:
            shift_start_dt = pd.Timestamp(day_s) + pd.Timedelta(minutes=int(shift_start_min))
        except Exception:
            continue

        # En turnos nocturnos el mismo día civil puede contener dos trozos de
        # trabajo distintos: la cola 00:00-06:00 del turno iniciado la noche
        # anterior y, más tarde, la entrada del nuevo turno nocturno. La cola
        # de madrugada NO es trabajo "antes del inicio" del nuevo turno y no
        # debe restarse del balance. Usamos el mismo corte de las 06:00 que la
        # aplicación ya emplea para asignar fichajes de turno nocturno.
        day_start_dt = pd.Timestamp(day_s)
        if int(shift_start_min) >= 18 * 60:
            pre_window_start_dt = day_start_dt + pd.Timedelta(hours=6)
        else:
            pre_window_start_dt = day_start_dt

        pre_seconds = 0.0
        i = 0
        while i < len(sub) - 1:
            a = sub.iloc[i]
            b = sub.iloc[i + 1]
            if a.get("direccion") == "entrada" and b.get("direccion") == "salida":
                a_dt = pd.to_datetime(a.get("fecha_dt"), errors="coerce")
                b_dt = pd.to_datetime(b.get("fecha_dt"), errors="coerce")
                if pd.notna(a_dt) and pd.notna(b_dt) and b_dt >= a_dt:
                    try:
                        tipo_id = int(a.get("tipo")) if pd.notna(a.get("tipo")) else None
                    except Exception:
                        tipo_id = None
                    props = tipos_map.get(tipo_id, {}) if tipo_id is not None else {}
                    if int(props.get("descuenta_tiempo", 0) or 0) == 0:
                        overlap_start = max(a_dt, pre_window_start_dt)
                        overlap_end = min(b_dt, shift_start_dt)
                        if overlap_end > overlap_start:
                            pre_seconds += (overlap_end - overlap_start).total_seconds()
                i += 2
            else:
                i += 1

        if pre_seconds > 0:
            out[(nif_s, day_s)] = max(0, int(round(pre_seconds / 60.0)))

    return out



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
    """Descifra y autentica un payload CRECE (AES-256-CBC + HMAC-SHA256)."""
    try:
        json_raw = base64.b64decode(payload_b64, validate=True).decode("utf-8")
        payload = json.loads(json_raw)
    except Exception as exc:
        raise ValueError("Payload CRECE no válido") from exc

    if not isinstance(payload, dict) or not all(k in payload for k in ("iv", "value", "mac")):
        raise ValueError("Payload CRECE incompleto")

    try:
        key = base64.b64decode(app_key_b64, validate=True)
        iv_b64 = str(payload["iv"])
        value_b64 = str(payload["value"])
        received_mac = str(payload["mac"])
        iv = base64.b64decode(iv_b64, validate=True)
        ct = base64.b64decode(value_b64, validate=True)
    except Exception as exc:
        raise ValueError("Payload CRECE no decodificable") from exc

    if len(iv) != AES.block_size:
        raise ValueError("IV CRECE no válido")

    calculated_mac = hmac.new(
        key,
        (iv_b64 + value_b64).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(received_mac.lower(), calculated_mac.lower()):
        raise ValueError("MAC CRECE no válido")

    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ct), AES.block_size)
        return decrypted.decode("utf-8")
    except Exception as exc:
        raise ValueError("No se pueden desencriptar los datos CRECE") from exc




def _try_parse_encrypted_response(resp: requests.Response):
    if resp is None:
        return None

    raw_text = (resp.text or "").strip()
    candidates = []

    try:
        candidates.append(resp.json())
    except Exception:
        pass
    if raw_text:
        candidates.append(raw_text)

    for c in candidates:
        try:
            # Compatibilidad con respuestas que ya materializan el JSON final.
            if isinstance(c, list):
                return c
            if isinstance(c, dict) and not ({"iv", "value", "mac"} <= set(c.keys())):
                return c

            if isinstance(c, dict) and {"iv", "value", "mac"} <= set(c.keys()):
                payload_b64 = base64.b64encode(
                    json.dumps(
                        {"iv": c["iv"], "value": c["value"], "mac": c["mac"]},
                        separators=(",", ":"),
                    ).encode("utf-8")
                ).decode("utf-8")
                return json.loads(decrypt_crece_payload(payload_b64, APP_KEY_B64))

            if isinstance(c, str):
                s = c.strip().strip('"').strip()
                if not s:
                    continue

                if s.startswith("{") and s.endswith("}"):
                    obj = json.loads(s)
                    if isinstance(obj, dict) and {"iv", "value", "mac"} <= set(obj.keys()):
                        payload_b64 = base64.b64encode(
                            json.dumps(obj, separators=(",", ":")).encode("utf-8")
                        ).decode("utf-8")
                        return json.loads(decrypt_crece_payload(payload_b64, APP_KEY_B64))
                    if isinstance(obj, dict):
                        return obj

                # Forma documentada: cadena base64(JSON({iv,value,mac})).
                dec_json_raw = base64.b64decode(s, validate=True).decode("utf-8")
                obj = json.loads(dec_json_raw)
                if isinstance(obj, dict) and {"iv", "value", "mac"} <= set(obj.keys()):
                    return json.loads(decrypt_crece_payload(s, APP_KEY_B64))

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


def required_min_fichajes(depto: str, nombre: str, expected_minutes) -> int | None:
    """Mínimo de fichajes aplicable según departamento y jornada CRECE."""
    depto_norm = str(depto or "").upper().strip()
    nombre_norm = norm_name(nombre)
    try:
        exp_min = int(expected_minutes) if expected_minutes is not None else None
    except Exception:
        exp_min = None

    min_f = None
    if depto_norm in {"MOI", "ESTRUCTURA"}:
        if exp_min is not None and exp_min > 0:
            min_f = 2 if exp_min <= (6 * 60 + 35) else 4
    elif depto_norm == "MOD":
        min_f = 2

    sp = _lookup_special(depto_norm, nombre_norm)
    if sp and "min_fichajes" in sp:
        min_f = int(sp["min_fichajes"])
    return min_f


def is_sin_fichajes_candidate(
    *,
    contratado: bool,
    horas_programadas,
    tiene_fichajes: bool,
    esta_baja: bool,
    tc_known: bool,
    tiempo_contabilizado,
) -> bool:
    """Regla exacta de inclusión en Sin fichajes para un empleado/día."""
    if contratado is not True or tiene_fichajes or esta_baja:
        return False
    try:
        hp = int(horas_programadas)
    except Exception:
        return False
    if hp <= 0 or not tc_known:
        return False
    try:
        tc = int(tiempo_contabilizado)
    except Exception:
        return False
    return tc < max(0, hp - TOLERANCIA_MINUTOS)


def validar_horario(
    depto: str,
    nombre: str,
    dia: int,
    primera_entrada_hhmm: str,
    ultima_salida_hhmm: str,
    expected_minutes=None,
    sede: str = "",
    empresa: str = "",
    completed_day: bool = True,
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

            # Una salida intermedia del día actual no es aún la salida final.
            if completed_day and salida_min is not None and s_min is not None and s_min < (salida_min - MARGEN_HORARIO_MIN):
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
    """Sedes CRECE. No usa endpoints alternativos no documentados."""
    url = f"{API_URL_BASE}/exportacion/sedes"
    resp = safe_request("GET", url)
    if resp is None:
        return pd.DataFrame(columns=["sede_id", "sede_nombre"])
    try:
        resp.raise_for_status()
    except Exception:
        return pd.DataFrame(columns=["sede_id", "sede_nombre"])

    data = _try_parse_encrypted_response(resp)
    if not isinstance(data, list):
        return pd.DataFrame(columns=["sede_id", "sede_nombre"])
    return pd.DataFrame(
        [{"sede_id": s.get("id"), "sede_nombre": s.get("nombre")} for s in (data or [])]
    )



@st.cache_data(show_spinner=False, ttl=300)
def api_exportar_empleados_completos() -> pd.DataFrame:
    url = f"{API_URL_BASE}/exportacion/empleados"
    data = {"solo_nif": 0}

    resp = safe_request("POST", url, data=data)
    if resp is None:
        return pd.DataFrame(columns=["nif", "nombre_completo", "departamento_id", "empresa_id", "sede_id", "num_empleado", "empleado_id"])
    try:
        resp.raise_for_status()
    except Exception:
        _safe_fail(Exception(f"HTTP {getattr(resp,'status_code', 'ERR')} exportacion/empleados"))
        return pd.DataFrame(columns=["nif", "nombre_completo", "departamento_id", "empresa_id", "sede_id", "num_empleado", "empleado_id"])

    data_dec = _try_parse_encrypted_response(resp)
    if not isinstance(data_dec, list):
        return pd.DataFrame(columns=["nif", "nombre_completo", "departamento_id", "empresa_id", "sede_id", "num_empleado", "empleado_id"])

    lista = []
    for e in (data_dec or []):
        if not isinstance(e, dict):
            continue
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

        # Fuente de enlace con /informes/empleados: Nº empleado <-> num_empleado.
        # No se utiliza el ID interno de CRECE como sustituto.
        num_empleado = (
            e.get("num_empleado")
            or e.get("Num_empleado")
            or e.get("numEmpleado")
            or e.get("numero_empleado")
            or e.get("Numero_empleado")
            or e.get("numeroEmpleado")
            or e.get("employee_number")
            or e.get("employeeNumber")
        )

        empleado_id = (
            e.get("id")
            or e.get("ID")
            or e.get("empleado_id")
            or e.get("id_empleado")
            or e.get("employee_id")
        )

        row = {
            "nif": e.get("nif"),
            "nombre_completo": nombre_completo,
            "departamento_id": e.get("departamento"),
            "empresa_id": empresa_id,
            "sede_id": sede_id,
            "num_empleado": str(num_empleado).strip() if num_empleado is not None else "",
            "empleado_id": _canonical_crece_id(empleado_id),
        }

        for k in [
            "deleted_at", "activo", "estado", "situacion", "fecha_baja",
            "fecha_fin_contrato", "fin_contrato", "contrato_activo", "en_activo",
        ]:
            if k in e:
                row[k] = e.get(k)

        lista.append(row)

    df = pd.DataFrame(lista)
    if not df.empty:
        df["nif"] = df["nif"].fillna("").astype(str).str.upper().str.strip()
        df["num_empleado"] = df["num_empleado"].astype(str).str.strip()
        df["empleado_id"] = df.get("empleado_id", pd.Series("", index=df.index)).apply(_canonical_crece_id)
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


def _clock_to_minutes(value):
    if value is None:
        return None
    try:
        if pd.isna(value):
            return None
    except Exception:
        pass
    s = str(value).strip()
    if not s:
        return None
    try:
        parts = s.split(":")
        if len(parts) >= 2:
            h = int(parts[0])
            m = int(parts[1])
            if 0 <= h <= 23 and 0 <= m <= 59:
                return h * 60 + m
    except Exception:
        return None
    return None


@st.cache_data(show_spinner=False, ttl=3600)
def api_exportar_horarios() -> dict:
    """Mapa de horarios CRECE por ID, usado para conocer el inicio real del turno."""
    url = f"{API_URL_BASE}/exportacion/horarios"
    try:
        resp = safe_request("POST", url)
        if resp is None:
            return {}
        resp.raise_for_status()
        data_dec = _try_parse_encrypted_response(resp)
        if not isinstance(data_dec, list):
            return {}
        out = {}
        for h in data_dec:
            if not isinstance(h, dict):
                continue

            _ok_id, _hid_raw = _row_get_alias(h, ["id", "horario id", "horario_id"])
            hid = _canonical_crece_id(_hid_raw if _ok_id else h.get("id"))
            if not hid:
                continue

            _ok_ini, _ini_raw = _row_get_alias(
                h, ["hora_inicio", "hora inicio", "inicio", "horaInicio"]
            )
            start_min = _clock_to_minutes(_ini_raw if _ok_ini else None)

            # Algunas respuestas/versiones pueden no exponer hora_inicio con la
            # etiqueta literal del manual. Como fallback, extraemos el primer
            # HH:MM del horario_texto oficial de CRECE; nunca se inventa una
            # hora de turno.
            if start_min is None:
                _ok_txt, _txt_raw = _row_get_alias(
                    h, ["horario_texto", "horario texto", "texto", "descripcion", "descripción"]
                )
                if _ok_txt and _txt_raw not in (None, ""):
                    txt = str(_txt_raw)
                    for token in txt.replace("-", " ").replace("/", " ").replace(";", " ").split():
                        cand = token.strip(" ,()[]{}")
                        m = _clock_to_minutes(cand)
                        if m is not None:
                            start_min = m
                            break

            _ok_dur, _dur_raw = _row_get_alias(
                h, ["duracion_computada", "duración computada", "duracion computada"]
            )
            _ok_libre, _libre_val = _row_get_alias(h, ["libre"])
            _ok_abrev, _abrev_val = _row_get_alias(h, ["abreviatura"])

            libre_raw = str(_libre_val if _ok_libre else "").strip().lower()
            out[hid] = {
                "hora_inicio_min": start_min,
                "duracion_min": _duration_value_to_minutes(_dur_raw if _ok_dur else None),
                "libre": libre_raw in {"1", "true", "t", "si", "sí", "yes"},
                "abreviatura": str(_abrev_val if _ok_abrev else "").strip(),
            }
        return out
    except Exception as exc:
        _safe_fail(exc)
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



def _parse_tiempo_trabajado_payload(parsed) -> tuple[pd.DataFrame, bool]:
    """Normaliza la respuesta documentada de /tiempo-trabajado.

    Devuelve (dataframe, estructura_reconocida). Un empleado solo se incorpora
    cuando CRECE devuelve explícitamente ``tiempoContabilizado``; ausencia de
    dato nunca se transforma en cero.
    """
    cols = ["nif", "tiempoEfectivo_seg", "tiempoContabilizado_seg"]
    filas: list[dict] = []
    recognized = False

    def add_row(key, val, identifier_kind: str = "nif"):
        nonlocal recognized
        if isinstance(val, dict):
            has_tc = "tiempoContabilizado" in val
            has_te = "tiempoEfectivo" in val
            if not (has_tc or has_te):
                return
            recognized = True
            nif_val = val.get("nif")
            if not nif_val and identifier_kind == "nif":
                nif_val = key
            nif_s = str(nif_val or "").upper().strip()
            if not nif_s:
                return
            filas.append({
                "nif": nif_s,
                "tiempoEfectivo_seg": val.get("tiempoEfectivo"),
                "tiempoContabilizado_seg": val.get("tiempoContabilizado"),
            })
            return

        if isinstance(val, (list, tuple)) and len(val) >= 4 and identifier_kind == "nif":
            recognized = True
            nif_s = str(key or "").upper().strip()
            if nif_s:
                filas.append({
                    "nif": nif_s,
                    "tiempoEfectivo_seg": val[-2],
                    "tiempoContabilizado_seg": val[-1],
                })

    def walk(obj):
        nonlocal recognized
        if isinstance(obj, list):
            if len(obj) == 0:
                recognized = True
                return
            for item in obj:
                if isinstance(item, dict):
                    nif_v = item.get("nif")
                    if "tiempoContabilizado" in item or "tiempoEfectivo" in item:
                        add_row(nif_v, item, "nif")
            return

        if not isinstance(obj, dict):
            return

        # Wrappers habituales, si existen.
        for wrapper in ("data", "resultado", "result", "results", "items"):
            if wrapper in obj and isinstance(obj.get(wrapper), (dict, list)):
                walk(obj.get(wrapper))
                if recognized:
                    return

        # Variante: {"nif": {"123...": {...}, ...}}
        for kind in ("nif", "email", "num_seg_social", "num_empleado"):
            group = obj.get(kind)
            if isinstance(group, dict):
                if "tiempoContabilizado" in group or "tiempoEfectivo" in group:
                    add_row(group.get(kind), group, kind)
                else:
                    for key, val in group.items():
                        add_row(key, val, kind)
                if recognized:
                    return
            elif isinstance(group, list):
                if len(group) == 0:
                    recognized = True
                for item in group:
                    if isinstance(item, dict):
                        add_row(item.get("nif"), item, kind)
                if recognized:
                    return

        # Forma directa documentada en muchas instalaciones: {NIF: {...}}.
        for key, val in obj.items():
            add_row(key, val, "nif")

    walk(parsed)
    df = pd.DataFrame(filas, columns=cols)
    if not df.empty:
        df["nif"] = df["nif"].astype(str).str.upper().str.strip()
        df = df.drop_duplicates(subset=["nif"], keep="last").reset_index(drop=True)
    return df, bool(recognized)




def api_exportar_tiempo_trabajado(desde: str, hasta: str, nifs=None) -> tuple[pd.DataFrame, bool]:
    """Consulta tiempo trabajado y distingue respuesta válida de fallo de API."""
    url = f"{API_URL_BASE}/exportacion/tiempo-trabajado"
    payload = [("desde", desde), ("hasta", hasta)]

    if nifs:
        for v in nifs:
            s = str(v).strip() if v is not None else ""
            if s:
                # El manual define nif como Array; PHP recibe arrays mediante nif[].
                payload.append(("nif[]", s))

    empty = pd.DataFrame(columns=["nif", "tiempoEfectivo_seg", "tiempoContabilizado_seg"])
    try:
        resp = safe_request("POST", url, data=payload)
        if resp is None:
            return empty, False
        resp.raise_for_status()

        data_dec = _try_parse_encrypted_response(resp)
        if data_dec is None:
            return empty, False
        df, recognized = _parse_tiempo_trabajado_payload(data_dec)
        return df, recognized

    except Exception as e:
        _safe_fail(e)
        return empty, False





@st.cache_data(show_spinner=False, ttl=300)
def _cached_tiempo_contabilizado_map(
    d0_iso: str,
    d1_iso: str,
    nifs_fingerprint: str,
    _nifs: tuple[str, ...],
) -> dict:
    """Cache pseudonimizada de tiempoContabilizado diario.

    CRECE se consulta por día porque RRHH necesita la dimensión diaria. Se usa
    el mismo rango D..D que ya admite la instalación; si CRECE rechaza o no
    devuelve una estructura interpretable, ese día queda marcado como fallido
    y nunca se convierte en cero.
    """
    try:
        d0 = datetime.strptime(d0_iso, "%Y-%m-%d").date()
        d1 = datetime.strptime(d1_iso, "%Y-%m-%d").date()
    except Exception:
        return {"values": {}, "failed_days": []}

    nifs = [str(x).upper().strip() for x in (_nifs or ()) if str(x).strip()]
    if not nifs:
        return {"values": {}, "failed_days": []}

    days = [d.strftime("%Y-%m-%d") for d in _iter_days(d0, d1)]
    if not days:
        return {"values": {}, "failed_days": []}

    out: dict[tuple[str, str], int] = {}
    failed_days: set[str] = set()

    def _fetch_day(day: str):
        df_tc, ok = api_exportar_tiempo_trabajado(day, day, nifs=nifs)
        return day, df_tc, ok

    with ThreadPoolExecutor(max_workers=_max_workers_days(len(days))) as exe:
        futs = [exe.submit(_fetch_day, day) for day in days]
        for fut in as_completed(futs):
            try:
                day, df_tc, ok = fut.result()
            except Exception as exc:
                _safe_fail(exc)
                continue
            if not ok:
                failed_days.add(day)
                continue
            if df_tc is None or df_tc.empty:
                continue
            for _, rr in df_tc.iterrows():
                nif_tc = str(rr.get("nif") or "").upper().strip()
                if not nif_tc:
                    continue
                seg = rr.get("tiempoContabilizado_seg")
                if seg is None:
                    continue
                try:
                    if pd.isna(seg):
                        continue
                except Exception:
                    pass
                try:
                    num = float(str(seg).replace(",", "."))
                    if num < 0:
                        continue
                    mins = int(round(num / 60.0))
                except Exception:
                    continue
                out[(_hash_nif(nif_tc), day)] = max(0, mins)

    return {"values": out, "failed_days": sorted(failed_days)}




def build_tiempo_contabilizado_map(d0: date, d1: date, nifs: list[str]) -> tuple[dict, list[str]]:
    """Devuelve TC diario y fechas cuyo endpoint no pudo leerse.

    Mapa: {(NIF, YYYY-MM-DD): minutos_contabilizados}. Un cero solo existe si
    CRECE lo devolvió explícitamente.
    """
    nifs_norm = tuple(sorted({str(x).upper().strip() for x in (nifs or []) if str(x).strip()}))
    if not nifs_norm:
        return {}, []
    fp = _fingerprint_nifs(nifs_norm)
    cached = _cached_tiempo_contabilizado_map(
        d0.strftime("%Y-%m-%d"), d1.strftime("%Y-%m-%d"), fp, nifs_norm
    )
    hashed = (cached or {}).get("values", {}) or {}
    failed_days = list((cached or {}).get("failed_days", []) or [])
    hash_to_nif = {_hash_nif(n): n for n in nifs_norm}
    out: dict[tuple[str, str], int] = {}
    for (hn, day), mins in hashed.items():
        nif = hash_to_nif.get(hn)
        if nif:
            out[(nif, day)] = int(mins)
    return out, failed_days




def api_informe_empleados(fecha_desde: str, fecha_hasta: str):
    """Consulta robusta y SERIAL de /api/informes/empleados.

    Versión instrumentada: registra únicamente metadatos técnicos no sensibles
    para distinguir HTTP/rate-limit/timeout de errores de descifrado o parsing.
    """
    global _INFORME_LAST_FINISH_MONO

    url = f"{API_URL_BASE}/informes/empleados"
    body = {"fecha_desde": fecha_desde, "fecha_hasta": fecha_hasta}

    def _parse_valid(resp, mode: str):
        if resp is None:
            _diag_informe_event(kind="parse", label=f"{fecha_desde}..{fecha_hasta}:{mode}", outcome="no_response")
            return None
        status = getattr(resp, "status_code", None)
        try:
            resp.raise_for_status()
        except Exception:
            _diag_informe_event(kind="parse", label=f"{fecha_desde}..{fecha_hasta}:{mode}", outcome="http_error", status=status)
            return None
        parsed = _try_parse_encrypted_response(resp)
        if parsed is None:
            _diag_informe_event(kind="parse", label=f"{fecha_desde}..{fecha_hasta}:{mode}", outcome="decrypt_or_json_failed", status=status)
            return None
        rows = _extract_rows_from_informe(parsed)
        if not rows:
            _diag_informe_event(kind="parse", label=f"{fecha_desde}..{fecha_hasta}:{mode}", outcome="no_rows", status=status)
            return None
        _diag_informe_event(kind="parse", label=f"{fecha_desde}..{fecha_hasta}:{mode}", outcome="ok", status=status, rows=len(rows))
        return parsed

    with _INFORME_GATE_LOCK:
        elapsed = time.monotonic() - float(_INFORME_LAST_FINISH_MONO or 0.0)
        if elapsed < INFORME_MIN_INTERVAL_SECONDS:
            time.sleep(INFORME_MIN_INTERVAL_SECONDS - elapsed)

        try:
            label_form = f"{fecha_desde}..{fecha_hasta}:form"
            resp = safe_request("POST", url, data=body, timeout=(5, 75), trace_label=label_form)
            parsed = _parse_valid(resp, "form")
            if parsed is not None:
                return parsed

            status = getattr(resp, "status_code", None) if resp is not None else None
            if status in {400, 415, 422}:
                label_json = f"{fecha_desde}..{fecha_hasta}:json"
                resp_json = safe_request("POST", url, json_body=body, timeout=(5, 75), trace_label=label_json)
                parsed_json = _parse_valid(resp_json, "json")
                if parsed_json is not None:
                    return parsed_json

            return None
        except Exception as e:
            _diag_informe_event(kind="api_exception", label=f"{fecha_desde}..{fecha_hasta}", error=type(e).__name__)
            _safe_fail(e)
            return None
        finally:
            _INFORME_LAST_FINISH_MONO = time.monotonic()



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


# ============================================================
# DIAGNÓSTICO TEMPORAL — /api/informes/turnos
# ============================================================

_TURNOS_POS = {
    "turno_id": 0,
    "empleado_id": 1,
    "num_empleado": 2,
    "nombre": 3,
    "fecha": 4,
    "horario_id": 5,
    "horario_abreviatura": 6,
    "horario_color": 7,
    "horario_duracion_computada": 8,
    "horario_texto": 9,
    "ausencia": 10,
}


def _extract_generic_rows(payload):
    """Extrae filas de una respuesta de informe sin asumir un wrapper concreto."""
    if payload is None:
        return []
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        # Wrappers habituales en APIs/reportes.
        for key in ("data", "datos", "results", "resultado", "rows", "turnos"):
            value = payload.get(key)
            if isinstance(value, list):
                return value
            if isinstance(value, dict):
                nested = _extract_generic_rows(value)
                if nested:
                    return nested
        # Como último recurso, si todos los valores son filas, devolverlos.
        vals = list(payload.values())
        if vals and all(isinstance(v, (dict, list, tuple)) for v in vals):
            return vals
    return []


def _turno_value(row, aliases, pos_key):
    if isinstance(row, dict):
        found, value = _row_get_alias(row, aliases)
        return value if found else None
    if isinstance(row, (list, tuple)):
        pos = _TURNOS_POS[pos_key]
        return row[pos] if len(row) > pos else None
    return None


def _diag_json(value) -> str:
    """Representación compacta y estable para inspeccionar el nuevo campo ausencia."""
    if value is None:
        return ""
    if isinstance(value, float) and pd.isna(value):
        return ""
    if isinstance(value, (dict, list, tuple)):
        try:
            return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
        except Exception:
            return str(value)
    return str(value).strip()


def _absence_label(value) -> str:
    """Extrae una etiqueta legible sin asumir todavía la estructura exacta de CRECE."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        for key in (
            "tipo", "nombre", "descripcion", "descripción", "motivo",
            "ausencia", "label", "texto", "name", "description"
        ):
            if key in value and value.get(key) not in (None, ""):
                return _diag_json(value.get(key))
        return _diag_json(value)
    if isinstance(value, (list, tuple)):
        labels = [_absence_label(v) for v in value]
        labels = [x for x in labels if x]
        return " | ".join(dict.fromkeys(labels)) if labels else _diag_json(value)
    return str(value).strip()


def _normalize_turno_row(row):
    if not isinstance(row, (dict, list, tuple)):
        return None
    return {
        "Turno ID": _turno_value(row, ["Turno ID", "turno_id", "id_turno"], "turno_id"),
        "Empleado ID": _turno_value(row, ["Empleado ID", "empleado_id", "id_empleado"], "empleado_id"),
        "Nº empleado": _turno_value(
            row,
            ["Número de empleado", "Nº empleado", "Numero empleado", "num_empleado", "numero_empleado"],
            "num_empleado",
        ),
        "Nombre y apellidos": _turno_value(
            row, ["Nombre y apellidos", "Nombre", "nombre_apellidos", "nombre"], "nombre"
        ),
        "Fecha": _turno_value(row, ["Fecha", "fecha"], "fecha"),
        "Horario ID": _turno_value(row, ["Horario ID", "horario_id", "id_horario"], "horario_id"),
        "Horario abreviatura": _turno_value(
            row, ["Horario abreviatura", "horario_abreviatura", "abreviatura"], "horario_abreviatura"
        ),
        "Horario color": _turno_value(row, ["Horario color", "horario_color", "color"], "horario_color"),
        "Horario duración computada": _turno_value(
            row,
            ["Horario duración computada", "Horario duracion computada", "horario_duracion_computada", "duracion_computada"],
            "horario_duracion_computada",
        ),
        "Horario texto": _turno_value(row, ["Horario texto", "horario_texto"], "horario_texto"),
        "Ausencia": _turno_value(
            row,
            ["ausencia", "Ausencia", "absence", "tipo_ausencia", "tipoAusencia"],
            "ausencia",
        ),
    }


def _extract_http_error_message(resp) -> str:
    if resp is None:
        return ""
    try:
        obj = resp.json()
        if isinstance(obj, dict):
            return str(obj.get("message") or obj.get("error") or obj.get("errors") or "")[:400]
        if obj is not None:
            return str(obj)[:400]
    except Exception:
        pass
    try:
        return str(resp.text or "")[:400]
    except Exception:
        return ""


def _blocked_retry_seconds(message: str) -> float | None:
    """Extrae 'Intente de nuevo en N segundos' de los 422 de CRECE."""
    import re
    m = re.search(r"(?:nuevo|again)\s+en\s+(\d+)\s+seg", str(message or ""), flags=re.I)
    if not m:
        return None
    try:
        return max(0.0, min(65.0, float(m.group(1))))
    except Exception:
        return None


def api_informe_turnos(fecha_desde: str, fecha_hasta: str):
    """Obtiene /api/informes/turnos respetando el límite oficial de 1 petición/minuto.

    CRECE confirmó que todos los endpoints de informes están limitados a una
    petición por minuto. Si el servidor devuelve el 422 temporal con el tiempo
    restante, se espera exactamente ese cooldown y se hace un único reintento.
    """
    global _INFORME_LAST_FINISH_MONO

    url = f"{API_URL_BASE}/informes/turnos"
    body = {"fecha_desde": fecha_desde, "fecha_hasta": fecha_hasta}

    with _INFORME_GATE_LOCK:
        elapsed = time.monotonic() - float(_INFORME_LAST_FINISH_MONO or 0.0)
        if elapsed < INFORME_MIN_INTERVAL_SECONDS:
            time.sleep(INFORME_MIN_INTERVAL_SECONDS - elapsed)

        last_status = None
        last_error = ""
        total_t0 = time.monotonic()
        try:
            for attempt in range(2):
                resp = safe_request("POST", url, data=body, timeout=(5, 90))
                if resp is None:
                    return {
                        "ok": False,
                        "status": None,
                        "elapsed_ms": int(round((time.monotonic() - total_t0) * 1000)),
                        "error": "No se ha podido conectar con /informes/turnos.",
                        "rows": [],
                    }

                last_status = int(resp.status_code)
                if last_status == 200:
                    parsed = _try_parse_encrypted_response(resp)
                    if parsed is None:
                        return {
                            "ok": False,
                            "status": 200,
                            "elapsed_ms": int(round((time.monotonic() - total_t0) * 1000)),
                            "error": "HTTP 200 pero no se pudo descifrar/interpretar la respuesta.",
                            "rows": [],
                        }
                    raw_rows = _extract_generic_rows(parsed)
                    rows = []
                    for raw in raw_rows:
                        item = _normalize_turno_row(raw)
                        if item is not None:
                            rows.append(item)
                    return {
                        "ok": True,
                        "status": 200,
                        "elapsed_ms": int(round((time.monotonic() - total_t0) * 1000)),
                        "error": "",
                        "rows": rows,
                    }

                last_error = _extract_http_error_message(resp) or f"HTTP {last_status}"
                if last_status == 422 and attempt == 0:
                    wait = _blocked_retry_seconds(last_error)
                    if wait is not None:
                        time.sleep(wait + 1.0)
                        continue
                break

            return {
                "ok": False,
                "status": last_status,
                "elapsed_ms": int(round((time.monotonic() - total_t0) * 1000)),
                "error": last_error or (f"HTTP {last_status}" if last_status else "Error de informe de turnos"),
                "rows": [],
            }
        finally:
            _INFORME_LAST_FINISH_MONO = time.monotonic()


def _build_turnos_diagnostic(result: dict, fecha_desde: date, fecha_hasta: date, scope_emp_df: pd.DataFrame):
    """Genera detalle, matriz empleado/día y resumen del informe de turnos."""
    rows = list((result or {}).get("rows", []) or [])
    detail = pd.DataFrame(rows)
    if detail.empty:
        detail = pd.DataFrame(columns=[
            "Turno ID", "Empleado ID", "Nº empleado", "Nombre y apellidos", "Fecha",
            "Horario ID", "Horario abreviatura", "Horario color",
            "Horario duración computada", "Horario texto", "Ausencia",
        ])

    detail["num_code"] = detail.get("Nº empleado", pd.Series(index=detail.index, dtype=object)).apply(_canonical_emp_code)
    # Misma regla de fecha que la lógica productiva: CRECE usa también DD/MM/YYYY.
    detail["Fecha"] = detail.get("Fecha", pd.Series(index=detail.index, dtype=object)).apply(
        lambda x: (_parse_date_any(x).strftime("%Y-%m-%d") if _parse_date_any(x) is not None else "")
    )
    detail["Duración minutos"] = detail.get(
        "Horario duración computada", pd.Series(index=detail.index, dtype=object)
    ).apply(_duration_value_to_minutes)
    detail["Duración HH:MM"] = detail["Duración minutos"].apply(
        lambda x: segundos_a_hhmm(int(x) * 60) if pd.notna(x) else ""
    )
    detail["Ausencia raw"] = detail.get(
        "Ausencia", pd.Series(index=detail.index, dtype=object)
    ).apply(_diag_json)
    detail["Ausencia tipo"] = detail.get(
        "Ausencia", pd.Series(index=detail.index, dtype=object)
    ).apply(_absence_label)
    detail["Tiene ausencia"] = detail["Ausencia raw"].astype(str).str.strip().ne("")

    scope = scope_emp_df.copy()
    if "num_empleado" not in scope.columns:
        scope["num_empleado"] = ""
    scope["num_code"] = scope["num_empleado"].apply(_canonical_emp_code)
    scope = scope[scope["num_code"].astype(str).str.strip().ne("")].copy()
    scope_codes = set(scope["num_code"].tolist())
    if scope_codes:
        detail = detail[detail["num_code"].isin(scope_codes)].copy()

    name_map = dict(zip(scope["num_code"], scope.get("nombre_completo", pd.Series("", index=scope.index)).fillna("")))
    empresa_map = dict(zip(scope["num_code"], scope.get("Empresa", pd.Series("", index=scope.index)).fillna("")))
    sede_map_local = dict(zip(scope["num_code"], scope.get("Sede", pd.Series("", index=scope.index)).fillna("")))
    dept_map = dict(zip(scope["num_code"], scope.get("departamento_nombre", pd.Series("", index=scope.index)).fillna("")))

    if not detail.empty:
        detail["Nombre app"] = detail["num_code"].map(name_map).fillna("")
        detail["Empresa"] = detail["num_code"].map(empresa_map).fillna("")
        detail["Sede"] = detail["num_code"].map(sede_map_local).fillna("")
        detail["Departamento"] = detail["num_code"].map(dept_map).fillna("")

    # Agregación por empleado/día de todas las filas de turno encontradas.
    if detail.empty:
        daily_found = pd.DataFrame(columns=["num_code", "Fecha", "Nº turnos", "Jornada turnos minutos", "Horarios"])
    else:
        tmp = detail.copy()
        tmp["Duración minutos num"] = pd.to_numeric(tmp["Duración minutos"], errors="coerce").fillna(0).astype(int)
        daily_found = (
            tmp.groupby(["num_code", "Fecha"], as_index=False)
            .agg(
                **{
                    "Nº turnos": ("Turno ID", "size"),
                    "Jornada turnos minutos": ("Duración minutos num", "sum"),
                    "Horarios": ("Horario texto", lambda s: " | ".join(dict.fromkeys(str(x) for x in s if str(x).strip()))),
                    "Abreviaturas": ("Horario abreviatura", lambda s: " | ".join(dict.fromkeys(str(x) for x in s if str(x).strip()))),
                    "Ausencias": ("Ausencia tipo", lambda s: " | ".join(dict.fromkeys(str(x) for x in s if str(x).strip()))),
                    "Ausencias raw": ("Ausencia raw", lambda s: " | ".join(dict.fromkeys(str(x) for x in s if str(x).strip()))),
                }
            )
        )

    days = []
    cur = fecha_desde
    while cur <= fecha_hasta:
        days.append(cur.strftime("%Y-%m-%d"))
        cur += timedelta(days=1)

    matrix_rows = []
    found_lookup = {
        (str(r["num_code"]), str(r["Fecha"])): r
        for _, r in daily_found.iterrows()
    }
    for _, emp in scope.sort_values(["nombre_completo"], kind="mergesort").iterrows():
        code = str(emp.get("num_code") or "")
        for day in days:
            hit = found_lookup.get((code, day))
            mins = int(hit.get("Jornada turnos minutos", 0)) if hit is not None else 0
            n_turnos = int(hit.get("Nº turnos", 0)) if hit is not None else 0
            matrix_rows.append({
                "Fecha": day,
                "Nº empleado": str(emp.get("num_empleado") or ""),
                "Nombre": str(emp.get("nombre_completo") or ""),
                "Empresa": str(emp.get("Empresa") or ""),
                "Sede": str(emp.get("Sede") or ""),
                "Departamento": str(emp.get("departamento_nombre") or ""),
                "Nº turnos": n_turnos,
                "Jornada turnos": segundos_a_hhmm(int(mins) * 60),
                "Jornada turnos minutos": mins,
                "Estado turno": "CON TURNO" if hit is not None else "SIN FILA DE TURNO",
                "Abreviaturas": str(hit.get("Abreviaturas") or "") if hit is not None else "",
                "Horario texto": str(hit.get("Horarios") or "") if hit is not None else "",
                "Ausencia": str(hit.get("Ausencias") or "") if hit is not None else "",
                "Ausencia raw": str(hit.get("Ausencias raw") or "") if hit is not None else "",
            })
    matrix = pd.DataFrame(matrix_rows)

    if matrix.empty:
        summary = pd.DataFrame(columns=["Nº empleado", "Nombre", "Días con turno", "Días sin fila", "Total turnos"])
    else:
        summary = (
            matrix.groupby(["Nº empleado", "Nombre"], as_index=False)
            .agg(
                **{
                    "Días con turno": ("Estado turno", lambda s: int((s == "CON TURNO").sum())),
                    "Días sin fila": ("Estado turno", lambda s: int((s == "SIN FILA DE TURNO").sum())),
                    "Días con ausencia": ("Ausencia", lambda s: int(s.astype(str).str.strip().ne("").sum())),
                    "Total minutos": ("Jornada turnos minutos", "sum"),
                }
            )
        )
        summary["Total turnos"] = summary["Total minutos"].apply(lambda x: segundos_a_hhmm(int(x) * 60))
        summary = summary.drop(columns=["Total minutos"])

    detail_cols = [
        "Fecha", "Nº empleado", "Nombre y apellidos", "Nombre app", "Empresa", "Sede", "Departamento",
        "Turno ID", "Empleado ID", "Horario ID", "Horario abreviatura",
        "Horario duración computada", "Duración HH:MM", "Duración minutos", "Horario texto",
        "Ausencia tipo", "Ausencia raw", "Tiene ausencia",
    ]
    detail_cols = [c for c in detail_cols if c in detail.columns]
    detail = detail[detail_cols].sort_values([c for c in ["Fecha", "Nombre app", "Nº empleado"] if c in detail.columns], kind="mergesort") if not detail.empty else detail

    return detail.reset_index(drop=True), matrix.reset_index(drop=True), summary.reset_index(drop=True)


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
            "employee_number", "employeeNumber",
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


def _canonical_absence(value) -> str:
    """Normaliza un valor escalar de ausencia confirmado por CRECE."""
    raw = _absence_label(value)
    if not raw:
        return ""
    s = unicodedata.normalize("NFKD", str(raw))
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    s = s.lower().replace("_", " ").replace("-", " ")
    s = " ".join(s.split())
    aliases = {
        "no contrato": "no-contrato",
        "festivo": "festivo",
        "permiso": "permiso",
        "vacaciones": "vacaciones",
        "vacaciones medio dia": "vacaciones medio dia",
        "asuntos propios": "asuntos propios",
        # Observado en producción en /informes/turnos aunque no figuró en la
        # última enumeración escrita del proveedor.
        "baja": "baja",
    }
    return aliases.get(s, s)


def _absence_types(value) -> set[str]:
    """Extrae uno o varios tipos sin asumir que `ausencia` sea siempre string."""
    if value is None:
        return set()
    if isinstance(value, (list, tuple, set)):
        out = set()
        for item in value:
            out.update(_absence_types(item))
        return {x for x in out if x}
    if isinstance(value, dict):
        for key in ("tipo", "nombre", "descripcion", "descripción", "motivo", "ausencia", "label", "texto", "name", "description"):
            if key in value and value.get(key) not in (None, ""):
                return _absence_types(value.get(key))
        return {_canonical_absence(value)} if _canonical_absence(value) else set()

    raw = str(value).strip()
    if not raw:
        return set()
    # Por compatibilidad con posibles respuestas múltiples serializadas.
    parts = [p.strip() for p in raw.replace(";", "|").split("|") if p.strip()]
    out = {_canonical_absence(p) for p in parts}
    return {x for x in out if x}


def _expected_minutes_from_turno(base_minutes, base_known: bool, absences: set[str]) -> tuple[int | None, bool]:
    """Aplica la semántica diaria de Turnos/Ausencias confirmada por CRECE."""
    absences = set(absences or set())
    contracted = "no-contrato" not in absences
    if not base_known:
        return None, contracted
    base = max(0, int(base_minutes or 0))
    if not contracted:
        return 0, False
    if absences.intersection({"festivo", "vacaciones", "asuntos propios", "baja"}):
        return 0, True
    if "vacaciones medio dia" in absences:
        return int(round(base / 2.0)), True
    unknown = absences.difference({"permiso"})
    if unknown:
        return None, True
    return base, True


@st.cache_data(show_spinner=False, ttl=900)
def _cached_turnos_period_metrics(fecha_desde: str, fecha_hasta: str) -> dict:
    """Devuelve solo métricas pseudonimizadas de /informes/turnos.

    No se cachean nombres, NIF ni IDs CRECE en claro. La respuesta bruta se
    transforma dentro de esta función y el valor persistido contiene hashes.
    """
    result = api_informe_turnos(fecha_desde, fecha_hasta)
    if not result.get("ok"):
        raise RuntimeError(result.get("error") or "No se pudo obtener /informes/turnos")

    horarios = api_exportar_horarios()
    grouped: dict[tuple[str, str], dict] = {}
    unknown_absences: set[str] = set()

    for row in list(result.get("rows") or []):
        emp_id = _canonical_crece_id(row.get("Empleado ID"))
        num_code = _canonical_emp_code(row.get("Nº empleado"))
        # CRECE puede devolver Fecha como DD/MM/YYYY. No usar pd.to_datetime
        # genérico aquí: en fechas ambiguas (p. ej. 08/09/2026) pandas puede
        # interpretarlo como MM/DD/YYYY y cruzar meses.
        try:
            day = _parse_date_any(row.get("Fecha"))
            day_iso = day.strftime("%Y-%m-%d") if day is not None else ""
        except Exception:
            day_iso = ""
        if not day_iso or not (emp_id or num_code):
            continue

        emp_hash = _hash_crece_employee_id(emp_id) if emp_id else ""
        num_hash = _hash_emp_code(num_code) if num_code else ""
        group_key = ((emp_hash or f"NUM:{num_hash}"), day_iso)
        g = grouped.setdefault(group_key, {
            "emp_hash": emp_hash,
            "num_hash": num_hash,
            "day": day_iso,
            "durations": [],
            "blank_schedule_rows": 0,
            "invalid_schedule_rows": 0,
            "absence_types": set(),
            "shift_starts": [],
        })

        row_absences = _absence_types(row.get("Ausencia"))
        for absence in row_absences:
            g["absence_types"].add(absence)
            if absence not in {
                "no-contrato", "festivo", "permiso", "vacaciones",
                "vacaciones medio dia", "asuntos propios", "baja",
            }:
                unknown_absences.add(absence)

        horario_id = _canonical_crece_id(row.get("Horario ID"))
        if not horario_id:
            # Confirmado por CRECE: empleado+día sin Horario ID = 0 horas
            # programadas por ausencia de horario en el cuadrante.
            g["blank_schedule_rows"] += 1
            continue

        dur = _duration_value_to_minutes(row.get("Horario duración computada"))
        if dur is None:
            g["invalid_schedule_rows"] += 1
            continue
        g["durations"].append(max(0, int(dur)))

        if int(dur) > 0:
            hinfo = horarios.get(horario_id, {}) if isinstance(horarios, dict) else {}
            start_min = hinfo.get("hora_inicio_min") if isinstance(hinfo, dict) else None
            if start_min is not None:
                try:
                    g["shift_starts"].append(int(start_min))
                except Exception:
                    pass

    records = []
    for g in grouped.values():
        durations = list(g.get("durations") or [])
        blank_rows = int(g.get("blank_schedule_rows") or 0)
        invalid_rows = int(g.get("invalid_schedule_rows") or 0)
        absences = set(g.get("absence_types") or set())

        if durations:
            base_minutes = int(sum(durations))
            base_known = True
        elif blank_rows > 0 and invalid_rows == 0:
            base_minutes = 0
            base_known = True
        else:
            base_minutes = None
            base_known = False

        expected, contracted = _expected_minutes_from_turno(base_minutes, base_known, absences)

        baja_minutes = 0
        if "baja" in absences and base_minutes is not None and int(base_minutes) > 0:
            baja_minutes = int(base_minutes)

        shift_start = None
        starts = [int(x) for x in (g.get("shift_starts") or []) if x is not None]
        if starts and expected is not None and int(expected) > 0:
            shift_start = min(starts)

        records.append({
            "emp_hash": g.get("emp_hash") or "",
            "num_hash": g.get("num_hash") or "",
            "day": g.get("day") or "",
            "expected_minutes": expected,
            "contracted": bool(contracted),
            "baja_minutes": int(baja_minutes),
            "shift_start_min": shift_start,
            "absence_types": tuple(sorted(absences)),
        })

    return {
        "records": records,
        "unknown_absences": sorted(unknown_absences),
        "rows_received": len(result.get("rows") or []),
    }


def build_turnos_daily_maps(
    d0: date,
    d1: date,
    base_emp: pd.DataFrame,
) -> tuple[dict, dict, dict, dict, list[str], list[str]]:
    """Construye jornada diaria, bajas y vigencia desde /informes/turnos.

    Fuentes semánticas confirmadas por CRECE:
    - Horario duración computada = turno programado del día.
    - Sin Horario ID = 0 h programadas (distinto de horario libre, pero ambos 0).
    - no-contrato/festivo/vacaciones/asuntos propios/baja = 0 h esperadas.
    - vacaciones medio dia = 50 % del turno.
    - permiso = mantiene turno; tiempoContabilizado cubre el permiso retribuido.
    """
    if base_emp is None or base_emp.empty or d0 > d1:
        return {}, {}, {}, {}, [], []

    all_days = [d.strftime("%Y-%m-%d") for d in _iter_days(d0, d1)]
    try:
        metrics = _cached_turnos_period_metrics(
            d0.strftime("%Y-%m-%d"), d1.strftime("%Y-%m-%d")
        )
    except Exception as exc:
        _safe_fail(exc)
        return {}, {}, {}, {}, all_days, []

    be = base_emp.copy()
    be["nif"] = be.get("nif", pd.Series("", index=be.index)).fillna("").astype(str).str.upper().str.strip()
    be["empleado_id"] = be.get("empleado_id", pd.Series("", index=be.index)).apply(_canonical_crece_id)
    be["num_code"] = be.get("num_empleado", pd.Series("", index=be.index)).apply(_canonical_emp_code)

    id_to_nif = {}
    for _, row in be.iterrows():
        nif = str(row.get("nif") or "").upper().strip()
        eid = _canonical_crece_id(row.get("empleado_id"))
        if nif and eid:
            id_to_nif[_hash_crece_employee_id(eid)] = nif

    # Fallback por Nº empleado solo si ese número es único en todo el universo
    # permitido. Esto evita atribuciones cruzadas cuando CRECE tiene duplicados.
    num_to_nif = {}
    for _, row in be.iterrows():
        nif = str(row.get("nif") or "").upper().strip()
        code = str(row.get("num_code") or "").strip()
        unique_global = bool(row.get("num_empleado_unique_global", False))
        if nif and code and unique_global:
            num_to_nif[_hash_emp_code(code)] = nif

    hp_out: dict[tuple[str, str], int] = {}
    baja_out: dict[tuple[str, str], int] = {}
    contratado_out: dict[tuple[str, str], bool] = {}
    shift_start_out: dict[tuple[str, str], int] = {}

    for rec in list((metrics or {}).get("records", []) or []):
        nif = id_to_nif.get(str(rec.get("emp_hash") or ""))
        if not nif:
            nif = num_to_nif.get(str(rec.get("num_hash") or ""))
        day = str(rec.get("day") or "")
        if not nif or not day:
            continue

        key = (nif, day)
        contratado_out[key] = bool(rec.get("contracted") is True)

        expected = rec.get("expected_minutes")
        if expected is not None:
            try:
                hp_out[key] = max(0, int(expected))
            except Exception:
                pass

        try:
            baja = max(0, int(rec.get("baja_minutes") or 0))
        except Exception:
            baja = 0
        if baja > 0:
            baja_out[key] = baja

        start_min = rec.get("shift_start_min")
        if start_min is not None:
            try:
                shift_start_out[key] = int(start_min)
            except Exception:
                pass

    unknown_absences = list((metrics or {}).get("unknown_absences", []) or [])
    return hp_out, baja_out, contratado_out, shift_start_out, [], unknown_absences



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
_INFORME_EMP_IDX_DIAS_CONTRATADO = 14
_INFORME_EMP_IDX_HORAS_PROGRAMADAS = 25
_INFORME_EMP_IDX_HORAS_BAJA = 33



def _normalize_informe_employee_row(item):
    if isinstance(item, dict):
        return item
    if isinstance(item, (list, tuple)):
        row = {}
        if len(item) > _INFORME_EMP_IDX_NUM:
            row["Nº empleado"] = item[_INFORME_EMP_IDX_NUM]
        if len(item) > _INFORME_EMP_IDX_DIAS_CONTRATADO:
            row["Días contratado en el periodo"] = item[_INFORME_EMP_IDX_DIAS_CONTRATADO]
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



def _get_dias_contratado_from_row(row: dict):
    """Devuelve (campo_encontrado, días_contratado) del informe CRECE."""
    if not isinstance(row, dict):
        return False, None
    found, value = _row_get_alias(
        row,
        [
            "Días contratado en el periodo", "Dias contratado en el periodo",
            "dias_contratado_periodo", "diasContratadoPeriodo",
            "dias_contratado", "diasContratado",
        ],
    )
    if not found or value is None or isinstance(value, bool):
        return False, None
    try:
        num = float(str(value).strip().replace(",", "."))
        if pd.isna(num) or num < 0:
            return False, None
        return True, num
    except Exception:
        return False, None


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
# DIAGNÓSTICO TEMPORAL — comparación semanal /informes/empleados
# ============================================================

def api_informe_empleados_once_diag(fecha_desde: str, fecha_hasta: str):
    """Una sola petición a /api/informes/empleados, sin retries ni fallback.

    Se usa únicamente para comparar el total semanal de Horas programadas
    con el detalle diario ya descargado de /informes/turnos. No ejecuta la
    consulta normal de la aplicación ni hace llamadas adicionales.
    """
    url = f"{API_URL_BASE}/informes/empleados"
    body = {"fecha_desde": fecha_desde, "fecha_hasta": fecha_hasta}
    t0 = time.monotonic()
    try:
        resp = _get_http_session().post(url, data=body, timeout=(5, 90), verify=True)
    except Exception as exc:
        return {
            "ok": False,
            "status": None,
            "elapsed_ms": int(round((time.monotonic() - t0) * 1000)),
            "error": f"{type(exc).__name__}: {str(exc)[:180]}",
            "rows": [],
        }

    elapsed_ms = int(round((time.monotonic() - t0) * 1000))
    status = int(resp.status_code)
    if status != 200:
        msg = ""
        try:
            obj = resp.json()
            if isinstance(obj, dict):
                msg = str(obj.get("message") or obj.get("error") or obj.get("errors") or "")[:300]
            elif obj is not None:
                msg = str(obj)[:300]
        except Exception:
            try:
                msg = str(resp.text or "")[:300]
            except Exception:
                msg = ""
        return {
            "ok": False,
            "status": status,
            "elapsed_ms": elapsed_ms,
            "error": msg or f"HTTP {status}",
            "rows": [],
        }

    parsed = _try_parse_encrypted_response(resp)
    if parsed is None:
        return {
            "ok": False,
            "status": status,
            "elapsed_ms": elapsed_ms,
            "error": "HTTP 200 pero no se pudo descifrar/interpretar la respuesta.",
            "rows": [],
        }

    raw_rows = _extract_rows_from_informe(parsed)
    rows_out = []
    for idx, row in enumerate(raw_rows):
        code = _get_employee_number_from_row(row)
        found_hp, hp_mins = _get_horas_programadas_minutes_from_row(row)
        found_days, dias_contratado = _get_dias_contratado_from_row(row)
        baja_h = _get_horas_baja_from_row(row)
        rows_out.append({
            "Fila informe": idx + 1,
            "Nº empleado": code,
            "Horas programadas": (segundos_a_hhmm(int(hp_mins) * 60) if found_hp and hp_mins is not None else ""),
            "Horas programadas minutos": (int(hp_mins) if found_hp and hp_mins is not None else None),
            "Días contratado en el periodo": (float(dias_contratado) if found_days and dias_contratado is not None else None),
            "Horas baja": float(baja_h or 0.0),
        })

    return {
        "ok": True,
        "status": status,
        "elapsed_ms": elapsed_ms,
        "error": "",
        "rows": rows_out,
    }



# ============================================================
# DIAGNÓSTICO TEMPORAL — /api/exportacion/vacaciones
# ============================================================

def api_exportacion_vacaciones_once_diag(fecha_inicio: str, fecha_fin: str):
    """Una única petición a /api/exportacion/vacaciones para validar ausencias.

    Solicita únicamente vacaciones aprobadas (Estado=1) en el rango indicado.
    No hace retries ni fallback para mantener la prueba aislada.
    """
    url = f"{API_URL_BASE}/exportacion/vacaciones"
    body = {"fecha_inicio": fecha_inicio, "fecha_fin": fecha_fin, "Estado": 1}
    t0 = time.monotonic()
    try:
        resp = _get_http_session().post(url, data=body, timeout=(5, 90), verify=True)
    except Exception as exc:
        return {
            "ok": False,
            "status": None,
            "elapsed_ms": int(round((time.monotonic() - t0) * 1000)),
            "error": f"{type(exc).__name__}: {str(exc)[:180]}",
            "rows": [],
        }

    elapsed_ms = int(round((time.monotonic() - t0) * 1000))
    status = int(resp.status_code)
    if status != 200:
        msg = ""
        try:
            obj = resp.json()
            if isinstance(obj, dict):
                msg = str(obj.get("message") or obj.get("error") or obj.get("errors") or "")[:300]
            elif obj is not None:
                msg = str(obj)[:300]
        except Exception:
            try:
                msg = str(resp.text or "")[:300]
            except Exception:
                msg = ""
        return {
            "ok": False,
            "status": status,
            "elapsed_ms": elapsed_ms,
            "error": msg or f"HTTP {status}",
            "rows": [],
        }

    parsed = _try_parse_encrypted_response(resp)
    if parsed is None:
        return {
            "ok": False,
            "status": status,
            "elapsed_ms": elapsed_ms,
            "error": "HTTP 200 pero no se pudo descifrar/interpretar la respuesta.",
            "rows": [],
        }

    raw_rows = _extract_generic_rows(parsed)
    rows = []
    for raw in raw_rows:
        if not isinstance(raw, dict):
            continue
        usuario = raw.get("usuario") if isinstance(raw.get("usuario"), dict) else {}
        num_emp = (
            usuario.get("Num_empleado") or usuario.get("num_empleado") or
            usuario.get("Número de empleado") or usuario.get("Nº empleado")
        )
        nombre_parts = [
            usuario.get("Name") or usuario.get("name") or "",
            usuario.get("Primer_apellido") or usuario.get("primer_apellido") or "",
            usuario.get("Segundo_apellido") or usuario.get("segundo_apellido") or "",
        ]
        nombre = " ".join(str(x).strip() for x in nombre_parts if str(x or "").strip()).strip()
        rows.append({
            "Vacaciones ID": raw.get("ID", raw.get("id")),
            "Empleado ID": raw.get("empleado_id", raw.get("Empleado ID")),
            "Nº empleado": num_emp,
            "Nombre": nombre,
            "Fecha inicio": raw.get("fecha_inicio", raw.get("Fecha inicio")),
            "Fecha fin": raw.get("fecha_fin", raw.get("Fecha fin")),
            "Días laborables": raw.get("días_laborables", raw.get("dias_laborables", raw.get("Días laborables"))),
            "Tipo": raw.get("tipo", raw.get("Tipo")),
            "Estado": raw.get("estado", raw.get("Estado")),
        })

    return {
        "ok": True,
        "status": status,
        "elapsed_ms": elapsed_ms,
        "error": "",
        "rows": rows,
    }


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
    """Extrae HP, bajas y contratación por Nº empleado pseudonimizado."""
    hp_by_emp: dict[str, int] = {}
    baja_by_emp: dict[str, int] = {}
    contratado_by_emp: dict[str, int] = {}

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

        found_days, dias_contratado = _get_dias_contratado_from_row(row)
        if found_days and dias_contratado is not None:
            contratado_by_emp[he] = 1 if float(dias_contratado) > 0 else 0

    return {"hp": hp_by_emp, "baja": baja_by_emp, "contratado": contratado_by_emp}



@st.cache_data(show_spinner=False, ttl=900)
def _cached_informe_period_metrics(fecha_desde: str, fecha_hasta: str) -> dict:
    """Métricas de /informes/empleados para el periodo solicitado.

    Se cachean solo hashes de Nº empleado y métricas numéricas; nunca el payload
    completo ni PII. Para dimensión diaria se invoca con fecha_desde=fecha_hasta.
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
) -> tuple[dict, dict, dict, list[str]]:
    """Obtiene el informe CRECE de cada día SIN concurrencia.

    No reconstruye jornadas por diferencias entre informes agregados. Cada
    fecha usa /informes/empleados con fecha_desde=fecha_hasta=D y enlaza
    exclusivamente Nº empleado con num_empleado. Los éxitos quedan cacheados
    por fecha; los fallos se reintentan secuencialmente con enfriamiento.
    """
    if base_emp is None or base_emp.empty or d0 > d1:
        return {}, {}, {}, []

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

    all_days = [d.strftime("%Y-%m-%d") for d in _iter_days(d0, d1)]
    if not emp_hash_to_nif:
        return {}, {}, {}, all_days

    metrics_by_day: dict[str, dict] = {}
    failed_days: set[str] = set()

    # No ThreadPoolExecutor aquí. En la prueba real, las ráfagas concurrentes
    # dejaron casi todo el rango sin informe. Una única petición en vuelo es
    # deliberada: primero exactitud; la caché evita repetir días ya obtenidos.
    for day in all_days:
        metrics = None
        for attempt in range(3):
            if attempt:
                time.sleep(1.25 * attempt)
            try:
                metrics = _cached_informe_period_metrics(day, day)
                if metrics:
                    break
            except Exception as exc:
                _safe_fail(exc)
                metrics = None

        if metrics:
            metrics_by_day[day] = metrics
        else:
            failed_days.add(day)

    hp_out: dict[tuple[str, str], int] = {}
    baja_out: dict[tuple[str, str], int] = {}
    contratado_out: dict[tuple[str, str], bool] = {}
    unavailable_days: set[str] = set(failed_days)

    for day in all_days:
        metrics = metrics_by_day.get(day)
        if metrics is None:
            _diag_informe_event(kind="day", day=day, outcome="no_metrics")
            unavailable_days.add(day)
            continue

        hp_sec = (metrics.get("hp", {}) or {})
        baja_sec = (metrics.get("baja", {}) or {})
        contratado_sec = (metrics.get("contratado", {}) or {})

        # Un HTTP 200 no basta: al menos una persona del alcance debe enlazar
        # por Nº empleado/num_empleado con métricas del informe.
        matched = sum(
            1 for he in emp_hash_to_nif
            if he in hp_sec or he in baja_sec or he in contratado_sec
        )
        if matched == 0:
            _diag_informe_event(
                kind="day", day=day, outcome="no_employee_match",
                scope=len(emp_hash_to_nif), hp_entries=len(hp_sec),
                baja_entries=len(baja_sec), contratado_entries=len(contratado_sec),
            )
            unavailable_days.add(day)
            continue

        _diag_informe_event(
            kind="day", day=day, outcome="ok", matched=matched,
            scope=len(emp_hash_to_nif), hp_entries=len(hp_sec),
            baja_entries=len(baja_sec), contratado_entries=len(contratado_sec),
        )

        for he, nif in emp_hash_to_nif.items():
            if he in hp_sec:
                try:
                    hp_out[(nif, day)] = max(0, int(hp_sec[he]))
                except Exception:
                    pass

            if he in baja_sec:
                try:
                    mins_baja = max(0, int(baja_sec[he]))
                    if mins_baja > 0:
                        baja_out[(nif, day)] = mins_baja
                except Exception:
                    pass

            if he in contratado_sec:
                try:
                    contratado_out[(nif, day)] = bool(int(contratado_sec[he]))
                except Exception:
                    pass

    return hp_out, baja_out, contratado_out, sorted(unavailable_days)



def build_weekly_official_hp_map(
    full_weeks: list,
    base_emp: pd.DataFrame,
) -> dict:
    """Horas programadas OFICIALES por empleado/semana desde /informes/empleados.

    Clave: (NIF, week_start_iso, week_end_iso) -> minutos.
    Una semana de vacaciones/cierre con HP=0 queda explícitamente a cero.
    """
    if not full_weeks or base_emp is None or base_emp.empty:
        return {}

    be = base_emp.copy()
    be["nif"] = be["nif"].fillna("").astype(str).str.upper().str.strip()
    if "num_empleado" not in be.columns:
        be["num_empleado"] = ""
    be["num_empleado_code"] = be["num_empleado"].apply(_canonical_emp_code)

    hash_to_nif = {}
    for _, row in be.iterrows():
        code = _text(row.get("num_empleado_code"))
        nif = _text(row.get("nif")).upper()
        if code and nif:
            hash_to_nif[_hash_emp_code(code)] = nif

    out = {}
    for wk_start, wk_end, _mode in full_weeks:
        a = wk_start.strftime("%Y-%m-%d")
        b = wk_end.strftime("%Y-%m-%d")
        try:
            metrics = _cached_informe_period_metrics(a, b)
        except Exception as exc:
            _safe_fail(exc)
            continue
        for he, mins in ((metrics or {}).get("hp", {}) or {}).items():
            nif = hash_to_nif.get(he)
            if nif:
                out[(nif, a, b)] = max(0, int(mins))
    return out



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

# Nº empleado no es necesariamente único en CRECE. Solo se permite como fallback
# de enlace con Turnos cuando es único en TODO el universo permitido.
empleados_df["_num_code_global"] = empleados_df.get(
    "num_empleado", pd.Series("", index=empleados_df.index)
).apply(_canonical_emp_code)
_num_counts_global = empleados_df["_num_code_global"].replace("", pd.NA).dropna().value_counts()
empleados_df["num_empleado_unique_global"] = empleados_df["_num_code_global"].apply(
    lambda x: bool(x) and int(_num_counts_global.get(x, 0)) == 1
)

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


APP_STATE_VERSION = "turnos-ausencias-date-nightfix-2026-09-22-v2"
if st.session_state.get("_app_state_version") != APP_STATE_VERSION:
    for _state_key in [
        "last_sig", "result_incidencias", "result_bajas", "result_sin_fichajes",
        "result_excesos_semana", "result_csv_incidencias", "result_csv_bajas",
        "result_csv_sin", "result_csv_excesos", "scope_fi", "scope_ff",
        "scope_empresas_norm", "scope_sedes_norm", "scope_empleados_nif",
        "scope_used_employee_filter", "result_informe_missing_days",
        "result_tiempo_missing_days", "result_exceso_incomplete_count",
        "result_turnos_unknown_absences",
    ]:
        st.session_state.pop(_state_key, None)
    st.session_state["_app_state_version"] = APP_STATE_VERSION


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
    ("result_tiempo_missing_days", []),
    ("result_exceso_incomplete_count", 0),
    ("result_turnos_unknown_absences", []),
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
    # Contexto de un día a cada lado para poder unir de forma exacta los
    # turnos que cruzan medianoche, incluso si el rango visible empieza o
    # termina en mitad de un turno nocturno. Los resultados UI se filtran
    # después estrictamente al rango solicitado.
    d0_ctx = fecha_inicio - timedelta(days=1)
    d1_ctx = fecha_fin + timedelta(days=1)
    fi_ctx = d0_ctx.strftime("%Y-%m-%d")
    ff_ctx = d1_ctx.strftime("%Y-%m-%d")
    signature = _sig(fi, ff, sel_empresas, sel_sedes, sel_empleados_nifs)

    with st.spinner("Procesando…"):
        tipos_map = api_exportar_tipos_fichaje()

        # --------- FICHAJES ----------
        fichajes_rows = []
        with ThreadPoolExecutor(max_workers=_max_workers_emps(len(empleados_filtrados))) as exe:
            futures = {exe.submit(api_exportar_fichajes, r["nif"], fi_ctx, ff_ctx): r for _, r in empleados_filtrados.iterrows()}
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
        d0_context = d0 - timedelta(days=1)
        d1_context = d1 + timedelta(days=1)

        base_emp = empleados_filtrados.copy()
        base_emp["nif"] = base_emp["nif"].fillna("").astype(str).str.upper().str.strip()
        base_emp["num_empleado"] = base_emp.get(
            "num_empleado", pd.Series("", index=base_emp.index)
        ).fillna("").astype(str).str.strip()
        base_emp["empleado_id"] = base_emp.get(
            "empleado_id", pd.Series("", index=base_emp.index)
        ).apply(_canonical_crece_id)

        try:
            (
                horas_prog_map_query,
                bajas_min_map_query,
                contratado_map_query,
                turno_start_map_query,
                informe_missing_days,
                turnos_unknown_absences,
            ) = build_turnos_daily_maps(d0_context, d1_context, base_emp)
        except Exception as _e:
            _safe_fail(_e)
            horas_prog_map_query, bajas_min_map_query, contratado_map_query = {}, {}, {}
            turno_start_map_query, informe_missing_days, turnos_unknown_absences = {}, [], []

        nifs_all_query = [
            n for n in base_emp["nif"].dropna().astype(str).str.upper().str.strip().unique().tolist()
            if n
        ]
        try:
            tc_map_query, tiempo_missing_days = build_tiempo_contabilizado_map(d0_context, d1_context, nifs_all_query)
        except Exception as _e:
            _safe_fail(_e)
            tc_map_query, tiempo_missing_days = {}, []

        # Alineación de continuaciones 23:59 -> 00:00 con el día real de
        # inicio del turno. El TC bruto se conserva aparte para la columna
        # semanal; ``tc_balance_map_query`` solo se usa en validaciones y
        # balances por turno.
        try:
            df_fich, midnight_transfers = normalize_midnight_continuations(df_fich)
        except Exception as _e:
            _safe_fail(_e)
            midnight_transfers = {}

        # Cada continuidad nocturna detectada contiene dos marcajes técnicos de
        # corte de día (salida ~23:59 + entrada ~00:00). Para RRHH forman parte
        # de un único turno y no deben contar como dos fichajes adicionales ni
        # disparar validaciones horarias de turno diurno.
        midnight_bridge_counts = {}
        for (_nif_b, _from_day_b, _to_day_b), _mins_b in (midnight_transfers or {}).items():
            _bk = (str(_nif_b or "").upper().strip(), str(_to_day_b or ""))
            midnight_bridge_counts[_bk] = int(midnight_bridge_counts.get(_bk, 0)) + 1

        tc_balance_map_query = apply_midnight_tc_transfers(tc_map_query, midnight_transfers)

        # Los dos días de contexto son internos y nunca deben generar avisos UI.
        tiempo_missing_days = [d for d in (tiempo_missing_days or []) if fi <= str(d) <= ff]
        informe_missing_days = [d for d in (informe_missing_days or []) if fi <= str(d) <= ff]

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

            # En un turno cruzado por medianoche CRECE introduce el par técnico
            # 23:59/00:00. El número mostrado/validado debe ser el número lógico
            # de fichajes del turno, no esos dos marcajes de frontera.
            def _logical_fichajes_count(r):
                try:
                    raw = int(r.get("Numero de fichajes", 0) or 0)
                except Exception:
                    raw = 0
                key = (
                    str(r.get("nif") or "").upper().strip(),
                    str(r.get("Fecha") or ""),
                )
                bridges = int((midnight_bridge_counts or {}).get(key, 0) or 0)
                return max(0, raw - 2 * bridges)

            conteo["Numero de fichajes"] = conteo.apply(_logical_fichajes_count, axis=1)

            neto = calcular_tiempos_neto(df_fich, tipos_map)
            resumen = conteo.merge(neto, on=["nif", "Fecha"], how="left")
            resumen["segundos_neto"] = resumen["segundos_neto"].fillna(0)

            resumen["Total trabajado"] = resumen["segundos_neto"].apply(segundos_a_hhmm)

            io = calcular_primera_ultima(df_fich)
            resumen = resumen.merge(io, on=["nif", "Fecha"], how="left")
            resumen["Primera entrada"] = resumen["primera_entrada_dt"].apply(ts_to_hhmm)
            resumen["Última salida"] = resumen["ultima_salida_dt"].apply(ts_to_hhmm)

            horas_prog_map_incid = horas_prog_map_query
            tc_map_incid = tc_balance_map_query

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
            # La validación de horas nunca cae a la duración calculada de marcajes.
            resumen["tc_known"] = resumen.apply(
                lambda r: (str(r.get("nif") or "").upper().strip(), str(r.get("Fecha") or "")) in tc_map_incid,
                axis=1,
            )

            # Oculta los días de contexto usados solo para cerrar turnos nocturnos.
            resumen = resumen[(resumen["Fecha"].astype(str) >= fi) & (resumen["Fecha"].astype(str) <= ff)].copy()
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
                try:
                    row_day = datetime.strptime(day_str, "%Y-%m-%d").date()
                except Exception:
                    row_day = None
                completed_day = bool(row_day is not None and row_day < date.today())

                exp_key = (nif_str, day_str)
                exp_known = exp_key in (horas_prog_map_incid or {})
                exp_min = None
                if exp_known:
                    try:
                        exp_min = int(horas_prog_map_incid[exp_key])
                    except Exception:
                        exp_known = False
                        exp_min = None

                tc_key = (nif_str, day_str)
                tc_known = tc_key in (tc_map_incid or {})
                worked_minutes = int(tc_map_incid[tc_key]) if tc_known else 0
                num_fich = int(r.get("Numero de fichajes", 0) or 0)
                worked = (tc_known and worked_minutes > 0) or num_fich > 0

                # Solo un cero explícito de CRECE significa día no laborable.
                if exp_known and exp_min == 0 and worked:
                    return "Trabajado en día no laborable"

                # Horas insuficientes solo con la jornada ya cerrada.
                if completed_day and tc_known and exp_known and exp_min is not None and exp_min > 0 and worked_minutes < (exp_min - TOLERANCIA_MINUTOS):
                    motivos.append(f"Horas insuficientes (mín {segundos_a_hhmm(exp_min * 60)})")

                depto_norm = str(r.get("Departamento") or "").upper().strip()

                # CRECE divide los turnos nocturnos en el cambio de día. En el
                # resumen diario esto puede verse como 00:00 ... 23:59 y 4
                # fichajes (dos pares), aun siendo un único turno real. No debe
                # generar por ello "entrada temprana" ni "fichajes excesivos".
                shift_start_for_day = (turno_start_map_query or {}).get(exp_key)
                try:
                    night_by_schedule = shift_start_for_day is not None and int(shift_start_for_day) >= 18 * 60
                except Exception:
                    night_by_schedule = False
                bridge_night_pattern = bool(
                    (nif_str, day_str) in (midnight_bridge_counts or {})
                )
                # Compatibilidad defensiva con datos que todavía llegasen sin
                # normalizar: el patrón 00:00..23:59 + 4 marcas también indica
                # un turno nocturno partido por CRECE.
                visible_night_pattern = bool(
                    str(r.get("Primera entrada") or "") == "00:00"
                    and str(r.get("Última salida") or "") == "23:59"
                    and int(r.get("Numero de fichajes", 0) or 0) >= 4
                )
                is_night_mod = bool(
                    depto_norm == "MOD"
                    and (night_by_schedule or bridge_night_pattern or visible_night_pattern)
                )

                # Cantidad de fichajes determinada por la jornada programada real.
                min_f = required_min_fichajes(
                    depto_norm, r.get("Nombre"), (exp_min if exp_known else None)
                )

                hours_ok = bool(
                    tc_known
                    and exp_known
                    and exp_min is not None
                    and exp_min > 0
                    and worked_minutes >= max(0, exp_min - TOLERANCIA_MINUTOS)
                )

                if completed_day and min_f is not None:
                    try:
                        min_f_i = int(min_f)
                        if num_fich < min_f_i:
                            motivos.append(f"Fichajes insuficientes (mín {min_f_i})")

                        max_ok = r.get("max_fichajes_ok")
                        if pd.notna(max_ok):
                            max_ok_i = int(max_ok)
                            if hours_ok and num_fich > max_ok_i:
                                motivos.append(f"Fichajes excesivos (máx {max_ok_i})")
                        elif hours_ok and num_fich > min_f_i and not is_night_mod:
                            motivos.append(f"Fichajes excesivos (mín {min_f_i})")
                    except Exception:
                        pass

                if not is_night_mod:
                    motivos += validar_horario(
                        r.get("Departamento"),
                        r.get("Nombre"),
                        int(r.get("dia", 0)),
                        r.get("Primera entrada", ""),
                        r.get("Última salida", ""),
                        expected_minutes=(exp_min if exp_known else None),
                        sede=r.get("Sede", ""),
                        empresa=r.get("Empresa", ""),
                        completed_day=completed_day,
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
        # Se reutiliza la misma lectura de /informes/turnos + ausencia usada
        # para la jornada programada. No se hace una segunda llamada a informes.
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

        # La elegibilidad histórica por día procede de /informes/turnos:
        # no-contrato excluye; una fila de cuadrante sin Horario ID sigue siendo
        # un día contratado con 0 h programadas.
        base_emp_sin = base_emp.copy()
        empleados_nifs = [
            n for n in base_emp_sin["nif"].dropna().astype(str).str.upper().str.strip().unique().tolist()
            if n
        ]

        presentes: dict[str, set[str]] = {}
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
            # Una jornada aún abierta no puede clasificarse como "sin fichajes".
            if cur >= date.today():
                continue
            day = cur.strftime("%Y-%m-%d")
            present_set = presentes.get(day, set())
            on_sick_leave = bajas_nifs_by_day.get(day, set())
            missing: list[str] = []

            for nif in empleados_nifs:
                key = (nif, day)

                if key not in horas_prog_map_query:
                    continue
                tc_known = key in tc_balance_map_query
                if is_sin_fichajes_candidate(
                    contratado=(contratado_map_query.get(key) is True),
                    horas_programadas=horas_prog_map_query[key],
                    tiene_fichajes=(nif in present_set),
                    esta_baja=(nif in on_sick_leave),
                    tc_known=tc_known,
                    tiempo_contabilizado=(tc_balance_map_query.get(key) if tc_known else None),
                ):
                    missing.append(nif)

            if not missing:
                continue

            miss_df = base_emp_sin[base_emp_sin["nif"].isin(sorted(set(missing)))].copy()
            if miss_df.empty:
                continue

            out = miss_df[["Empresa", "Sede", "nombre_completo", "departamento_nombre", "nif"]].copy()
            out = out.rename(columns={"nombre_completo": "Nombre", "departamento_nombre": "Departamento"})
            out.insert(0, "Fecha", day)
            out = out.sort_values(["Nombre"], kind="mergesort").reset_index(drop=True)
            sin_por_dia[day] = out


        # --------- EXCESO SEMANAL (MOI + ESTRUCTURA + MOD) ----------
        # Fuentes:
        #   trabajado diario = tiempoContabilizado
        #   esperado diario  = /informes/turnos + ausencia (validado contra HP semanal)
        # Balance diario cuantizado; balance semanal = suma de balances diarios.
        try:
            full_weeks = [
                w for w in list_full_workweeks_in_range(d0, d1)
                if w[1] < date.today()
            ]
        except Exception:
            full_weeks = []

        excesos_por_semana = {}
        csv_excesos = b""
        exceso_incomplete_count = 0

        if full_weeks:
            horas_prog_map = horas_prog_map_query
            tc_map = tc_map_query  # bruto: fuente de la columna Trabajado semanal
            tc_balance_map = tc_balance_map_query  # alineado por turno: solo balance diario
            mod_pre_shift_map = build_mod_pre_shift_work_map(df_fich, tipos_map, turno_start_map_query)

            base_exc = base_emp.copy()
            base_exc["Departamento_norm"] = (
                base_exc.get("departamento_nombre", base_exc.get("Departamento", ""))
                .astype(str).str.upper().str.strip()
            )
            base_exc = base_exc[
                base_exc["Departamento_norm"].isin(["MOI", "ESTRUCTURA", "MOD"])
            ].copy()

            all_rows = []

            for wk_start, wk_end_incl, mode in full_weeks:
                if mode == "LD":
                    label = f"{wk_start:%Y-%m-%d} → {wk_end_incl:%Y-%m-%d} (L-D)"
                elif mode == "LS":
                    label = f"{wk_start:%Y-%m-%d} → {wk_end_incl:%Y-%m-%d} (L-S)"
                else:
                    label = f"{wk_start:%Y-%m-%d} → {wk_end_incl:%Y-%m-%d} (L-V)"

                week_days = list(_iter_days(wk_start, wk_end_incl))
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

                        keys = [(nif, d.strftime("%Y-%m-%d")) for d in week_days]

                        # Empleado sin presencia contractual ni HP en toda la semana:
                        # no es una semana evaluable para esa persona.
                        any_contract = any(contratado_map_query.get(k) is True for k in keys)
                        any_hp = any(k in horas_prog_map for k in keys)
                        if not any_contract and not any_hp:
                            continue

                        if any(k not in horas_prog_map for k in keys) or any(k not in tc_map for k in keys):
                            exceso_incomplete_count += 1
                            continue

                        daily_expected = {k[1]: max(0, int(horas_prog_map[k])) for k in keys}
                        jornada_sem_min = sum(daily_expected.values())
                        trabajado_sem_min = 0
                        exceso_sem_min = 0

                        for cur_day in week_days:
                            day_iso = cur_day.strftime("%Y-%m-%d")
                            key = (nif, day_iso)
                            mins_tc = int(tc_map[key])
                            exp_day = int(daily_expected[day_iso])

                            # Columna visual: siempre TC bruto.
                            trabajado_sem_min += mins_tc

                            # Para MOD el balance se alinea al turno real cuando CRECE
                            # ha partido una continuación nocturna a las 00:00. La
                            # columna semanal sigue usando ``mins_tc`` bruto.
                            mins_balance = int(tc_balance_map.get(key, mins_tc)) if depto.upper().strip() == "MOD" else mins_tc
                            if depto.upper().strip() == "MOD":
                                # Regla RRHH MOD: el tiempo realmente trabajado antes del
                                # inicio oficial del turno (06:00 / 14:00 / 22:00) no suma
                                # al balance de exceso, incluso cuando CRECE tenga ese día
                                # como L/libre (HP=0). Ej.: 21:30-22:00 no es exceso de un
                                # turno nocturno extraordinario; la columna Trabajado semanal
                                # sigue mostrando el tiempoContabilizado bruto completo.
                                pre_shift = int(mod_pre_shift_map.get(key, 0) or 0)
                                mins_balance = effective_worked_minutes_for_mod(mins_balance, pre_shift)

                            diff_day = int(mins_balance) - exp_day
                            exceso_sem_min += quantize_daily_balance_30(
                                diff_day, tol=TOLERANCIA_MINUTOS
                            )

                        # Semana con jornada=0 y trabajado=0 cae aquí (balance 0)
                        # y nunca aparece como -40:00 ni como fila vacía.
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
                        all_rows.append({
                            "Semana": label,
                            **{k: v for k, v in row.items() if k != "nif"},
                        })

                if rows:
                    dfw = (
                        pd.DataFrame(rows)
                        .sort_values(
                            ["Empresa", "Sede", "Departamento", "Nombre"],
                            kind="mergesort",
                        )
                        .reset_index(drop=True)
                    )
                else:
                    dfw = pd.DataFrame(columns=[
                        "Empresa", "Sede", "Nombre", "Departamento",
                        "Trabajado semanal", "Jornada semanal", "Exceso", "nif",
                    ])

                excesos_por_semana[label] = dfw

            if all_rows:
                df_all = (
                    pd.DataFrame(all_rows)
                    .sort_values(
                        ["Semana", "Empresa", "Sede", "Departamento", "Nombre"],
                        kind="mergesort",
                    )
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
    st.session_state["result_tiempo_missing_days"] = list(tiempo_missing_days or [])
    st.session_state["result_exceso_incomplete_count"] = int(exceso_incomplete_count or 0)
    st.session_state["result_turnos_unknown_absences"] = list(turnos_unknown_absences or [])

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


# Avisos no bloqueantes únicamente cuando CRECE no ha podido proporcionar datos.
_missing_days_ui = list(st.session_state.get("result_informe_missing_days", []) or [])
_missing_tc_days_ui = list(st.session_state.get("result_tiempo_missing_days", []) or [])
_unknown_abs_ui = list(st.session_state.get("result_turnos_unknown_absences", []) or [])
if _missing_days_ui:
    st.warning(
        "No se ha podido obtener /informes/turnos de CRECE para el rango consultado. "
        "Las validaciones que dependen de la jornada programada se omiten sin inventar datos."
    )
if _missing_tc_days_ui:
    st.warning(
        f"No se ha podido obtener tiempoContabilizado de CRECE para "
        f"{len(_missing_tc_days_ui)} fecha(s). Esas fechas no se interpretan como 00:00."
    )
if _unknown_abs_ui:
    st.warning(
        "CRECE ha devuelto tipos de ausencia no reconocidos por la integración: "
        + ", ".join(sorted(set(map(str, _unknown_abs_ui))))
        + ". Esos días no se interpretan automáticamente como jornada 0."
    )


# Exceso solo se muestra cuando el rango contiene al menos una semana completa.
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
            if _missing_days_ui or _missing_tc_days_ui:
                st.warning(
                    "No hay incidencias mostrables, pero faltan datos oficiales de CRECE "
                    "para parte del rango y no se pueden validar todas las reglas de jornada."
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
            if _missing_days_ui or _missing_tc_days_ui:
                st.warning(
                    "No se puede confirmar que no haya empleados sin fichajes en todo el rango "
                    "porque faltan Horas programadas o tiempoContabilizado para algunas fechas."
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
            _exc_incomplete = int(st.session_state.get("result_exceso_incomplete_count", 0) or 0)
            if _exc_incomplete > 0 or _missing_days_ui or _missing_tc_days_ui:
                st.warning(
                    "No se puede confirmar que no haya excesos de jornada: "
                    "faltan datos diarios suficientes para validar algunas semanas/empleados "
                    "contra Horas programadas y tiempoContabilizado oficiales de CRECE."
                )
            else:
                st.info("No hay excesos de jornada en el rango seleccionado.")

        csv_w = _csv_from_result_dict(res_exc, week_mode=True)
        if csv_w:
            st.download_button("⬇ Descargar CSV excesos (todas las semanas)", csv_w, "excesos_jornada_semanal.csv", "text/csv")
