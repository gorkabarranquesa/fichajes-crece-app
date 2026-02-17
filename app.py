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

# Tolerancia RRHH (±5 min) aplicada al mínimo de horas (para "insuficientes")
TOLERANCIA_MINUTOS = 5
TOLERANCIA_HORAS = TOLERANCIA_MINUTOS / 60.0

# Margen horario SOLO para MOI y ESTRUCTURA (entrada temprana y salida temprana)
MARGEN_HORARIO_MIN = 5

# Identificación fija del cliente (trazabilidad)
USER_AGENT = "RRHH-Fichajes-Crece/1.0 (Streamlit)"

# Backoff/retry seguro
RETRY_STATUS = {429, 502, 503, 504}
MAX_RETRIES = 4  # total intentos = 1 + MAX_RETRIES
BACKOFF_BASE_SECONDS = 0.6  # base
BACKOFF_MAX_SECONDS = 6.0   # techo

# Restricción RRHH: solo estas empresas y sedes
ALLOWED_COMPANIES = [
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
# SEGURIDAD: sesión compartida + no loguear PII, tokens, payloads
# ============================================================

_SESSION = requests.Session()
_SESSION.headers.update(
    {
        "Accept": "application/json",
        "Authorization": f"Bearer {API_TOKEN}",
        "User-Agent": USER_AGENT,
    }
)

def _safe_fail(_exc: Exception) -> None:
    # No loguear detalles (PII/tokens/payloads)
    return None

# ============================================================
# SAFE REQUEST: centraliza peticiones + verify=True + retries
# ============================================================

def safe_request(method: str, url: str, *, data=None, json_body=None, params=None, timeout=HTTP_TIMEOUT):
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
                json=json_body,
                params=params,
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
# NORMALIZACIÓN NOMBRES / KEYS
# ============================================================

def norm_name(s: str) -> str:
    if s is None:
        return ""
    return " ".join(str(s).upper().strip().split())

def _norm_key(s: str) -> str:
    return (str(s) if s is not None else "").strip().upper()

ALLOWED_COMPANIES_N = {_norm_key(x) for x in ALLOWED_COMPANIES}
ALLOWED_SEDES_N = {_norm_key(x) for x in ALLOWED_SEDES}

# ============================================================
# EXCLUSIONES (Sin fichajes)
# - RRHH pide excluir estos empleados (por NOMBRE)
# ============================================================

EXCLUDE_SIN_FICHAJES_NAMES_N = {
    norm_name("Mikel Arzallus Marco"),
    norm_name("Jose Angel Ochagavia Satrustegui"),
    norm_name("Benito Mendinueta Andueza"),
}

def name_startswith(nombre_norm: str, prefix_norm: str) -> bool:
    return bool(nombre_norm) and bool(prefix_norm) and nombre_norm.startswith(prefix_norm)

# ============================================================
# NOMBRES (tal cual CRECE)
# ============================================================

N_DAVID = norm_name("David Rodriguez Vazquez")
N_DEBORA = norm_name("Debora Luis Soto")
N_ETOR = norm_name("Etor Alegria Reparaz")
N_FRAN = norm_name("Fran Diaz Arozarena")
N_MIRIAM = norm_name("Miriam Martín Muñoz")
N_BEATRIZ = norm_name("Beatriz Andueza Roncal")

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

def _extract_payload_b64(resp: requests.Response) -> str:
    return (resp.text or "").strip().strip('"').strip()

# ============================================================
# TIEMPOS
# ============================================================

def segundos_a_hhmm(seg: float) -> str:
    if seg is None or pd.isna(seg):
        return ""
    try:
        seg_i = int(float(seg))
    except Exception:
        return ""
    if seg_i < 0:
        seg_i = 0

    # Normalizamos a minutos (redondeo a minuto más cercano)
    total_min = int(round(seg_i / 60.0))
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

    if tc_min == tt_min:
        return ""

    # Redondeo/normalización RRHH: diferencias de ±1 minuto se consideran 0
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
# REGLAS ESPECIALES RRHH (mínimos)
# + Beatriz (ESTRUCTURA) con umbral excesivos especial
# ============================================================

SPECIAL_RULES_PREFIX = [
    ("MOD", N_DAVID, {"min_horas": 4.5, "min_fichajes": 2}),
    ("MOI", N_DEBORA, {"min_fichajes": 2}),
    ("MOI", N_ETOR, {"min_fichajes": 2}),
    ("MOI", N_MIRIAM, {"min_horas": 5.5, "min_fichajes": 2}),
    # NUEVO: Beatriz (ESTRUCTURA)
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

# ============================================================
# REGLAS BASE DE JORNADA
# ============================================================

def calcular_minimos(depto: str, dia: int, nombre: str):
    depto_norm = (depto or "").upper().strip()
    nombre_norm = norm_name(nombre)

    min_h, min_f = None, None

    if depto_norm in ["ESTRUCTURA", "MOI"]:
        if dia in [0, 1, 2, 3]:       # L-J
            min_h, min_f = 8.5, 4
        elif dia == 4:                # V
            min_h, min_f = 6.5, 2
        else:
            min_h, min_f = None, None

    elif depto_norm == "MOD":
        if dia in [0, 1, 2, 3, 4]:    # L-V
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
# VALIDACIÓN HORARIA (MOI/ESTRUCTURA + MOD por turnos)
# ============================================================

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

# ============================================================
# API EXPORTACIÓN
# ============================================================

@st.cache_data(show_spinner=False, ttl=3600)
def api_exportar_departamentos() -> pd.DataFrame:
    url = f"{API_URL_BASE}/exportacion/departamentos"
    resp = safe_request("GET", url)
    if resp is None:
        return pd.DataFrame(columns=["departamento_id", "departamento_nombre"])
    resp.raise_for_status()

    payload_b64 = _extract_payload_b64(resp)
    decrypted = decrypt_crece_payload(payload_b64, APP_KEY_B64)
    departamentos = json.loads(decrypted)

    return pd.DataFrame(
        [{"departamento_id": d.get("id"), "departamento_nombre": d.get("nombre")}
         for d in (departamentos or [])]
    )

def _build_nombre_completo(e: dict) -> str:
    nombre = e.get("name") or e.get("nombre") or ""
    primer_apellido = e.get("primer_apellido") or ""
    segundo_apellido = e.get("segundo_apellido") or ""

    if not (primer_apellido or segundo_apellido) and e.get("apellidos"):
        partes = str(e["apellidos"]).split()
        primer_apellido = partes[0] if len(partes) > 0 else ""
        segundo_apellido = " ".join(partes[1:]) if len(partes) > 1 else ""

    return f"{nombre} {primer_apellido} {segundo_apellido}".strip()

def _safe_int(v, default=0):
    try:
        return int(v)
    except Exception:
        return default

@st.cache_data(show_spinner=False, ttl=3600)
def api_exportar_empleados_full() -> pd.DataFrame:
    """
    Exportación empleados (de /exportacion/empleados).
    Incluye: nif, num_empleado (si existe), nombre_completo, departamento_id, empresa_id, sede_id, estado_laboral.
    """
    url = f"{API_URL_BASE}/exportacion/empleados"
    data = {"solo_nif": 0}

    resp = safe_request("POST", url, data=data)
    if resp is None:
        return pd.DataFrame(columns=["nif", "num_empleado", "nombre_completo", "departamento_id", "empresa_id", "sede_id", "estado_laboral"])
    resp.raise_for_status()

    payload_b64 = _extract_payload_b64(resp)
    decrypted = decrypt_crece_payload(payload_b64, APP_KEY_B64)
    empleados = json.loads(decrypted)

    rows = []
    for e in (empleados or []):
        rows.append(
            {
                "nif": (e.get("nif") or "").strip(),
                "num_empleado": (e.get("num_empleado") or e.get("codigo") or e.get("id") or ""),
                "nombre_completo": _build_nombre_completo(e),
                "departamento_id": e.get("departamento"),
                "empresa_id": e.get("empresa"),
                "sede_id": e.get("sede"),
                "estado_laboral": (e.get("estado_laboral") or e.get("estado") or "").strip().lower(),
            }
        )

    df = pd.DataFrame(rows)
    if not df.empty:
        df["nif"] = df["nif"].astype(str).str.upper().str.strip()
        df["num_empleado"] = df["num_empleado"].astype(str).str.strip()
    return df

@st.cache_data(show_spinner=False, ttl=3600)
def api_exportar_empresas() -> pd.DataFrame:
    url = f"{API_URL_BASE}/exportacion/empresas"
    resp = safe_request("GET", url)
    if resp is None:
        return pd.DataFrame(columns=["empresa_id", "empresa_nombre"])
    resp.raise_for_status()
    payload_b64 = _extract_payload_b64(resp)
    decrypted = decrypt_crece_payload(payload_b64, APP_KEY_B64)
    empresas = json.loads(decrypted) or []
    return pd.DataFrame([{"empresa_id": x.get("id"), "empresa_nombre": x.get("nombre")} for x in empresas])

@st.cache_data(show_spinner=False, ttl=3600)
def api_exportar_sedes() -> pd.DataFrame:
    url = f"{API_URL_BASE}/exportacion/sedes"
    resp = safe_request("GET", url)
    if resp is None:
        return pd.DataFrame(columns=["sede_id", "sede_nombre"])
    resp.raise_for_status()
    payload_b64 = _extract_payload_b64(resp)
    decrypted = decrypt_crece_payload(payload_b64, APP_KEY_B64)
    sedes = json.loads(decrypted) or []
    return pd.DataFrame([{"sede_id": x.get("id"), "sede_nombre": x.get("nombre")} for x in sedes])

@st.cache_data(show_spinner=False, ttl=3600)
def api_exportar_tipos_fichaje() -> dict:
    url = f"{API_URL_BASE}/exportacion/tipos-fichaje"
    try:
        resp = safe_request("POST", url)
        if resp is None:
            return {}
        resp.raise_for_status()

        payload_b64 = _extract_payload_b64(resp)
        decrypted = decrypt_crece_payload(payload_b64, APP_KEY_B64)
        tipos = json.loads(decrypted)

        out = {}
        if isinstance(tipos, list):
            for t in tipos:
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

        payload_b64 = _extract_payload_b64(resp)
        if not payload_b64:
            return []

        decrypted = decrypt_crece_payload(payload_b64, APP_KEY_B64)
        out = json.loads(decrypted)
        return out if isinstance(out, list) else []
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

        payload_b64 = _extract_payload_b64(resp)
        if not payload_b64:
            return pd.DataFrame(columns=["nif", "tiempoEfectivo_seg", "tiempoContabilizado_seg"])

        decrypted = decrypt_crece_payload(payload_b64, APP_KEY_B64)
        parsed = json.loads(decrypted)
        return _parse_tiempo_trabajado_payload(parsed)

    except Exception as e:
        _safe_fail(e)
        return pd.DataFrame(columns=["nif", "tiempoEfectivo_seg", "tiempoContabilizado_seg"])

# ============================================================
# INFORME EMPLEADOS (bajas)
# ============================================================

def _try_decode_informe_empleados(resp: requests.Response):
    """
    Intenta interpretar /informes/empleados en varios formatos:
    - texto base64/cifrado (como exportación): resp.text con base64 de {iv,value}
    - JSON directo: resp.json()
    - JSON con campo 'payload' o similar
    Devuelve lista (empleados) o None si no se puede.
    """
    if resp is None:
        return None

    # Intento 1: JSON directo
    try:
        j = resp.json()
        if isinstance(j, list):
            return j
        if isinstance(j, dict):
            for k in ["data", "empleados", "resultado", "result"]:
                if k in j and isinstance(j[k], list):
                    return j[k]
            # Puede venir como { "payload": "...." }
            for k in ["payload", "payload_b64", "value", "ciphertext"]:
                if k in j and isinstance(j[k], str) and j[k].strip():
                    s = j[k].strip()
                    # probar si es el mismo formato que exportación
                    try:
                        dec = decrypt_crece_payload(s.strip().strip('"'), APP_KEY_B64)
                        parsed = json.loads(dec)
                        return parsed if isinstance(parsed, list) else None
                    except Exception:
                        pass
        # si es otra cosa, seguimos
    except Exception:
        pass

    # Intento 2: texto base64 (como exportación)
    try:
        payload_b64 = _extract_payload_b64(resp)
        if payload_b64:
            dec = decrypt_crece_payload(payload_b64, APP_KEY_B64)
            parsed = json.loads(dec)
            return parsed if isinstance(parsed, list) else None
    except Exception:
        pass

    return None

def api_informe_empleados(fecha_desde: str, fecha_hasta: str):
    url = f"{API_URL_BASE}/informes/empleados"
    # robusto: usar JSON body con keys fecha_desde/fecha_hasta
    body = {"fecha_desde": fecha_desde, "fecha_hasta": fecha_hasta}
    resp = safe_request("POST", url, json_body=body)
    if resp is None:
        return []
    try:
        resp.raise_for_status()
    except Exception:
        return []
    parsed = _try_decode_informe_empleados(resp)
    return parsed if isinstance(parsed, list) else []

# ============================================================
# DÍA (turno nocturno)
# ============================================================

def ajustar_fecha_dia(fecha_dt: pd.Timestamp, turno_nocturno: int) -> str:
    if turno_nocturno == 1 and fecha_dt.hour < 6:
        return (fecha_dt.date() - timedelta(days=1)).strftime("%Y-%m-%d")
    return fecha_dt.date().strftime("%Y-%m-%d")

# ============================================================
# TIEMPO POR FICHAJES (neto)
# ============================================================

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
                        delta_i = int(delta)
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
# VALIDACIÓN HORAS/FICHAJES
# - Beatriz: excesivos solo si > 4
# ============================================================

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
        motivos.append(f"Horas insuficientes (mín {min_h}h, tol {TOLERANCIA_MINUTOS}m)")

    if num_fich < int(min_f):
        motivos.append(f"Fichajes insuficientes (mín {min_f})")

    # Umbral de excesivos: por defecto > min_f, pero Beatriz tiene >4
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
# UI
# ============================================================

st.set_page_config(page_title="Fichajes CRECE Personas", layout="wide")
st.title("📊 Fichajes CRECE Personas")

hoy = date.today()

# --- Precarga de empresas/sedes para filtros previos (sin consultar fichajes) ---
with st.spinner("Cargando catálogos…"):
    empresas_df = api_exportar_empresas()
    sedes_df = api_exportar_sedes()

# Mapas id->nombre
empresa_map = {}
sede_map = {}
if not empresas_df.empty:
    empresas_df["empresa_nombre"] = empresas_df["empresa_nombre"].astype(str).str.strip()
    empresa_map = dict(zip(empresas_df["empresa_id"], empresas_df["empresa_nombre"]))
if not sedes_df.empty:
    sedes_df["sede_nombre"] = sedes_df["sede_nombre"].astype(str).str.strip()
    sede_map = dict(zip(sedes_df["sede_id"], sedes_df["sede_nombre"]))

# listas permitidas (por nombre)
empresas_opts = [x for x in empresas_df.get("empresa_nombre", pd.Series(dtype=str)).tolist() if _norm_key(x) in ALLOWED_COMPANIES_N]
sedes_opts = [x for x in sedes_df.get("sede_nombre", pd.Series(dtype=str)).tolist() if _norm_key(x) in ALLOWED_SEDES_N]

col1, col2 = st.columns(2)
with col1:
    fecha_inicio = st.date_input("Fecha inicio", value=hoy, max_value=hoy)
with col2:
    fecha_fin = st.date_input("Fecha fin", value=hoy, max_value=hoy)

st.write("---")

st.markdown("### 🔎 Filtros")
fcol1, fcol2 = st.columns(2)
with fcol1:
    empresas_sel = st.multiselect("Empresa", options=empresas_opts, default=empresas_opts)
with fcol2:
    sedes_sel = st.multiselect("Sede", options=sedes_opts, default=sedes_opts)

# Si el usuario selecciona sedes que no existen para las empresas seleccionadas, se filtrará a vacío (empresa manda).
empresas_sel_n = {_norm_key(x) for x in empresas_sel}
sedes_sel_n = {_norm_key(x) for x in sedes_sel}

if st.button("Consultar"):
    if fecha_inicio > fecha_fin:
        st.error("❌ La fecha inicio no puede ser posterior a la fecha fin.")
        st.stop()
    if fecha_fin > hoy:
        st.error("❌ La fecha fin no puede ser mayor que hoy.")
        st.stop()

    fi = fecha_inicio.strftime("%Y-%m-%d")
    ff = fecha_fin.strftime("%Y-%m-%d")

    with st.spinner("Procesando…"):
        tipos_map = api_exportar_tipos_fichaje()
        departamentos_df = api_exportar_departamentos()
        empleados_df = api_exportar_empleados_full()

        if empleados_df.empty:
            st.warning("No hay empleados disponibles.")
            st.stop()

        # Mapear empresa/sede por nombre y filtrar SOLO allowed + selección
        empleados_df["empresa_nombre"] = empleados_df["empresa_id"].map(empresa_map).fillna("").astype(str).str.strip()
        empleados_df["sede_nombre"] = empleados_df["sede_id"].map(sede_map).fillna("").astype(str).str.strip()

        empleados_df["empresa_nombre_n"] = empleados_df["empresa_nombre"].apply(_norm_key)
        empleados_df["sede_nombre_n"] = empleados_df["sede_nombre"].apply(_norm_key)

        # Restricciones RRHH (solo estas empresas/sedes)
        empleados_df = empleados_df[empleados_df["empresa_nombre_n"].isin(ALLOWED_COMPANIES_N)].copy()
        empleados_df = empleados_df[empleados_df["sede_nombre_n"].isin(ALLOWED_SEDES_N)].copy()

        # Filtro selección usuario
        if empresas_sel_n:
            empleados_df = empleados_df[empleados_df["empresa_nombre_n"].isin(empresas_sel_n)].copy()
        if sedes_sel_n:
            empleados_df = empleados_df[empleados_df["sede_nombre_n"].isin(sedes_sel_n)].copy()

        if empleados_df.empty:
            st.info("No hay empleados que cumplan los filtros seleccionados.")
            st.stop()

        empleados_df = empleados_df.merge(departamentos_df, on="departamento_id", how="left")
        empleados_df["nif"] = empleados_df["nif"].astype(str).str.upper().str.strip()

        fichajes_rows = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as exe:
            futures = {exe.submit(api_exportar_fichajes, r["nif"], fi, ff): r for _, r in empleados_df.iterrows()}
            for fut in as_completed(futures):
                emp = futures[fut]
                for x in (fut.result() or []):
                    fichajes_rows.append(
                        {
                            "nif": emp["nif"],
                            "Nombre": emp["nombre_completo"],
                            "Departamento": emp.get("departamento_nombre"),
                            "Empresa": emp.get("empresa_nombre"),
                            "Sede": emp.get("sede_nombre"),
                            "id": x.get("id"),
                            "tipo": x.get("tipo"),
                            "direccion": x.get("direccion"),
                            "fecha": x.get("fecha"),
                        }
                    )

        # Tabs: Fichajes | Bajas | Sin fichajes
        tab_f, tab_b, tab_s = st.tabs(["🕒 Fichajes", "🩺 Bajas", "🚫 Sin fichajes"])

        # ============================================================
        # TAB FICHAJES (incidencias)
        # ============================================================
        with tab_f:
            if not fichajes_rows:
                st.info("No se encontraron fichajes en el rango seleccionado.")
            else:
                df = pd.DataFrame(fichajes_rows)
                df["nif"] = df["nif"].astype(str).str.upper().str.strip()
                df["fecha_dt"] = pd.to_datetime(df["fecha"], errors="coerce")
                df = df.dropna(subset=["fecha_dt"])

                def _dia_row(r):
                    props = tipos_map.get(int(r["tipo"]), {}) if pd.notna(r.get("tipo")) else {}
                    return ajustar_fecha_dia(r["fecha_dt"], int(props.get("turno_nocturno", 0)))

                df["fecha_dia"] = df.apply(_dia_row, axis=1)

                df["Numero"] = df.groupby(["nif", "fecha_dia"])["id"].transform("count")
                conteo = (
                    df.groupby(["nif", "Empresa", "Sede", "Nombre", "Departamento", "fecha_dia"], as_index=False)
                    .agg(Numero=("Numero", "max"))
                    .rename(columns={"fecha_dia": "Fecha", "Numero": "Numero de fichajes"})
                )

                neto = calcular_tiempos_neto(df, tipos_map)
                resumen = conteo.merge(neto, on=["nif", "Fecha"], how="left")
                resumen["segundos_neto"] = resumen["segundos_neto"].fillna(0)
                resumen["Total trabajado"] = resumen["segundos_neto"].apply(segundos_a_hhmm)

                io = calcular_primera_ultima(df)
                resumen = resumen.merge(io, on=["nif", "Fecha"], how="left")
                resumen["Primera entrada"] = resumen["primera_entrada_dt"].apply(ts_to_hhmm)
                resumen["Última salida"] = resumen["ultima_salida_dt"].apply(ts_to_hhmm)

                nifs = resumen["nif"].dropna().astype(str).str.upper().str.strip().unique().tolist()

                tc_rows = []
                d0 = datetime.strptime(fi, "%Y-%m-%d").date()
                d1 = datetime.strptime(ff, "%Y-%m-%d").date()

                cur = d0
                while cur <= d1:
                    desde = cur.strftime("%Y-%m-%d")

                    df_tc = api_exportar_tiempo_trabajado(desde, desde, nifs=nifs)
                    if df_tc.empty or df_tc["tiempoContabilizado_seg"].isna().all():
                        hasta = (cur + timedelta(days=1)).strftime("%Y-%m-%d")
                        df_tc = api_exportar_tiempo_trabajado(desde, hasta, nifs=nifs)

                    if not df_tc.empty:
                        df_tc["Fecha"] = desde
                        tc_rows.append(df_tc)

                    cur += timedelta(days=1)

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

                # Añadimos max_fichajes_ok cuando aplique (Beatriz)
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

                salida = resumen[resumen["Incidencia"].astype(str).str.strip().ne("")].copy()

                if salida.empty:
                    st.success("🎉 No hay incidencias ni trabajos en fin de semana en el rango seleccionado.")
                else:
                    salida = salida[
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
                    ].sort_values(["Fecha", "Empresa", "Sede", "Nombre"], kind="mergesort")

                    for f_dia in salida["Fecha"].unique():
                        st.markdown(f"### 📅 {f_dia}")
                        sub = salida[salida["Fecha"] == f_dia]
                        st.data_editor(sub, use_container_width=True, hide_index=True, disabled=True, num_rows="fixed")

                    csv = salida.to_csv(index=False).encode("utf-8")
                    st.download_button("⬇ Descargar CSV", csv, "fichajes_incidencias.csv", "text/csv")

        # ============================================================
        # TAB BAJAS (por día dentro del rango, horas_baja > 0)
        # ============================================================
        with tab_b:
            d0 = datetime.strptime(fi, "%Y-%m-%d").date()
            d1 = datetime.strptime(ff, "%Y-%m-%d").date()

            bajas_por_dia = []
            cur = d0
            while cur <= d1:
                desde = cur.strftime("%Y-%m-%d")
                hasta = cur.strftime("%Y-%m-%d")

                info = api_informe_empleados(desde, hasta)
                if info:
                    # Construimos DF y filtramos por horas_baja > 0
                    rows = []
                    for e in info:
                        horas_baja = e.get("horas_baja") or e.get("horasBaja") or 0
                        try:
                            hb = float(horas_baja)
                        except Exception:
                            hb = 0.0
                        if hb <= 0:
                            continue

                        nif = str(e.get("nif") or "").upper().strip()
                        # Join a empleados_df para nombre/empresa/sede/depto
                        rows.append({"Fecha": desde, "nif": nif, "Horas baja": hb})

                    if rows:
                        tmp = pd.DataFrame(rows)
                        tmp = tmp.merge(
                            empleados_df[["nif", "empresa_nombre", "sede_nombre", "nombre_completo", "departamento_nombre"]],
                            on="nif",
                            how="left",
                        )
                        tmp = tmp.rename(
                            columns={
                                "empresa_nombre": "Empresa",
                                "sede_nombre": "Sede",
                                "nombre_completo": "Nombre",
                                "departamento_nombre": "Departamento",
                            }
                        )
                        tmp["Empresa"] = tmp["Empresa"].fillna("")
                        tmp["Sede"] = tmp["Sede"].fillna("")
                        tmp["Nombre"] = tmp["Nombre"].fillna("")
                        tmp["Departamento"] = tmp["Departamento"].fillna("")

                        # Solo mostrar bajas de empresas/sedes filtradas (empresa manda)
                        tmp["Empresa_n"] = tmp["Empresa"].apply(_norm_key)
                        tmp["Sede_n"] = tmp["Sede"].apply(_norm_key)
                        tmp = tmp[tmp["Empresa_n"].isin(empresas_sel_n)].copy() if empresas_sel_n else tmp
                        tmp = tmp[tmp["Sede_n"].isin(sedes_sel_n)].copy() if sedes_sel_n else tmp
                        tmp = tmp.drop(columns=["Empresa_n", "Sede_n"], errors="ignore")

                        if not tmp.empty:
                            bajas_por_dia.append(tmp[["Fecha", "Empresa", "Sede", "Nombre", "Departamento", "Horas baja"]])

                cur += timedelta(days=1)

            if not bajas_por_dia:
                st.info("No hay empleados de baja en el rango/filtrado seleccionado.")
            else:
                bajas_df = pd.concat(bajas_por_dia, ignore_index=True)
                for f_dia in bajas_df["Fecha"].unique():
                    sub = bajas_df[bajas_df["Fecha"] == f_dia].copy()
                    if sub.empty:
                        continue
                    st.markdown(f"### 🩺 Empleados de baja — {f_dia}")
                    st.data_editor(sub, use_container_width=True, hide_index=True, disabled=True, num_rows="fixed")

                csv_b = bajas_df.to_csv(index=False).encode("utf-8")
                st.download_button("⬇ Descargar CSV (bajas)", csv_b, "empleados_baja.csv", "text/csv")

        # ============================================================
        # TAB SIN FICHAJES (por día, empleados activos/contrato sin fichar)
        # ============================================================
        with tab_s:
            # empleados base (activos/contrato) ya filtrados por empresa/sede permitidas + selección
            empleados_base = empleados_df.copy()
            empleados_base["estado_laboral"] = empleados_base.get("estado_laboral", "").fillna("").astype(str).str.lower().str.strip()

            # Si estado_laboral está vacío en exportación, consideramos "activo" por defecto (no excluir por falta de dato)
            mask_activo = empleados_base["estado_laboral"].isin(["activo", "contrato"]) | (empleados_base["estado_laboral"] == "")
            base_emp_sin = empleados_base[mask_activo].copy()

            # Excluir personas concretas de 'Sin fichajes' (por nombre)
            if "nombre_completo" in base_emp_sin.columns:
                base_emp_sin = base_emp_sin[~base_emp_sin["nombre_completo"].apply(lambda x: norm_name(x) in EXCLUDE_SIN_FICHAJES_NAMES_N)].copy()

            if base_emp_sin.empty:
                st.info("No hay empleados activos/contrato para evaluar 'Sin fichajes' con los filtros actuales.")
            else:
                # Si no hay fichajes en el rango, todos serían "sin fichajes"
                if not fichajes_rows:
                    fich_df = pd.DataFrame(columns=["nif", "fecha_dia"])
                else:
                    fich_df = pd.DataFrame(fichajes_rows)
                    fich_df["fecha_dt"] = pd.to_datetime(fich_df["fecha"], errors="coerce")
                    fich_df = fich_df.dropna(subset=["fecha_dt"])

                    def _dia_row2(r):
                        props = tipos_map.get(int(r["tipo"]), {}) if pd.notna(r.get("tipo")) else {}
                        return ajustar_fecha_dia(r["fecha_dt"], int(props.get("turno_nocturno", 0)))

                    fich_df["fecha_dia"] = fich_df.apply(_dia_row2, axis=1)
                    fich_df = fich_df[["nif", "fecha_dia"]].copy()

                # Generar lista días del rango
                days = []
                cur = datetime.strptime(fi, "%Y-%m-%d").date()
                end = datetime.strptime(ff, "%Y-%m-%d").date()
                while cur <= end:
                    days.append(cur.strftime("%Y-%m-%d"))
                    cur += timedelta(days=1)

                sin_por_dia = []
                base_nifs = set(base_emp_sin["nif"].astype(str).str.upper().str.strip().tolist())

                # Precalcular set de (nif, fecha_dia) con fichajes
                fich_pairs = set()
                if not fich_df.empty:
                    fich_df["nif"] = fich_df["nif"].astype(str).str.upper().str.strip()
                    for _, r in fich_df.dropna(subset=["nif", "fecha_dia"]).iterrows():
                        fich_pairs.add((r["nif"], r["fecha_dia"]))

                for d in days:
                    nifs_con = {n for (n, fd) in fich_pairs if fd == d}
                    nifs_sin = sorted(list(base_nifs - nifs_con))
                    if not nifs_sin:
                        continue

                    tmp = base_emp_sin[base_emp_sin["nif"].isin(nifs_sin)].copy()
                    if tmp.empty:
                        continue

                    tmp["Fecha"] = d
                    tmp = tmp.rename(
                        columns={
                            "empresa_nombre": "Empresa",
                            "sede_nombre": "Sede",
                            "nombre_completo": "Nombre",
                            "departamento_nombre": "Departamento",
                        }
                    )
                    # Solo columnas necesarias
                    tmp = tmp[["Fecha", "Empresa", "Sede", "Nombre", "Departamento", "nif"]].copy()
                    tmp = tmp.drop(columns=["nif"], errors="ignore")
                    sin_por_dia.append(tmp)

                if not sin_por_dia:
                    st.info("No hay empleados 'Sin fichajes' en el rango/filtrado seleccionado.")
                else:
                    sin_df = pd.concat(sin_por_dia, ignore_index=True)
                    for f_dia in sin_df["Fecha"].unique():
                        sub = sin_df[sin_df["Fecha"] == f_dia].copy()
                        if sub.empty:
                            continue
                        st.markdown(f"### 🚫 Empleados sin fichajes — {f_dia}")
                        st.data_editor(sub, use_container_width=True, hide_index=True, disabled=True, num_rows="fixed")

                    csv_s = sin_df.to_csv(index=False).encode("utf-8")
                    st.download_button("⬇ Descargar CSV (sin fichajes)", csv_s, "empleados_sin_fichajes.csv", "text/csv")
