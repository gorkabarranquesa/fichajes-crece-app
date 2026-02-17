# app.py — Fichajes CRECE Personas (seguro + optimizado + tabs)
# ✅ Fixes incluidos:
#  - Exclusión de “Sin fichajes” por CÓDIGO DE EMPLEADO (num_empleado) y/o por nombre (no por NIF)
#  - Redondeo consistente (a minuto) en Total trabajado / Tiempo Contabilizado + Diferencia con tolerancia 1 minuto (evita +00:01)
#  - Limpieza de código “colado” al inicio (variables sueltas que podían romper la app)
#  - Mantiene filtros por Empresa/Sede, tabs (Fichajes | Bajas | Sin fichajes), seguridad y rendimiento

import base64
import json
import multiprocessing
import random
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date, datetime, timedelta

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

# Redondeo / tolerancias
ROUND_TO_MINUTE = True
DIF_TOL_MINUTES = 1  # si la diferencia absoluta es <= 1 min, mostramos "" (equivale a 0)

# ============================================================
# FILTROS NEGOCIO (empresas/sedes permitidas)
# ============================================================

EMPRESAS_PERMITIDAS = [
    "Barranquesa Tower Flanges, S.L.",
    "Barranquesa Anchor Cages, S.L.",
    "Industrial Barranquesa S.A.",
]

SEDES_PERMITIDAS = [
    "P0 IBSA",
    "P1 LAKUNTZA",
    "P2 COMARCA II",
    "P3 UHARTE",
]

# ============================================================
# EXCLUSIONES "SIN FICHAJES" (por CODIGO EMPLEADO y/o por NOMBRE)
#  - OJO: los códigos (0000000139, etc.) NO son NIF, son num_empleado.
# ============================================================

EXCLUDE_SIN_FICHAJES_NUM_EMPLEADO = {
    "0000000139",  # Mikel Arzallus Marco
    "0000000012",  # Jose Angel Ochagavia Satrustegui
    "0000000010",  # Benito Mendinueta Andueza
}

EXCLUDE_SIN_FICHAJES_NOMBRES = {
    "MIKEL ARZALLUS MARCO",
    "JOSE ANGEL OCHAGAVIA SATRUSTEGUI",
    "BENITO MENDINUETA ANDUEZA",
}

# ============================================================
# SESSION
# ============================================================

_SESSION = requests.Session()
_SESSION.headers.update(
    {
        "Accept": "application/json",
        "Authorization": f"Bearer {API_TOKEN}",
        "User-Agent": USER_AGENT,
    }
)

# ============================================================
# SEGURIDAD: no loguear detalles (PII, tokens, payloads)
# ============================================================

def _safe_fail(_exc: Exception) -> None:
    return None

# ============================================================
# SAFE REQUEST: centraliza peticiones + verify=True + retries
# ============================================================

def safe_request(method: str, url: str, *, data=None, params=None, timeout=HTTP_TIMEOUT):
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
# NORMALIZACIÓN NOMBRES
# ============================================================

def norm_name(s: str) -> str:
    if s is None:
        return ""
    return " ".join(str(s).upper().strip().split())

def name_startswith(nombre_norm: str, prefix_norm: str) -> bool:
    return bool(nombre_norm) and bool(prefix_norm) and nombre_norm.startswith(prefix_norm)

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
# TIEMPOS (redondeo consistente)
# ============================================================

def segundos_a_hhmm(seg: float) -> str:
    """
    Redondeo consistente:
      - Si ROUND_TO_MINUTE=True: redondea a minuto (>=30s sube)
      - Si False: trunca a minuto (floor)
    """
    if seg is None or pd.isna(seg):
        return ""
    try:
        seg_f = float(seg)
    except Exception:
        return ""
    if seg_f < 0:
        seg_f = 0.0

    if ROUND_TO_MINUTE:
        total_min = int((seg_f + 30) // 60)  # redondeo al minuto
    else:
        total_min = int(seg_f) // 60         # truncado al minuto

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
    """
    Diferencia = Tiempo Contabilizado - Total trabajado (en minutos)
    Si abs(diff) <= DIF_TOL_MINUTES, devuelve "" (evita +00:01 / -00:01).
    """
    tc_hhmm = (tc_hhmm or "").strip()
    tt_hhmm = (tt_hhmm or "").strip()
    if not tc_hhmm or not tt_hhmm:
        return ""

    tc_min = hhmm_to_min(tc_hhmm)
    tt_min = hhmm_to_min(tt_hhmm)

    diff = tc_min - tt_min
    if abs(diff) <= DIF_TOL_MINUTES:
        return ""

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
# NOMBRES (tal cual CRECE)
# ============================================================

N_DAVID = norm_name("David Rodriguez Vazquez")
N_DEBORA = norm_name("Debora Luis Soto")
N_ETOR = norm_name("Etor Alegria Reparaz")
N_FRAN = norm_name("Fran Diaz Arozarena")
N_MIRIAM = norm_name("Miriam Martín Muñoz")
N_BEATRIZ = norm_name("Beatriz Andueza Roncal")

# ============================================================
# REGLAS ESPECIALES RRHH (mínimos)
# + Beatriz (ESTRUCTURA) con umbral excesivos especial
# ============================================================

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
# API EXPORTACIÓN (Empresas / Sedes / Departamentos / Empleados)
# ============================================================

@st.cache_data(show_spinner=False, ttl=3600)
def api_exportar_empresas() -> pd.DataFrame:
    url = f"{API_URL_BASE}/exportacion/empresas"
    resp = safe_request("GET", url)
    if resp is None:
        return pd.DataFrame(columns=["empresa_id", "empresa_nombre"])
    resp.raise_for_status()

    payload_b64 = _extract_payload_b64(resp)
    decrypted = decrypt_crece_payload(payload_b64, APP_KEY_B64)
    data = json.loads(decrypted)

    rows = []
    for x in (data or []):
        rows.append({"empresa_id": x.get("id"), "empresa_nombre": x.get("nombre")})
    df = pd.DataFrame(rows)
    return df

@st.cache_data(show_spinner=False, ttl=3600)
def api_exportar_sedes() -> pd.DataFrame:
    url = f"{API_URL_BASE}/exportacion/sedes"
    resp = safe_request("GET", url)
    if resp is None:
        return pd.DataFrame(columns=["sede_id", "sede_nombre"])
    resp.raise_for_status()

    payload_b64 = _extract_payload_b64(resp)
    decrypted = decrypt_crece_payload(payload_b64, APP_KEY_B64)
    data = json.loads(decrypted)

    rows = []
    for x in (data or []):
        rows.append({"sede_id": x.get("id"), "sede_nombre": x.get("nombre")})
    df = pd.DataFrame(rows)
    return df

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

def api_exportar_empleados_completos() -> pd.DataFrame:
    """
    Incluye:
      - nif
      - nombre_completo
      - departamento_id
      - empresa_id
      - sede_id
      - num_empleado (código empleado)  ✅ necesario para exclusiones de sin fichajes
      - estado/contrato (si existe)
    """
    url = f"{API_URL_BASE}/exportacion/empleados"
    data = {"solo_nif": 0}

    resp = safe_request("POST", url, data=data)
    if resp is None:
        return pd.DataFrame(columns=["nif", "nombre_completo", "departamento_id", "empresa_id", "sede_id", "num_empleado"])
    resp.raise_for_status()

    payload_b64 = _extract_payload_b64(resp)
    decrypted = decrypt_crece_payload(payload_b64, APP_KEY_B64)
    empleados = json.loads(decrypted)

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

        # num_empleado / codigo
        num_emp = e.get("num_empleado") or e.get("numero_empleado") or e.get("codigo_empleado") or e.get("employee_number") or ""

        lista.append(
            {
                "nif": e.get("nif"),
                "nombre_completo": nombre_completo,
                "departamento_id": e.get("departamento"),
                "empresa_id": e.get("empresa") or e.get("empresa_id"),
                "sede_id": e.get("sede") or e.get("sede_id"),
                "num_empleado": str(num_emp).strip(),
                # campos opcionales, por si CRECE los entrega
                "estado": e.get("estado"),
                "fecha_baja": e.get("fecha_baja"),
                "motivo_baja": e.get("motivo_baja"),
                "contrato": e.get("contrato"),
                "fecha_alta": e.get("fecha_alta"),
            }
        )

    df = pd.DataFrame(lista)
    if not df.empty:
        df["nif"] = df["nif"].astype(str).str.upper().str.strip()
        df["num_empleado"] = df["num_empleado"].astype(str).str.strip()
    return df

# ============================================================
# API: Tipos fichaje / Fichajes / Tiempo trabajado
# ============================================================

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
# API: Informes empleados (bajas) — /informes/empleados
# ============================================================

def api_informe_empleados(fecha_desde: str, fecha_hasta: str):
    """
    Endpoint: /informes/empleados
    Devuelve (según entorno) un JSON plano o un base64 de un JSON con {iv,value}.
    """
    url = f"{API_URL_BASE}/informes/empleados"
    body_json = {"fecha_desde": fecha_desde, "fecha_hasta": fecha_hasta}

    # Intento 1: JSON body
    try:
        resp = _SESSION.post(url, json=body_json, timeout=HTTP_TIMEOUT, verify=True)
    except Exception:
        resp = None

    # Si falla, intento 2: form-data (data)
    if resp is None or resp.status_code >= 400:
        try:
            resp = safe_request("POST", url, data=body_json)
        except Exception:
            resp = None

    if resp is None:
        return None

    try:
        resp.raise_for_status()
    except Exception:
        return None

    raw = (resp.text or "").strip().strip('"').strip()
    if not raw:
        return None

    # 1) Si es JSON plano
    try:
        parsed = resp.json()
        return parsed
    except Exception:
        pass

    # 2) Si es base64 con envolvente {iv,value}
    try:
        decrypted = decrypt_crece_payload(raw, APP_KEY_B64)
        return json.loads(decrypted)
    except Exception:
        return None

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
# Helpers filtros Empresa/Sede (prioridad empresa)
# ============================================================

def _safe_str(x):
    return "" if x is None else str(x)

def _iter_days(d0: date, d1: date):
    cur = d0
    while cur <= d1:
        yield cur
        cur += timedelta(days=1)

def _sig(fi: str, ff: str, empresas: list[str], sedes: list[str]) -> str:
    e = ",".join(sorted(empresas or []))
    s = ",".join(sorted(sedes or []))
    return f"{fi}|{ff}|{e}|{s}"

def _mask_digit_snippet(s: str) -> str:
    if not s:
        return ""
    # enmascara dígitos (no mostrar PII)
    return re.sub(r"\d", "•", s)[:140]

# ============================================================
# Determinar empleado ACTIVO / CONTRATO (para "Sin fichajes")
# ============================================================

def empleado_activo_o_contrato(df_emp: pd.DataFrame) -> pd.Series:
    """
    Heurística defensiva:
      - si existe columna 'estado' y contiene 'activo' => True
      - si existe 'fecha_baja' no vacía => False
      - si existe 'contrato' no vacío => True
    En caso de duda => True (para no ocultar empleados por error)
    """
    if df_emp is None or df_emp.empty:
        return pd.Series([], dtype=bool)

    out = pd.Series([True] * len(df_emp), index=df_emp.index, dtype=bool)

    if "fecha_baja" in df_emp.columns:
        fb = df_emp["fecha_baja"].astype(str).str.strip()
        out = out & fb.isin(["", "None", "nan", "NaT", "NULL", "null"])

    if "estado" in df_emp.columns:
        est = df_emp["estado"].astype(str).str.upper()
        # si explícitamente dice BAJA, desactiva
        out = out & (~est.str.contains("BAJA", na=False))
        # si explícitamente dice ACTIVO, activa (no cambia a False)
        # (ya está en True por defecto)
    if "contrato" in df_emp.columns:
        con = df_emp["contrato"].astype(str).str.strip()
        out = out | con.ne("")

    return out.fillna(True)

# ============================================================
# UI
# ============================================================

st.set_page_config(page_title="Fichajes CRECE Personas", layout="wide")
st.title("📊 Fichajes CRECE Personas")

# Cargar catálogos (una vez)
with st.spinner("Cargando catálogos…"):
    empresas_df = api_exportar_empresas()
    sedes_df = api_exportar_sedes()
    departamentos_df = api_exportar_departamentos()

# Filtros de fechas
hoy = date.today()
col1, col2 = st.columns(2)
with col1:
    fecha_inicio = st.date_input("Fecha inicio", value=hoy, max_value=hoy)
with col2:
    fecha_fin = st.date_input("Fecha fin", value=hoy, max_value=hoy)

st.write("---")

# Filtros Empresa/Sede PRE-consulta
st.subheader("🔎 Filtros")

# Empresas permitidas (por nombre)
empresas_disponibles = []
if not empresas_df.empty and "empresa_nombre" in empresas_df.columns:
    empresas_disponibles = (
        empresas_df["empresa_nombre"].dropna().astype(str).tolist()
    )
# aplicar whitelist
empresas_disponibles = [e for e in empresas_disponibles if e in EMPRESAS_PERMITIDAS]
empresas_disponibles = sorted(set(empresas_disponibles))

# Sedes permitidas (por nombre)
sedes_disponibles = []
if not sedes_df.empty and "sede_nombre" in sedes_df.columns:
    sedes_disponibles = sedes_df["sede_nombre"].dropna().astype(str).tolist()
sedes_disponibles = [s for s in sedes_disponibles if s in SEDES_PERMITIDAS]
sedes_disponibles = sorted(set(sedes_disponibles))

c1, c2 = st.columns(2)
with c1:
    sel_empresas = st.multiselect("Empresa", options=empresas_disponibles, default=empresas_disponibles)
with c2:
    sel_sedes = st.multiselect("Sede", options=sedes_disponibles, default=sedes_disponibles)

# Si el usuario quita todas las empresas, no hay nada que consultar
if not sel_empresas:
    st.warning("Selecciona al menos una empresa.")
    st.stop()

# Botón
btn = st.button("Consultar")

# Estado
if "last_sig" not in st.session_state:
    st.session_state["last_sig"] = ""
    st.session_state["result_incidencias"] = {}
    st.session_state["result_bajas"] = {}
    st.session_state["result_sin_fichajes"] = {}
    st.session_state["result_csv_incidencias"] = b""
    st.session_state["result_csv_bajas"] = b""
    st.session_state["result_csv_sin"] = b""

# ============================================================
# CONSULTA
# ============================================================

if btn:
    if fecha_inicio > fecha_fin:
        st.error("❌ La fecha inicio no puede ser posterior a la fecha fin.")
        st.stop()
    if fecha_fin > hoy:
        st.error("❌ La fecha fin no puede ser mayor que hoy.")
        st.stop()

    fi = fecha_inicio.strftime("%Y-%m-%d")
    ff = fecha_fin.strftime("%Y-%m-%d")
    signature = _sig(fi, ff, sel_empresas, sel_sedes)

    with st.spinner("Procesando…"):
        tipos_map = api_exportar_tipos_fichaje()
        empleados_df = api_exportar_empleados_completos()
        if empleados_df.empty:
            st.warning("No hay empleados disponibles.")
            st.stop()

        # --- Mapear IDs a nombres (Empresa/Sede/Departamento)
        # empresa
        if not empresas_df.empty:
            empresas_df2 = empresas_df.rename(columns={"empresa_id": "empresa_id", "empresa_nombre": "Empresa"})
            empleados_df = empleados_df.merge(
                empresas_df2[["empresa_id", "Empresa"]],
                on="empresa_id",
                how="left",
            )
        else:
            empleados_df["Empresa"] = ""

        # sede
        if not sedes_df.empty:
            sedes_df2 = sedes_df.rename(columns={"sede_id": "sede_id", "sede_nombre": "Sede"})
            empleados_df = empleados_df.merge(
                sedes_df2[["sede_id", "Sede"]],
                on="sede_id",
                how="left",
            )
        else:
            empleados_df["Sede"] = ""

        # departamento
        if not departamentos_df.empty:
            empleados_df = empleados_df.merge(
                departamentos_df.rename(columns={"departamento_id": "departamento_id", "departamento_nombre": "departamento_nombre"}),
                on="departamento_id",
                how="left",
            )
        else:
            empleados_df["departamento_nombre"] = ""

        empleados_df["nif"] = empleados_df["nif"].astype(str).str.upper().str.strip()
        empleados_df["num_empleado"] = empleados_df.get("num_empleado", "").astype(str).str.strip()

        # --- Aplicar filtros Empresa/Sede (empresa prioritaria)
        # Primero filtramos por Empresa (siempre)
        empleados_df = empleados_df[empleados_df["Empresa"].isin(sel_empresas)].copy()

        # Luego por Sede (solo entre las empresas ya filtradas)
        # Nota: si el usuario deja una sede asociada a empresa no seleccionada, no aparece nada (empresa manda).
        if sel_sedes:
            empleados_df = empleados_df[empleados_df["Sede"].isin(sel_sedes)].copy()

        if empleados_df.empty:
            st.info("No hay empleados que cumplan los filtros de Empresa/Sede.")
            st.session_state["last_sig"] = signature
            st.session_state["result_incidencias"] = {}
            st.session_state["result_bajas"] = {}
            st.session_state["result_sin_fichajes"] = {}
            st.session_state["result_csv_incidencias"] = b""
            st.session_state["result_csv_bajas"] = b""
            st.session_state["result_csv_sin"] = b""
            st.stop()

        base_emp = empleados_df.copy()

        # ============================================================
        # FICHAJES: traer fichajes por empleado (filtrado ya por Empresa/Sede)
        # ============================================================

        fichajes_rows = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as exe:
            futures = {exe.submit(api_exportar_fichajes, r["nif"], fi, ff): r for _, r in base_emp.iterrows()}
            for fut in as_completed(futures):
                emp = futures[fut]
                for x in (fut.result() or []):
                    fichajes_rows.append(
                        {
                            "nif": emp["nif"],
                            "Nombre": emp["nombre_completo"],
                            "Departamento": emp.get("departamento_nombre"),
                            "Empresa": emp.get("Empresa", ""),
                            "Sede": emp.get("Sede", ""),
                            "id": x.get("id"),
                            "tipo": x.get("tipo"),
                            "direccion": x.get("direccion"),
                            "fecha": x.get("fecha"),
                        }
                    )

        if not fichajes_rows:
            # aun así, podemos mostrar SIN FICHAJES (y BAJAS) según filtros
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

        # ============================================================
        # INCIDENCIAS (si hay fichajes)
        # ============================================================

        salida_incidencias = pd.DataFrame()
        if not df_fich.empty:
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

            # Tiempo contabilizado día a día (robusto)
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

            # Diferencia (con tolerancia de 1 minuto)
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

        # ============================================================
        # BAJAS: día a día (para identificar día exacto con horas_baja > 0)
        # ============================================================

        bajas_por_dia = {}
        d0 = datetime.strptime(fi, "%Y-%m-%d").date()
        d1 = datetime.strptime(ff, "%Y-%m-%d").date()

        for cur in _iter_days(d0, d1):
            day = cur.strftime("%Y-%m-%d")
            info = api_informe_empleados(day, day)
            if info is None:
                continue

            # info puede ser lista, dict, etc. Normalizamos a lista de registros.
            if isinstance(info, dict):
                # algunos formatos vienen como {"data":[...]} o similar
                if "data" in info and isinstance(info["data"], list):
                    rows = info["data"]
                else:
                    # dict con claves por empleado
                    rows = []
                    for _, v in info.items():
                        if isinstance(v, dict):
                            rows.append(v)
            elif isinstance(info, list):
                rows = info
            else:
                rows = []

            if not rows:
                continue

            out_rows = []
            for r in rows:
                try:
                    hb = float(r.get("horas_baja") or 0)
                except Exception:
                    hb = 0.0
                if hb <= 0:
                    continue

                # Identificación del empleado para enriquecer con base_emp (filtrada por empresa/sede)
                nif = str(r.get("nif") or "").upper().strip()
                num_emp = str(r.get("num_empleado") or r.get("numero_empleado") or "").strip()
                nombre = str(r.get("nombre_completo") or r.get("nombre") or "").strip()

                out_rows.append(
                    {
                        "Fecha": day,
                        "nif": nif,
                        "num_empleado": num_emp,
                        "Nombre_raw": nombre,
                        "Horas baja": hb,
                    }
                )

            if not out_rows:
                continue

            df_b = pd.DataFrame(out_rows)

            # Enriquecer con base_emp (ya filtrado por empresa/sede)
            # Priorizamos match por nif; si no, por num_empleado; si no, por nombre normalizado
            base_tmp = base_emp.copy()
            base_tmp["nombre_norm"] = base_tmp["nombre_completo"].apply(norm_name)
            df_b["nombre_norm"] = df_b["Nombre_raw"].apply(norm_name)

            df_b["nif"] = df_b["nif"].astype(str).str.upper().str.strip()
            df_b["num_empleado"] = df_b["num_empleado"].astype(str).str.strip()

            merged = df_b.merge(
                base_tmp[["nif", "num_empleado", "Empresa", "Sede", "nombre_completo", "departamento_nombre", "nombre_norm"]],
                on="nif",
                how="left",
                suffixes=("", "_emp"),
            )

            # completar por num_empleado si falta
            miss = merged["nombre_completo"].isna()
            if miss.any():
                m2 = merged[miss].merge(
                    base_tmp[["num_empleado", "Empresa", "Sede", "nombre_completo", "departamento_nombre", "nombre_norm"]],
                    on="num_empleado",
                    how="left",
                    suffixes=("", "_emp2"),
                )
                for col in ["Empresa", "Sede", "nombre_completo", "departamento_nombre", "nombre_norm"]:
                    merged.loc[miss, col] = m2[col].values

            # completar por nombre_norm si falta
            miss = merged["nombre_completo"].isna()
            if miss.any():
                m3 = merged[miss].merge(
                    base_tmp[["nombre_norm", "Empresa", "Sede", "nombre_completo", "departamento_nombre"]],
                    on="nombre_norm",
                    how="left",
                    suffixes=("", "_emp3"),
                )
                for col in ["Empresa", "Sede", "nombre_completo", "departamento_nombre"]:
                    merged.loc[miss, col] = m3[col].values

            # quedarnos solo con empleados dentro del filtro empresa/sede (si no matchea => fuera)
            merged = merged[merged["nombre_completo"].notna()].copy()
            if merged.empty:
                continue

            out = merged.rename(
                columns={
                    "nombre_completo": "Nombre",
                    "departamento_nombre": "Departamento",
                }
            )
            out["Horas baja"] = out["Horas baja"].apply(lambda x: float(x) if pd.notna(x) else 0.0)

            out = out[["Fecha", "Empresa", "Sede", "Nombre", "Departamento", "Horas baja"]].copy()
            out = out[out["Nombre"].astype(str).str.strip().ne("")]
            if not out.empty:
                bajas_por_dia[day] = out.sort_values(["Nombre"], kind="mergesort").reset_index(drop=True)

        # ============================================================
        # SIN FICHAJES (solo ACTIVO / CONTRATO, + exclusiones)
        # ============================================================

        sin_por_dia = {}

        base_emp_sin = base_emp.copy()
        mask_activo = empleado_activo_o_contrato(base_emp_sin)
        base_emp_sin = base_emp_sin[mask_activo].copy()

        # Exclusiones (por num_empleado y por nombre)
        base_emp_sin["num_empleado"] = base_emp_sin.get("num_empleado", "").astype(str).str.strip()
        base_emp_sin["nombre_norm"] = base_emp_sin["nombre_completo"].apply(norm_name)

        base_emp_sin = base_emp_sin[
            ~base_emp_sin["num_empleado"].isin(EXCLUDE_SIN_FICHAJES_NUM_EMPLEADO)
        ].copy()
        base_emp_sin = base_emp_sin[
            ~base_emp_sin["nombre_norm"].isin(EXCLUDE_SIN_FICHAJES_NOMBRES)
        ].copy()

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

        # ============================================================
        # Guardar en estado + CSVs
        # ============================================================

        incidencias_por_dia = {}
        if not salida_incidencias.empty:
            for day, sub in salida_incidencias.groupby("Fecha"):
                incidencias_por_dia[str(day)] = sub.reset_index(drop=True)

        st.session_state["last_sig"] = signature
        st.session_state["result_incidencias"] = incidencias_por_dia
        st.session_state["result_bajas"] = bajas_por_dia
        st.session_state["result_sin_fichajes"] = sin_por_dia

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

# ------------------------------------------------------------
# Render: Tabs
# ------------------------------------------------------------
fi_sig = fecha_inicio.strftime("%Y-%m-%d")
ff_sig = fecha_fin.strftime("%Y-%m-%d")
current_sig = _sig(fi_sig, ff_sig, sel_empresas, sel_sedes)

if st.session_state["last_sig"] != current_sig:
    st.info("Ajusta filtros/fechas y pulsa **Consultar** para ver resultados.")
    st.stop()

tab1, tab2, tab3 = st.tabs(["📌 Fichajes", "🏥 Bajas", "⛔ Sin fichajes"])

with tab1:
    incid = st.session_state.get("result_incidencias", {}) or {}
    if not incid:
        st.success("🎉 No hay incidencias en el rango seleccionado.")
    else:
        for day in sorted(incid.keys()):
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
