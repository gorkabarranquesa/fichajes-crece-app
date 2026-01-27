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
# NORMALIZACIÓN NOMBRES
# ============================================================

def norm_name(s: str) -> str:
    if s is None:
        return ""
    return " ".join(str(s).upper().strip().split())

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
# BASE64 ROBUSTO (normal y URL-safe)
# ============================================================

def b64decode_any(s: str) -> bytes:
    """
    Decodifica base64 estándar o base64url, con/sin padding.
    """
    if s is None:
        raise ValueError("b64decode_any: empty")
    s = str(s).strip()
    # eliminar comillas externas si vienen
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        s = s[1:-1].strip()

    pad = (-len(s)) % 4
    if pad:
        s += "=" * pad

    try:
        return base64.urlsafe_b64decode(s.encode("utf-8"))
    except Exception:
        return base64.b64decode(s.encode("utf-8"))

def _looks_like_b64_any(s: str) -> bool:
    s = (s or "").strip()
    if len(s) < 40:
        return False
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-\n\r")
    return all(c in allowed for c in s)

# ============================================================
# DESCIFRADO CRECE (AES-CBC) + soporta base64url
# ============================================================

def decrypt_crece_payload(payload_b64: str, app_key_b64: str) -> str:
    """
    payload_b64: base64/base64url de un JSON {"iv":"...","value":"..."}
    """
    json_raw = b64decode_any(payload_b64).decode("utf-8", errors="strict")
    payload = json.loads(json_raw)

    iv = b64decode_any(payload["iv"])
    ct = b64decode_any(payload["value"])
    key = b64decode_any(app_key_b64)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ct), AES.block_size)
    return decrypted.decode("utf-8")

def decrypt_crece_payload_from_dict(payload: dict, app_key_b64: str) -> str:
    iv = b64decode_any(payload.get("iv") or "")
    ct = b64decode_any(payload.get("value") or payload.get("ciphertext") or "")
    key = b64decode_any(app_key_b64)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ct), AES.block_size)
    return decrypted.decode("utf-8")

def _extract_payload_b64(resp: requests.Response) -> str:
    return (resp.text or "").strip().strip('"').strip("'").strip()

# ============================================================
# HELPERS: extracción robusta de respuesta (plano/cifrado/base64url)
# ============================================================

def _try_parse_json_text(txt: str):
    txt = (txt or "").strip()
    if not txt:
        return None
    try:
        return json.loads(txt)
    except Exception:
        return None

def _extract_possible_payload(resp: requests.Response):
    """
    Soporta:
      - JSON plano list/dict
      - dict {iv,value}
      - wrapper dict con payload en data/payload/result/encrypted/content
      - JSON-string que contiene base64url "eyJpdiI6..."
      - body base64 directo
    """
    raw_text = (resp.text or "").strip()

    # 1) resp.json()
    try:
        parsed = resp.json()

        if isinstance(parsed, str) and _looks_like_b64_any(parsed):
            return None, parsed.strip(), None, raw_text

        if isinstance(parsed, (list, dict)):
            if isinstance(parsed, dict) and ("iv" in parsed) and (("value" in parsed) or ("ciphertext" in parsed)):
                return None, None, parsed, raw_text

            if isinstance(parsed, dict):
                for k in ["data", "payload", "result", "encrypted", "content"]:
                    v = parsed.get(k)
                    if isinstance(v, str) and _looks_like_b64_any(v):
                        return None, v.strip(), None, raw_text
                    if isinstance(v, dict) and ("iv" in v) and (("value" in v) or ("ciphertext" in v)):
                        return None, None, v, raw_text

            return parsed, None, None, raw_text
    except Exception:
        pass

    # 2) JSON desde texto
    parsed_text = _try_parse_json_text(raw_text)
    if isinstance(parsed_text, str) and _looks_like_b64_any(parsed_text):
        return None, parsed_text.strip(), None, raw_text

    if isinstance(parsed_text, (list, dict)):
        if isinstance(parsed_text, dict) and ("iv" in parsed_text) and (("value" in parsed_text) or ("ciphertext" in parsed_text)):
            return None, None, parsed_text, raw_text

        if isinstance(parsed_text, dict):
            for k in ["data", "payload", "result", "encrypted", "content"]:
                v = parsed_text.get(k)
                if isinstance(v, str) and _looks_like_b64_any(v):
                    return None, v.strip(), None, raw_text
                if isinstance(v, dict) and ("iv" in v) and (("value" in v) or ("ciphertext" in v)):
                    return None, None, v, raw_text

        return parsed_text, None, None, raw_text

    # 3) base64 directo
    body = raw_text.strip().strip('"').strip("'").strip()
    if _looks_like_b64_any(body):
        return None, body, None, raw_text

    return None, None, None, raw_text

def _flatten_records(parsed):
    if parsed is None:
        return []
    if isinstance(parsed, list):
        return [x for x in parsed if isinstance(x, dict)]
    if isinstance(parsed, dict):
        for k in ["empleados", "data", "result"]:
            v = parsed.get(k)
            if isinstance(v, list):
                return [x for x in v if isinstance(x, dict)]
        out = []
        for _, v in parsed.items():
            if isinstance(v, dict):
                out.append(v)
            elif isinstance(v, list):
                out.extend([x for x in v if isinstance(x, dict)])
        return out
    return []

def _pick_key_case_insensitive(d: dict, candidates: list[str]):
    if not isinstance(d, dict):
        return None
    lower_map = {str(k).lower(): k for k in d.keys()}
    for c in candidates:
        kc = lower_map.get(str(c).lower())
        if kc is not None:
            return kc
    return None

def _as_float(x):
    try:
        if x is None or (isinstance(x, str) and x.strip() == ""):
            return 0.0
        return float(x)
    except Exception:
        return 0.0

def _as_str(x):
    return "" if x is None else str(x).strip()

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

def hhmm_to_min_clock(hhmm: str):
    if not isinstance(hhmm, str) or ":" not in hhmm:
        return None
    try:
        h, m = map(int, hhmm.split(":"))
        return h * 60 + m
    except Exception:
        return None

# ============================================================
# REGLAS ESPECIALES RRHH
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
# VALIDACIÓN HORARIA
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
# API: Export genérico (para mapping id->nombre)
# ============================================================

def _export_list_try(endpoint: str, *, method_prefer="GET"):
    """
    Intenta llamar al endpoint y devolver lista parseada descifrada.
    Soporta respuesta cifrada tipo exportación CRECE.
    """
    url = f"{API_URL_BASE}/{endpoint.lstrip('/')}"
    methods = ["GET", "POST"] if method_prefer == "GET" else ["POST", "GET"]

    for m in methods:
        try:
            resp = safe_request(m, url)
            if resp is None:
                continue
            if resp.status_code >= 400:
                continue

            payload_b64 = _extract_payload_b64(resp)
            if not payload_b64:
                continue

            decrypted = decrypt_crece_payload(payload_b64, APP_KEY_B64)
            parsed = json.loads(decrypted)
            if isinstance(parsed, list):
                return parsed
        except Exception as e:
            _safe_fail(e)
            continue

    return None

def _build_id_name_df(items, id_keys, name_keys, df_cols=("id", "nombre")) -> pd.DataFrame:
    rows = []
    for it in (items or []):
        if not isinstance(it, dict):
            continue

        id_val = None
        for k in id_keys:
            if k in it and it.get(k) is not None:
                id_val = it.get(k)
                break

        name_val = None
        for k in name_keys:
            if k in it and it.get(k) is not None:
                name_val = it.get(k)
                break

        if id_val is None:
            continue

        rows.append({"id": str(id_val).strip(), "nombre": "" if name_val is None else str(name_val).strip()})

    df = pd.DataFrame(rows)
    if df.empty:
        return pd.DataFrame(columns=list(df_cols))
    df = df.drop_duplicates(subset=["id"], keep="first")
    return df.rename(columns={"id": df_cols[0], "nombre": df_cols[1]})

@st.cache_data(show_spinner=False, ttl=3600)
def api_exportar_empresas() -> pd.DataFrame:
    """
    Construye mapping empresa_id -> empresa_nombre probando endpoints habituales.
    Si tu instancia usa otro endpoint, no rompe: devuelve DF vacío.
    """
    candidates = [
        ("exportacion/empresas", "GET"),
        ("exportacion/empresa", "GET"),
        ("exportacion/companias", "GET"),
        ("exportacion/compania", "GET"),
    ]
    for ep, pref in candidates:
        items = _export_list_try(ep, method_prefer=pref)
        if items:
            return _build_id_name_df(items, id_keys=["id", "empresa_id", "cod", "codigo"], name_keys=["nombre", "name", "descripcion", "description"],
                                     df_cols=("empresa_id", "empresa_nombre"))
    return pd.DataFrame(columns=["empresa_id", "empresa_nombre"])

@st.cache_data(show_spinner=False, ttl=3600)
def api_exportar_sedes() -> pd.DataFrame:
    """
    Construye mapping sede_id -> sede_nombre probando endpoints habituales.
    """
    candidates = [
        ("exportacion/sedes", "GET"),
        ("exportacion/sede", "GET"),
        ("exportacion/centros", "GET"),
        ("exportacion/centros-trabajo", "GET"),
        ("exportacion/centros_trabajo", "GET"),
    ]
    for ep, pref in candidates:
        items = _export_list_try(ep, method_prefer=pref)
        if items:
            return _build_id_name_df(items, id_keys=["id", "sede_id", "centro_id", "codigo", "cod"], name_keys=["nombre", "name", "descripcion", "description"],
                                     df_cols=("sede_id", "sede_nombre"))
    return pd.DataFrame(columns=["sede_id", "sede_nombre"])

# ============================================================
# API EXPORTACIÓN: Departamentos / Empleados / Tipos / Fichajes / Tiempo
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

def api_exportar_empleados_completos() -> pd.DataFrame:
    """
    Devuelve empleados con:
      - nif
      - num_empleado (si existe)
      - departamento_id
      - empresa_id / sede_id (si existen)
    Luego en UI se traducen a nombres con mappings.
    """
    url = f"{API_URL_BASE}/exportacion/empleados"
    data = {"solo_nif": 0}

    resp = safe_request("POST", url, data=data)
    if resp is None:
        return pd.DataFrame(columns=["nif", "num_empleado", "nombre_completo", "departamento_id", "empresa_id", "sede_id"])
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

        # claves frecuentes
        nif = e.get("nif")
        num_empleado = e.get("num_empleado") or e.get("numero_empleado") or e.get("empleado") or e.get("id_empleado") or e.get("id")
        empresa_id = e.get("empresa") or e.get("empresa_id") or e.get("cod_empresa")
        sede_id = e.get("sede") or e.get("sede_id") or e.get("centro") or e.get("centro_id")

        lista.append(
            {
                "nif": nif,
                "num_empleado": "" if num_empleado is None else str(num_empleado).strip(),
                "nombre_completo": nombre_completo,
                "departamento_id": e.get("departamento"),
                "empresa_id": "" if empresa_id is None else str(empresa_id).strip(),
                "sede_id": "" if sede_id is None else str(sede_id).strip(),
            }
        )

    df = pd.DataFrame(lista)
    if not df.empty:
        df["nif"] = df["nif"].astype(str).str.upper().str.strip()
        df["num_empleado"] = df["num_empleado"].astype(str).str.strip()
        df["empresa_id"] = df["empresa_id"].astype(str).str.strip()
        df["sede_id"] = df["sede_id"].astype(str).str.strip()
    return df

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
# INFORMES: /informes/empleados (DESCIFRADO ROBUSTO)
# ============================================================

@st.cache_data(show_spinner=False, ttl=3600)
def api_informes_empleados(fecha_desde: str, fecha_hasta: str):
    url = f"{API_URL_BASE}/informes/empleados"
    try:
        resp = safe_request("POST", url, json_body={"fecha_desde": fecha_desde, "fecha_hasta": fecha_hasta})
        if resp is None:
            return None
        resp.raise_for_status()

        parsed_json, payload_b64, payload_dict, _ = _extract_possible_payload(resp)

        if isinstance(parsed_json, (list, dict)):
            return parsed_json

        if isinstance(payload_dict, dict):
            decrypted = decrypt_crece_payload_from_dict(payload_dict, APP_KEY_B64)
            return json.loads(decrypted)

        if payload_b64:
            decrypted = decrypt_crece_payload(payload_b64, APP_KEY_B64)
            return json.loads(decrypted)

        return None
    except Exception as e:
        _safe_fail(e)
        return None

@st.cache_data(show_spinner=False, ttl=3600)
def obtener_bajas_por_dia(fi: str, ff: str) -> pd.DataFrame:
    """
    Consulta /informes/empleados día a día:
      - detecta horas_baja > 0
      - guarda nif y num_empleado si existen (para poder enriquecer)
    """
    d0 = datetime.strptime(fi, "%Y-%m-%d").date()
    d1 = datetime.strptime(ff, "%Y-%m-%d").date()

    rows = []
    cur = d0
    while cur <= d1:
        day = cur.strftime("%Y-%m-%d")
        parsed = api_informes_empleados(day, day)
        recs = _flatten_records(parsed)

        for r in recs:
            k_nif = _pick_key_case_insensitive(r, ["nif", "dni", "documento"])
            k_num = _pick_key_case_insensitive(r, ["num_empleado", "numero_empleado", "empleado", "id_empleado", "id"])
            k_horas = _pick_key_case_insensitive(r, ["horas_baja", "horas baja", "horasbaja"])

            nif = _as_str(r.get(k_nif)).upper() if k_nif else ""
            num_emp = _as_str(r.get(k_num)) if k_num else ""
            horas_baja = _as_float(r.get(k_horas)) if k_horas else 0.0

            if horas_baja > 0:
                rows.append(
                    {"Fecha": day, "nif": nif, "num_empleado": num_emp, "horas_baja": horas_baja}
                )

        cur += timedelta(days=1)

    df = pd.DataFrame(rows)
    if df.empty:
        return pd.DataFrame(columns=["Fecha", "nif", "num_empleado", "horas_baja"])
    df["nif"] = df["nif"].astype(str).str.upper().str.strip()
    df["num_empleado"] = df["num_empleado"].astype(str).str.strip()
    return df

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
# UI
# ============================================================

st.set_page_config(page_title="Fichajes CRECE Personas", layout="wide")
st.title("📊 Fichajes CRECE Personas")

hoy = date.today()

# --- Carga base (para filtros antes de consultar)
departamentos_df = api_exportar_departamentos()
empresas_map = api_exportar_empresas()
sedes_map = api_exportar_sedes()

empleados_df_base = api_exportar_empleados_completos()

if not empleados_df_base.empty:
    empleados_df_base = empleados_df_base.merge(departamentos_df, on="departamento_id", how="left")

    # traducir Empresa/Sede a nombres (si tenemos mappings)
    if not empresas_map.empty:
        empleados_df_base = empleados_df_base.merge(empresas_map, on="empresa_id", how="left")
    else:
        empleados_df_base["empresa_nombre"] = pd.NA

    if not sedes_map.empty:
        empleados_df_base = empleados_df_base.merge(sedes_map, on="sede_id", how="left")
    else:
        empleados_df_base["sede_nombre"] = pd.NA

    # columnas finales SIEMPRE en nombre (fallback a id si no hay mapping)
    empleados_df_base["Empresa"] = empleados_df_base["empresa_nombre"]
    empleados_df_base.loc[empleados_df_base["Empresa"].isna() | (empleados_df_base["Empresa"].astype(str).str.strip() == ""), "Empresa"] = empleados_df_base["empresa_id"]

    empleados_df_base["Sede"] = empleados_df_base["sede_nombre"]
    empleados_df_base.loc[empleados_df_base["Sede"].isna() | (empleados_df_base["Sede"].astype(str).str.strip() == ""), "Sede"] = empleados_df_base["sede_id"]

    # limpieza
    empleados_df_base["nif"] = empleados_df_base["nif"].astype(str).str.upper().str.strip()
    empleados_df_base["Empresa"] = empleados_df_base["Empresa"].astype(str).str.strip()
    empleados_df_base["Sede"] = empleados_df_base["Sede"].astype(str).str.strip()
    empleados_df_base["Departamento"] = empleados_df_base.get("departamento_nombre")

# --- Inputs
st.write("---")
col1, col2 = st.columns(2)
with col1:
    fecha_inicio = st.date_input("Fecha inicio", value=hoy, max_value=hoy)
with col2:
    fecha_fin = st.date_input("Fecha fin", value=hoy, max_value=hoy)

st.write("---")
st.markdown("### 🔎 Filtros")

f1, f2 = st.columns(2)

empresas_opts = sorted([x for x in empleados_df_base["Empresa"].dropna().astype(str).unique().tolist() if x.strip()]) if not empleados_df_base.empty else []
sedes_opts = sorted([x for x in empleados_df_base["Sede"].dropna().astype(str).unique().tolist() if x.strip()]) if not empleados_df_base.empty else []

with f1:
    empresas_sel = st.multiselect("Empresa", options=empresas_opts, default=empresas_opts)
with f2:
    sedes_sel = st.multiselect("Sede", options=sedes_opts, default=sedes_opts)

st.write("---")

# Persistencia resultados
if "ultimo_resultado" not in st.session_state:
    st.session_state.ultimo_resultado = None
if "ultimo_bajas" not in st.session_state:
    st.session_state.ultimo_bajas = None
if "ultimo_rango" not in st.session_state:
    st.session_state.ultimo_rango = None

if st.button("Consultar"):
    if fecha_inicio > fecha_fin:
        st.error("❌ La fecha inicio no puede ser posterior a la fecha fin.")
        st.stop()
    if fecha_fin > hoy:
        st.error("❌ La fecha fin no puede ser mayor que hoy.")
        st.stop()

    if empleados_df_base.empty:
        st.warning("No hay empleados disponibles.")
        st.stop()

    fi = fecha_inicio.strftime("%Y-%m-%d")
    ff = fecha_fin.strftime("%Y-%m-%d")

    # Filtrar empleados antes de consultar
    empleados_df = empleados_df_base.copy()
    if empresas_opts:
        empleados_df = empleados_df[empleados_df["Empresa"].isin(empresas_sel)]
    if sedes_opts:
        empleados_df = empleados_df[empleados_df["Sede"].isin(sedes_sel)]

    if empleados_df.empty:
        st.warning("No hay empleados para los filtros seleccionados.")
        st.stop()

    with st.spinner("Procesando…"):
        tipos_map = api_exportar_tipos_fichaje()

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
                            "Empresa": emp.get("Empresa", ""),
                            "Sede": emp.get("Sede", ""),
                            "id": x.get("id"),
                            "tipo": x.get("tipo"),
                            "direccion": x.get("direccion"),
                            "fecha": x.get("fecha"),
                        }
                    )

        if not fichajes_rows:
            st.info("No se encontraron fichajes en el rango seleccionado.")
            st.session_state.ultimo_resultado = None
            st.session_state.ultimo_bajas = None
            st.session_state.ultimo_rango = (fi, ff)
            st.stop()

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
            df.groupby(["nif", "Nombre", "Departamento", "Empresa", "Sede", "fecha_dia"], as_index=False)
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

        # --- BAJAS: día a día
        bajas_df = obtener_bajas_por_dia(fi, ff)

        # Enriquecer bajas con datos del empleado:
        #   1) merge por nif
        #   2) para los que falten, merge por num_empleado
        if not bajas_df.empty:
            base_min = empleados_df_base[
                ["nif", "num_empleado", "nombre_completo", "Empresa", "Sede", "departamento_nombre"]
            ].copy()
            base_min["nif"] = base_min["nif"].astype(str).str.upper().str.strip()
            base_min["num_empleado"] = base_min["num_empleado"].astype(str).str.strip()

            # merge por nif
            bx = bajas_df.merge(base_min, on="nif", how="left", suffixes=("", "_b"))

            # los que no tengan nombre y sí tengan num_empleado, intentamos por num_empleado
            mask_missing = bx["nombre_completo"].isna() | (bx["nombre_completo"].astype(str).str.strip() == "")
            if mask_missing.any():
                bx_missing = bx[mask_missing].copy()
                bx_ok = bx[~mask_missing].copy()

                # para evitar conflictos, quitamos columnas del merge anterior
                cols_to_drop = ["nombre_completo", "Empresa", "Sede", "departamento_nombre", "num_empleado_b"]
                for c in cols_to_drop:
                    if c in bx_missing.columns:
                        bx_missing = bx_missing.drop(columns=[c])

                bx_missing = bx_missing.merge(
                    base_min.rename(columns={"num_empleado": "num_empleado"}),
                    on="num_empleado",
                    how="left",
                    suffixes=("", "_b2"),
                )

                bx = pd.concat([bx_ok, bx_missing], ignore_index=True)

            bx = bx.rename(
                columns={
                    "nombre_completo": "Nombre",
                    "departamento_nombre": "Departamento",
                }
            )
            bx["Nombre"] = bx["Nombre"].fillna("")
            bx["Empresa"] = bx["Empresa"].fillna("")
            bx["Sede"] = bx["Sede"].fillna("")
            bx["Departamento"] = bx["Departamento"].fillna("")

            # Horas baja (solo esta columna; quitamos días baja)
            bx["Horas baja"] = bx["horas_baja"].apply(lambda x: f"{x:.2f}".rstrip("0").rstrip("."))

            bajas_df = bx[["Fecha", "Empresa", "Sede", "Nombre", "Departamento", "Horas baja"]].copy()
            bajas_df = bajas_df.sort_values(["Fecha", "Empresa", "Sede", "Nombre"], kind="mergesort")

        # guardar resultados
        st.session_state.ultimo_resultado = salida
        st.session_state.ultimo_bajas = bajas_df
        st.session_state.ultimo_rango = (fi, ff)

# ============================================================
# RENDER RESULTADOS (persistentes)
# ============================================================

salida = st.session_state.ultimo_resultado
bajas_df = st.session_state.ultimo_bajas

if salida is None:
    st.info("Selecciona rango y filtros y pulsa **Consultar**.")
    st.stop()

if salida.empty:
    st.success("🎉 No hay incidencias ni trabajos en fin de semana en el rango seleccionado.")
    if bajas_df is not None and not bajas_df.empty:
        for f_dia in bajas_df["Fecha"].unique():
            st.markdown(f"### 🏥 Bajas — {f_dia}")
            subb = bajas_df[bajas_df["Fecha"] == f_dia].copy()
            st.data_editor(subb, use_container_width=True, hide_index=True, disabled=True, num_rows="fixed")
    st.stop()

# Tabla incidencias (ya con nombres Empresa/Sede)
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

# Pintado por día (incidencias + bajas)
for f_dia in salida["Fecha"].unique():
    st.markdown(f"### 📅 {f_dia}")

    sub = salida[salida["Fecha"] == f_dia].copy()
    st.data_editor(sub, use_container_width=True, hide_index=True, disabled=True, num_rows="fixed")

    if bajas_df is not None and not bajas_df.empty:
        subb = bajas_df[bajas_df["Fecha"] == f_dia].copy()
        if not subb.empty:
            st.markdown(f"#### 🏥 Empleados de baja — {f_dia}")
            st.data_editor(subb, use_container_width=True, hide_index=True, disabled=True, num_rows="fixed")

csv = salida.to_csv(index=False).encode("utf-8")
st.download_button("⬇ Descargar CSV", csv, "fichajes_incidencias.csv", "text/csv")
