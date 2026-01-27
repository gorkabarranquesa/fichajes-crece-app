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

# Para no saturar /informes/empleados cuando vamos día a día
MAX_WORKERS_BAJAS_DIAS = 6

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
# DEBUG / INSPECCIÓN SEGURA: /informes/empleados (ULTRA ROBUSTO)
# - Soporta JSON plano
# - Soporta cifrado directo {iv,value}
# - Soporta base64 envolvente (como exportación)
# - Soporta wrappers {data: ...}
# - Debug seguro (sin tokens, sin payload completo)
# ============================================================

def decrypt_crece_payload_from_dict(payload: dict, app_key_b64: str) -> str:
    """
    Descifra cuando el endpoint devuelve DIRECTAMENTE:
      {"iv":"...","value":"..."}   (sin base64 envolvente)
    """
    iv = base64.b64decode(payload.get("iv") or "")
    ct = base64.b64decode(payload.get("value") or payload.get("ciphertext") or "")
    key = base64.b64decode(app_key_b64)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ct), AES.block_size)
    return decrypted.decode("utf-8")

def _try_parse_json_text(txt: str):
    txt = (txt or "").strip()
    if not txt:
        return None
    if (txt.startswith('"') and txt.endswith('"')) or (txt.startswith("'") and txt.endswith("'")):
        txt = txt[1:-1].strip()
    try:
        return json.loads(txt)
    except Exception:
        return None

def _looks_like_b64(s: str) -> bool:
    s = (s or "").strip()
    if len(s) < 40:
        return False
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n\r")
    return all(c in allowed for c in s)

def _mask_snippet(s: str, max_len: int = 240) -> str:
    """
    Mascara dígitos para evitar exponer NIF/teléfonos/etc.
    """
    s = (s or "").strip().replace("\r", " ").replace("\n", " ")
    s = s[:max_len]
    return "".join("•" if ch.isdigit() else ch for ch in s)

def _extract_possible_payload(resp: requests.Response):
    """
    Devuelve:
      - parsed_json (list/dict si JSON plano)
      - payload_b64 (str si base64 directo o embebido)
      - payload_dict (dict si {iv,value} directo o embebido)
      - raw_text
    """
    raw_text = (resp.text or "").strip()

    # Intento JSON directo (por headers)
    try:
        parsed = resp.json()
        if isinstance(parsed, (list, dict)):
            # ¿Cifrado directo {iv,value}?
            if isinstance(parsed, dict) and ("iv" in parsed) and (("value" in parsed) or ("ciphertext" in parsed)):
                return None, None, parsed, raw_text

            # ¿Wrapper con payload dentro?
            if isinstance(parsed, dict):
                for k in ["data", "payload", "result", "encrypted", "content", "value"]:
                    v = parsed.get(k)
                    # wrapper -> dict cifrado directo
                    if isinstance(v, dict) and ("iv" in v) and (("value" in v) or ("ciphertext" in v)):
                        return None, None, v, raw_text
                    # wrapper -> base64
                    if isinstance(v, str) and _looks_like_b64(v):
                        return None, v.strip(), None, raw_text

            # Si es JSON plano usable
            return parsed, None, None, raw_text
    except Exception:
        pass

    # Intento parsear JSON aunque venga como texto (sin content-type correcto)
    parsed_text = _try_parse_json_text(raw_text)
    if isinstance(parsed_text, (list, dict)):
        if isinstance(parsed_text, dict) and ("iv" in parsed_text) and (("value" in parsed_text) or ("ciphertext" in parsed_text)):
            return None, None, parsed_text, raw_text

        if isinstance(parsed_text, dict):
            for k in ["data", "payload", "result", "encrypted", "content", "value"]:
                v = parsed_text.get(k)
                if isinstance(v, dict) and ("iv" in v) and (("value" in v) or ("ciphertext" in v)):
                    return None, None, v, raw_text
                if isinstance(v, str) and _looks_like_b64(v):
                    return None, v.strip(), None, raw_text

        return parsed_text, None, None, raw_text

    # Body base64 directo
    payload_b64 = raw_text.strip().strip('"').strip("'").strip()
    if _looks_like_b64(payload_b64):
        return None, payload_b64, None, raw_text

    return None, None, None, raw_text

def api_informes_empleados_raw(fecha_desde: str, fecha_hasta: str, *, debug: bool = False):
    """
    Llama a /informes/empleados probando:
      - json body
      - form-data
      - dos pares de nombres de campo
    Devuelve (parsed, debug_info)
    """
    url = f"{API_URL_BASE}/informes/empleados"

    attempts = [
        ("json", {"fecha_desde": fecha_desde, "fecha_hasta": fecha_hasta}),
        ("data", {"fecha_desde": fecha_desde, "fecha_hasta": fecha_hasta}),
        ("json", {"fecha_inicio": fecha_desde, "fecha_fin": fecha_hasta}),
        ("data", {"fecha_inicio": fecha_desde, "fecha_fin": fecha_hasta}),
        # Variante form-data como lista de tuplas (algunos backends lo tratan distinto)
        ("data_tuples", [("fecha_desde", fecha_desde), ("fecha_hasta", fecha_hasta)]),
        ("data_tuples", [("fecha_inicio", fecha_desde), ("fecha_fin", fecha_hasta)]),
    ]

    debug_rows = []
    last_reason = None

    for mode, body in attempts:
        try:
            if mode == "json":
                resp = _SESSION.post(url, json=body, timeout=HTTP_TIMEOUT, verify=True)
            elif mode == "data_tuples":
                resp = _SESSION.post(url, data=body, timeout=HTTP_TIMEOUT, verify=True)
            else:
                resp = _SESSION.post(url, data=body, timeout=HTTP_TIMEOUT, verify=True)

            if resp is None:
                last_reason = "No response"
                continue

            ct = (resp.headers.get("Content-Type") or "").lower()
            status = resp.status_code
            raw_text = (resp.text or "").strip()

            # Guardamos debug seguro
            debug_rows.append({
                "mode": mode,
                "fields": ",".join(list(body.keys())) if isinstance(body, dict) else ",".join([k for k, _ in body]),
                "status": status,
                "content_type": ct[:60],
                "snippet": _mask_snippet(raw_text, 240),
            })

            # Si HTML, no seguimos con decrypt: es un proxy/error page
            if "text/html" in ct or raw_text.lstrip().lower().startswith("<!doctype html") or raw_text.lstrip().startswith("<html"):
                last_reason = f"HTML response (status {status})"
                continue

            # Si HTTP error, probamos siguiente intento
            if status >= 400:
                last_reason = f"HTTP {status}"
                continue

            parsed_json, payload_b64, payload_dict, _ = _extract_possible_payload(resp)

            # 1) JSON plano
            if isinstance(parsed_json, (list, dict)):
                return parsed_json, (debug_rows if debug else None)

            # 2) Cifrado directo {iv,value}
            if isinstance(payload_dict, dict):
                try:
                    decrypted = decrypt_crece_payload_from_dict(payload_dict, APP_KEY_B64)
                    return json.loads(decrypted), (debug_rows if debug else None)
                except Exception as e:
                    last_reason = f"Decrypt(dict) failed: {type(e).__name__}"
                    continue

            # 3) Base64 envolvente (exportación)
            if payload_b64:
                try:
                    decrypted = decrypt_crece_payload(payload_b64, APP_KEY_B64)
                    return json.loads(decrypted), (debug_rows if debug else None)
                except Exception as e:
                    last_reason = f"Decrypt(b64) failed: {type(e).__name__}"
                    continue

            last_reason = "Unrecognized format"
            continue

        except Exception as e:
            _safe_fail(e)
            last_reason = f"Exception: {type(e).__name__}"
            continue

    _safe_fail(Exception(f"api_informes_empleados_raw failed: {last_reason}"))
    return None, (debug_rows if debug else None)

def _flatten_records(parsed):
    if parsed is None:
        return []
    if isinstance(parsed, list):
        return [x for x in parsed if isinstance(x, dict)]
    if isinstance(parsed, dict):
        # Si el endpoint devuelve algo tipo {"empleados":[...]}
        for k in ["empleados", "data", "result"]:
            v = parsed.get(k) if isinstance(parsed, dict) else None
            if isinstance(v, list):
                return [x for x in v if isinstance(x, dict)]
        # fallback: intentamos “aplanar”
        out = []
        for _, v in parsed.items():
            if isinstance(v, dict):
                out.append(v)
            elif isinstance(v, list):
                out.extend([x for x in v if isinstance(x, dict)])
        return out
    return []

def _guess_leave_keys(records):
    if not records:
        return []
    candidates = set()
    key_words = ["baja", "ausen", "it", "incap", "leave", "sick", "absence", "horas", "dias"]
    for r in records:
        for k in r.keys():
            ks = str(k).lower()
            if any(w in ks for w in key_words):
                candidates.add(k)
    return sorted(candidates)

# ============================================================
# UI: Panel de inspección
# ============================================================

with st.expander("🧪 Inspeccionar /informes/empleados (robusto + debug seguro)", expanded=False):
    st.caption(
        "Detecta si el endpoint devuelve JSON plano o cifrado (directo {iv,value} o base64 envolvente). "
        "El debug NO muestra tokens y en el snippet enmascara dígitos."
    )

    c1, c2 = st.columns(2)
    with c1:
        dbg_desde = st.text_input("fecha_desde (YYYY-MM-DD)", value="2026-01-01")
    with c2:
        dbg_hasta = st.text_input("fecha_hasta (YYYY-MM-DD)", value="2026-12-31")

    if st.button("Ejecutar inspección /informes/empleados"):
        parsed, dbg = api_informes_empleados_raw(dbg_desde, dbg_hasta, debug=True)

        if dbg:
            st.write("Intentos realizados (debug seguro):")
            st.dataframe(pd.DataFrame(dbg), use_container_width=True, hide_index=True)

        if parsed is None:
            st.error("No se pudo obtener/interpretar el informe. Mira la tabla de debug: status/content-type/snippet.")
        else:
            st.success(f"OK. Tipo parseado final: {type(parsed).__name__}")

            records = _flatten_records(parsed)
            st.write(f"Registros detectados: {len(records)}")

            all_keys = set()
            for r in records:
                all_keys |= set(r.keys())
            all_keys = sorted(all_keys)

            st.write("Claves detectadas:")
            st.code("\n".join(all_keys) if all_keys else "(sin claves)")

            leave_keys = _guess_leave_keys(records)
            st.write("Candidatos de campos baja/ausencia:")
            st.code("\n".join(leave_keys) if leave_keys else "(no se detectaron por nombre)")


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
# TIEMPOS (TRUNCADO A MINUTO)
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
# API EXPORTACIÓN (catálogos + empleados/fichajes)
# ============================================================

def _try_export_list(endpoint: str) -> list:
    """
    Intenta GET y luego POST para un endpoint de exportación.
    Devuelve lista (si la API responde y se puede descifrar), si no [].
    """
    url = f"{API_URL_BASE}{endpoint}"

    resp = safe_request("GET", url)
    if resp is not None and resp.status_code < 400:
        try:
            payload_b64 = _extract_payload_b64(resp)
            if payload_b64:
                decrypted = decrypt_crece_payload(payload_b64, APP_KEY_B64)
                parsed = json.loads(decrypted)
                return parsed if isinstance(parsed, list) else []
        except Exception as e:
            _safe_fail(e)

    resp = safe_request("POST", url)
    if resp is not None and resp.status_code < 400:
        try:
            payload_b64 = _extract_payload_b64(resp)
            if payload_b64:
                decrypted = decrypt_crece_payload(payload_b64, APP_KEY_B64)
                parsed = json.loads(decrypted)
                return parsed if isinstance(parsed, list) else []
        except Exception as e:
            _safe_fail(e)

    return []

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

@st.cache_data(show_spinner=False, ttl=3600)
def api_exportar_empresas() -> pd.DataFrame:
    candidates = [
        "/exportacion/empresas",
        "/exportacion/empresa",
    ]
    for ep in candidates:
        lst = _try_export_list(ep)
        if lst:
            rows = []
            for x in lst:
                if isinstance(x, dict):
                    eid = x.get("id")
                    nom = x.get("nombre") or x.get("name") or x.get("empresa") or x.get("razon_social")
                    if eid is not None:
                        rows.append({"empresa_id": eid, "empresa_nombre": str(nom or "").strip()})
            df = pd.DataFrame(rows)
            if not df.empty:
                df["empresa_nombre"] = df["empresa_nombre"].replace("", pd.NA).fillna("—")
            return df
    return pd.DataFrame(columns=["empresa_id", "empresa_nombre"])

@st.cache_data(show_spinner=False, ttl=3600)
def api_exportar_sedes() -> pd.DataFrame:
    candidates = [
        "/exportacion/sedes",
        "/exportacion/sede",
        "/exportacion/centros",
        "/exportacion/centros-trabajo",
    ]
    for ep in candidates:
        lst = _try_export_list(ep)
        if lst:
            rows = []
            for x in lst:
                if isinstance(x, dict):
                    sid = x.get("id")
                    nom = x.get("nombre") or x.get("name") or x.get("sede") or x.get("centro")
                    if sid is not None:
                        rows.append({"sede_id": sid, "sede_nombre": str(nom or "").strip()})
            df = pd.DataFrame(rows)
            if not df.empty:
                df["sede_nombre"] = df["sede_nombre"].replace("", pd.NA).fillna("—")
            return df
    return pd.DataFrame(columns=["sede_id", "sede_nombre"])

def api_exportar_empleados_completos() -> pd.DataFrame:
    url = f"{API_URL_BASE}/exportacion/empleados"
    data = {"solo_nif": 0}

    resp = safe_request("POST", url, data=data)
    if resp is None:
        return pd.DataFrame(columns=["nif", "nombre_completo", "departamento_id", "empresa_id", "sede_id"])
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

        lista.append(
            {
                "nif": e.get("nif"),
                "nombre_completo": nombre_completo,
                "departamento_id": e.get("departamento"),
                "empresa_id": e.get("empresa"),
                "sede_id": e.get("sede"),
            }
        )

    df = pd.DataFrame(lista)
    if not df.empty:
        df["nif"] = df["nif"].astype(str).str.upper().str.strip()
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
# INFORME EMPLEADOS (BAJAS) - CORREGIDO: día a día
# ============================================================

def _parse_horas_baja(val) -> float:
    if val is None or (isinstance(val, float) and pd.isna(val)):
        return 0.0
    if isinstance(val, (int, float)):
        return max(0.0, float(val))
    s = str(val).strip()
    if not s:
        return 0.0
    if ":" in s:
        try:
            h, m = s.split(":")
            return max(0.0, int(h) + int(m) / 60.0)
        except Exception:
            return 0.0
    try:
        return max(0.0, float(s.replace(",", ".")))
    except Exception:
        return 0.0

def _infer_nif_from_record(rec: dict) -> str:
    for k in ("nif", "NIF", "dni", "DNI", "documento", "num_documento"):
        if k in rec and rec.get(k):
            return str(rec.get(k)).upper().strip()
    return ""

def _infer_dias_baja(rec: dict) -> float:
    for k in ("dias_baja", "días_baja", "diasBaja", "dias_de_baja", "days_leave"):
        if k in rec and rec.get(k) is not None:
            try:
                return max(0.0, float(rec.get(k)))
            except Exception:
                return 0.0
    return 0.0

def _infer_horas_baja(rec: dict) -> float:
    for k in ("horas_baja", "horasBaja", "horas_de_baja", "hours_leave"):
        if k in rec and rec.get(k) is not None:
            return _parse_horas_baja(rec.get(k))
    return 0.0

def _call_informe_empleados_1dia(fecha: str, nifs: list[str]) -> list[dict]:
    """
    Llama a /informes/empleados para un solo día (desde=hasta=fecha).
    Devuelve lista de dicts (por empleado) parseada/normalizada mínimamente.
    """
    url = f"{API_URL_BASE}/informes/empleados"

    # Intentamos variantes por compatibilidad
    payload_variants = [
        [("desde", fecha), ("hasta", fecha)],
        [("fecha_desde", fecha), ("fecha_hasta", fecha)],
        [("fecha_inicio", fecha), ("fecha_fin", fecha)],
    ]

    # Añadimos nifs a cada payload si procede
    out_rows = []
    for base_payload in payload_variants:
        payload = list(base_payload)
        if nifs:
            for x in nifs:
                if x:
                    payload.append(("nif[]", x))

        try:
            resp = safe_request("POST", url, data=payload)
            if resp is None or resp.status_code >= 400:
                continue

            payload_b64 = _extract_payload_b64(resp)
            if not payload_b64:
                continue

            decrypted = decrypt_crece_payload(payload_b64, APP_KEY_B64)
            parsed = json.loads(decrypted)

            # Caso A: lista de dicts por empleado
            if isinstance(parsed, list):
                for rec in parsed:
                    if isinstance(rec, dict):
                        out_rows.append(rec)
                return out_rows

            # Caso B: dict por empleado
            if isinstance(parsed, dict):
                for _, v in parsed.items():
                    if isinstance(v, dict):
                        out_rows.append(v)
                    elif isinstance(v, list):
                        for rec in v:
                            if isinstance(rec, dict):
                                out_rows.append(rec)
                return out_rows

        except Exception as e:
            _safe_fail(e)
            continue

    return []

@st.cache_data(show_spinner=False, ttl=600)
def api_informe_empleados_bajas_dia_a_dia(fi: str, ff: str, nifs_key: str) -> pd.DataFrame:
    """
    Cachea por (fi, ff, nifs_key). nifs_key es una string estable (p.ej. 'NIF1|NIF2|...').
    """
    nifs = [x for x in (nifs_key or "").split("|") if x.strip()]
    d0 = datetime.strptime(fi, "%Y-%m-%d").date()
    d1 = datetime.strptime(ff, "%Y-%m-%d").date()

    # Ejecutar en paralelo por días (suave)
    fechas = []
    cur = d0
    while cur <= d1:
        fechas.append(cur.strftime("%Y-%m-%d"))
        cur += timedelta(days=1)

    rows = []

    def worker(f):
        recs = _call_informe_empleados_1dia(f, nifs)
        return f, recs

    with ThreadPoolExecutor(max_workers=MAX_WORKERS_BAJAS_DIAS) as exe:
        futs = [exe.submit(worker, f) for f in fechas]
        for fut in as_completed(futs):
            fecha, recs = fut.result()
            for rec in (recs or []):
                nif = _infer_nif_from_record(rec)
                if not nif:
                    continue
                dias = _infer_dias_baja(rec)
                horas = _infer_horas_baja(rec)
                if (dias > 0.0) or (horas > 0.0):
                    rows.append(
                        {
                            "nif": nif,
                            "Fecha": fecha,
                            "dias_baja": float(dias),
                            "horas_baja": float(horas),
                        }
                    )

    df = pd.DataFrame(rows)
    if df.empty:
        return pd.DataFrame(columns=["nif", "Fecha", "dias_baja", "horas_baja"])

    df["nif"] = df["nif"].astype(str).str.upper().str.strip()
    df["Fecha"] = pd.to_datetime(df["Fecha"], errors="coerce").dt.date.astype(str)
    df["dias_baja"] = pd.to_numeric(df["dias_baja"], errors="coerce").fillna(0.0)
    df["horas_baja"] = pd.to_numeric(df["horas_baja"], errors="coerce").fillna(0.0)

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

# ---- Cargar catálogos para filtros previos (cacheado) ----
empresas_df = api_exportar_empresas()
sedes_df = api_exportar_sedes()

empresas_map = {}
if not empresas_df.empty:
    empresas_map = {str(r["empresa_id"]): str(r["empresa_nombre"]) for _, r in empresas_df.iterrows()}

sedes_map = {}
if not sedes_df.empty:
    sedes_map = {str(r["sede_id"]): str(r["sede_nombre"]) for _, r in sedes_df.iterrows()}

# ---- Inputs fecha ----
hoy = date.today()
col1, col2 = st.columns(2)
with col1:
    fecha_inicio = st.date_input("Fecha inicio", value=hoy, max_value=hoy, key="fi_input")
with col2:
    fecha_fin = st.date_input("Fecha fin", value=hoy, max_value=hoy, key="ff_input")

st.write("---")

# ============================================================
# FILTROS PREVIOS (ANTES DE CONSULTAR)
# ============================================================
st.subheader("🔎 Filtros (antes de consultar)")

pre1, pre2 = st.columns(2)

def _fmt_empresa(x):
    return empresas_map.get(str(x), str(x))

def _fmt_sede(x):
    return sedes_map.get(str(x), str(x))

if not empresas_df.empty:
    emp_opts = [str(x) for x in empresas_df["empresa_id"].tolist()]
    with pre1:
        pre_empresas = st.multiselect(
            "Empresa",
            options=emp_opts,
            default=st.session_state.get("pre_empresas", emp_opts),
            format_func=_fmt_empresa,
            key="pre_empresas",
        )
else:
    with pre1:
        st.caption("Catálogo de empresas no disponible (se mostrará ID).")
        pre_empresas = []

if not sedes_df.empty:
    sede_opts = [str(x) for x in sedes_df["sede_id"].tolist()]
    with pre2:
        pre_sedes = st.multiselect(
            "Sede",
            options=sede_opts,
            default=st.session_state.get("pre_sedes", sede_opts),
            format_func=_fmt_sede,
            key="pre_sedes",
        )
else:
    with pre2:
        st.caption("Catálogo de sedes no disponible (se mostrará ID).")
        pre_sedes = []

# Botones
b1, b2 = st.columns([1, 1])
with b1:
    do_query = st.button("Consultar", use_container_width=True)
with b2:
    if st.button("Limpiar resultados", use_container_width=True):
        st.session_state.pop("salida_base", None)
        st.session_state.pop("bajas_base", None)
        st.session_state.pop("salida_fi", None)
        st.session_state.pop("salida_ff", None)

# ============================================================
# EJECUCIÓN CONSULTA (solo cuando se pulsa)
# ============================================================
if do_query:
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
        empleados_df = api_exportar_empleados_completos()

        if empleados_df.empty:
            st.warning("No hay empleados disponibles.")
            st.stop()

        empleados_df["nif"] = empleados_df["nif"].astype(str).str.upper().str.strip()
        empleados_df = empleados_df.merge(departamentos_df, on="departamento_id", how="left")

        if "empresa_id" not in empleados_df.columns:
            empleados_df["empresa_id"] = None
        if "sede_id" not in empleados_df.columns:
            empleados_df["sede_id"] = None

        empleados_df["empresa_id"] = empleados_df["empresa_id"].apply(
            lambda x: str(int(x)) if pd.notna(x) and str(x).strip().isdigit() else (str(x).strip() if pd.notna(x) else "")
        )
        empleados_df["sede_id"] = empleados_df["sede_id"].apply(
            lambda x: str(int(x)) if pd.notna(x) and str(x).strip().isdigit() else (str(x).strip() if pd.notna(x) else "")
        )

        # Aplicar filtros previos (consultar solo lo filtrado)
        if pre_empresas:
            empleados_df = empleados_df[empleados_df["empresa_id"].isin(set(pre_empresas))].copy()
        if pre_sedes:
            empleados_df = empleados_df[empleados_df["sede_id"].isin(set(pre_sedes))].copy()

        if empleados_df.empty:
            st.info("No hay empleados que coincidan con Empresa/Sede seleccionadas.")
            st.stop()

        def _empresa_nombre(eid: str) -> str:
            s = (eid or "").strip()
            if not s:
                return "—"
            return empresas_map.get(s, s)

        def _sede_nombre(sid: str) -> str:
            s = (sid or "").strip()
            if not s:
                return "—"
            return sedes_map.get(s, s)

        empleados_df["Empresa"] = empleados_df["empresa_id"].apply(_empresa_nombre)
        empleados_df["Sede"] = empleados_df["sede_id"].apply(_sede_nombre)

        # ---- BAJAS: CORREGIDO día a día ----
        nifs_filtrados = empleados_df["nif"].dropna().astype(str).str.upper().str.strip().unique().tolist()
        nifs_key = "|".join(sorted(nifs_filtrados))
        bajas_raw = api_informe_empleados_bajas_dia_a_dia(fi, ff, nifs_key=nifs_key)

        if bajas_raw.empty:
            bajas_base = pd.DataFrame(columns=["Fecha", "Empresa", "Sede", "Nombre", "Departamento", "dias_baja", "horas_baja"])
        else:
            emp_info = empleados_df[["nif", "nombre_completo", "Empresa", "Sede", "departamento_nombre"]].copy()
            emp_info = emp_info.rename(columns={"nombre_completo": "Nombre", "departamento_nombre": "Departamento"})

            bajas_base = bajas_raw.merge(emp_info, on="nif", how="left")
            bajas_base["Nombre"] = bajas_base["Nombre"].fillna(bajas_base["nif"])
            bajas_base["Empresa"] = bajas_base["Empresa"].fillna("—")
            bajas_base["Sede"] = bajas_base["Sede"].fillna("—")
            bajas_base["Departamento"] = bajas_base["Departamento"].fillna("—")

            bajas_base["dias_baja"] = bajas_base["dias_baja"].astype(float).round(2)
            bajas_base["horas_baja"] = bajas_base["horas_baja"].astype(float).round(2)

            bajas_base = bajas_base[
                ["Fecha", "Empresa", "Sede", "Nombre", "Departamento", "dias_baja", "horas_baja"]
            ].sort_values(["Fecha", "Empresa", "Sede", "Nombre"], kind="mergesort")

        st.session_state["bajas_base"] = bajas_base

        # ---- Fichajes ----
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
                            "Empresa": emp.get("Empresa", "—"),
                            "Sede": emp.get("Sede", "—"),
                            "Departamento": emp.get("departamento_nombre"),
                            "id": x.get("id"),
                            "tipo": x.get("tipo"),
                            "direccion": x.get("direccion"),
                            "fecha": x.get("fecha"),
                        }
                    )

        if not fichajes_rows:
            # Guardamos vacío pero mantenemos bajas_base en sesión
            st.info("No se encontraron fichajes en el rango seleccionado.")
            st.session_state["salida_base"] = pd.DataFrame()
            st.session_state["salida_fi"] = fi
            st.session_state["salida_ff"] = ff
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
            df.groupby(["nif", "Nombre", "Empresa", "Sede", "Departamento", "fecha_dia"], as_index=False)
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

        salida_base = resumen[resumen["Incidencia"].astype(str).str.strip().ne("")].copy()

        if salida_base.empty:
            st.session_state["salida_base"] = salida_base
            st.session_state["salida_fi"] = fi
            st.session_state["salida_ff"] = ff
        else:
            salida_base = salida_base[
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

            st.session_state["salida_base"] = salida_base
            st.session_state["salida_fi"] = fi
            st.session_state["salida_ff"] = ff

# ============================================================
# MOSTRAR RESULTADOS + FILTROS (SIN PERDER EL RESULTADO)
# ============================================================
salida_base = st.session_state.get("salida_base", None)
bajas_base = st.session_state.get(
    "bajas_base",
    pd.DataFrame(columns=["Fecha", "Empresa", "Sede", "Nombre", "Departamento", "dias_baja", "horas_baja"])
)

if salida_base is None:
    st.info("Selecciona fechas, filtra si quieres, y pulsa **Consultar**.")
    st.stop()

# Aunque no haya incidencias, mantenemos la app viva para poder mostrar bajas si existen
st.write("---")
st.subheader("🧰 Filtros (sobre el resultado)")

# Construimos opciones desde lo disponible (incidencias o bajas)
empresas_set = set()
sedes_set = set()

if salida_base is not None and not salida_base.empty:
    empresas_set |= set(salida_base["Empresa"].fillna("—").astype(str).unique().tolist())
    sedes_set |= set(salida_base["Sede"].fillna("—").astype(str).unique().tolist())
if bajas_base is not None and not bajas_base.empty:
    empresas_set |= set(bajas_base["Empresa"].fillna("—").astype(str).unique().tolist())
    sedes_set |= set(bajas_base["Sede"].fillna("—").astype(str).unique().tolist())

empresas_res = sorted(list(empresas_set)) if empresas_set else ["—"]
sedes_res = sorted(list(sedes_set)) if sedes_set else ["—"]

f1, f2 = st.columns(2)
with f1:
    sel_empresas_res = st.multiselect(
        "Empresa (resultado)",
        options=empresas_res,
        default=st.session_state.get("sel_empresas_res", empresas_res),
        key="sel_empresas_res",
    )
with f2:
    sel_sedes_res = st.multiselect(
        "Sede (resultado)",
        options=sedes_res,
        default=st.session_state.get("sel_sedes_res", sedes_res),
        key="sel_sedes_res",
    )

def _apply_filters(df_in: pd.DataFrame) -> pd.DataFrame:
    if df_in is None or df_in.empty:
        return df_in
    df_out = df_in.copy()
    if sel_empresas_res:
        df_out = df_out[df_out["Empresa"].astype(str).isin(set(sel_empresas_res))].copy()
    else:
        return df_out.iloc[0:0].copy()

    if sel_sedes_res:
        df_out = df_out[df_out["Sede"].astype(str).isin(set(sel_sedes_res))].copy()
    else:
        return df_out.iloc[0:0].copy()

    return df_out

salida = _apply_filters(salida_base) if salida_base is not None else pd.DataFrame()
bajas_show = _apply_filters(bajas_base) if bajas_base is not None else pd.DataFrame()

# Pintar por día: incidencias + tabla de bajas si aplica
# Priorizamos días presentes en cualquiera de los dos (para que si solo hay bajas, se vea)
dias = []
if salida is not None and not salida.empty:
    dias += list(salida["Fecha"].unique())
if bajas_show is not None and not bajas_show.empty:
    dias += list(bajas_show["Fecha"].unique())

dias = sorted(set(dias))

if not dias:
    st.info("No hay resultados con los filtros seleccionados.")
    st.stop()

for f_dia in dias:
    st.markdown(f"### 📅 {f_dia}")

    sub = salida[salida["Fecha"] == f_dia] if (salida is not None and not salida.empty) else pd.DataFrame()
    if sub is not None and not sub.empty:
        st.data_editor(sub, use_container_width=True, hide_index=True, disabled=True, num_rows="fixed")
    else:
        st.caption("Sin incidencias este día.")

    sub_b = bajas_show[bajas_show["Fecha"] == f_dia] if (bajas_show is not None and not bajas_show.empty) else pd.DataFrame()
    if sub_b is not None and not sub_b.empty:
        st.markdown("#### 🏥 Empleados de baja")
        st.data_editor(
            sub_b[["Empresa", "Sede", "Nombre", "Departamento", "dias_baja", "horas_baja"]],
            use_container_width=True,
            hide_index=True,
            disabled=True,
            num_rows="fixed",
        )

# CSV: solo incidencias (como antes)
csv = (salida if salida is not None else pd.DataFrame()).to_csv(index=False).encode("utf-8")
st.download_button("⬇ Descargar CSV", csv, "fichajes_incidencias.csv", "text/csv")
