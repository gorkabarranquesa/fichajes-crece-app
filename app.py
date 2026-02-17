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
# EXCLUSIONES RRHH (Sin fichajes)  -> POR NOMBRE (NO POR NIF)
# ============================================================

EXCLUDE_SIN_FICHAJES_NAMES_NORM = {
    "MIKEL ARZALLUS MARCO",
    "JOSE ANGEL OCHAGAVIA SATRUSTEGUI",
    "BENITO MENDINUETA ANDUEZA",
}


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
# CIFRADO / DESCIFRADO (AES-256-CBC)
# ============================================================

def _b64decode(s: str) -> bytes:
    return base64.b64decode(s)


def decrypt_payload(payload_b64: str) -> str:
    """
    Descifra respuesta encriptada CRECE (base64(JSON({iv,value,mac}))) -> devuelve str descifrado (serialized PHP).
    NOTA: No se valida mac aquí (mantenemos el comportamiento que ya tenías validado en tu app "buena").
    """
    if not payload_b64:
        return ""

    payload = json.loads(base64.b64decode(payload_b64).decode("utf-8"))
    iv_b = base64.b64decode(payload["iv"])
    value_b64 = payload["value"]

    key = base64.b64decode(APP_KEY_B64)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv_b)

    dec = cipher.decrypt(base64.b64decode(value_b64))
    dec = unpad(dec, AES.block_size)
    return dec.decode("utf-8", errors="ignore")


def _try_parse_encrypted_response(resp: requests.Response):
    """
    Respuestas en exportaciones/informes: cadena única encriptada (texto).
    Intentamos descifrar -> parsear lo que venga como JSON o como estructura simple ya manejada por tu app.
    """
    if resp is None:
        return None

    txt = (resp.text or "").strip()
    if not txt:
        return None

    try:
        dec = decrypt_payload(txt)
    except Exception:
        return None

    if not dec:
        return None

    # Tu app ya trabajaba con list/dict según endpoint tras descifrado+parse.
    try:
        return json.loads(dec)
    except Exception:
        # Si no es JSON, devolvemos tal cual (hay endpoints que devuelven otras cosas)
        return dec


# ============================================================
# CACHES: catálogos básicos
# ============================================================

@st.cache_data(ttl=3600)
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


@st.cache_data(ttl=3600)
def api_exportar_sedes() -> pd.DataFrame:
    url = f"{API_URL_BASE}/exportacion/sedes"
    resp2 = safe_request("GET", url)
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
        num_empleado = e.get("num_empleado") or e.get("employee_number") or e.get("id_empleado") or e.get("Num_empleado")

        departamento_id = e.get("departamento") or e.get("departamento_id") or e.get("department_id")

        nif = (e.get("nif") or e.get("Nif") or "").upper().strip()

        lista.append(
            {
                "nif": nif,
                "nombre_completo": nombre_completo,
                "departamento_id": departamento_id,
                "empresa_id": empresa_id,
                "sede_id": sede_id,
                "num_empleado": num_empleado,
            }
        )

    return pd.DataFrame(lista)


@st.cache_data(ttl=3600)
def api_exportar_departamentos() -> pd.DataFrame:
    url = f"{API_URL_BASE}/exportacion/departamentos"
    resp = safe_request("GET", url)
    if resp is None:
        return pd.DataFrame(columns=["departamento_id", "departamento_nombre"])
    try:
        resp.raise_for_status()
    except Exception:
        return pd.DataFrame(columns=["departamento_id", "departamento_nombre"])

    data = _try_parse_encrypted_response(resp)
    if not isinstance(data, list):
        return pd.DataFrame(columns=["departamento_id", "departamento_nombre"])
    return pd.DataFrame(
        [{"departamento_id": d.get("id"), "departamento_nombre": d.get("nombre")}
         for d in (data or [])]
    )


# ============================================================
# TIEMPO TRABAJADO / FICHAJES
# ============================================================

def api_exportar_fichajes_por_empleado(fi: str, ff: str, nif: str) -> pd.DataFrame:
    """
    POST /exportacion/fichajes:
      fecha_inicio, fecha_fin, nif, order=asc
    Devuelve encriptado => lista de fichajes
    """
    url = f"{API_URL_BASE}/exportacion/fichajes"
    data = {
        "fecha_inicio": fi,
        "fecha_fin": ff,
        "nif": nif,
        "order": "asc",
    }

    resp = safe_request("POST", url, data=data)
    if resp is None:
        return pd.DataFrame(columns=["id", "tipo", "fecha", "direccion", "terminal", "tarjeta", "ubicacion", "centro", "latitud", "longitud", "temperatura", "nif"])
    try:
        resp.raise_for_status()
    except Exception:
        return pd.DataFrame(columns=["id", "tipo", "fecha", "direccion", "terminal", "tarjeta", "ubicacion", "centro", "latitud", "longitud", "temperatura", "nif"])

    data_dec = _try_parse_encrypted_response(resp)
    if not isinstance(data_dec, list):
        return pd.DataFrame(columns=["id", "tipo", "fecha", "direccion", "terminal", "tarjeta", "ubicacion", "centro", "latitud", "longitud", "temperatura", "nif"])

    rows = []
    for x in (data_dec or []):
        rows.append(
            {
                "id": x.get("id"),
                "tipo": x.get("tipo"),
                "fecha": x.get("fecha"),
                "direccion": x.get("direccion"),
                "terminal": x.get("terminal"),
                "tarjeta": x.get("tarjeta"),
                "ubicacion": x.get("ubicacion"),
                "centro": x.get("centro"),
                "latitud": x.get("latitud"),
                "longitud": x.get("longitud"),
                "temperatura": x.get("temperatura"),
                "nif": (nif or "").upper().strip(),
            }
        )
    return pd.DataFrame(rows)


def api_exportar_tiempo_trabajado(fi: str, ff: str, nifs: list[str]) -> pd.DataFrame:
    """
    POST /exportacion/tiempo-trabajado:
      desde, hasta, nif=array
    Devuelve encriptado => dict con claves nif/email/... y valores con tiempos en segundos
    """
    url = f"{API_URL_BASE}/exportacion/tiempo-trabajado"
    data = {
        "desde": fi,
        "hasta": ff,
        "nif[]": nifs,  # requests construirá múltiples nif[] si pasamos lista
    }
    resp = safe_request("POST", url, data=data)
    if resp is None:
        return pd.DataFrame(columns=["nif", "tiempoEfectivo_seg", "tiempoContabilizado_seg"])
    try:
        resp.raise_for_status()
    except Exception:
        return pd.DataFrame(columns=["nif", "tiempoEfectivo_seg", "tiempoContabilizado_seg"])

    parsed = _try_parse_encrypted_response(resp)
    if parsed is None:
        return pd.DataFrame(columns=["nif", "tiempoEfectivo_seg", "tiempoContabilizado_seg"])

    return parse_tiempo_trabajado_payload(parsed)


def parse_tiempo_trabajado_payload(parsed) -> pd.DataFrame:
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

    elif isinstance(parsed, list):
        for it in parsed:
            if isinstance(it, dict):
                add_row(it.get("nif") or it.get("Nif") or it.get("num_empleado") or "", it)

    return pd.DataFrame(filas)


# ============================================================
# TIEMPOS (redondeo consistente)
# ============================================================

def _round_seconds_to_minute(seg: float) -> int:
    """
    Redondeo consistente a minuto (en segundos).
    """
    try:
        s = float(seg)
    except Exception:
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

    # Anti-ruido por redondeos: tratamos como igual si la diferencia es <= 1 minuto
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
        if isinstance(ts, str):
            dt = pd.to_datetime(ts, errors="coerce")
        else:
            dt = pd.to_datetime(ts, errors="coerce")
        if pd.isna(dt):
            return ""
        return dt.strftime("%H:%M")
    except Exception:
        return ""


def hhmm_to_min_clock(hhmm: str) -> int:
    """
    HH:MM -> minutos desde 00:00 (para horas del día)
    """
    if not isinstance(hhmm, str) or ":" not in hhmm:
        return 0
    try:
        h, m = map(int, hhmm.split(":"))
        return h * 60 + m
    except Exception:
        return 0


# ============================================================
# LÓGICA / REGLAS RRHH (incidencias)
# ============================================================

def weekday_name(d: date) -> str:
    return ["L", "M", "X", "J", "V", "S", "D"][d.weekday()]


def is_weekend(d: date) -> bool:
    return d.weekday() >= 5


def reglas_minimos(departamento: str, dia_semana: str, nombre_norm: str):
    """
    Devuelve (min_horas, min_fichajes) según RRHH + excepciones.
    """
    dep = (departamento or "").upper().strip()
    ds = (dia_semana or "").upper().strip()
    nn = nombre_norm or ""

    # Excepciones por persona (prefijos)
    if name_startswith(nn, "DAVID") and dep == "MOD":
        return 4.5, 2
    if name_startswith(nn, "DÉBORA") and dep == "MOI":
        return 0.0, 2
    if name_startswith(nn, "DEBORA") and dep == "MOI":
        return 0.0, 2
    if name_startswith(nn, "ETOR") and dep == "MOI":
        return 0.0, 2
    if name_startswith(nn, "MIRIAM") and dep == "MOI":
        return 5.5, 2
    if name_startswith(nn, "BEATRIZ") and dep == "ESTRUCTURA":
        return 6.5, 2

    # Base por departamento
    if dep in {"ESTRUCTURA", "MOI"}:
        if ds in {"L", "M", "X", "J"}:
            return 8.5, 4
        if ds == "V":
            return 6.5, 2
        return 0.0, 0

    if dep == "MOD":
        # L-V 8h / 2 fichajes
        if ds in {"L", "M", "X", "J", "V"}:
            return 8.0, 2
        return 0.0, 0

    return 0.0, 0


def es_flex(nombre_norm: str, departamento: str) -> bool:
    dep = (departamento or "").upper().strip()
    nn = nombre_norm or ""
    # Fran (ESTRUCTURA) flex (no aplica regla estricta)
    if dep == "ESTRUCTURA" and name_startswith(nn, "FRAN"):
        return True
    # Miriam exenta de horario
    if dep == "MOI" and name_startswith(nn, "MIRIAM"):
        return True
    return False


def validar_horario(departamento: str, dia_semana: str, primera_entrada: str, ultima_salida: str, nombre_norm: str):
    """
    Devuelve lista de incidencias de horario (entrada/salida temprana/tarde) según departamento.
    """
    inc = []
    dep = (departamento or "").upper().strip()
    ds = (dia_semana or "").upper().strip()

    if es_flex(nombre_norm, dep):
        return inc

    pe = (primera_entrada or "").strip()
    us = (ultima_salida or "").strip()

    if dep in {"ESTRUCTURA", "MOI"}:
        # ventana entrada 7:00–9:00 (con margen)
        if pe:
            pe_min = hhmm_to_min_clock(pe)
            if pe_min < (7 * 60 - MARGEN_HORARIO_MIN):
                inc.append(f"Entrada temprana ({pe})")
            elif pe_min > (9 * 60 + MARGEN_HORARIO_MIN):
                inc.append(f"Entrada tarde ({pe})")

        # salida mínima 16:30 (L-J) o 13:30 (V) con margen
        if us:
            us_min = hhmm_to_min_clock(us)
            if ds in {"L", "M", "X", "J"}:
                if us_min < (16 * 60 + 30 - MARGEN_HORARIO_MIN):
                    inc.append(f"Salida temprana ({us})")
            elif ds == "V":
                if us_min < (13 * 60 + 30 - MARGEN_HORARIO_MIN):
                    inc.append(f"Salida temprana ({us})")

    if dep == "MOD":
        # Reglas de turnos mañana/tarde (simplificado; se mantiene lo ya implementado en tu versión)
        if pe:
            pe_min = hhmm_to_min_clock(pe)
            # Si entra antes de 6:00, marcar temprana; si entra después de 15:30, marcar tarde (heurística)
            if pe_min < (6 * 60 - MARGEN_HORARIO_MIN):
                inc.append(f"Entrada temprana ({pe})")
            elif pe_min > (15 * 60 + 30 + MARGEN_HORARIO_MIN):
                inc.append(f"Entrada tarde ({pe})")

    return inc


def calcular_primera_ultima(df_fich: pd.DataFrame) -> pd.DataFrame:
    if df_fich.empty:
        return pd.DataFrame(columns=["nif", "Fecha", "primera_entrada_dt", "ultima_salida_dt"])

    # Asegurar datetime
    df = df_fich.copy()
    df["fecha_dt"] = pd.to_datetime(df["fecha"], errors="coerce")
    df["Fecha"] = df["fecha_dt"].dt.date.astype(str)

    grp = df.groupby(["nif", "Fecha"], as_index=False)
    out = grp.agg(
        primera_entrada_dt=("fecha_dt", "min"),
        ultima_salida_dt=("fecha_dt", "max"),
    )
    return out


def calcular_segundos_neto(df_fich: pd.DataFrame) -> pd.DataFrame:
    """
    Cálculo aproximado del tiempo trabajado neto por día y empleado:
    - toma primer fichaje y último fichaje
    - descuenta pausas si hay pares salida/entrada intermedios (heurística)
    Mantiene la lógica ya validada por tu app.
    """
    if df_fich.empty:
        return pd.DataFrame(columns=["nif", "Fecha", "segundos_neto"])

    df = df_fich.copy()
    df["fecha_dt"] = pd.to_datetime(df["fecha"], errors="coerce")
    df = df.dropna(subset=["fecha_dt"]).copy()
    df["Fecha"] = df["fecha_dt"].dt.date.astype(str)

    # Orden por tiempo
    df = df.sort_values(["nif", "Fecha", "fecha_dt"], kind="mergesort")

    rows = []
    for (nif, fecha), sub in df.groupby(["nif", "Fecha"]):
        times = sub["fecha_dt"].tolist()
        if not times:
            rows.append({"nif": nif, "Fecha": fecha, "segundos_neto": 0})
            continue

        # bruto
        bruto = (times[-1] - times[0]).total_seconds()
        bruto = max(0.0, bruto)

        # pausa: heurística por pares intermedios
        pausa = 0.0
        if len(times) >= 4:
            # Consideramos (salida, entrada) intermedios como pausas
            # Pares: 2-3, 4-5, ...
            for i in range(1, len(times) - 1, 2):
                if i + 1 < len(times) - 1:
                    pausa += max(0.0, (times[i + 1] - times[i]).total_seconds())

        neto = max(0.0, bruto - pausa)
        rows.append({"nif": nif, "Fecha": fecha, "segundos_neto": neto})

    return pd.DataFrame(rows)


# ============================================================
# STREAMLIT UI
# ============================================================

st.set_page_config(page_title="Fichajes CRECE Personas", layout="wide")
st.title("Fichajes CRECE Personas — RRHH")

with st.sidebar:
    st.header("Filtros")
    today = date.today()
    default_start = today - timedelta(days=7)

    fi = st.date_input("Fecha inicio", value=default_start)
    ff = st.date_input("Fecha fin", value=today)

    # Catálogos
    emp_df = api_exportar_empresas()
    sed_df = api_exportar_sedes()
    dep_df = api_exportar_departamentos()

    # Solo allowed
    emp_df["empresa_nombre_norm"] = emp_df["empresa_nombre"].apply(_norm_key)
    sed_df["sede_nombre_norm"] = sed_df["sede_nombre"].apply(_norm_key)

    emp_df_allowed = emp_df[emp_df["empresa_nombre_norm"].isin(ALLOWED_EMPRESAS_N)].copy()
    sed_df_allowed = sed_df[sed_df["sede_nombre_norm"].isin(ALLOWED_SEDES_N)].copy()

    empresas = ["(Todas)"] + sorted(emp_df_allowed["empresa_nombre"].dropna().unique().tolist())
    sedes = ["(Todas)"] + sorted(sed_df_allowed["sede_nombre"].dropna().unique().tolist())

    empresa_sel = st.selectbox("Empresa", empresas, index=0)
    sede_sel = st.selectbox("Sede", sedes, index=0)

    consultar = st.button("Consultar", type="primary")


def _filter_emp_sede(df: pd.DataFrame, empresa_sel: str, sede_sel: str) -> pd.DataFrame:
    if df.empty:
        return df

    out = df.copy()
    if empresa_sel and empresa_sel != "(Todas)":
        out = out[out["Empresa_norm"] == _norm_key(empresa_sel)]
    if sede_sel and sede_sel != "(Todas)":
        out = out[out["Sede_norm"] == _norm_key(sede_sel)]
    return out


def _build_cat_maps():
    emp_map = {int(r["empresa_id"]): r["empresa_nombre"] for _, r in emp_df_allowed.iterrows() if pd.notna(r["empresa_id"])}
    sed_map = {int(r["sede_id"]): r["sede_nombre"] for _, r in sed_df_allowed.iterrows() if pd.notna(r["sede_id"])}
    dep_map = {int(r["departamento_id"]): r["departamento_nombre"] for _, r in dep_df.iterrows() if pd.notna(r["departamento_id"])}
    return emp_map, sed_map, dep_map


def _safe_int(x):
    try:
        if x is None or pd.isna(x):
            return None
        return int(x)
    except Exception:
        return None


def _enrich_empleados(df_emp: pd.DataFrame) -> pd.DataFrame:
    if df_emp.empty:
        return df_emp

    emp_map, sed_map, dep_map = _build_cat_maps()

    df = df_emp.copy()
    df["empresa_id_i"] = df["empresa_id"].apply(_safe_int)
    df["sede_id_i"] = df["sede_id"].apply(_safe_int)
    df["departamento_id_i"] = df["departamento_id"].apply(_safe_int)

    df["Empresa"] = df["empresa_id_i"].map(emp_map)
    df["Sede"] = df["sede_id_i"].map(sed_map)
    df["Departamento"] = df["departamento_id_i"].map(dep_map)

    df["Empresa_norm"] = df["Empresa"].apply(_norm_key)
    df["Sede_norm"] = df["Sede"].apply(_norm_key)
    df["nombre_norm"] = df["nombre_completo"].apply(norm_name)

    # Restringir estrictamente al catálogo permitido
    df = df[df["Empresa_norm"].isin(ALLOWED_EMPRESAS_N)].copy()
    df = df[df["Sede_norm"].isin(ALLOWED_SEDES_N)].copy()

    return df


def _split_range(fi: str, ff: str) -> list[date]:
    d0 = datetime.strptime(fi, "%Y-%m-%d").date()
    d1 = datetime.strptime(ff, "%Y-%m-%d").date()
    out = []
    d = d0
    while d <= d1:
        out.append(d)
        d += timedelta(days=1)
    return out


if consultar:
    fi_s = fi.strftime("%Y-%m-%d")
    ff_s = ff.strftime("%Y-%m-%d")

    # Cargar empleados
    emp_all = api_exportar_empleados_completos()
    emp_all = _enrich_empleados(emp_all)

    # Filtrado por empresa/sede
    emp_fil = _filter_emp_sede(emp_all, empresa_sel, sede_sel)

    empleados_filtrados = emp_fil.copy()

    if empleados_filtrados.empty:
        st.warning("No hay empleados para los filtros seleccionados.")
    else:
        nifs = empleados_filtrados["nif"].dropna().astype(str).str.upper().str.strip().unique().tolist()

        # -------------------------
        # FICHAJES: concurrente por empleado
        # -------------------------
        dfs = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futs = {ex.submit(api_exportar_fichajes_por_empleado, fi_s, ff_s, nif): nif for nif in nifs}
            for f in as_completed(futs):
                try:
                    df_i = f.result()
                    if df_i is not None and not df_i.empty:
                        dfs.append(df_i)
                except Exception:
                    continue

        if dfs:
            df_fich = pd.concat(dfs, ignore_index=True)
        else:
            df_fich = pd.DataFrame(columns=["id", "tipo", "fecha", "direccion", "terminal", "tarjeta", "ubicacion", "centro", "latitud", "longitud", "temperatura", "nif"])

        if not df_fich.empty:
            df_fich["fecha_dt"] = pd.to_datetime(df_fich["fecha"], errors="coerce")
            df_fich = df_fich.dropna(subset=["fecha_dt"]).copy()
            df_fich["fecha_dia"] = df_fich["fecha_dt"].dt.date.astype(str)
        else:
            df_fich["fecha_dia"] = ""

        # -------------------------
        # Construcción resumen incidencias por día
        # -------------------------
        if df_fich.empty:
            salida_incidencias = pd.DataFrame(columns=[
                "Fecha", "Empresa", "Sede", "Nombre", "Departamento",
                "Primera entrada", "Última salida", "Total trabajado",
                "Tiempo Contabilizado", "Diferencia", "Numero de fichajes", "Incidencia"
            ])
        else:
            df_fich["Numero"] = df_fich.groupby(["nif", "fecha_dia"])["id"].transform("count")
            conteo = (
                df_fich.groupby(["nif", "fecha_dia"], as_index=False)
                .agg(Numero=("id", "count"))
                .rename(columns={"fecha_dia": "Fecha"})
            )

            # Tiempo neto desde fichajes
            neto = calcular_segundos_neto(df_fich)  # nif, Fecha, segundos_neto

            # Merge básico
            resumen = conteo.merge(neto, on=["nif", "Fecha"], how="left")
            resumen["segundos_neto"] = resumen["segundos_neto"].fillna(0)

            # Total trabajado con redondeo consistente (segundos_a_hhmm ya redondea)
            resumen["Total trabajado"] = resumen["segundos_neto"].apply(segundos_a_hhmm)

            io = calcular_primera_ultima(df_fich)
            resumen = resumen.merge(io, on=["nif", "Fecha"], how="left")
            resumen["Primera entrada"] = resumen["primera_entrada_dt"].apply(ts_to_hhmm)
            resumen["Última salida"] = resumen["ultima_salida_dt"].apply(ts_to_hhmm)

            # Añadir datos empleado (nombre/dep/empresa/sede)
            emp_cols = empleados_filtrados[["nif", "nombre_completo", "Departamento", "Empresa", "Sede", "nombre_norm", "Empresa_norm", "Sede_norm"]].copy()
            emp_cols = emp_cols.rename(columns={"nombre_completo": "Nombre"})
            resumen = resumen.merge(emp_cols, on="nif", how="left")

            # Tiempo contabilizado (exportacion/tiempo-trabajado) - rango completo
            tc_raw = api_exportar_tiempo_trabajado(fi_s, ff_s, nifs)
            if not tc_raw.empty:
                # tc_raw es por empleado total del periodo; necesitamos por día:
                # Para mantener la lógica actual (ya validada), hacemos query día a día por empleado.
                # (Esto coincide con tu enfoque para bajas día a día)
                tc_rows = []
                days = _split_range(fi_s, ff_s)
                for d in days:
                    d_str = d.strftime("%Y-%m-%d")
                    tc_day = api_exportar_tiempo_trabajado(d_str, d_str, nifs)
                    if tc_day is not None and not tc_day.empty:
                        tc_day["Fecha"] = d_str
                        tc_rows.append(tc_day)
                if tc_rows:
                    tc = pd.concat(tc_rows, ignore_index=True)
                else:
                    tc = pd.DataFrame(columns=["nif", "Fecha", "tiempoContabilizado_seg"])

                # Convertir a HH:MM con el MISMO redondeo (segundos_a_hhmm ya redondea)
                tc["Tiempo Contabilizado"] = tc["tiempoContabilizado_seg"].apply(segundos_a_hhmm)
                tc = tc[["nif", "Fecha", "Tiempo Contabilizado"]]
            else:
                tc = pd.DataFrame(columns=["nif", "Fecha", "Tiempo Contabilizado"])

            resumen = resumen.merge(tc, on=["nif", "Fecha"], how="left")
            resumen["Tiempo Contabilizado"] = resumen["Tiempo Contabilizado"].fillna("")

            # Normalización anti ±00:01: si la diferencia entre Total trabajado y Tiempo Contabilizado
            # es de 1 minuto (típico por redondeos internos), igualamos ambos para evitar ruido visual
            # y coherencia en reglas/incidencias.
            tt_min = resumen["Total trabajado"].apply(hhmm_to_min)
            tc_min = resumen["Tiempo Contabilizado"].apply(hhmm_to_min)
            close_mask = (tt_min > 0) & (tc_min > 0) & ((tc_min - tt_min).abs() <= 1)
            resumen.loc[close_mask, "Tiempo Contabilizado"] = resumen.loc[close_mask, "Total trabajado"]

            resumen["Diferencia"] = resumen.apply(
                lambda r: diferencia_hhmm(r.get("Tiempo Contabilizado", ""), r.get("Total trabajado", "")),
                axis=1
            )

            resumen["horas_dec_marcajes"] = resumen["Total trabajado"].apply(hhmm_to_dec)
            resumen["horas_dec_contab"] = resumen["Tiempo Contabilizado"].apply(hhmm_to_dec)

            # Incidencias
            incidencias = []
            for _, r in resumen.iterrows():
                fecha_str = r.get("Fecha", "")
                try:
                    d = datetime.strptime(fecha_str, "%Y-%m-%d").date()
                except Exception:
                    d = None

                nombre = r.get("Nombre", "") or ""
                nombre_norm = r.get("nombre_norm", "") or norm_name(nombre)
                dep = r.get("Departamento", "") or ""
                ds = weekday_name(d) if d else ""

                total_h = float(r.get("horas_dec_marcajes") or 0.0)
                num_f = int(r.get("Numero") or 0)

                # Minimos
                min_h, min_f = reglas_minimos(dep, ds, nombre_norm)

                inc = []
                if d and is_weekend(d) and total_h > 0:
                    inc.append("Trabajo en fin de semana")

                # Fichajes insuficientes/excesivos (especial Beatriz: excesivos solo si >4)
                if min_f > 0 and num_f < min_f:
                    inc.append(f"Fichajes insuficientes (mín {min_f:.1f})" if isinstance(min_f, float) else f"Fichajes insuficientes (mín {min_f})")

                # Excesivos: default max 4 para ESTRUCTURA/MOI L-J, y max 4 para todos en general según RRHH
                if num_f > 4:
                    if name_startswith(nombre_norm, "BEATRIZ"):
                        if num_f > 4:
                            inc.append("Fichajes excesivos (máx 4)")
                    else:
                        inc.append("Fichajes excesivos (máx 4)")

                # Horas insuficientes
                if min_h > 0 and total_h + 1e-9 < (min_h - TOLERANCIA_HORAS):
                    inc.append(f"Horas insuficientes (mín {min_h:.1f}h)")

                # Horario (entrada/salida)
                inc += validar_horario(dep, ds, r.get("Primera entrada", ""), r.get("Última salida", ""), nombre_norm)

                incidencias.append("; ".join([x for x in inc if x]))

            resumen["Incidencia"] = incidencias

            # Solo filas con incidencia
            resumen_inc = resumen[resumen["Incidencia"].astype(str).str.strip() != ""].copy()

            if not resumen_inc.empty:
                salida_incidencias = resumen_inc[
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
                        "Numero",
                        "Incidencia",
                    ]
                ].rename(columns={"Numero": "Numero de fichajes"}).sort_values(["Fecha", "Nombre"], kind="mergesort")
            else:
                salida_incidencias = pd.DataFrame(columns=[
                    "Fecha", "Empresa", "Sede", "Nombre", "Departamento", "Primera entrada", "Última salida",
                    "Total trabajado", "Tiempo Contabilizado", "Diferencia", "Numero de fichajes", "Incidencia"
                ])

        # --------- BAJAS (día a día) - SIEMPRE filtrado por empleados_filtrados ----------
        bajas_por_dia = {}
        d0 = datetime.strptime(fi_s, "%Y-%m-%d").date()
        d1 = datetime.strptime(ff_s, "%Y-%m-%d").date()

        # Para bajas: se detecta por día consultando /informes/empleados y viendo horas_baja > 0 (lógica ya validada)
        # NOTA: endpoint /informes/empleados agrega por rango; por eso se hace día a día.
        for d in _split_range(fi_s, ff_s):
            d_str = d.strftime("%Y-%m-%d")
            url_inf = f"{API_URL_BASE}/informes/empleados"
            resp = safe_request("POST", url_inf, data={"fecha_desde": d_str, "fecha_hasta": d_str})
            if resp is None:
                continue
            try:
                resp.raise_for_status()
            except Exception:
                continue

            dec = _try_parse_encrypted_response(resp)
            if not isinstance(dec, list):
                continue

            # Intentar mapear por num_empleado y nombre, filtrando por empresa/sede (si el informe trae esos campos)
            rows = []
            for it in dec:
                if not isinstance(it, dict):
                    continue
                # Campos típicos de informe (depende del formato exacto)
                empresa = it.get("Empresa") or it.get("empresa") or it.get("empresa_nombre") or ""
                sede = it.get("Sede") or it.get("sede") or it.get("sede_nombre") or ""
                departamento = it.get("Departamento") or it.get("departamento") or ""
                num_emp = it.get("Nº empleado") or it.get("num_empleado") or it.get("Num_empleado") or it.get("Nº_empleado") or ""
                horas_baja = it.get("Horas de baja laboral (laborables, no naturales)") or it.get("horas_baja") or it.get("Horas baja") or 0
                motivo_baja = it.get("motivo_baja") or it.get("Motivo baja") or it.get("Motivo") or None

                # Sólo si hay baja real (horas_baja > 0)
                try:
                    hb = float(horas_baja) if horas_baja is not None else 0.0
                except Exception:
                    hb = 0.0
                if hb <= 0:
                    continue

                rows.append(
                    {
                        "Fecha": d_str,
                        "Empresa": empresa,
                        "Sede": sede,
                        "Departamento": departamento,
                        "Nº empleado": num_emp,
                        "Horas baja": hb,
                        "Motivo baja": motivo_baja,
                    }
                )

            if rows:
                df_b = pd.DataFrame(rows)
                df_b["Empresa_norm"] = df_b["Empresa"].apply(_norm_key)
                df_b["Sede_norm"] = df_b["Sede"].apply(_norm_key)

                # Filtrar por catálogo + filtros
                df_b = df_b[df_b["Empresa_norm"].isin(ALLOWED_EMPRESAS_N)]
                df_b = df_b[df_b["Sede_norm"].isin(ALLOWED_SEDES_N)]
                df_b = _filter_emp_sede(df_b, empresa_sel, sede_sel)

                if not df_b.empty:
                    bajas_por_dia[d_str] = df_b.drop(columns=["Empresa_norm", "Sede_norm"], errors="ignore")

        # --------- SIN FICHAJES (día a día) ----------
        sin_fichajes_por_dia = {}

        # Base de empleados activos/contrato: usamos el catálogo de empleados filtrados
        base_emp_sin = empleados_filtrados[["nif", "Nombre", "Departamento", "Empresa", "Sede", "Empresa_norm", "Sede_norm", "nombre_norm", "num_empleado"]].copy()
        base_emp_sin = base_emp_sin.rename(columns={"Nombre": "Nombre"})

        # Heurística de "activo/contrato": aquí se conserva tu comportamiento (basado en existencia en catálogo filtrado)
        mask_activo = base_emp_sin["nif"].astype(str).str.strip() != ""
        base_emp_sin = base_emp_sin[mask_activo].copy()

        # Excluir personas indicadas por RRHH (solo en 'Sin fichajes')
        base_emp_sin["nombre_completo"] = base_emp_sin["nombre_completo"].astype(str)
        base_emp_sin["nombre_completo_norm"] = base_emp_sin["nombre_completo"].apply(norm_name)
        base_emp_sin = base_emp_sin[~base_emp_sin["nombre_completo_norm"].isin(EXCLUDE_SIN_FICHAJES_NAMES_NORM)].copy()

        empleados_nifs = base_emp_sin["nif"].dropna().astype(str).str.upper().str.strip().unique().tolist()

        presentes = {}
        if not df_fich.empty:
            for day, sub in df_fich.groupby("fecha_dia"):
                presentes[day] = set(sub["nif"].dropna().astype(str).str.upper().str.strip().unique().tolist())

        for d in _split_range(fi_s, ff_s):
            d_str = d.strftime("%Y-%m-%d")
            present_set = presentes.get(d_str, set())
            faltan = base_emp_sin[~base_emp_sin["nif"].isin(present_set)].copy()
            if not faltan.empty:
                sin_fichajes_por_dia[d_str] = faltan[["nif", "nombre_completo", "Departamento", "Empresa", "Sede"]].rename(
                    columns={"nombre_completo": "Nombre"}
                ).sort_values(["Empresa", "Sede", "Nombre"], kind="mergesort")

        # ============================================================
        # UI: Tabs
        # ============================================================
        tab1, tab2, tab3 = st.tabs(["Fichajes (incidencias)", "Bajas", "Sin fichajes"])

        with tab1:
            st.subheader("Incidencias detectadas")
            st.dataframe(salida_incidencias, use_container_width=True, hide_index=True)

        with tab2:
            st.subheader("Bajas (por día)")
            if not bajas_por_dia:
                st.info("No hay bajas en el rango/filtrado seleccionado.")
            else:
                for day in sorted(bajas_por_dia.keys()):
                    st.markdown(f"### {day}")
                    st.dataframe(bajas_por_dia[day], use_container_width=True, hide_index=True)

        with tab3:
            st.subheader("Empleados sin fichajes (por día)")
            if not sin_fichajes_por_dia:
                st.info("No hay empleados sin fichajes en el rango/filtrado seleccionado.")
            else:
                for day in sorted(sin_fichajes_por_dia.keys()):
                    st.markdown(f"### {day}")
                    st.dataframe(sin_fichajes_por_dia[day], use_container_width=True, hide_index=True)
