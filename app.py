import base64
import json
import multiprocessing
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
HTTP_TIMEOUT = (5, 25)

# Tolerancia RRHH (±5 min) aplicada al mínimo de horas (para "insuficientes")
TOLERANCIA_MINUTOS = 5
TOLERANCIA_HORAS = TOLERANCIA_MINUTOS / 60.0

# Margen horario SOLO para MOI y ESTRUCTURA (entrada temprana y salida temprana)
MARGEN_HORARIO_MIN = 5

_SESSION = requests.Session()
_SESSION.headers.update({"Accept": "application/json", "Authorization": f"Bearer {API_TOKEN}"})


# ============================================================
# SEGURIDAD: no loguear detalles (PII, tokens, payloads)
# ============================================================

def _safe_fail(_exc: Exception) -> None:
    return None


# ============================================================
# NORMALIZACIÓN NOMBRES (para reglas especiales)
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
# TIEMPOS (TRUNCADO A MINUTO: estilo CRECE)
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
# ============================================================

SPECIAL_RULES = {
    # MOD David Rodriguez Vazquez: 09:30-14:00 => 4.5h, 2 fichajes
    ("MOD", norm_name("DAVID RODRIGUEZ VAZQUEZ")): {"min_horas": 4.5, "min_fichajes": 2},

    # MOI Debora Luis y Etor Alegria: mínimo 2 fichajes
    ("MOI", norm_name("DEBORA LUIS")): {"min_fichajes": 2},
    ("MOI", norm_name("ETOR ALEGRIA")): {"min_fichajes": 2},

    # MOI Miriam: 09:00-14:30 => 5.5h y 2 fichajes (por nombre)
    ("MOI", norm_name("MIRIAM")): {"min_horas": 5.5, "min_fichajes": 2},
}

# Exentos de validación de entrada/salida estándar (tienen horario especial)
SCHEDULE_EXEMPT = [
    ("MOD", norm_name("DAVID RODRIGUEZ VAZQUEZ")),
    ("MOI", norm_name("MIRIAM")),
]

# Excepciones MOI para poder entrar antes de 07:00 y salir antes de 16:30
FLEX_BY_DEPTO = {
    # Fran es de ESTRUCTURA (no MOI)
    "ESTRUCTURA": [
        norm_name("FRAN DIAZ"),
    ],
    # Débora y Etor son MOI
    "MOI": [
        norm_name("DEBORA LUIS"),
        norm_name("ETOR ALEGRIA"),
    ],
}


def _lookup_special(depto_norm: str, nombre_norm: str):
    key_full = (depto_norm, nombre_norm)
    if key_full in SPECIAL_RULES:
        return SPECIAL_RULES[key_full]

    first = (nombre_norm.split(" ")[0] if nombre_norm else "")
    key_first = (depto_norm, first)
    return SPECIAL_RULES.get(key_first)


def _is_schedule_exempt(depto_norm: str, nombre_norm: str) -> bool:
    for d, pref in SCHEDULE_EXEMPT:
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
# VALIDACIÓN HORARIA (entrada/salida)
# - MOI/ESTRUCTURA: margen 5 min SOLO para entrada temprana y salida temprana
# - MOD: SIN margen. Si entra más tarde del límite => Entrada tarde.
# ============================================================

def validar_horario(depto: str, nombre: str, dia: int, primera_entrada_hhmm: str, ultima_salida_hhmm: str) -> list[str]:
    depto_norm = (depto or "").upper().strip()
    nombre_norm = norm_name(nombre)

    # Solo L-V para reglas horarias
    if dia not in [0, 1, 2, 3, 4]:
        return []

    # Exentos por horario especial
    if _is_schedule_exempt(depto_norm, nombre_norm):
        return []

    incid = []

    e_min = hhmm_to_min_clock(primera_entrada_hhmm)
    s_min = hhmm_to_min_clock(ultima_salida_hhmm)

    # Si no hay entrada, no validamos horario
    if e_min is None:
        return incid

    # -------------------------
    # MOD: Entrada válida 05:30–06:00 o 13:00–14:00
    # SIN margen.
    # Si entra más tarde de 06:00 -> (si es entre 06:01 y 12:59) "fuera de rango"
    # Si entra más tarde de 14:00 -> "Entrada tarde"
    # -------------------------
    if depto_norm == "MOD":
        ma_ini, ma_fin = 5 * 60 + 30, 6 * 60
        ta_ini, ta_fin = 13 * 60, 14 * 60

        ok = (ma_ini <= e_min <= ma_fin) or (ta_ini <= e_min <= ta_fin)
        if not ok:
            if e_min < ma_ini:
                incid.append(f"Entrada temprana ({primera_entrada_hhmm})")
            elif ma_fin < e_min < ta_ini:
                incid.append(f"Entrada fuera de rango ({primera_entrada_hhmm})")
            elif e_min > ta_fin:
                incid.append(f"Entrada tarde ({primera_entrada_hhmm})")
            else:
                incid.append(f"Entrada fuera de rango ({primera_entrada_hhmm})")
        return incid

    # -------------------------
    # MOI y ESTRUCTURA:
    # Entrada válida 07:00–09:00
    # Salida mínima 16:30
    # Margen 5 min para:
    #   - Entrada temprana: solo si < 06:55
    #   - Salida temprana: solo si < 16:25
    # Entrada tarde: SIN margen (> 09:00)
    # -------------------------
    if depto_norm in ["MOI", "ESTRUCTURA"]:
        # Flex por departamento (Fran en ESTRUCTURA, Debora/Etor en MOI)
        flex = _is_flex(depto_norm, nombre_norm)

        if not flex:
            ini, fin = 7 * 60, 9 * 60
            salida_min = 16 * 60 + 30

            # Entrada temprana con margen
            if e_min < (ini - MARGEN_HORARIO_MIN):
                incid.append(f"Entrada temprana ({primera_entrada_hhmm})")
            # Entrada tarde sin margen
            elif e_min > fin:
                incid.append(f"Entrada tarde ({primera_entrada_hhmm})")

            # Salida temprana con margen
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
    resp = _SESSION.get(url, timeout=HTTP_TIMEOUT)
    resp.raise_for_status()

    payload_b64 = _extract_payload_b64(resp)
    decrypted = decrypt_crece_payload(payload_b64, APP_KEY_B64)
    departamentos = json.loads(decrypted)

    return pd.DataFrame(
        [{"departamento_id": d.get("id"), "departamento_nombre": d.get("nombre")}
         for d in (departamentos or [])]
    )


def api_exportar_empleados_completos() -> pd.DataFrame:
    url = f"{API_URL_BASE}/exportacion/empleados"
    data = {"solo_nif": 0}

    resp = _SESSION.post(url, data=data, timeout=HTTP_TIMEOUT)
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
        resp = _SESSION.post(url, timeout=HTTP_TIMEOUT)
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
        resp = _SESSION.post(url, data=data, timeout=HTTP_TIMEOUT)
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
                {
                    "nif": k,
                    "tiempoEfectivo_seg": val[-2],
                    "tiempoContabilizado_seg": val[-1],
                }
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
        resp = _SESSION.post(url, data=payload, timeout=HTTP_TIMEOUT)
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
# DÍA (turno nocturno)
# ============================================================

def ajustar_fecha_dia(fecha_dt: pd.Timestamp, turno_nocturno: int) -> str:
    if turno_nocturno == 1 and fecha_dt.hour < 6:
        return (fecha_dt.date() - timedelta(days=1)).strftime("%Y-%m-%d")
    return fecha_dt.date().strftime("%Y-%m-%d")


# ============================================================
# TIEMPO POR FICHAJES (neto) - segundos enteros
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
                        delta_i = int(delta)  # truncado
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
# VALIDACIÓN HORAS/FICHAJES (con tolerancia de 5 min en horas)
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

    if horas_val >= umbral_inferior and num_fich > int(min_f):
        motivos.append(f"Fichajes excesivos (mín {min_f})")

    return motivos


# ============================================================
# UI
# ============================================================

st.set_page_config(page_title="Fichajes CRECE Personas", layout="wide")
st.title("📊 Fichajes CRECE Personas")

hoy = date.today()
col1, col2 = st.columns(2)
with col1:
    fecha_inicio = st.date_input("Fecha inicio", value=hoy, max_value=hoy)
with col2:
    fecha_fin = st.date_input("Fecha fin", value=hoy, max_value=hoy)

st.write("---")

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
        try:
            tipos_map = api_exportar_tipos_fichaje()
            departamentos_df = api_exportar_departamentos()
            empleados_df = api_exportar_empleados_completos()
            if empleados_df.empty:
                st.warning("No hay empleados disponibles.")
                st.stop()

            empleados_df = empleados_df.merge(departamentos_df, on="departamento_id", how="left")
            empleados_df["nif"] = empleados_df["nif"].astype(str).str.upper().str.strip()

        except Exception as e:
            _safe_fail(e)
            st.error("❌ No se pudo cargar la información base.")
            st.stop()

        # Fichajes en paralelo
        fichajes_rows = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as exe:
            futures = {exe.submit(api_exportar_fichajes, r["nif"], fi, ff): r for _, r in empleados_df.iterrows()}
            for fut in as_completed(futures):
                emp = futures[fut]
                for x in (fut.result() or []):
                    try:
                        fichajes_rows.append(
                            {
                                "nif": emp["nif"],
                                "Nombre": emp["nombre_completo"],
                                "Departamento": emp.get("departamento_nombre"),
                                "id": x.get("id"),
                                "tipo": x.get("tipo"),
                                "direccion": x.get("direccion"),
                                "fecha": x.get("fecha"),
                            }
                        )
                    except Exception:
                        continue

        if not fichajes_rows:
            st.info("No se encontraron fichajes en el rango seleccionado.")
            st.stop()

        df = pd.DataFrame(fichajes_rows)
        df["nif"] = df["nif"].astype(str).str.upper().str.strip()
        df["fecha_dt"] = pd.to_datetime(df["fecha"], errors="coerce")
        df = df.dropna(subset=["fecha_dt"])

        # día ajustado por nocturno
        def _dia_row(r):
            props = tipos_map.get(int(r["tipo"]), {}) if pd.notna(r.get("tipo")) else {}
            return ajustar_fecha_dia(r["fecha_dt"], int(props.get("turno_nocturno", 0)))

        df["fecha_dia"] = df.apply(_dia_row, axis=1)

        # Nº fichajes por día
        df["Numero"] = df.groupby(["nif", "fecha_dia"])["id"].transform("count")
        conteo = (
            df.groupby(["nif", "Nombre", "Departamento", "fecha_dia"], as_index=False)
            .agg(Numero=("Numero", "max"))
            .rename(columns={"fecha_dia": "Fecha", "Numero": "Numero de fichajes"})
        )

        # Total trabajado por marcajes
        neto = calcular_tiempos_neto(df, tipos_map)
        resumen = conteo.merge(neto, on=["nif", "Fecha"], how="left")
        resumen["segundos_neto"] = resumen["segundos_neto"].fillna(0)
        resumen["Total trabajado"] = resumen["segundos_neto"].apply(segundos_a_hhmm)

        # Primera entrada / última salida
        io = calcular_primera_ultima(df)
        resumen = resumen.merge(io, on=["nif", "Fecha"], how="left")
        resumen["Primera entrada"] = resumen["primera_entrada_dt"].apply(ts_to_hhmm)
        resumen["Última salida"] = resumen["ultima_salida_dt"].apply(ts_to_hhmm)

        # Tiempo contabilizado por día (misma forma: intento mismo día, fallback día+1)
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

        # Diferencia
        resumen["Diferencia"] = resumen.apply(
            lambda r: diferencia_hhmm(r.get("Tiempo Contabilizado", ""), r.get("Total trabajado", "")),
            axis=1
        )

        # Validación usa contabilizado si existe; si no, marcajes
        resumen["horas_dec_marcajes"] = resumen["Total trabajado"].apply(hhmm_to_dec)
        resumen["horas_dec_contabilizado"] = resumen["Tiempo Contabilizado"].apply(hhmm_to_dec)

        resumen["horas_dec_validacion"] = resumen["horas_dec_marcajes"]
        mask_tc = resumen["Tiempo Contabilizado"].astype(str).str.strip().ne("")
        resumen.loc[mask_tc, "horas_dec_validacion"] = resumen.loc[mask_tc, "horas_dec_contabilizado"]

        resumen["dia"] = pd.to_datetime(resumen["Fecha"]).dt.weekday

        # Minimos por depto + día + persona (especiales)
        resumen[["min_horas", "min_fichajes"]] = resumen.apply(
            lambda r: pd.Series(calcular_minimos(r.get("Departamento"), int(r["dia"]), r.get("Nombre"))),
            axis=1,
        )

        # Construimos incidencia final
        def build_incidencia(r) -> str:
            motivos = []

            # Fin de semana: no validamos mínimos ni horario, pero si trabaja lo mostramos
            if int(r.get("dia", 0)) in [5, 6]:
                try:
                    worked = (float(r.get("horas_dec_validacion", 0.0) or 0.0) > 0.0) or (
                        int(r.get("Numero de fichajes", 0) or 0) > 0
                    )
                except Exception:
                    worked = False

                if worked:
                    motivos.append("Trabajo en fin de semana")
                return "; ".join(motivos)

            # Laborables: horas/fichajes
            motivos += validar_incidencia_horas_fichajes(r)

            # Laborables: horario
            motivos += validar_horario(
                r.get("Departamento"),
                r.get("Nombre"),
                int(r.get("dia", 0)),
                r.get("Primera entrada", ""),
                r.get("Última salida", ""),
            )

            return "; ".join(motivos)

        resumen["Incidencia"] = resumen.apply(build_incidencia, axis=1)

        # Solo mostramos quien tenga incidencia (incluye fin de semana trabajado)
        salida = resumen[resumen["Incidencia"].astype(str).str.strip().ne("")].copy()

        if salida.empty:
            st.success("🎉 No hay incidencias ni trabajos en fin de semana en el rango seleccionado.")
            st.stop()

        salida = salida[
            [
                "Fecha",
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

    for f_dia in salida["Fecha"].unique():
        st.markdown(f"### 📅 {f_dia}")
        sub = salida[salida["Fecha"] == f_dia]
        st.data_editor(sub, use_container_width=True, hide_index=True, disabled=True, num_rows="fixed")

    csv = salida.to_csv(index=False).encode("utf-8")
    st.download_button("⬇ Descargar CSV", csv, "fichajes_incidencias.csv", "text/csv")
