import base64
import json
import requests
import pandas as pd
import streamlit as st
import hmac
import hashlib

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, date, timedelta
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


# ==========================================
# CONFIG
# ==========================================
API_URL_BASE = "https://sincronizaciones.crecepersonas.es/api"
API_TOKEN = st.secrets["API_TOKEN"]
APP_KEY_B64 = st.secrets["APP_KEY_B64"]

MAX_WORKERS = 1000
REQ_TIMEOUT = 45


# ==========================================
# DESCIFRADO CRECE (Laravel) + MAC correcto
# ==========================================
def decrypt_crece_payload(payload_b64: str, app_key_b64: str) -> str:
    if not payload_b64:
        return ""

    payload_json = base64.b64decode(payload_b64).decode("utf-8")
    payload = json.loads(payload_json)

    if not (isinstance(payload, dict) and "iv" in payload and "value" in payload and "mac" in payload):
        raise ValueError("Payload inválido: faltan iv/value/mac")

    key = base64.b64decode(app_key_b64)

    msg = (payload["iv"] + payload["value"]).encode("utf-8")
    expected_mac = hmac.new(key, msg, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_mac.lower(), str(payload["mac"]).lower()):
        raise ValueError("MAC inválido (clave incorrecta o payload manipulado)")

    iv = base64.b64decode(payload["iv"])
    ct = base64.b64decode(payload["value"])

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ct), AES.block_size)
    return decrypted.decode("utf-8")


def safe_strip_quotes(s: str) -> str:
    if s is None:
        return ""
    s = s.strip()
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        s = s[1:-1]
    return s.strip()


# ==========================================
# TIEMPO HELPERS
# ==========================================
def horas_a_hhmm(horas: float) -> str:
    if horas is None or pd.isna(horas):
        return "00:00"
    total_min = int(round(float(horas) * 60))
    h = total_min // 60
    m = total_min % 60
    return f"{h:02d}:{m:02d}"


def daterange(d1: date, d2: date):
    cur = d1
    while cur <= d2:
        yield cur
        cur += timedelta(days=1)


# ==========================================
# HTTP session pool
# ==========================================
def make_session():
    s = requests.Session()
    adapter = requests.adapters.HTTPAdapter(pool_connections=200, pool_maxsize=200, max_retries=0)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    return s


def headers():
    return {"Accept": "application/json", "Authorization": f"Bearer {API_TOKEN}"}


# ==========================================
# EXPORT: DEPARTAMENTOS / EMPLEADOS
# ==========================================
@st.cache_data(show_spinner=False, ttl=60 * 60)
def api_exportar_departamentos() -> pd.DataFrame:
    url = f"{API_URL_BASE}/exportacion/departamentos"
    s = make_session()
    resp = s.get(url, headers=headers(), timeout=REQ_TIMEOUT)
    resp.raise_for_status()

    payload_b64 = safe_strip_quotes(resp.text)
    decrypted = decrypt_crece_payload(payload_b64, APP_KEY_B64)
    departamentos = json.loads(decrypted)

    rows = [{"departamento_id": d.get("id"), "departamento_nombre": d.get("nombre")} for d in departamentos]
    return pd.DataFrame(rows)


@st.cache_data(show_spinner=False, ttl=60 * 60)
def api_exportar_empleados_completos() -> pd.DataFrame:
    url = f"{API_URL_BASE}/exportacion/empleados"
    s = make_session()
    resp = s.post(url, headers=headers(), data={"solo_nif": 0}, timeout=REQ_TIMEOUT)
    resp.raise_for_status()

    payload_b64 = safe_strip_quotes(resp.text)
    decrypted = decrypt_crece_payload(payload_b64, APP_KEY_B64)
    empleados = json.loads(decrypted)

    rows = []
    for e in empleados:
        nombre = e.get("name") or e.get("nombre") or ""
        primer_apellido = e.get("primer_apellido") or ""
        segundo_apellido = e.get("segundo_apellido") or ""

        if (not primer_apellido and not segundo_apellido) and e.get("apellidos"):
            partes = str(e["apellidos"]).split()
            primer_apellido = partes[0] if len(partes) > 0 else ""
            segundo_apellido = " ".join(partes[1:]) if len(partes) > 1 else ""

        nombre_completo = f"{nombre} {primer_apellido} {segundo_apellido}".strip()

        rows.append({
            "nif": e.get("nif"),
            "nombre_completo": nombre_completo,
            "departamento_id": e.get("departamento"),
        })

    df = pd.DataFrame(rows).dropna(subset=["nif"])
    df["nif"] = df["nif"].astype(str)
    return df


# ==========================================
# EXPORT: FICHAJES (solo para contar)
# ==========================================
def api_exportar_fichajes(s: requests.Session, nif: str, fi: str, ff: str):
    url = f"{API_URL_BASE}/exportacion/fichajes"
    data = {"fecha_inicio": fi, "fecha_fin": ff, "nif": nif, "order": "desc"}
    try:
        resp = s.post(url, headers=headers(), data=data, timeout=REQ_TIMEOUT)
        if resp.status_code >= 400:
            return []
        payload_b64 = safe_strip_quotes(resp.text)
        if not payload_b64:
            return []
        decrypted = decrypt_crece_payload(payload_b64, APP_KEY_B64)
        return json.loads(decrypted)
    except Exception:
        return []


def contar_fichajes_por_dia(fichajes: list) -> dict:
    out = {}
    for f in fichajes:
        fecha = f.get("fecha")
        if not fecha:
            continue
        dt = pd.to_datetime(fecha, format="%Y-%m-%d %H:%M:%S", errors="coerce")
        if pd.isna(dt):
            continue
        day = dt.strftime("%Y-%m-%d")
        out[day] = out.get(day, 0) + 1
    return out


# ==========================================
# EXPORT: TIEMPO TRABAJADO (tiempoContabilizado)
# ==========================================
def _parse_tiempo_trabajado(decoded) -> dict:
    """
    Devuelve dict nif -> {"tiempoContabilizado": seconds, "tiempoEfectivo": seconds}
    Soporta múltiples formatos de respuesta (dict/list).
    """
    out = {}

    # Caso 1: dict (p.ej. {"44649081D": {...}})
    if isinstance(decoded, dict):
        for key, val in decoded.items():
            nif_key = str(key)

            if isinstance(val, dict):
                tc = val.get("tiempoContabilizado", 0) or 0
                te = val.get("tiempoEfectivo", 0) or 0
            elif isinstance(val, (list, tuple)):
                # si viene como lista, intentamos localizar los dos últimos numéricos
                nums = [x for x in val if isinstance(x, (int, float))]
                tc = nums[-1] if len(nums) >= 1 else 0
                te = nums[-2] if len(nums) >= 2 else 0
            else:
                tc, te = 0, 0

            out[nif_key] = {"tiempoContabilizado": float(tc), "tiempoEfectivo": float(te)}

        return out

    # Caso 2: lista de dicts
    if isinstance(decoded, list):
        for item in decoded:
            if not isinstance(item, dict):
                continue

            nif = item.get("nif") or item.get("Nif") or item.get("nif_empleado")
            if not nif:
                # a veces el “parámetro” puede venir en otra clave
                for k in ("email", "num_empleado", "num_seg_social"):
                    if item.get(k):
                        nif = item.get(k)
                        break
            if not nif:
                continue

            tc = item.get("tiempoContabilizado", 0) or 0
            te = item.get("tiempoEfectivo", 0) or 0
            out[str(nif)] = {"tiempoContabilizado": float(tc), "tiempoEfectivo": float(te)}

        return out

    return out


def api_tiempo_trabajado_un_dia(s: requests.Session, fecha_str: str, nifs: list[str]) -> dict:
    """
    Llama a /exportacion/tiempo-trabajado con desde=hasta=fecha_str.
    Probamos dos codificaciones del array (nif[] y nif) para compatibilidad.
    Devuelve dict nif -> seconds
    """
    url = f"{API_URL_BASE}/exportacion/tiempo-trabajado"

    # Intento 1: nif[]
    data1 = [("desde", fecha_str), ("hasta", fecha_str)] + [("nif[]", n) for n in nifs]
    try:
        resp = s.post(url, headers=headers(), data=data1, timeout=REQ_TIMEOUT)
        if resp.status_code < 400:
            payload_b64 = safe_strip_quotes(resp.text)
            if payload_b64:
                decrypted = decrypt_crece_payload(payload_b64, APP_KEY_B64)
                decoded = json.loads(decrypted)
                parsed = _parse_tiempo_trabajado(decoded)
                if parsed:
                    return parsed
    except Exception:
        pass

    # Intento 2: nif (repetido)
    data2 = [("desde", fecha_str), ("hasta", fecha_str)] + [("nif", n) for n in nifs]
    try:
        resp = s.post(url, headers=headers(), data=data2, timeout=REQ_TIMEOUT)
        if resp.status_code < 400:
            payload_b64 = safe_strip_quotes(resp.text)
            if payload_b64:
                decrypted = decrypt_crece_payload(payload_b64, APP_KEY_B64)
                decoded = json.loads(decrypted)
                return _parse_tiempo_trabajado(decoded)
    except Exception:
        pass

    return {}


# ==========================================
# VALIDACIÓN (la que ya tenías)
# ==========================================
def calcular_minimos(depto: str, dia_semana: int):
    depto = (depto or "").strip().upper()
    if depto in ["ESTRUCTURA", "MOI"]:
        if dia_semana in [0, 1, 2, 3]:
            return 8.5, 4
        elif dia_semana == 4:
            return 6.5, 2
        return None, None
    if depto == "MOD":
        if dia_semana in [0, 1, 2, 3, 4]:
            return 8.0, 2
        return None, None
    return None, None


# ==========================================
# UI STREAMLIT
# ==========================================
st.set_page_config(page_title="Fichajes CRECE", layout="wide")
st.title("📊 Fichajes CRECE Personas")

hoy = date.today()
c1, c2 = st.columns(2)
with c1:
    fecha_inicio = st.date_input("Fecha inicio", value=hoy, max_value=hoy)
with c2:
    fecha_fin = st.date_input("Fecha fin", value=hoy, max_value=hoy)

st.write("---")

if st.button("▶ Obtener incidencias (Total trabajado = tiempoContabilizado)"):
    if fecha_inicio > fecha_fin:
        st.error("❌ La fecha inicio no puede ser posterior a la fecha fin.")
        st.stop()
    if fecha_fin > hoy:
        st.error("❌ La fecha fin no puede ser mayor que hoy.")
        st.stop()

    with st.spinner("Cargando empleados y departamentos…"):
        departamentos_df = api_exportar_departamentos()
        empleados_df = api_exportar_empleados_completos()
        empleados_df = empleados_df.merge(departamentos_df, on="departamento_id", how="left")
        empleados_df["departamento_nombre"] = empleados_df["departamento_nombre"].fillna("")

    nifs = empleados_df["nif"].dropna().astype(str).unique().tolist()

    # 1) Tiempo trabajado por día (tiempoContabilizado)
    with st.spinner("Obteniendo tiempo trabajado (tiempoContabilizado) por día…"):
        s = make_session()
        tiempo_por_dia = {}  # (Fecha, nif) -> horas_contabilizadas
        for d in daterange(fecha_inicio, fecha_fin):
            ds = d.strftime("%Y-%m-%d")
            data_day = api_tiempo_trabajado_un_dia(s, ds, nifs)

            # guardamos siempre, aunque venga parcial
            for nif, vv in data_day.items():
                tc = float(vv.get("tiempoContabilizado", 0.0))
                tiempo_por_dia[(ds, str(nif))] = tc / 3600.0

    # 2) Fichajes en paralelo SOLO para contar
    with st.spinner("Contando fichajes por día…"):
        fi_str = fecha_inicio.strftime("%Y-%m-%d")
        ff_str = fecha_fin.strftime("%Y-%m-%d")
        s2 = make_session()

        def worker(emp_row):
            nif = str(emp_row["nif"])
            fichajes = api_exportar_fichajes(s2, nif, fi_str, ff_str)
            counts = contar_fichajes_por_dia(fichajes)

            rows = []
            for d in daterange(fecha_inicio, fecha_fin):
                ds = d.strftime("%Y-%m-%d")
                horas_cont = float(tiempo_por_dia.get((ds, nif), 0.0))
                rows.append({
                    "Fecha": ds,
                    "nif": nif,
                    "Nombre Completo": emp_row["nombre_completo"],
                    "Departamento": emp_row["departamento_nombre"],
                    "horas_trabajadas": horas_cont,            # <- EXACTAMENTE tiempoContabilizado (horas)
                    "Numero de fichajes": int(counts.get(ds, 0)),
                })
            return rows

        rows_all = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futs = [ex.submit(worker, r) for _, r in empleados_df.iterrows()]
            for fut in as_completed(futs):
                try:
                    rows_all.extend(fut.result())
                except Exception:
                    pass

    base = pd.DataFrame(rows_all)
    if base.empty:
        st.info("No hay datos en el rango.")
        st.stop()

    # Total trabajado = horas_trabajadas (tiempoContabilizado)
    base["Total trabajado"] = base["horas_trabajadas"].apply(horas_a_hhmm)
    base["dia_semana"] = pd.to_datetime(base["Fecha"]).dt.weekday

    def validar(row):
        min_h, min_f = calcular_minimos(row["Departamento"], int(row["dia_semana"]))
        if min_h is None or min_f is None:
            return None

        horas = float(row["horas_trabajadas"])
        fich = int(row["Numero de fichajes"])
        motivos = []

        if horas < float(min_h):
            motivos.append(f"Horas insuficientes (mín {min_h}h, tiene {horas:.2f}h)")
        if fich < int(min_f):
            motivos.append(f"Fichajes insuficientes (mín {min_f}, tiene {fich})")
        if horas >= float(min_h) and fich > int(min_f):
            motivos.append(f"Fichajes excesivos (mín {min_f}, tiene {fich})")

        return "; ".join(motivos) if motivos else None

    base["Motivo"] = base.apply(validar, axis=1)
    out = base[base["Motivo"].notna()].copy()

    if out.empty:
        st.success("🎉 No hay incidencias en el rango seleccionado.")
        st.stop()

    out = out.sort_values(["Fecha", "Nombre Completo"], ascending=[True, True])

    out_final = out[[
        "Fecha",
        "Nombre Completo",
        "Departamento",
        "Total trabajado",
        "Numero de fichajes",
        "Motivo"
    ]].copy()

    st.subheader("📄 Incidencias (Total trabajado = tiempoContabilizado)")
    for ds in out_final["Fecha"].unique():
        st.markdown(f"### 📅 Fecha {ds}")
        st.dataframe(out_final[out_final["Fecha"] == ds], use_container_width=True, hide_index=True)

    csv_bytes = out_final.to_csv(index=False).encode("utf-8")
    st.download_button(
        "⬇ Descargar CSV (incidencias)",
        csv_bytes,
        "fichajes_incidencias_tiempocontabilizado.csv",
        "text/csv"
    )
