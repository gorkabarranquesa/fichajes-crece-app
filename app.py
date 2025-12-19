import base64
import json
import hmac
import hashlib
import requests
import pandas as pd
import streamlit as st

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
REQ_TIMEOUT = 30


# ==========================================
# DESCIFRADO CRECE (Laravel)
# ==========================================
def _strip_quotes(s: str) -> str:
    if s is None:
        return ""
    s = s.strip()
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        s = s[1:-1]
    return s.strip()


def decrypt_crece_payload(payload_b64: str, app_key_b64: str) -> str:
    payload_b64 = _strip_quotes(payload_b64)
    if not payload_b64:
        return ""

    raw = base64.b64decode(payload_b64).decode("utf-8")
    payload = json.loads(raw)

    if not isinstance(payload, dict) or "iv" not in payload or "value" not in payload or "mac" not in payload:
        raise ValueError("Payload inválido: faltan iv/value/mac")

    key = base64.b64decode(app_key_b64)

    # MAC = HMAC-SHA256(key, iv+value) en hex
    msg = (payload["iv"] + payload["value"]).encode("utf-8")
    expected = hmac.new(key, msg, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected.lower(), str(payload["mac"]).lower()):
        raise ValueError("MAC inválido (clave incorrecta o payload manipulado)")

    iv = base64.b64decode(payload["iv"])
    ct = base64.b64decode(payload["value"])

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ct), AES.block_size)
    return decrypted.decode("utf-8")


# ==========================================
# HTTP SESSION
# ==========================================
def make_session() -> requests.Session:
    s = requests.Session()
    adapter = requests.adapters.HTTPAdapter(pool_connections=200, pool_maxsize=200, max_retries=0)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    return s


def auth_headers():
    return {"Accept": "application/json", "Authorization": f"Bearer {API_TOKEN}"}


# ==========================================
# HELPERS TIEMPO
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
# EXPORT: DEPARTAMENTOS / EMPLEADOS
# ==========================================
@st.cache_data(show_spinner=False, ttl=60 * 60)
def api_exportar_departamentos() -> pd.DataFrame:
    url = f"{API_URL_BASE}/exportacion/departamentos"
    s = make_session()
    resp = s.get(url, headers=auth_headers(), timeout=REQ_TIMEOUT)
    resp.raise_for_status()

    decrypted = decrypt_crece_payload(resp.text, APP_KEY_B64)
    departamentos = json.loads(decrypted)

    rows = [{"departamento_id": d.get("id"), "departamento_nombre": d.get("nombre")} for d in departamentos]
    return pd.DataFrame(rows)


@st.cache_data(show_spinner=False, ttl=60 * 60)
def api_exportar_empleados_completos() -> pd.DataFrame:
    url = f"{API_URL_BASE}/exportacion/empleados"
    s = make_session()
    resp = s.post(url, headers=auth_headers(), data={"solo_nif": 0}, timeout=REQ_TIMEOUT)
    resp.raise_for_status()

    decrypted = decrypt_crece_payload(resp.text, APP_KEY_B64)
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
            "nif": str(e.get("nif") or "").strip(),
            "nombre_completo": nombre_completo,
            "departamento_id": e.get("departamento"),
        })

    df = pd.DataFrame(rows)
    df = df[df["nif"] != ""].copy()
    return df


# ==========================================
# EXPORT: FICHAJES POR EMPLEADO
# ==========================================
def api_exportar_fichajes(session: requests.Session, nif: str, fi: str, ff: str) -> list:
    url = f"{API_URL_BASE}/exportacion/fichajes"
    data = {"fecha_inicio": fi, "fecha_fin": ff, "nif": nif, "order": "asc"}

    try:
        resp = session.post(url, headers=auth_headers(), data=data, timeout=REQ_TIMEOUT)
        if resp.status_code >= 400:
            return []
        decrypted = decrypt_crece_payload(resp.text, APP_KEY_B64)
        return json.loads(decrypted) if decrypted else []
    except Exception:
        return []


# ==========================================
# CÁLCULO DIARIO DE HORAS (por parejas entrada->salida)
# ==========================================
def calcular_diario_desde_fichajes(fichajes: list):
    """
    Devuelve:
      - horas_por_dia: {YYYY-MM-DD: horas}
      - num_fichajes_por_dia: {YYYY-MM-DD: count}
    """
    horas_por_dia = {}
    num_por_dia = {}

    parsed = []
    for f in fichajes:
        dt = pd.to_datetime(f.get("fecha"), format="%Y-%m-%d %H:%M:%S", errors="coerce")
        if pd.isna(dt):
            continue
        d = dt.strftime("%Y-%m-%d")
        num_por_dia[d] = num_por_dia.get(d, 0) + 1

        parsed.append({
            "dt": dt.to_pydatetime(),
            "direccion": f.get("direccion"),
        })

    parsed.sort(key=lambda x: x["dt"])

    i = 0
    while i < len(parsed) - 1:
        a = parsed[i]
        b = parsed[i + 1]

        if a["direccion"] == "entrada" and b["direccion"] == "salida":
            start_dt = a["dt"]
            end_dt = b["dt"]
            if end_dt > start_dt:
                secs = (end_dt - start_dt).total_seconds()
                if 0 < secs <= 20 * 3600:
                    day = start_dt.strftime("%Y-%m-%d")
                    horas_por_dia[day] = horas_por_dia.get(day, 0.0) + secs / 3600.0
            i += 2
        else:
            i += 1

    return horas_por_dia, num_por_dia


# ==========================================
# REGLAS DE VALIDACIÓN
# ==========================================
def calcular_minimos(depto: str, dia_semana: int):
    depto = (depto or "").strip().upper()
    if depto in ["ESTRUCTURA", "MOI"]:
        if dia_semana in [0, 1, 2, 3]:
            return 8.5, 4
        if dia_semana == 4:
            return 6.5, 2
        return None, None
    if depto == "MOD":
        if dia_semana in [0, 1, 2, 3, 4]:
            return 8.0, 2
        return None, None
    return None, None


def validar_fila(row):
    min_h, min_f = calcular_minimos(row["Departamento"], int(row["dia_semana"]))
    if min_h is None or min_f is None:
        return None

    horas = float(row["horas_trabajadas"] or 0.0)
    fich = int(row["Numero de fichajes"] or 0)

    motivos = []
    if horas < float(min_h):
        motivos.append(f"Horas insuficientes (mín {min_h}h, tiene {horas:.2f}h)")
    if fich < int(min_f):
        motivos.append(f"Fichajes insuficientes (mín {min_f}, tiene {fich})")
    if horas >= float(min_h) and fich > int(min_f):
        motivos.append(f"Fichajes excesivos (mín {min_f}, tiene {fich})")

    return "; ".join(motivos) if motivos else None


# ==========================================
# UI
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

if st.button("▶ Obtener incidencias (Total trabajado por fichajes)"):
    if fecha_inicio > fecha_fin:
        st.error("❌ La fecha inicio no puede ser posterior a la fecha fin.")
        st.stop()

    fi = fecha_inicio.strftime("%Y-%m-%d")
    ff = fecha_fin.strftime("%Y-%m-%d")

    with st.spinner("Cargando empleados y departamentos…"):
        departamentos_df = api_exportar_departamentos()
        empleados_df = api_exportar_empleados_completos()
        empleados_df = empleados_df.merge(departamentos_df, on="departamento_id", how="left")
        empleados_df["departamento_nombre"] = empleados_df["departamento_nombre"].fillna("")
        empleados_df["nombre_completo"] = empleados_df["nombre_completo"].fillna("")

    with st.spinner("Obteniendo fichajes y calculando horas diarias…"):
        session = make_session()
        rows = []

        def worker(emp_row):
            nif = str(emp_row["nif"])
            fichajes = api_exportar_fichajes(session, nif, fi, ff)
            horas_por_dia, num_por_dia = calcular_diario_desde_fichajes(fichajes)

            out = []
            for d in daterange(fecha_inicio, fecha_fin):
                ds = d.strftime("%Y-%m-%d")
                out.append({
                    "Fecha": ds,
                    "Nombre Completo": emp_row["nombre_completo"],
                    "Departamento": emp_row["departamento_nombre"],
                    "nif": nif,
                    "horas_trabajadas": float(horas_por_dia.get(ds, 0.0)),
                    "Numero de fichajes": int(num_por_dia.get(ds, 0)),
                })
            return out

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futs = [ex.submit(worker, r) for _, r in empleados_df.iterrows()]
            for fut in as_completed(futs):
                try:
                    rows.extend(fut.result())
                except Exception:
                    pass

    df = pd.DataFrame(rows)
    if df.empty:
        st.info("No se encontraron datos en el rango.")
        st.stop()

    df["Total trabajado"] = df["horas_trabajadas"].apply(horas_a_hhmm)
    df["dia_semana"] = pd.to_datetime(df["Fecha"]).dt.weekday

    df["Motivo"] = df.apply(validar_fila, axis=1)
    out = df[df["Motivo"].notna()].copy()

    if out.empty:
        st.success("🎉 No hay incidencias en el rango seleccionado.")
        st.stop()

    out = out.sort_values(["Fecha", "Nombre Completo"], ascending=[True, True])

    st.subheader("📄 Incidencias (Total trabajado calculado por fichajes)")
    for ds in out["Fecha"].unique():
        st.markdown(f"### 📅 Fecha {ds}")
        st.dataframe(
            out[out["Fecha"] == ds][[
                "Fecha",
                "Nombre Completo",
                "Departamento",
                "Total trabajado",
                "Numero de fichajes",
                "Motivo"
            ]],
            use_container_width=True,
            hide_index=True
        )

    csv_bytes = out[[
        "Fecha",
        "Nombre Completo",
        "Departamento",
        "Total trabajado",
        "Numero de fichajes",
        "Motivo"
    ]].to_csv(index=False).encode("utf-8")

    st.download_button(
        "⬇ Descargar CSV (incidencias)",
        csv_bytes,
        "fichajes_incidencias_total_trabajado_por_fichajes.csv",
        "text/csv"
    )
