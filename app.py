import base64
import json
import requests
import pandas as pd
import streamlit as st
from concurrent.futures import ThreadPoolExecutor, as_completed
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from datetime import datetime, date, timedelta
import multiprocessing
import time
import threading

# ==========================================
# CONFIG: rápido + seguro
# ==========================================
API_URL_BASE = "https://sincronizaciones.crecepersonas.es/api"
API_TOKEN = st.secrets["API_TOKEN"]
APP_KEY_B64 = st.secrets["APP_KEY_B64"]

# IMPORTANTE: endpoint real de permisos (NO vacaciones) -> lo ajustamos cuando me pases el del manual
PERMISOS_PATH = st.secrets.get("PERMISOS_PATH", "/exportacion/permisos")  # <-- AJUSTAR

CPU = multiprocessing.cpu_count()
MAX_WORKERS = min(64, max(8, CPU * 8))  # rápido sin saturar

REQ_TIMEOUT = 20
RETRIES = 2
BACKOFF = 0.6  # segundos

# Nunca enseñamos errores con datos personales
GENERIC_ERR = "⚠️ Se produjo un error consultando datos. La app continuará con el resto."

st.set_page_config(page_title="Fichajes CRECE Personas", layout="wide")
st.title("📊 Fichajes CRECE Personas")

# ==========================================
# HTTP: sesión por hilo (thread-local) para rendimiento
# ==========================================
_thread_local = threading.local()

def get_session() -> requests.Session:
    s = getattr(_thread_local, "session", None)
    if s is None:
        s = requests.Session()
        _thread_local.session = s
    return s

def request_with_retries(method, url, headers=None, data=None, timeout=REQ_TIMEOUT):
    last_exc = None
    for attempt in range(RETRIES + 1):
        try:
            s = get_session()
            resp = s.request(method, url, headers=headers, data=data, timeout=timeout)
            resp.raise_for_status()
            return resp
        except Exception as e:
            last_exc = e
            if attempt < RETRIES:
                time.sleep(BACKOFF * (attempt + 1))
            else:
                raise last_exc

# ==========================================
# DESCIFRADO CRECE
# ==========================================
def decrypt_crece_payload(payload_b64: str, app_key_b64: str) -> str:
    json_raw = base64.b64decode(payload_b64).decode("utf-8")
    payload = json.loads(json_raw)

    iv = base64.b64decode(payload["iv"])
    ct = base64.b64decode(payload["value"])
    key = base64.b64decode(app_key_b64)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ct), AES.block_size)
    return decrypted.decode("utf-8")

def decrypt_response_text(resp_text: str) -> list | dict:
    payload_b64 = (resp_text or "").strip().strip('"')
    if not payload_b64:
        return []
    decrypted = decrypt_crece_payload(payload_b64, APP_KEY_B64)
    return json.loads(decrypted)

# ==========================================
# HORAS
# ==========================================
def horas_a_hhmm(horas):
    if horas is None or pd.isna(horas):
        return "00:00"
    total_min = round(float(horas) * 60)
    h = total_min // 60
    m = total_min % 60
    return f"{h:02d}:{m:02d}"

def hhmm_to_dec(hhmm):
    if not isinstance(hhmm, str) or ":" not in hhmm:
        return 0.0
    h, m = map(int, hhmm.split(":"))
    return h + m / 60.0

# ==========================================
# EXPORTACIÓN BASE
# ==========================================
def api_exportar_departamentos():
    url = f"{API_URL_BASE}/exportacion/departamentos"
    headers = {"Accept": "application/json", "Authorization": f"Bearer {API_TOKEN}"}
    resp = request_with_retries("GET", url, headers=headers)
    data = decrypt_response_text(resp.text)
    return pd.DataFrame([{"departamento_id": d.get("id"), "departamento_nombre": d.get("nombre")} for d in data])

def api_exportar_empleados_completos():
    url = f"{API_URL_BASE}/exportacion/empleados"
    headers = {"Accept": "application/json", "Authorization": f"Bearer {API_TOKEN}"}
    data = {"solo_nif": 0}
    resp = request_with_retries("POST", url, headers=headers, data=data)
    empleados = decrypt_response_text(resp.text)

    rows = []
    for e in empleados:
        nombre = e.get("name") or e.get("nombre") or ""
        pa = e.get("primer_apellido") or ""
        sa = e.get("segundo_apellido") or ""
        if not (pa or sa) and e.get("apellidos"):
            partes = str(e["apellidos"]).split()
            pa = partes[0] if len(partes) > 0 else ""
            sa = " ".join(partes[1:]) if len(partes) > 1 else ""
        rows.append({
            "nif": (e.get("nif") or ""),
            "nombre_completo": f"{nombre} {pa} {sa}".strip(),
            "departamento_id": e.get("departamento"),
        })
    df = pd.DataFrame(rows)
    if not df.empty:
        df["nif"] = df["nif"].astype(str).str.upper().str.strip()
    return df

def api_exportar_fichajes(nif, fi, ff):
    url = f"{API_URL_BASE}/exportacion/fichajes"
    headers = {"Accept": "application/json", "Authorization": f"Bearer {API_TOKEN}"}
    data = {"fecha_inicio": fi, "fecha_fin": ff, "nif": nif, "order": "desc"}
    try:
        resp = request_with_retries("POST", url, headers=headers, data=data, timeout=REQ_TIMEOUT)
        return decrypt_response_text(resp.text) or []
    except Exception:
        return []

# ==========================================
# PERMISOS (DETALLE REAL POR DÍA) - ADAPTADOR
# ==========================================
def api_exportar_permisos_detalle(fi: str, ff: str):
    """
    IMPORTANTE:
    - Este debe ser el endpoint REAL de permisos (ej. hospitalización familiar, médico, etc.)
    - Debe devolver NIF + fecha + duración (horas o hora_inicio/hora_fin)
    Ajustaremos el mapeo cuando me pegues el apartado exacto del manual.
    """
    url = f"{API_URL_BASE}{PERMISOS_PATH}"
    headers = {"Accept": "application/json", "Authorization": f"Bearer {API_TOKEN}"}
    data = {"fecha_inicio": fi, "fecha_fin": ff}
    try:
        resp = request_with_retries("POST", url, headers=headers, data=data, timeout=REQ_TIMEOUT)
        return decrypt_response_text(resp.text) or []
    except Exception:
        return []

def permisos_detalle_por_dia(fi: str, ff: str) -> pd.DataFrame:
    """
    Devuelve DF: Fecha, nif, permiso_tipo, permiso_horas
    Reglas:
    - permiso_horas = horas solicitadas reales (no min_horas)
    """
    raw = api_exportar_permisos_detalle(fi, ff)
    if not raw:
        return pd.DataFrame(columns=["Fecha", "nif", "permiso_tipo", "permiso_horas"])

    rows = []
    for p in raw:
        # ==== TODO: Ajustar nombres de campos exactos cuando me pases el endpoint del manual ====
        nif = (p.get("nif") or p.get("Nif") or p.get("usuario", {}).get("nif") or p.get("usuario", {}).get("Nif") or "")
        nif = str(nif).upper().strip()
        if not nif:
            continue

        # fecha: puede venir como fecha, fecha_inicio, etc.
        f = p.get("fecha") or p.get("Fecha") or p.get("fecha_dia")
        f_ini = p.get("fecha_inicio") or p.get("desde") or p.get("fecha_desde")
        f_fin = p.get("fecha_fin") or p.get("hasta") or p.get("fecha_hasta")

        # tipo/nombre permiso
        tipo = p.get("tipo_nombre") or p.get("tipo") or p.get("nombre") or p.get("motivo") or "Permiso"

        # horas solicitadas:
        # - si viene "horas" o "duracion_horas" -> perfecto
        # - si viene hora_inicio/hora_fin -> calculamos
        horas = None
        for k in ["horas", "duracion_horas", "horas_solicitadas", "duracion"]:
            if k in p and p[k] is not None:
                try:
                    horas = float(p[k])
                    break
                except Exception:
                    pass

        if horas is None:
            hi = p.get("hora_inicio") or p.get("desde_hora")
            hf = p.get("hora_fin") or p.get("hasta_hora")
            if hi and hf and f_ini:
                try:
                    t1 = datetime.strptime(f"{f_ini} {hi}", "%Y-%m-%d %H:%M:%S")
                    t2 = datetime.strptime(f"{f_ini} {hf}", "%Y-%m-%d %H:%M:%S")
                    horas = max(0.0, (t2 - t1).total_seconds() / 3600.0)
                except Exception:
                    horas = 0.0
            else:
                horas = 0.0

        # permisos multi-día
        def _to_date(x):
            try:
                return datetime.strptime(x, "%Y-%m-%d").date()
            except Exception:
                return None

        if f:
            rows.append({"Fecha": str(f)[:10], "nif": nif, "permiso_tipo": str(tipo), "permiso_horas": float(horas)})
        else:
            d1 = _to_date(f_ini)
            d2 = _to_date(f_fin)
            if d1 and d2:
                cur = d1
                while cur <= d2:
                    # Si el permiso es multi-día y no tenemos reparto diario, asignamos 0 salvo que API lo permita.
                    # AJUSTAREMOS cuando sepamos los campos exactos del endpoint.
                    rows.append({"Fecha": cur.strftime("%Y-%m-%d"), "nif": nif, "permiso_tipo": str(tipo), "permiso_horas": float(horas) if d1 == d2 else 0.0})
                    cur += timedelta(days=1)

    dfp = pd.DataFrame(rows)
    if dfp.empty:
        return pd.DataFrame(columns=["Fecha", "nif", "permiso_tipo", "permiso_horas"])

    dfp["nif"] = dfp["nif"].astype(str).str.upper().str.strip()
    dfp["Fecha"] = dfp["Fecha"].astype(str).str.slice(0, 10)

    # sumar si hay más de un permiso el mismo día
    out = dfp.groupby(["Fecha", "nif"], as_index=False).agg(
        permiso_horas=("permiso_horas", "sum"),
        permiso_tipo=("permiso_tipo", lambda s: " + ".join(sorted(set(map(str, s)))))
    )
    return out

# ==========================================
# CÁLCULO HORAS TRABAJADAS (solo fichajes)
# ==========================================
def calcular_horas_trabajadas_por_dia(df_fichajes: pd.DataFrame) -> pd.DataFrame:
    """
    Entrada/salida por pares, por NIF y día.
    Retorna DF por evento con horas_acumuladas.
    """
    if df_fichajes.empty:
        return df_fichajes

    df_fichajes = df_fichajes.sort_values(["nif", "fecha_dt"])
    result = []

    for nif in df_fichajes["nif"].unique():
        sub_emp = df_fichajes[df_fichajes["nif"] == nif].copy()
        for fecha_dia in sub_emp["fecha_dia"].unique():
            sub = sub_emp[sub_emp["fecha_dia"] == fecha_dia].copy().sort_values("fecha_dt")
            horas_acum = 0.0
            i = 0
            while i < len(sub) - 1:
                e1 = sub.iloc[i]
                e2 = sub.iloc[i + 1]
                if e1["direccion"] == "entrada" and e2["direccion"] == "salida":
                    horas = max(0.0, (e2["fecha_dt"] - e1["fecha_dt"]).total_seconds() / 3600.0)
                    horas_acum += horas
                    e1["horas_acumuladas"] = horas_acum
                    result.append(e1)
                    e2["horas_acumuladas"] = horas_acum
                    result.append(e2)
                    i += 2
                else:
                    e1["horas_acumuladas"] = horas_acum
                    result.append(e1)
                    i += 1
            if i == len(sub) - 1:
                last = sub.iloc[i]
                last["horas_acumuladas"] = horas_acum
                result.append(last)

    out = pd.DataFrame(result)
    return out.sort_values(["fecha_dt", "nif"])

# ==========================================
# REGLAS (las que ya tenías)
# ==========================================
def calcular_minimos(depto: str, dia_semana: int):
    depto = (depto or "").strip().upper()
    if depto in ["ESTRUCTURA", "MOI"]:
        if dia_semana in [0, 1, 2, 3]:
            return 8.5, 4
        elif dia_semana == 4:
            return 6.5, 2
        else:
            return None, None
    elif depto == "MOD":
        if dia_semana in [0, 1, 2, 3, 4]:
            return 8.0, 2
        else:
            return None, None
    return None, None

# ==========================================
# UI
# ==========================================
hoy = date.today()
c1, c2 = st.columns(2)
with c1:
    fecha_inicio = st.date_input("Fecha inicio", value=hoy, max_value=hoy)
with c2:
    fecha_fin = st.date_input("Fecha fin", value=hoy, max_value=hoy)

st.write("---")

if st.button("▶ Obtener resumen"):
    if fecha_inicio > fecha_fin:
        st.error("❌ La fecha inicio no puede ser posterior a la fecha fin.")
        st.stop()

    if fecha_fin > hoy:
        st.error("❌ La fecha fin no puede ser mayor que hoy.")
        st.stop()

    fi = fecha_inicio.strftime("%Y-%m-%d")
    ff = fecha_fin.strftime("%Y-%m-%d")

    with st.spinner("Cargando datos…"):
        try:
            departamentos_df = api_exportar_departamentos()
            empleados_df = api_exportar_empleados_completos()
            empleados_df = empleados_df.merge(departamentos_df, on="departamento_id", how="left")
            empleados_df["nif"] = empleados_df["nif"].astype(str).str.upper().str.strip()
        except Exception:
            st.error(GENERIC_ERR)
            st.stop()

        # --- Fichajes (paralelo) ---
        fichajes_totales = []
        with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, max(1, len(empleados_df)))) as executor:
            futures = {executor.submit(api_exportar_fichajes, r["nif"], fi, ff): r for _, r in empleados_df.iterrows()}
            for fut in as_completed(futures):
                emp = futures[fut]
                try:
                    fichajes = fut.result() or []
                    for f in fichajes:
                        fichajes_totales.append({
                            "nif": emp["nif"],
                            "nombre_completo": emp["nombre_completo"],
                            "departamento_nombre": emp["departamento_nombre"],
                            "id": f.get("id"),
                            "fecha": f.get("fecha"),
                            "direccion": f.get("direccion"),
                        })
                except Exception:
                    # silencioso por privacidad
                    continue

        # --- Permisos (detalle real por día) ---
        permisos_df = permisos_detalle_por_dia(fi, ff)

        # --- Construir resumen trabajado ---
        if fichajes_totales:
            df = pd.DataFrame(fichajes_totales)
            df["nif"] = df["nif"].astype(str).str.upper().str.strip()
            df["fecha_dt"] = pd.to_datetime(df["fecha"], errors="coerce")
            df = df[df["fecha_dt"].notna()].copy()
            df["fecha_dia"] = df["fecha_dt"].dt.strftime("%Y-%m-%d")

            df = calcular_horas_trabajadas_por_dia(df)

            df["Numero de fichajes"] = df.groupby(["nif", "fecha_dia"])["id"].transform("count")

            resumen = df.groupby(["nif", "nombre_completo", "departamento_nombre", "fecha_dia"], as_index=False).agg(
                horas_trabajadas=("horas_acumuladas", "max"),
                **{"Numero de fichajes": ("Numero de fichajes", "max")}
            )
            resumen["Total trabajado"] = resumen["horas_trabajadas"].apply(horas_a_hhmm)
            resumen = resumen.rename(columns={
                "fecha_dia": "Fecha",
                "nombre_completo": "Nombre Completo",
                "departamento_nombre": "Departamento"
            })
        else:
            resumen = pd.DataFrame(columns=["nif", "Fecha", "Nombre Completo", "Departamento", "Total trabajado", "Numero de fichajes", "horas_trabajadas"])
            resumen["Total trabajado"] = "00:00"
            resumen["Numero de fichajes"] = 0
            resumen["horas_trabajadas"] = 0.0

        # --- Añadir filas para gente con permiso sin fichajes ---
        if not permisos_df.empty:
            base_perm = permisos_df.merge(
                empleados_df[["nif", "nombre_completo", "departamento_nombre"]],
                on="nif",
                how="left"
            ).rename(columns={"nombre_completo": "Nombre Completo", "departamento_nombre": "Departamento"})

            if resumen.empty:
                resumen = base_perm.copy()
                resumen["Total trabajado"] = "00:00"
                resumen["Numero de fichajes"] = 0
                resumen["horas_trabajadas"] = 0.0
            else:
                key_res = resumen[["nif", "Fecha"]].drop_duplicates()
                key_perm = base_perm[["nif", "Fecha"]].drop_duplicates()
                faltan = key_perm.merge(key_res, on=["nif", "Fecha"], how="left", indicator=True)
                faltan = faltan[faltan["_merge"] == "left_only"][["nif", "Fecha"]]
                if not faltan.empty:
                    faltan = faltan.merge(
                        empleados_df[["nif", "nombre_completo", "departamento_nombre"]],
                        on="nif",
                        how="left"
                    ).rename(columns={"nombre_completo": "Nombre Completo", "departamento_nombre": "Departamento"})
                    faltan["Total trabajado"] = "00:00"
                    faltan["Numero de fichajes"] = 0
                    faltan["horas_trabajadas"] = 0.0
                    resumen = pd.concat([resumen, faltan], ignore_index=True)

        # --- Merge permisos (horas reales) ---
        if permisos_df.empty:
            resumen["Horas permiso"] = "00:00"
            resumen["permiso_horas"] = 0.0
            resumen["permiso_tipo"] = None
        else:
            resumen = resumen.merge(permisos_df, on=["Fecha", "nif"], how="left")
            resumen["permiso_horas"] = resumen["permiso_horas"].fillna(0.0)
            resumen["permiso_tipo"] = resumen["permiso_tipo"].fillna("")
            resumen["Horas permiso"] = resumen["permiso_horas"].apply(horas_a_hhmm)

        # --- Totales (trabajo + permiso real) ---
        resumen["horas_totales"] = resumen["horas_trabajadas"].fillna(0.0) + resumen["permiso_horas"].fillna(0.0)
        resumen["Horas totales"] = resumen["horas_totales"].apply(horas_a_hhmm)

        # --- Validación ---
        resumen["dia_semana"] = pd.to_datetime(resumen["Fecha"]).dt.weekday

        def aplicar_min(row):
            mh, mf = calcular_minimos(row.get("Departamento"), int(row["dia_semana"]))
            return pd.Series({"min_horas": mh, "min_fichajes": mf})

        mins = resumen.apply(aplicar_min, axis=1)
        resumen["min_horas"] = mins["min_horas"]
        resumen["min_fichajes"] = mins["min_fichajes"]

        def validar(row):
            mh = row["min_horas"]
            mf = row["min_fichajes"]
            if pd.isna(mh) or pd.isna(mf):
                return None
            motivo = []
            if float(row["horas_totales"]) < float(mh):
                motivo.append(f"Horas insuficientes (mín {mh}h)")
            if int(row["Numero de fichajes"]) < int(mf):
                motivo.append(f"Fichajes insuficientes (mín {mf})")
            if float(row["horas_totales"]) >= float(mh) and int(row["Numero de fichajes"]) > int(mf):
                motivo.append(f"Fichajes excesivos (mín {mf})")
            return "; ".join(motivo) if motivo else None

        resumen["Motivo_incidencia"] = resumen.apply(validar, axis=1)

        # Motivo: mostrar permiso si existe + incidencia si existe
        def motivo_final(row):
            parts = []
            if row.get("permiso_tipo") and str(row.get("permiso_tipo")).strip():
                parts.append(f"Permiso: {row.get('permiso_tipo')} ({horas_a_hhmm(row.get('permiso_horas', 0))})")
            if row.get("Motivo_incidencia"):
                parts.append(row["Motivo_incidencia"])
            return " | ".join(parts) if parts else None

        resumen["Motivo"] = resumen.apply(motivo_final, axis=1)

        resumen_out = resumen[resumen["Motivo"].notna()].copy()
        resumen_out = resumen_out.sort_values(["Fecha", "Nombre Completo"], ascending=[True, True])

        cols = ["Fecha", "Nombre Completo", "Departamento", "Total trabajado", "Horas permiso", "Horas totales", "Numero de fichajes", "Motivo"]
        resumen_out = resumen_out[cols]

        # Mostrar por fecha
        st.subheader("📄 Incidencias y/o permisos")
        for f_dia in resumen_out["Fecha"].unique():
            st.markdown(f"### 📅 {f_dia}")
            sub = resumen_out[resumen_out["Fecha"] == f_dia]
            st.data_editor(sub, use_container_width=True, hide_index=True, disabled=True, num_rows="fixed")

        st.download_button(
            "⬇ Descargar CSV",
            resumen_out.to_csv(index=False).encode("utf-8"),
            "fichajes_resumen.csv",
            "text/csv"
        )
