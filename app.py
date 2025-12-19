import base64
import json
import multiprocessing
from datetime import date, datetime
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

# Concurrencia segura (evita saturar API/Cloud)
CPU = multiprocessing.cpu_count()
MAX_WORKERS = max(8, min(24, CPU * 3))  # equilibrado: rápido sin “apisonadora”

# Timeouts robustos (conexión, lectura)
HTTP_TIMEOUT = (5, 25)

# Session global (reutiliza conexiones, más rápido)
_SESSION = requests.Session()
_SESSION.headers.update(
    {
        "Accept": "application/json",
        "Authorization": f"Bearer {API_TOKEN}",
    }
)

# ============================================================
# SEGURIDAD: utilidades internas (NO mostrar PII/secretos)
# ============================================================

def _safe_fail(_exc: Exception) -> None:
    """
    No mostrar detalles (evita filtrar respuestas, tokens, payloads).
    Aquí deliberadamente no se hace nada.
    """
    return None


# ============================================================
# DESCIFRADO CRECE (AES-CBC)
# ============================================================

def decrypt_crece_payload(payload_b64: str, app_key_b64: str) -> str:
    """
    Descifra payloads cifrados por CRECE.

    Seguridad:
    - No loguea nada.
    - Lanza excepción si el formato es inválido para que el caller gestione silenciosamente.
    """
    json_raw = base64.b64decode(payload_b64).decode("utf-8")
    payload = json.loads(json_raw)

    iv = base64.b64decode(payload["iv"])
    ct = base64.b64decode(payload["value"])
    key = base64.b64decode(app_key_b64)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ct), AES.block_size)
    return decrypted.decode("utf-8")


def _extract_payload_b64(resp: requests.Response) -> str:
    """
    Algunas APIs devuelven el string base64 entrecomillado.
    """
    return (resp.text or "").strip().strip('"').strip()


# ============================================================
# FORMATEOS HORAS
# ============================================================

def horas_a_hhmm(horas: float) -> str:
    if horas is None or pd.isna(horas):
        return "00:00"
    total_min = int(round(float(horas) * 60))
    h = total_min // 60
    m = total_min % 60
    return f"{h:02d}:{m:02d}"


def hhmm_to_dec(hhmm: str) -> float:
    if not isinstance(hhmm, str) or ":" not in hhmm:
        return 0.0
    try:
        h, m = map(int, hhmm.split(":"))
        return float(h) + float(m) / 60.0
    except Exception:
        return 0.0


# ============================================================
# API EXPORTACIÓN
# ============================================================

@st.cache_data(show_spinner=False, ttl=3600)
def api_exportar_departamentos() -> pd.DataFrame:
    """
    Departamentos (normalmente no PII) -> cache seguro con TTL.
    """
    url = f"{API_URL_BASE}/exportacion/departamentos"

    resp = _SESSION.get(url, timeout=HTTP_TIMEOUT)
    resp.raise_for_status()

    payload_b64 = _extract_payload_b64(resp)
    decrypted = decrypt_crece_payload(payload_b64, APP_KEY_B64)
    departamentos = json.loads(decrypted)

    lista = []
    for d in departamentos:
        lista.append(
            {
                "departamento_id": d.get("id"),
                "departamento_nombre": d.get("nombre"),
            }
        )
    return pd.DataFrame(lista)


def api_exportar_empleados_completos() -> pd.DataFrame:
    """
    Empleados: contiene PII -> NO cache por defecto.
    """
    url = f"{API_URL_BASE}/exportacion/empleados"
    data = {"solo_nif": 0}

    resp = _SESSION.post(url, data=data, timeout=HTTP_TIMEOUT)
    resp.raise_for_status()

    payload_b64 = _extract_payload_b64(resp)
    decrypted = decrypt_crece_payload(payload_b64, APP_KEY_B64)
    empleados = json.loads(decrypted)

    lista = []
    for e in empleados:
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

    df_emp = pd.DataFrame(lista)

    if not df_emp.empty:
        df_emp["nif"] = df_emp["nif"].astype(str).str.upper().str.strip()

    return df_emp


def api_exportar_fichajes(nif: str, fi: str, ff: str) -> list:
    """
    Fichajes por empleado y rango.
    Seguridad:
    - Ante error, devuelve [] sin exponer detalles.
    """
    url = f"{API_URL_BASE}/exportacion/fichajes"
    data = {
        "fecha_inicio": fi,
        "fecha_fin": ff,
        "nif": nif,
        "order": "desc",
    }

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


# ============================================================
# CÁLCULO DE HORAS (sin SettingWithCopy)
# ============================================================

def calcular_horas(df: pd.DataFrame) -> pd.DataFrame:
    """
    Calcula horas trabajadas por pares entrada->salida y acumulado diario.
    - Robusto: no usa asignaciones ambiguas en sub.iloc[i]["..."].
    - No inventa pares si el orden es raro: deja horas_trabajadas=0 y solo acumula cuando hay par válido.
    """
    if df.empty:
        return df

    df = df.copy()
    df["horas_trabajadas"] = 0.0
    df["horas_acumuladas"] = 0.0

    rows_out = []

    # Procesar por empleado y día
    for nif in df["nif"].unique():
        sub_emp = df[df["nif"] == nif].copy()

        for fecha_dia in sub_emp["fecha_dia"].unique():
            sub = sub_emp[sub_emp["fecha_dia"] == fecha_dia].copy()
            sub = sub.sort_values("fecha_dt")

            horas_acum = 0.0
            i = 0
            n = len(sub)

            while i < n:
                row_i = sub.iloc[i].copy()
                row_i["horas_trabajadas"] = 0.0
                row_i["horas_acumuladas"] = horas_acum

                if i < n - 1:
                    row_next = sub.iloc[i + 1].copy()

                    if row_i.get("direccion") == "entrada" and row_next.get("direccion") == "salida":
                        # Par válido
                        total_seconds = (row_next["fecha_dt"] - row_i["fecha_dt"]).total_seconds()
                        if total_seconds < 0:
                            # Datos corruptos / desorden: no acumular
                            rows_out.append(row_i)
                            i += 1
                            continue

                        horas = total_seconds / 3600.0
                        horas_acum += horas

                        row_i["horas_trabajadas"] = horas
                        row_i["horas_acumuladas"] = horas_acum
                        rows_out.append(row_i)

                        row_next = row_next.copy()
                        row_next["horas_trabajadas"] = 0.0
                        row_next["horas_acumuladas"] = horas_acum
                        rows_out.append(row_next)

                        i += 2
                        continue

                # No hay par válido -> solo volcamos la fila con acumulado actual
                rows_out.append(row_i)
                i += 1

    out = pd.DataFrame(rows_out)
    out = out.sort_values(["fecha_dt", "nif"], kind="mergesort")
    return out


# ============================================================
# REGLAS DE JORNADA (validación base, sin permisos)
# ============================================================

def calcular_minimos(depto: str, dia: int):
    depto = (depto or "").upper().strip()

    if depto in ["ESTRUCTURA", "MOI"]:
        if dia in [0, 1, 2, 3]:  # L-J
            return 8.5, 4
        if dia == 4:  # V
            return 6.5, 2
        return None, None  # fin de semana u otros

    if depto == "MOD":
        if dia in [0, 1, 2, 3, 4]:  # L-V
            return 8.0, 2
        return None, None

    return None, None


def validar_incidencia(r):
    """
    Validación SIN permisos:
    - Horas insuficientes
    - Fichajes insuficientes
    - Fichajes excesivos (cuando supera el mínimo; mantiene tu regla original)
    """
    min_h, min_f = r["min_horas"], r["min_fichajes"]
    if pd.isna(min_h) or pd.isna(min_f):
        return None

    motivo = []

    if r["horas_dec"] < float(min_h):
        motivo.append(f"Horas insuficientes (mín {min_h}h, tiene {r['horas_dec']:.2f}h)")

    if int(r["Numero de fichajes"]) < int(min_f):
        motivo.append(f"Fichajes insuficientes (mín {min_f}, tiene {int(r['Numero de fichajes'])})")

    if r["horas_dec"] >= float(min_h) and int(r["Numero de fichajes"]) > int(min_f):
        motivo.append(f"Fichajes excesivos (mín {min_f}, tiene {int(r['Numero de fichajes'])})")

    return "; ".join(motivo) if motivo else None


# ============================================================
# UI STREAMLIT (mínima, sin “ruido”)
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

if st.button("▶ Obtener incidencias"):
    if fecha_inicio > fecha_fin:
        st.error("❌ La fecha inicio no puede ser posterior a la fecha fin.")
        st.stop()

    if fecha_fin > hoy:
        st.error("❌ La fecha fin no puede ser mayor que hoy.")
        st.stop()

    fi = fecha_inicio.strftime("%Y-%m-%d")
    ff = fecha_fin.strftime("%Y-%m-%d")

    # Mensaje mínimo (sin detalles de proceso)
    with st.spinner("Procesando…"):
        try:
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

        # Fichajes en paralelo (sin bloquear; si falla un empleado, se continúa)
        fichajes_rows = []
        total_empleados = int(len(empleados_df))

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as exe:
            futures = {
                exe.submit(api_exportar_fichajes, row["nif"], fi, ff): row
                for _, row in empleados_df.iterrows()
            }

            for fut in as_completed(futures):
                emp = futures[fut]
                resp_list = fut.result() or []
                for x in resp_list:
                    try:
                        fichajes_rows.append(
                            {
                                "nif": emp["nif"],
                                "nombre_completo": emp["nombre_completo"],
                                "departamento_nombre": emp.get("departamento_nombre"),
                                "id": x.get("id"),
                                "direccion": x.get("direccion"),
                                "fecha": x.get("fecha"),
                            }
                        )
                    except Exception:
                        # Si una fila viene rara, la saltamos sin romper el proceso
                        continue

        if not fichajes_rows:
            st.info("No se encontraron fichajes en el rango seleccionado.")
            st.stop()

        # Construcción dataframe fichajes
        df = pd.DataFrame(fichajes_rows)
        df["nif"] = df["nif"].astype(str).str.upper().str.strip()
        df["fecha_dt"] = pd.to_datetime(df["fecha"], errors="coerce")
        df = df.dropna(subset=["fecha_dt"])
        df["fecha_dia"] = df["fecha_dt"].dt.strftime("%Y-%m-%d")

        # Cálculo horas por día
        df = calcular_horas(df)

        # Nº fichajes por día
        df["Numero"] = df.groupby(["nif", "fecha_dia"])["id"].transform("count")

        # Resumen diario
        resumen = (
            df.groupby(["nif", "nombre_completo", "departamento_nombre", "fecha_dia"], as_index=False)
            .agg(horas=("horas_acumuladas", "max"), fichajes=("Numero", "max"))
        )

        resumen["Total trabajado"] = resumen["horas"].apply(horas_a_hhmm)

        resumen = resumen.rename(
            columns={
                "nombre_completo": "Nombre",
                "departamento_nombre": "Departamento",
                "fecha_dia": "Fecha",
                "fichajes": "Numero de fichajes",
            }
        )

        # Validaciones
        resumen["horas_dec"] = resumen["Total trabajado"].apply(hhmm_to_dec)
        resumen["dia"] = pd.to_datetime(resumen["Fecha"]).dt.weekday

        resumen[["min_horas", "min_fichajes"]] = resumen.apply(
            lambda r: pd.Series(calcular_minimos(r.get("Departamento"), int(r["dia"]))),
            axis=1,
        )

        resumen["Incidencia"] = resumen.apply(validar_incidencia, axis=1)

        resumen_final = resumen[resumen["Incidencia"].notna()].copy()

        if resumen_final.empty:
            st.success("🎉 No hay incidencias en el rango seleccionado.")
            st.stop()

        # Salida mínima (lo necesario)
        resumen_final = resumen_final[
            ["Fecha", "Nombre", "Departamento", "Total trabajado", "Numero de fichajes", "Incidencia"]
        ].sort_values(["Fecha", "Nombre"], kind="mergesort")

    st.subheader("📄 Incidencias")

    # Mostrar por fecha (sin detalles internos)
    for f_dia in resumen_final["Fecha"].unique():
        st.markdown(f"### 📅 {f_dia}")
        sub = resumen_final[resumen_final["Fecha"] == f_dia]

        st.data_editor(
            sub,
            use_container_width=True,
            hide_index=True,
            disabled=True,
            num_rows="fixed",
        )

    csv = resumen_final.to_csv(index=False).encode("utf-8")
    st.download_button(
        "⬇ Descargar CSV",
        csv,
        "fichajes_incidencias.csv",
        "text/csv",
    )
