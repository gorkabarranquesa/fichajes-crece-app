import base64
import json
import requests
import pandas as pd
import streamlit as st
from concurrent.futures import ThreadPoolExecutor, as_completed
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from datetime import datetime

# ==========================================
# CONFIG
# ==========================================

API_URL_BASE = "https://sincronizaciones.crecepersonas.es/api"
API_TOKEN = st.secrets["API_TOKEN"]
APP_KEY_B64 = st.secrets["APP_KEY_B64"]

MAX_WORKERS = 500  # Peticiones simultáneas


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


# ==========================================
# HORAS → HH:MM
# ==========================================

def horas_a_hhmm(horas):
    if horas is None or pd.isna(horas):
        return "00:00"
    total_min = int(horas * 60)
    h = total_min // 60
    m = total_min % 60
    return f"{h:02d}:{m:02d}"


# ==========================================
# EXPORTACIÓN DE DEPARTAMENTOS
# ==========================================

def api_exportar_departamentos():
    url = f"{API_URL_BASE}/exportacion/departamentos"
    headers = {"Accept": "application/json", "Authorization": f"Bearer {API_TOKEN}"}

    resp = requests.get(url, headers=headers)
    resp.raise_for_status()

    payload_b64 = resp.text.strip().strip('"')
    decrypted = decrypt_crece_payload(payload_b64, APP_KEY_B64)
    departamentos = json.loads(decrypted)

    lista = []
    for d in departamentos:
        lista.append({
            "departamento_id": d.get("id"),
            "departamento_nombre": d.get("nombre")
        })

    return pd.DataFrame(lista)


# ==========================================
# EXPORTACIÓN DE EMPLEADOS
# ==========================================

def api_exportar_empleados_completos():
    url = f"{API_URL_BASE}/exportacion/empleados"
    headers = {"Accept": "application/json", "Authorization": f"Bearer {API_TOKEN}"}
    data = {"solo_nif": 0}

    resp = requests.post(url, headers=headers, data=data)
    resp.raise_for_status()

    payload_b64 = resp.text.strip().strip('"')
    decrypted = decrypt_crece_payload(payload_b64, APP_KEY_B64)
    empleados = json.loads(decrypted)

    lista = []

    for e in empleados:
        nombre = e.get("name") or e.get("nombre") or ""
        primer_apellido = e.get("primer_apellido") or ""
        segundo_apellido = e.get("segundo_apellido") or ""

        if not (primer_apellido or segundo_apellido) and e.get("apellidos"):
            partes = e["apellidos"].split(" ")
            primer_apellido = partes[0] if len(partes) > 0 else ""
            segundo_apellido = " ".join(partes[1:]) if len(partes) > 1 else ""

        nombre_completo = f"{nombre} {primer_apellido} {segundo_apellido}".strip()

        lista.append({
            "nif": e.get("nif"),
            "nombre_completo": nombre_completo,
            "departamento_id": e.get("departamento"),
        })

    return pd.DataFrame(lista)


# ==========================================
# EXPORTACIÓN DE FICHAJES
# ==========================================

def api_exportar_fichajes(nif, fi, ff):
    url = f"{API_URL_BASE}/exportacion/fichajes"
    headers = {"Accept": "application/json", "Authorization": f"Bearer {API_TOKEN}"}

    data = {
        "fecha_inicio": fi,
        "fecha_fin": ff,
        "nif": nif,
        "order": "desc",
    }

    try:
        resp = requests.post(url, headers=headers, data=data, timeout=20)
        resp.raise_for_status()

        payload_b64 = resp.text.strip().strip('"')
        if not payload_b64:
            return []

        decrypted = decrypt_crece_payload(payload_b64, APP_KEY_B64)
        return json.loads(decrypted)

    except Exception:
        return []


# ==========================================
# CÁLCULO DE HORAS TRABAJADAS
# ==========================================

def calcular_horas(df):
    df["horas_trabajadas"] = 0.0
    df["horas_acumuladas"] = 0.0

    if df.empty:
        return df

    result = []

    for nif in df["nif"].unique():
        sub = df[df["nif"] == nif].copy()
        sub = sub.sort_values("fecha_dt")

        horas_acum = 0.0
        i = 0

        while i < len(sub) - 1:
            entrada = sub.iloc[i]
            salida = sub.iloc[i + 1]

            if entrada["direccion"] == "entrada" and salida["direccion"] == "salida":
                t1 = entrada["fecha_dt"]
                t2 = salida["fecha_dt"]
                horas = (t2 - t1).total_seconds() / 3600

                entrada["horas_trabajadas"] = horas
                horas_acum += horas
                entrada["horas_acumuladas"] = horas_acum
                result.append(entrada)

                salida["horas_trabajadas"] = 0
                salida["horas_acumuladas"] = horas_acum
                result.append(salida)

                i += 2
            else:
                sub.iloc[i]["horas_acumuladas"] = horas_acum
                result.append(sub.iloc[i])
                i += 1

        if i == len(sub) - 1:
            sub.iloc[i]["horas_acumuladas"] = horas_acum
            result.append(sub.iloc[i])

    df_final = pd.DataFrame(result)
    return df_final.sort_values(["nif", "fecha_dt"])


# ==========================================
# UI STREAMLIT
# ==========================================

st.set_page_config(page_title="Fichajes CRECE", layout="wide")
st.title("📊 Fichajes CRECE Personas")

col1, col2 = st.columns(2)
with col1:
    fecha_inicio = st.date_input("Fecha inicio")
with col2:
    fecha_fin = st.date_input("Fecha fin")

st.write("---")

if st.button("▶ Obtener resumen de fichajes"):
    if fecha_inicio > fecha_fin:
        st.error("❌ La fecha inicio no puede ser posterior a la fecha fin.")
    else:
        with st.spinner("Cargando empleados, departamentos y fichajes…"):

            fi = fecha_inicio.strftime("%Y-%m-%d")
            ff = fecha_fin.strftime("%Y-%m-%d")

            departamentos_df = api_exportar_departamentos()
            empleados_df = api_exportar_empleados_completos()

            empleados_df = empleados_df.merge(
                departamentos_df,
                on="departamento_id",
                how="left"
            )

            fichajes_totales = []

            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = {
                    executor.submit(api_exportar_fichajes, e["nif"], fi, ff): e
                    for _, e in empleados_df.iterrows()
                }

                for future in as_completed(futures):
                    emp = futures[future]
                    fichajes = future.result()

                    for f in fichajes:
                        fichajes_totales.append({
                            "nif": emp["nif"],
                            "nombre_completo": emp["nombre_completo"],
                            "departamento_nombre": emp["departamento_nombre"],
                            "id": f.get("id"),
                            "tipo": f.get("tipo"),
                            "fecha": f.get("fecha"),
                            "direccion": f.get("direccion"),
                        })

            # ==========================================
            # CONSTRUCCIÓN DEL RESUMEN FINAL
            # ==========================================

            if fichajes_totales:
                df = pd.DataFrame(fichajes_totales)

                df["fecha_dt"] = pd.to_datetime(df["fecha"], format="%Y-%m-%d %H:%M:%S", errors="coerce")
                df["fecha_dia"] = df["fecha_dt"].dt.strftime("%Y-%m-%d")

                df = df.sort_values(["nombre_completo", "fecha_dt"])

                df = calcular_horas(df)

                if df.empty:
                    st.warning("No se encontraron fichajes válidos en el rango seleccionado.")
                    st.stop()

                df = df.sort_values(["nombre_completo", "fecha_dt"])

                resumen = df.groupby(
                    ["nombre_completo", "departamento_nombre", "fecha_dia"],
                    as_index=False,
                    dropna=False
                ).agg(
                    Total_trabajado_horas=("horas_acumuladas", "max"),
                    Numero_fichajes=("nif", "count")
                )

                if resumen.empty:
                    st.info("No hay datos que resumir para este rango de fechas.")
                    st.stop()

                resumen["Total trabajado"] = resumen["Total_trabajado_horas"].apply(
                    lambda x: horas_a_hhmm(x)
                )

                resumen = resumen.rename(columns={
                    "fecha_dia": "Fecha",
                    "nombre_completo": "Nombre Completo",
                    "departamento_nombre": "Departamento"
                })

                columnas_finales = [
                    "Fecha",
                    "Nombre Completo",
                    "Departamento",
                    "Total trabajado",
                    "Numero de fichajes"
                ]

                for col in columnas_finales:
                    if col not in resumen.columns:
                        resumen[col] = ""

                resumen = resumen[columnas_finales]

                st.subheader("📄 Resumen Diario")
                st.dataframe(resumen, use_container_width=True)

                csv_bytes = resumen.to_csv(index=False).encode("utf-8")
                st.download_button(
                    "⬇ Descargar CSV",
                    csv_bytes,
                    "fichajes_crece_resumen.csv",
                    "text/csv"
                )

            else:
                st.info("No se encontraron fichajes.")
