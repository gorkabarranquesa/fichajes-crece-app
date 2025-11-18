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

MAX_WORKERS = 60  # número de peticiones simultáneas


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
# EMPLEADOS (NOMBRE + APELLIDOS)
# ==========================================

def api_exportar_empleados_completos():
    url = f"{API_URL_BASE}/exportacion/empleados"

    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {API_TOKEN}",
    }

    data = {"solo_nif": 0}

    resp = requests.post(url, headers=headers, data=data)
    resp.raise_for_status()

    payload_b64 = resp.text.strip().strip('"')
    decrypted = decrypt_crece_payload(payload_b64, APP_KEY_B64)
    empleados = json.loads(decrypted)

    lista = []

    for e in empleados:
        # CRECE usa estos nombres
        nombre = (
            e.get("name")
            or e.get("nombre")
            or ""
        )

        primer_apellido = e.get("primer_apellido") or ""
        segundo_apellido = e.get("segundo_apellido") or ""

        # fallback si devuelve un único campo "apellidos"
        if not (primer_apellido or segundo_apellido) and e.get("apellidos"):
            partes = e["apellidos"].split(" ")
            primer_apellido = partes[0] if len(partes) > 0 else ""
            segundo_apellido = " ".join(partes[1:]) if len(partes) > 1 else ""

        nombre_completo = f"{nombre} {primer_apellido} {segundo_apellido}".strip()

        lista.append({
            "nif": e.get("nif"),
            "nombre": nombre,
            "primer_apellido": primer_apellido,
            "segundo_apellido": segundo_apellido,
            "nombre_completo": nombre_completo,
        })

    return lista


# ==========================================
# FICHAJES
# ==========================================

def api_exportar_fichajes(nif, fi, ff):
    url = f"{API_URL_BASE}/exportacion/fichajes"

    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {API_TOKEN}",
    }

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
        return []  # IGNORAR LOS ERRORES


# ==========================================
# CÁLCULO DE HORAS TRABAJADAS
# ==========================================

def calcular_horas(df):
    """Devuelve el mismo DataFrame con columnas de horas trabajadas por fila."""

    df["horas_trabajadas"] = 0.0
    df["horas_acumuladas"] = 0.0

    if df.empty:
        return df

    result = []

    for nif in df["nif"].unique():
        sub = df[df["nif"] == nif].copy()
        sub = sub.sort_values("fecha")

        horas_acum = 0.0
        i = 0

        while i < len(sub) - 1:
            entrada = sub.iloc[i]
            salida = sub.iloc[i + 1]

            if entrada["direccion"] == "entrada" and salida["direccion"] == "salida":
                t1 = datetime.strptime(entrada["fecha"], "%Y-%m-%d %H:%M:%S")
                t2 = datetime.strptime(salida["fecha"], "%Y-%m-%d %H:%M:%S")
                horas = (t2 - t1).total_seconds() / 3600

                # asignamos
                entrada["horas_trabajadas"] = horas
                horas_acum += horas
                entrada["horas_acumuladas"] = horas_acum

                result.append(entrada)

                # añadimos salida también
                salida["horas_trabajadas"] = 0
                salida["horas_acumuladas"] = horas_acum
                result.append(salida)

                i += 2
            else:
                # si no cuadra entrada/salida → solo añadir sin horas
                sub.iloc[i]["horas_acumuladas"] = horas_acum
                result.append(sub.iloc[i])
                i += 1

        # añadir último si quedó suelto
        if i == len(sub) - 1:
            sub.iloc[i]["horas_acumuladas"] = horas_acum
            result.append(sub.iloc[i])

    df_final = pd.DataFrame(result)
    return df_final.sort_values("fecha", ascending=False)


# ==========================================
# INTERFAZ STREAMLIT
# ==========================================

st.set_page_config(page_title="Fichajes CRECE", layout="wide")
st.title("📊 Fichajes CRECE Personas – Horas trabajadas")

col1, col2 = st.columns(2)
with col1:
    fecha_inicio = st.date_input("Fecha inicio")
with col2:
    fecha_fin = st.date_input("Fecha fin")

st.write("---")

if st.button("▶ Obtener fichajes de todos los empleados"):
    if fecha_inicio > fecha_fin:
        st.error("❌ La fecha inicio no puede ser posterior a la fecha fin.")
    else:
        with st.spinner("Cargando empleados y fichajes…"):

            fi = fecha_inicio.strftime("%Y-%m-%d")
            ff = fecha_fin.strftime("%Y-%m-%d")

            empleados = api_exportar_empleados_completos()

            fichajes_totales = []
            tareas = []

            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = {
                    executor.submit(api_exportar_fichajes, e["nif"], fi, ff): e
                    for e in empleados
                }

                for future in as_completed(futures):
                    emp = futures[future]
                    fichajes = future.result()

                    for f in fichajes:
                        fichajes_totales.append({
                            "nif": emp["nif"],
                            "nombre": emp["nombre"],
                            "primer_apellido": emp["primer_apellido"],
                            "segundo_apellido": emp["segundo_apellido"],
                            "nombre_completo": emp["nombre_completo"],
                            "id": f.get("id"),
                            "tipo": f.get("tipo"),
                            "fecha": f.get("fecha"),
                            "direccion": f.get("direccion"),
                            "terminal": f.get("terminal"),
                            "latitud": f.get("latitud"),
                            "longitud": f.get("longitud"),
                            "tipo_nombre": f.get("tipo_obj", {}).get("nombre") if f.get("tipo_obj") else None,
                            "tipo_descripcion": f.get("tipo_obj", {}).get("descripcion") if f.get("tipo_obj") else None,
                        })

            if fichajes_totales:
                df = pd.DataFrame(fichajes_totales)

                # 1) Convertir fecha a datetime para ordenar bien
                df["fecha_dt"] = pd.to_datetime(df["fecha"], format="%Y-%m-%d %H:%M:%S")

                # 2) Ordenar por nombre completo y fecha ascendente
                df = df.sort_values(
                    ["nombre_completo", "fecha_dt"],
                    ascending=[True, True]
                )

                # 3) Calcular horas (usa el orden correcto)
                df = calcular_horas(df)

                # 4) Eliminar columna auxiliar
                df = df.sort_values(
                    ["nombre_completo", "fecha_dt"],
                    ascending=[True, True]
                )
                df = df.drop(columns=["fecha_dt"])

                # 5) Mostrar resultado final
                st.subheader("Resultados")
                st.dataframe(df, use_container_width=True)

                csv_bytes = df.to_csv(index=False).encode("utf-8")
                st.download_button(
                    "⬇ Descargar CSV",
                    csv_bytes,
                    "fichajes_crece.csv",
                    "text/csv"
                )
            else:
                st.info("No se encontraron fichajes.")


