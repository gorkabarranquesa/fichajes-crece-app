# app.py
import base64
import json
import requests
import pandas as pd
import streamlit as st
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# =========================
# CONFIGURACIÓN BÁSICA
# =========================

# Idealmente, pon estas claves en variables de entorno o en un .env
API_URL_BASE = "https://sincronizaciones.crecepersonas.es/api"
API_TOKEN = "TU_API_TOKEN_AQUI"       # Bearer
APP_KEY_B64 = "75q5Ty5zmRsTK9L3Du0nIp5XbL7owj0NHJeML81Mdfk="  # tu APP_KEY


# =========================
# FUNCIONES DE CIFRADO / API
# =========================

def decrypt_crece_payload(payload_b64: str, app_key_b64: str) -> str:
    """
    Descifra el string devuelto por Crece:
    1) Base64 externo -> JSON con {iv, value, mac}
    2) iv y value -> AES-256-CBC
    3) Devuelve el texto plano (JSON interno)
    """
    # 1) Base64 externo -> JSON
    json_raw = base64.b64decode(payload_b64).decode("utf-8")
    payload = json.loads(json_raw)

    iv = base64.b64decode(payload["iv"])
    ct = base64.b64decode(payload["value"])
    key = base64.b64decode(app_key_b64)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ct), AES.block_size)

    return decrypted.decode("utf-8")


def call_crece_exportacion_empleados_solo_nif():
    """
    Llama a /api/exportacion/empleados con solo_nif=1
    y devuelve una lista de NIFs.
    """
    url = f"{API_URL_BASE}/exportacion/empleados"
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {API_TOKEN}",
    }
    data = {
        "solo_nif": 1
        # podrías añadir fecha_modificado_desde / hasta si quieres filtrar
    }

    resp = requests.post(url, headers=headers, json=data)
    resp.raise_for_status()

    # el body es un string base64 (entrecomillado)
    payload_b64 = resp.text.strip().strip('"')
    decrypted_text = decrypt_crece_payload(payload_b64, APP_KEY_B64)

    empleados = json.loads(decrypted_text)
    # según el manual, si solo_nif=1, devolverá un listado de NIFs
    # si en tu entorno vuelve como lista de objetos con campo "nif", ajusta esto:
    nifs = []
    for e in empleados:
        if isinstance(e, dict) and "nif" in e:
            nifs.append(e["nif"])
        else:
            # si viene como string directamente
            nifs.append(e)

    return sorted(set(nifs))


def call_crece_exportacion_fichajes(nif: str, fecha_inicio: str, fecha_fin: str, order: str = "desc"):
    """
    Llama a /api/exportacion/fichajes para un NIF y rango de fechas.
    Devuelve una lista de fichajes (diccionarios).
    """
    url = f"{API_URL_BASE}/exportacion/fichajes"
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {API_TOKEN}",
    }
    data = {
        "fecha_inicio": fecha_inicio,
        "fecha_fin": fecha_fin,
        "nif": nif,
        "order": order,
    }

    resp = requests.post(url, headers=headers, json=data)
    resp.raise_for_status()

    payload_b64 = resp.text.strip().strip('"')

    if not payload_b64:
        return []

    decrypted_text = decrypt_crece_payload(payload_b64, APP_KEY_B64)
    fichajes = json.loads(decrypted_text)
    return fichajes


# =========================
# UI CON STREAMLIT
# =========================

st.set_page_config(page_title="Fichajes CRECE Personas", layout="wide")

st.title("📊 Fichajes CRECE Personas")

st.sidebar.header("Configuración")

# Selector de fechas
fecha_inicio = st.sidebar.date_input("Fecha inicio")
fecha_fin = st.sidebar.date_input("Fecha fin")

# Botón para cargar NIFs desde CRECE
if "nifs" not in st.session_state:
    st.session_state["nifs"] = []

st.sidebar.write("---")
if st.sidebar.button("🔄 Cargar NIFs desde CRECE"):
    try:
        nifs = call_crece_exportacion_empleados_solo_nif()
        st.session_state["nifs"] = nifs
        st.sidebar.success(f"{len(nifs)} NIF(s) cargados desde CRECE")
    except Exception as e:
        st.sidebar.error(f"Error cargando NIFs: {e}")

# Mostrar algunos NIFs (para info)
if st.session_state["nifs"]:
    st.sidebar.write("Ejemplo de NIFs cargados:")
    st.sidebar.write(st.session_state["nifs"][:10])

st.write("Selecciona un rango de fechas y pulsa **Obtener fichajes**.")

if st.button("▶ Obtener fichajes de todos los empleados"):
    if not st.session_state["nifs"]:
        st.error("No hay NIFs cargados. Pulsa antes 'Cargar NIFs desde CRECE'.")
    else:
        if fecha_inicio > fecha_fin:
            st.error("La fecha de inicio no puede ser posterior a la fecha fin.")
        else:
            with st.spinner("Consultando fichajes en CRECE..."):
                todos = []
                fi_str = fecha_inicio.strftime("%Y-%m-%d")
                ff_str = fecha_fin.strftime("%Y-%m-%d")

                for nif in st.session_state["nifs"]:
                    try:
                        fichajes = call_crece_exportacion_fichajes(nif, fi_str, ff_str, order="desc")
                        for f in fichajes:
                            fila = {
                                "nif": nif,
                                "id": f.get("id"),
                                "tipo": f.get("tipo"),
                                "fecha": f.get("fecha"),
                                "direccion": f.get("direccion"),
                                "terminal": f.get("terminal"),
                                "latitud": f.get("latitud"),
                                "longitud": f.get("longitud"),
                                "tipo_nombre": f.get("tipo_obj", {}).get("nombre") if f.get("tipo_obj") else None,
                                "tipo_descripcion": f.get("tipo_obj", {}).get("descripcion") if f.get("tipo_obj") else None,
                            }
                            todos.append(fila)
                    except Exception as e:
                        st.warning(f"Error con NIF {nif}: {e}")

                if todos:
                    df = pd.DataFrame(todos)
                    # ordenamos por fecha desc, por si acaso
                    df = df.sort_values("fecha", ascending=False)

                    st.subheader("Resultado")
                    st.dataframe(df, use_container_width=True)

                    # Descargar CSV
                    csv_bytes = df.to_csv(index=False).encode("utf-8")
                    st.download_button(
                        label="⬇ Descargar CSV",
                        data=csv_bytes,
                        file_name="fichajes_crece.csv",
                        mime="text/csv",
                    )
                else:
                    st.info("No se han encontrado fichajes en el rango indicado.")
