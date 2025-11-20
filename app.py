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

# ==========================================
# CONFIG (Rápido y Seguro)
# ==========================================

API_URL_BASE = "https://sincronizaciones.crecepersonas.es/api"
API_TOKEN = st.secrets["API_TOKEN"]
APP_KEY_B64 = st.secrets["APP_KEY_B64"]

CPU = multiprocessing.cpu_count()
MAX_WORKERS = min(32, CPU * 5)  # seguro y rápido


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
    total_min = round(float(horas) * 60)
    h = total_min // 60
    m = total_min % 60
    return f"{h:02d}:{m:02d}"


def hhmm_to_dec(hhmm):
    if not isinstance(hhmm, str) or ":" not in hhmm:
        return 0.0
    h, m = map(int, hhmm.split(":"))
    return h + m / 60


# ==========================================
# API EXPORTACIÓN DEPARTAMENTOS
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
# API EXPORTACIÓN EMPLEADOS
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
# API EXPORTACIÓN DE FICHAJES
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
        resp = requests.post(url, headers=headers, data=data, timeout=15)
        resp.raise_for_status()

        payload_b64 = resp.text.strip().strip('"')
        if not payload_b64:
            return []

        decrypted = decrypt_crece_payload(payload_b64, APP_KEY_B64)
        return json.loads(decrypted)

    except Exception:
        return []


# ==========================================
# API EXPORTACIÓN DE VACACIONES/PERMISOS
# ==========================================

def api_exportar_vacaciones(fi, ff):
    url = f"{API_URL_BASE}/exportacion/vacaciones"
    headers = {"Accept": "application/json", "Authorization": f"Bearer {API_TOKEN}"}
    data = {"fecha_inicio": fi, "fecha_fin": ff}

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


def map_tipo_vacaciones(tipo):
    mapping = {
        1: "Vacaciones",
        2: "Asuntos propios",
        8: "Asuntos propios año anterior",
        9: "Vacaciones año anterior",
    }
    return mapping.get(tipo, f"Tipo {tipo}")


def map_estado_vacaciones(estado):
    mapping = {
        0: "Pendientes",
        1: "Aprobadas",
        2: "Denegadas",
        3: "Canceladas empleado",
        4: "Denegación extraordinaria",
        5: "Solicitada cancelación",
        6: "Pendientes administrador",
    }
    return mapping.get(estado, f"Estado {estado}")


def obtener_permisos_por_dia(fi, ff):
    vacaciones = api_exportar_vacaciones(fi, ff)
    if not vacaciones:
        return pd.DataFrame(columns=["Fecha", "nif", "Permiso", "valido_permiso"])

    filas = []
    rango_ini = datetime.strptime(fi, "%Y-%m-%d").date()
    rango_fin = datetime.strptime(ff, "%Y-%m-%d").date()

    for v in vacaciones:
        usuario = v.get("usuario", {}) or {}
        nif = usuario.get("Nif") or usuario.get("nif") or v.get("nif")

        if not nif:
            continue

        try:
            f_ini = datetime.strptime(v["fecha_inicio"], "%Y-%m-%d").date()
            f_fin = datetime.strptime(v["fecha_fin"], "%Y-%m-%d").date()
        except:
            continue

        current = max(f_ini, rango_ini)
        last = min(f_fin, rango_fin)

        tipo = map_tipo_vacaciones(v.get("tipo"))
        estado = map_estado_vacaciones(v.get("estado"))
        valido = v.get("estado") in (0, 1, 5, 6)

        while current <= last:
            filas.append({
                "Fecha": current.strftime("%Y-%m-%d"),
                "nif": nif,
                "Permiso": f"{tipo} ({estado})",
                "valido_permiso": valido
            })
            current += timedelta(days=1)

    if not filas:
        return pd.DataFrame(columns=["Fecha", "nif", "Permiso", "valido_permiso"])

    dfp = pd.DataFrame(filas)

    dfp = dfp.groupby(["Fecha", "nif"], as_index=False).agg(
        Permiso=("Permiso", lambda s: " + ".join(sorted(set(s)))),
        valido_permiso=("valido_permiso", "max")
    )

    return dfp


# ==========================================
# CÁLCULO DE HORAS POR DÍA
# ==========================================

def calcular_horas(df):
    df["horas_trabajadas"] = 0.0
    df["horas_acumuladas"] = 0.0

    if df.empty:
        return df

    result = []

    for nif in df["nif"].unique():
        sub_emp = df[df["nif"] == nif].copy()

        for fecha_dia in sub_emp["fecha_dia"].unique():
            sub = sub_emp[sub_emp["fecha_dia"] == fecha_dia].copy()
            sub = sub.sort_values("fecha_dt")

            horas_acum = 0.0
            i = 0

            while i < len(sub) - 1:
                e1, e2 = sub.iloc[i], sub.iloc[i + 1]

                if e1["direccion"] == "entrada" and e2["direccion"] == "salida":
                    total_seconds = (e2["fecha_dt"] - e1["fecha_dt"]).total_seconds()
                    horas = total_seconds / 3600

                    e1["horas_trabajadas"] = horas
                    horas_acum += horas
                    e1["horas_acumuladas"] = horas_acum
                    result.append(e1)

                    e2["horas_acumuladas"] = horas_acum
                    result.append(e2)

                    i += 2
                else:
                    sub.iloc[i]["horas_acumuladas"] = horas_acum
                    result.append(sub.iloc[i])
                    i += 1

            if i == len(sub) - 1:
                sub.iloc[i]["horas_acumuladas"] = horas_acum
                result.append(sub.iloc[i])

    return pd.DataFrame(result).sort_values(["fecha_dt", "nif"])


# ==========================================
# REGLAS DE JORNADA
# ==========================================

def calcular_minimos(depto: str, dia: int):
    if depto in ["ESTRUCTURA", "MOI"]:
        if dia in [0, 1, 2, 3]:
            return 8.5, 4
        if dia == 4:
            return 6.5, 2
        return None, None

    if depto == "MOD":
        if dia in [0, 1, 2, 3, 4]:
            return 8.0, 2
        return None, None

    return None, None


# ==========================================
# UI STREAMLIT
# ==========================================

st.set_page_config(page_title="Fichajes CRECE Personas", layout="wide")
st.title("📊 Fichajes CRECE Personas")

hoy = date.today()

col1, col2 = st.columns(2)
with col1:
    fecha_inicio = st.date_input("Fecha inicio", value=hoy, max_value=hoy)
with col2:
    fecha_fin = st.date_input("Fecha fin", value=hoy, max_value=hoy)

st.write("---")

if st.button("▶ Obtener resumen de fichajes y permisos"):
    if fecha_inicio > fecha_fin:
        st.error("❌ La fecha inicio no puede ser posterior a la fecha fin.")
        st.stop()

    if fecha_fin > hoy:
        st.error("❌ La fecha fin no puede ser mayor que hoy.")
        st.stop()

    with st.spinner("Cargando información…"):

        fi = fecha_inicio.strftime("%Y-%m-%d")
        ff = fecha_fin.strftime("%Y-%m-%d")

        # 1) Empleados y departamentos
        departamentos_df = api_exportar_departamentos()
        empleados_df = api_exportar_empleados_completos()
        empleados_df = empleados_df.merge(departamentos_df, on="departamento_id", how="left")

        # 2) Fichajes paralelos
        fichajes = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as exe:
            futures = {
                exe.submit(api_exportar_fichajes, e["nif"], fi, ff): e
                for _, e in empleados_df.iterrows()
            }
            for f in as_completed(futures):
                emp = futures[f]
                resp = f.result()
                for x in resp:
                    fichajes.append({
                        "nif": emp["nif"],
                        "nombre_completo": emp["nombre_completo"],
                        "departamento_nombre": emp["departamento_nombre"],
                        "id": x["id"],
                        "direccion": x["direccion"],
                        "fecha": x["fecha"],
                    })

        # 3) Construcción de resumen base
        if fichajes:
            df = pd.DataFrame(fichajes)
            df["fecha_dt"] = pd.to_datetime(df["fecha"])
            df["fecha_dia"] = df["fecha_dt"].dt.strftime("%Y-%m-%d")
            df = calcular_horas(df)
            df["Numero"] = df.groupby(["nif", "fecha_dia"])["id"].transform("count")

            resumen = df.groupby(
                ["nif", "nombre_completo", "departamento_nombre", "fecha_dia"],
                as_index=False
            ).agg(
                horas=("horas_acumuladas", "max"),
                fichajes=("Numero", "max")
            )

            resumen["Total trabajado"] = resumen["horas"].apply(horas_a_hhmm)

        else:
            resumen = pd.DataFrame(columns=[
                "nif", "nombre_completo", "departamento_nombre",
                "fecha_dia", "horas", "fichajes", "Total trabajado"
            ])

        resumen = resumen.rename(columns={
            "nombre_completo": "Nombre",
            "departamento_nombre": "Departamento",
            "fecha_dia": "Fecha",
            "fichajes": "Numero de fichajes",
        })

        # 4) Permisos
        permisos = obtener_permisos_por_dia(fi, ff)

        # Añadir días con permisos sin fichajes
        if not permisos.empty:
            faltantes = permisos.merge(
                resumen[["nif", "Fecha"]],
                on=["nif", "Fecha"],
                how="left",
                indicator=True
            )
            faltantes = faltantes[faltantes["_merge"] == "left_only"][["nif", "Fecha"]]
            if not faltantes.empty:
                faltantes = faltantes.merge(
                    empleados_df[["nif", "nombre_completo", "departamento_nombre"]],
                    on="nif"
                )
                faltantes["horas"] = 0
                faltantes["Numero de fichajes"] = 0
                faltantes["Total trabajado"] = "00:00"
                faltantes = faltantes.rename(columns={
                    "nombre_completo": "Nombre",
                    "departamento_nombre": "Departamento"
                })
                resumen = pd.concat([resumen, faltantes], ignore_index=True)

        # Merge permisos
        resumen = resumen.merge(permisos, on=["nif", "Fecha"], how="left")

        # ==========================================
        # CÁLCULO DE HORAS TOTALES Y VALIDACIONES
        # ==========================================

        resumen["horas_dec"] = resumen["Total trabajado"].apply(hhmm_to_dec)
        resumen["dia"] = pd.to_datetime(resumen["Fecha"]).dt.weekday

        # Minimos
        resumen[["min_horas", "min_fichajes"]] = resumen.apply(
            lambda r: pd.Series(calcular_minimos((r["Departamento"] or "").upper(), r["dia"])),
            axis=1
        )

        # Horas permiso corregidas
        def calc_horas_permiso(r):
            p = r.get("Permiso")
            if p is None or pd.isna(p) or str(p).strip() == "":
                return 0.0
            if not bool(r.get("valido_permiso")):
                return 0.0
            if pd.isna(r.get("min_horas")):
                return 0.0
            return float(r["min_horas"])

        resumen["horas_permiso"] = resumen.apply(calc_horas_permiso, axis=1)

        resumen["horas_totales"] = resumen["horas_dec"] + resumen["horas_permiso"]

        # Validaciones
        def validar(r):
            min_h, min_f = r["min_horas"], r["min_fichajes"]
            if pd.isna(min_h) or pd.isna(min_f):
                # No validamos dep. sin reglas
                return None

            motivo = []

            if r["horas_totales"] < min_h:
                motivo.append(f"Horas totales insuficientes (mín {min_h}h, tiene {r['horas_totales']:.2f}h)")

            if r["Numero de fichajes"] < min_f:
                motivo.append(f"Fichajes insuficientes (mín {min_f}, tiene {r['Numero de fichajes']})")

            if r["horas_totales"] >= min_h and r["Numero de fichajes"] > min_f:
                motivo.append(f"Fichajes excesivos (mín {min_f}, tiene {r['Numero de fichajes']})")

            return "; ".join(motivo) if motivo else None

        resumen["Incidencia"] = resumen.apply(validar, axis=1)

        # Motivo final (opción O)
        def motivo_final(r):
            per = r.get("Permiso")
            inc = r.get("Incidencia")

            if per and not pd.isna(per) and per.strip():
                texto = f"Permiso: {per}"
                if "Pendiente" in per:
                    texto += " (pendiente)"
                return f"{texto}" + (f" | {inc}" if inc else "")

            return inc

        resumen["Motivo"] = resumen.apply(motivo_final, axis=1)

        resumen_final = resumen[resumen["Motivo"].notna()].copy()

        if resumen_final.empty:
            st.success("🎉 No hay incidencias ni permisos que mostrar.")
            st.stop()

        resumen_final["Horas permiso"] = resumen_final["horas_permiso"].apply(horas_a_hhmm)
        resumen_final["Horas totales"] = resumen_final["horas_totales"].apply(horas_a_hhmm)

        resumen_final = resumen_final[[
            "Fecha",
            "Nombre",
            "Departamento",
            "Total trabajado",
            "Horas permiso",
            "Horas totales",
            "Numero de fichajes",
            "Permiso",
            "Motivo"
        ]]

        resumen_final = resumen_final.sort_values(["Fecha", "Nombre"])

        # Mostrar tablas por fecha
        st.subheader("📄 Incidencias y permisos")

        fechas = resumen_final["Fecha"].unique()
        for f in fechas:
            st.markdown(f"### 📅 {f}")
            sub = resumen_final[resumen_final["Fecha"] == f]

            st.data_editor(
                sub,
                use_container_width=True,
                hide_index=True,
                disabled=True,
                num_rows="fixed"
            )

        csv = resumen_final.to_csv(index=False).encode("utf-8")
        st.download_button(
            "⬇ Descargar CSV",
            csv,
            "fichajes_validaciones_permisos.csv",
            "text/csv"
        )
