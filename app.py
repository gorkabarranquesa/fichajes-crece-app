import base64
import json
import requests
import pandas as pd
import streamlit as st
from concurrent.futures import ThreadPoolExecutor, as_completed
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from datetime import datetime, date, timedelta

# ==========================================
# CONFIG
# ==========================================

API_URL_BASE = "https://sincronizaciones.crecepersonas.es/api"
API_TOKEN = st.secrets["API_TOKEN"]
APP_KEY_B64 = st.secrets["APP_KEY_B64"]

MAX_WORKERS = 1000  # Peticiones simultáneas (ojo con saturar CRECE)


# ==========================================
# DESCIFRADO CRECE
# ==========================================

def decrypt_crece_payload(payload_b64: str, app_key_b64: str) -> str:
    """Descifra payload en base64 según Anexo 2 de CRECE."""
    json_raw = base64.b64decode(payload_b64).decode("utf-8")
    payload = json.loads(json_raw)

    iv = base64.b64decode(payload["iv"])
    ct = base64.b64decode(payload["value"])
    key = base64.b64decode(app_key_b64)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ct), AES.block_size)

    return decrypted.decode("utf-8")


# ==========================================
# UTILIDADES HORAS
# ==========================================

def horas_a_hhmm(horas):
    """Convierte horas decimales a 'HH:MM', redondeando minutos."""
    if horas is None or pd.isna(horas):
        return "00:00"
    total_min = round(float(horas) * 60)
    h = total_min // 60
    m = total_min % 60
    return f"{h:02d}:{m:02d}"


def hhmm_to_dec(hhmm):
    """Convierte 'HH:MM' a horas decimales."""
    if not isinstance(hhmm, str) or ":" not in hhmm:
        return 0.0
    h, m = map(int, hhmm.split(":"))
    return h + m / 60.0


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
    """
    Obtenemos empleados completos para:
    - NIF
    - Nombre completo
    - Departamento
    - num_empleado (para cruzar con /informes/empleados)
    """
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

        # fallback si solo viene "apellidos"
        if not (primer_apellido or segundo_apellido) and e.get("apellidos"):
            partes = e["apellidos"].split(" ")
            primer_apellido = partes[0] if len(partes) > 0 else ""
            segundo_apellido = " ".join(partes[1:]) if len(partes) > 1 else ""

        nombre_completo = f"{nombre} {primer_apellido} {segundo_apellido}".strip()

        lista.append({
            "nif": e.get("nif"),
            "nombre_completo": nombre_completo,
            "departamento_id": e.get("departamento"),
            # num_empleado para cruzar con /informes/empleados
            "num_empleado": e.get("num_empleado") or e.get("Num_empleado") or e.get("numero_empleado"),
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
        # Si falla, devolvemos lista vacía para no parar la app
        return []


# ==========================================
# EXPORTACIÓN DE VACACIONES (VACACIONES / AP)
# ==========================================

def api_exportar_vacaciones(fi, ff):
    """
    Exporta vacaciones / asuntos propios (tipos 1,2,8,9) para el rango.
    """
    url = f"{API_URL_BASE}/exportacion/vacaciones"
    headers = {"Accept": "application/json", "Authorization": f"Bearer {API_TOKEN}"}
    data = {
        "fecha_inicio": fi,
        "fecha_fin": ff
    }

    try:
        resp = requests.post(url, headers=headers, data=data, timeout=30)
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


def obtener_permisos_vacaciones_por_dia(fi, ff):
    """
    Devuelve DF con:
      - Fecha (YYYY-MM-DD)
      - nif
      - Permiso (texto vacaciones/AP)
      - estado (0..6)
      - valido_permiso (bool) -> estados 0,1,5,6
    """
    vacaciones = api_exportar_vacaciones(fi, ff)
    if not vacaciones:
        return pd.DataFrame(columns=["Fecha", "nif", "Permiso", "estado", "valido_permiso"])

    filas = []

    rango_ini = datetime.strptime(fi, "%Y-%m-%d").date()
    rango_fin = datetime.strptime(ff, "%Y-%m-%d").date()

    for v in vacaciones:
        usuario = v.get("usuario", {}) or {}
        nif = (
            usuario.get("Nif")
            or usuario.get("nif")
            or v.get("nif")
        )

        if not nif:
            continue

        f_ini_str = v.get("fecha_inicio")
        f_fin_str = v.get("fecha_fin")
        tipo = v.get("tipo")
        estado = v.get("estado")

        try:
            f_ini = datetime.strptime(f_ini_str, "%Y-%m-%d").date()
            f_fin = datetime.strptime(f_fin_str, "%Y-%m-%d").date()
        except Exception:
            continue

        current = max(f_ini, rango_ini)
        last = min(f_fin, rango_fin)

        tipo_txt = map_tipo_vacaciones(tipo)
        estado_txt = map_estado_vacaciones(estado)
        permiso_label = f"{tipo_txt} ({estado_txt})"

        while current <= last:
            filas.append({
                "Fecha": current.strftime("%Y-%m-%d"),
                "nif": nif,
                "Permiso": permiso_label,
                "estado": estado
            })
            current += timedelta(days=1)

    if not filas:
        return pd.DataFrame(columns=["Fecha", "nif", "Permiso", "estado", "valido_permiso"])

    dfp = pd.DataFrame(filas)

    # válidos para horas: pendientes / aprobadas / pendientes admin / solicitada cancelación
    dfp["valido_permiso"] = dfp["estado"].apply(lambda e: e in (0, 1, 5, 6))

    # Agrupamos por día y nif (puede haber varios registros)
    dfp_grp = dfp.groupby(["Fecha", "nif"], as_index=False).agg(
        Permiso=("Permiso", lambda s: " + ".join(sorted(set(s)))),
        estado=("estado", "max"),
        valido_permiso=("valido_permiso", "max")
    )

    return dfp_grp


# ==========================================
# INFORME DE EMPLEADOS (PERMISOS OTROS)
# ==========================================

def api_informe_empleados(fecha_desde: str, fecha_hasta: str):
    """
    Llama a /api/informes/empleados para un rango.
    El manual indica que devuelve, por empleado, un ARRAY con los campos
    (Nº empleado, ..., Horas de permisos retribuidos, Horas de permisos NO retribuidos, ...).
    """
    url = f"{API_URL_BASE}/informes/empleados"
    headers = {"Accept": "application/json", "Authorization": f"Bearer {API_TOKEN}"}
    data = {
        "fecha_desde": fecha_desde,
        "fecha_hasta": fecha_hasta,
    }

    try:
        resp = requests.post(url, headers=headers, data=data, timeout=30)
        resp.raise_for_status()
        payload_b64 = resp.text.strip().strip('"')
        if not payload_b64:
            return []

        decrypted = decrypt_crece_payload(payload_b64, APP_KEY_B64)
        return json.loads(decrypted)
    except Exception:
        return []


def obtener_permisos_otros_por_dia(fi: str, ff: str, empleados_df: pd.DataFrame) -> pd.DataFrame:
    """
    Usa /informes/empleados día a día para obtener:
      - Horas de permisos retribuidos
      - Horas de permisos NO retribuidos

    Devuelve DF:
      Fecha, nif, horas_perm_otros (decimal)
    """
    try:
        fi_d = datetime.strptime(fi, "%Y-%m-%d").date()
        ff_d = datetime.strptime(ff, "%Y-%m-%d").date()
    except Exception:
        return pd.DataFrame(columns=["Fecha", "nif", "horas_perm_otros"])

    if fi_d > ff_d:
        return pd.DataFrame(columns=["Fecha", "nif", "horas_perm_otros"])

    filas = []

    # Preparamos cruce num_empleado -> nif
    emp_keys = empleados_df[["nif", "num_empleado"]].dropna().copy()
    emp_keys["num_empleado"] = emp_keys["num_empleado"].astype(str)

    current = fi_d
    while current <= ff_d:
        d_str = current.strftime("%Y-%m-%d")
        registros = api_informe_empleados(d_str, d_str)

        for reg in registros:
            num_emp = None
            horas_ret = 0.0
            horas_noret = 0.0

            # Caso más probable según manual: array posicional
            if isinstance(reg, (list, tuple)):
                # índice 0: Nº empleado
                # índice 29: Horas de permisos retribuidos
                # índice 30: Horas de permisos NO retribuidos
                # (contando desde 0)
                if len(reg) >= 31:
                    num_emp = reg[0]
                    try:
                        horas_ret = float(reg[29] or 0)
                    except Exception:
                        horas_ret = 0.0
                    try:
                        horas_noret = float(reg[30] or 0)
                    except Exception:
                        horas_noret = 0.0

            # fallback por si alguna versión devolviera diccionarios
            elif isinstance(reg, dict):
                num_emp = reg.get("num_empleado") or reg.get("Nº empleado") or reg.get("numero_empleado")
                def _get_float(d, keys):
                    for k in keys:
                        if k in d and d[k] is not None:
                            try:
                                return float(d[k])
                            except Exception:
                                pass
                    return 0.0

                horas_ret = _get_float(reg, [
                    "Horas de permisos retribuidos",
                    "horas_permisos_retribuidos",
                    "horas_perm_retribuidos"
                ])
                horas_noret = _get_float(reg, [
                    "Horas de permisos NO retribuidos",
                    "horas_permisos_no_retribuidos",
                    "horas_perm_no_retribuidos"
                ])

            if not num_emp:
                continue

            total_perm = horas_ret + horas_noret
            if total_perm <= 0:
                continue

            filas.append({
                "Fecha": d_str,
                "num_empleado": str(num_emp),
                "horas_perm_otros": total_perm
            })

        current += timedelta(days=1)

    if not filas:
        return pd.DataFrame(columns=["Fecha", "nif", "horas_perm_otros"])

    df_per = pd.DataFrame(filas)
    df_per["num_empleado"] = df_per["num_empleado"].astype(str)

    df_per = df_per.merge(emp_keys, on="num_empleado", how="left")
    df_per = df_per[df_per["nif"].notna()]

    if df_per.empty:
        return pd.DataFrame(columns=["Fecha", "nif", "horas_perm_otros"])

    df_per = df_per.groupby(["Fecha", "nif"], as_index=False)["horas_perm_otros"].sum()
    return df_per


# ==========================================
# CÁLCULO DE HORAS A PARTIR DE FICHAJES
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
                entrada = sub.iloc[i]
                salida = sub.iloc[i + 1]

                if entrada["direccion"] == "entrada" and salida["direccion"] == "salida":
                    t1 = entrada["fecha_dt"]
                    t2 = salida["fecha_dt"]
                    total_seconds = (t2 - t1).total_seconds()
                    horas = total_seconds / 3600.0

                    entrada["horas_trabajadas"] = horas
                    horas_acum += horas
                    entrada["horas_acumuladas"] = horas_acum
                    result.append(entrada)

                    salida["horas_trabajadas"] = 0.0
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
    return df_final.sort_values(["fecha_dt", "nombre_completo"])


# ==========================================
# REGLAS DE JORNADA POR DEPARTAMENTO/DÍA
# ==========================================

def calcular_minimos(depto: str, dia_semana: int):
    """
    Devuelve (min_horas, min_fichajes) o (None, None) si no aplica.
    depto en mayúsculas, dia_semana: 0=Lunes ... 6=Domingo
    """
    if depto in ["ESTRUCTURA", "MOI"]:
        if dia_semana in [0, 1, 2, 3]:   # L-J
            return 8.5, 4
        elif dia_semana == 4:            # V
            return 6.5, 2
        else:
            return None, None
    elif depto == "MOD":
        if dia_semana in [0, 1, 2, 3, 4]:  # L-V
            return 8.0, 2
        else:
            return None, None
    else:
        return None, None


# ==========================================
# UI STREAMLIT
# ==========================================

st.set_page_config(page_title="Fichajes CRECE", layout="wide")
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
    elif fecha_fin > hoy:
        st.error("❌ La fecha fin no puede ser mayor que hoy.")
    else:
        with st.spinner("Cargando empleados, departamentos, fichajes y permisos…"):

            fi = fecha_inicio.strftime("%Y-%m-%d")
            ff = fecha_fin.strftime("%Y-%m-%d")

            # 1) Departamentos y empleados
            departamentos_df = api_exportar_departamentos()
            empleados_df = api_exportar_empleados_completos()

            empleados_df = empleados_df.merge(
                departamentos_df,
                on="departamento_id",
                how="left"
            )

            # 2) Fichajes en paralelo
            fichajes_totales = []

            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = {
                    executor.submit(api_exportar_fichajes, e["nif"], fi, ff): e
                    for _, e in empleados_df.iterrows()
                    if pd.notna(e.get("nif"))
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

            # 3) Construcción de resumen base (fichajes)
            if fichajes_totales:
                df = pd.DataFrame(fichajes_totales)

                df["fecha_dt"] = pd.to_datetime(df["fecha"], format="%Y-%m-%d %H:%M:%S", errors="coerce")
                df["fecha_dia"] = df["fecha_dt"].dt.strftime("%Y-%m-%d")

                df = df.sort_values(["nif", "fecha_dt", "nombre_completo"])
                df = calcular_horas(df)
                df = df.sort_values(["nif", "fecha_dt", "nombre_completo"])

                df["Numero_de_fichajes"] = df.groupby(
                    ["nif", "fecha_dia"]
                )["id"].transform("count")

                resumen = df.sort_values("fecha_dt").groupby(
                    ["nif", "nombre_completo", "departamento_nombre", "fecha_dia"],
                    as_index=False
                ).agg({
                    "horas_acumuladas": "max",
                    "Numero_de_fichajes": "max"
                })

                resumen["Total trabajado"] = resumen["horas_acumuladas"].apply(horas_a_hhmm)

                resumen = resumen.rename(columns={
                    "fecha_dia": "Fecha",
                    "nombre_completo": "Nombre Completo",
                    "departamento_nombre": "Departamento",
                    "Numero_de_fichajes": "Numero de fichajes"
                })

            else:
                resumen = pd.DataFrame(columns=[
                    "nif", "Nombre Completo", "Departamento",
                    "Fecha", "horas_acumuladas", "Numero de fichajes", "Total trabajado"
                ])

            # 4) Permisos/vacaciones por día (Vacaciones/AP)
            permisos_vac_df = obtener_permisos_vacaciones_por_dia(fi, ff)

            # 5) Añadir días con vacaciones pero sin fichajes
            if not permisos_vac_df.empty:
                perms_ext = permisos_vac_df.merge(
                    empleados_df[["nif", "nombre_completo", "departamento_nombre"]],
                    on="nif",
                    how="left"
                )

                if resumen.empty:
                    resumen = perms_ext.copy()
                    resumen = resumen.rename(columns={
                        "nombre_completo": "Nombre Completo",
                        "departamento_nombre": "Departamento"
                    })
                    resumen["horas_acumuladas"] = 0.0
                    resumen["Numero de fichajes"] = 0
                    resumen["Total trabajado"] = "00:00"
                else:
                    claves_res = resumen[["nif", "Fecha"]].drop_duplicates()
                    claves_perm = perms_ext[["nif", "Fecha"]].drop_duplicates()

                    faltan = claves_perm.merge(
                        claves_res,
                        on=["nif", "Fecha"],
                        how="left",
                        indicator=True
                    )
                    faltan = faltan[faltan["_merge"] == "left_only"][["nif", "Fecha"]]

                    if not faltan.empty:
                        faltan = faltan.merge(
                            empleados_df[["nif", "nombre_completo", "departamento_nombre"]],
                            on="nif",
                            how="left"
                        )
                        faltan["horas_acumuladas"] = 0.0
                        faltan["Numero de fichajes"] = 0
                        faltan["Total trabajado"] = "00:00"
                        faltan = faltan.rename(columns={
                            "nombre_completo": "Nombre Completo",
                            "departamento_nombre": "Departamento"
                        })
                        resumen = pd.concat([resumen, faltan], ignore_index=True)

            # 6) Merge permisos vacaciones al resumen
            if not permisos_vac_df.empty and not resumen.empty:
                resumen = resumen.merge(
                    permisos_vac_df,
                    on=["nif", "Fecha"],
                    how="left"
                )
            else:
                if "Permiso" not in resumen.columns:
                    resumen["Permiso"] = None
                if "valido_permiso" not in resumen.columns:
                    resumen["valido_permiso"] = False

            # 7) Permisos OTROS (hospitalización, médico, etc.) vía /informes/empleados
            permisos_otros_df = obtener_permisos_otros_por_dia(fi, ff, empleados_df)

            if not permisos_otros_df.empty:
                if resumen.empty:
                    base = permisos_otros_df.merge(
                        empleados_df[["nif", "nombre_completo", "departamento_nombre"]],
                        on="nif",
                        how="left"
                    )
                    base = base.rename(columns={
                        "nombre_completo": "Nombre Completo",
                        "departamento_nombre": "Departamento"
                    })
                    base["horas_acumuladas"] = 0.0
                    base["Numero de fichajes"] = 0
                    base["Total trabajado"] = "00:00"
                    base["Permiso"] = None
                    base["valido_permiso"] = False
                    resumen = base
                else:
                    # Días con permisos otros pero sin filas en resumen
                    claves_res2 = resumen[["nif", "Fecha"]].drop_duplicates()
                    claves_perm2 = permisos_otros_df[["nif", "Fecha"]].drop_duplicates()

                    faltan2 = claves_perm2.merge(
                        claves_res2,
                        on=["nif", "Fecha"],
                        how="left",
                        indicator=True
                    )
                    faltan2 = faltan2[faltan2["_merge"] == "left_only"][["nif", "Fecha"]]

                    if not faltan2.empty:
                        faltan2 = faltan2.merge(
                            empleados_df[["nif", "nombre_completo", "departamento_nombre"]],
                            on="nif",
                            how="left"
                        )
                        faltan2["horas_acumuladas"] = 0.0
                        faltan2["Numero de fichajes"] = 0
                        faltan2["Total trabajado"] = "00:00"
                        faltan2 = faltan2.rename(columns={
                            "nombre_completo": "Nombre Completo",
                            "departamento_nombre": "Departamento"
                        })
                        faltan2["Permiso"] = None
                        faltan2["valido_permiso"] = False
                        resumen = pd.concat([resumen, faltan2], ignore_index=True)

                resumen = resumen.merge(
                    permisos_otros_df,
                    on=["nif", "Fecha"],
                    how="left"
                )
            else:
                if "horas_perm_otros" not in resumen.columns:
                    resumen["horas_perm_otros"] = 0.0

            # Si sigue vacío, no hay fichajes ni permisos de ningún tipo
            if resumen.empty:
                st.info("No se encontraron fichajes ni permisos en el rango seleccionado.")
                st.stop()

            # ==========================================
            # CÁLCULO DE HORAS TOTALES Y VALIDACIONES
            # ==========================================

            resumen["horas_dec"] = resumen["Total trabajado"].apply(hhmm_to_dec)
            resumen["dia_semana"] = pd.to_datetime(resumen["Fecha"]).dt.weekday

            # Mínimos por depto/día
            def aplicar_minimos(row):
                depto = (row["Departamento"] or "").strip().upper()
                dia = int(row["dia_semana"])
                min_h, min_f = calcular_minimos(depto, dia)
                return pd.Series({"min_horas": min_h, "min_fichajes": min_f})

            mins = resumen.apply(aplicar_minimos, axis=1)
            resumen["min_horas"] = mins["min_horas"]
            resumen["min_fichajes"] = mins["min_fichajes"]

            # Horas de permiso por vacaciones/AP (cuando hay Permiso válido)
            def calc_horas_perm_vac(row):
                if not row.get("Permiso") or not row.get("valido_permiso"):
                    return 0.0
                if pd.isna(row["min_horas"]):
                    return 0.0
                # usamos min_horas como "jornada" cubierta por vacaciones/AP
                return float(row["min_horas"])

            resumen["horas_perm_vac"] = resumen.apply(calc_horas_perm_vac, axis=1)

            # Aseguramos columna permisos_otros
            if "horas_perm_otros" not in resumen.columns:
                resumen["horas_perm_otros"] = 0.0
            resumen["horas_perm_otros"] = resumen["horas_perm_otros"].fillna(0.0)

            # Horas totales = trabajadas + permiso vacaciones/AP + permisos otros (hospitalización, médico, etc.)
            resumen["horas_totales"] = (
                resumen["horas_dec"]
                + resumen["horas_perm_vac"]
                + resumen["horas_perm_otros"]
            )

            # Validación por reglas
            def validar(row):
                depto = (row["Departamento"] or "").strip().upper()
                horas_tot = float(row["horas_totales"])
                fich = int(row["Numero de fichajes"])
                min_h = row["min_horas"]
                min_f = row["min_fichajes"]

                motivo = []

                if pd.isna(min_h) or pd.isna(min_f):
                    # Departamento sin reglas → no validamos horas/fichajes
                    return None

                # Horas
                if horas_tot < min_h:
                    motivo.append(f"Horas totales insuficientes (mín {min_h}h, tiene {horas_tot:.2f}h)")

                # Fichajes
                if fich < min_f:
                    motivo.append(f"Fichajes insuficientes (mín {min_f}, tiene {fich})")

                # Fichajes excesivos (cumple horas mínimas)
                if horas_tot >= min_h and fich > min_f:
                    motivo.append(f"Fichajes excesivos (mín {min_f}, tiene {fich})")

                return "; ".join(motivo) if motivo else None

            resumen["Motivo_incidencia"] = resumen.apply(validar, axis=1)

            # Combinar incidencia + info de permisos (vacaciones/AP + otros permisos)
            def combinar_motivo(row):
                per = row.get("Permiso")
                inc = row.get("Motivo_incidencia")
                per_otros = float(row.get("horas_perm_otros", 0.0))

                texto_perm = None

                # Vacaciones / AP
                if per and isinstance(per, str) and per.strip():
                    texto_perm = f"Vacaciones/Asuntos propios: {per}"
                    if "Pendiente" in per or "Pendientes" in per:
                        texto_perm += " (pendiente, contado como horas para el cuadre)"

                # Otros permisos retribuidos / no retribuidos (ej. Hospitalización familiar)
                if per_otros > 0:
                    hhmm_otros = horas_a_hhmm(per_otros)
                    texto_otros = f"Permisos retribuidos/NO retribuidos: {hhmm_otros} (según informe de empleados)"
                    if texto_perm:
                        texto_perm = texto_perm + " | " + texto_otros
                    else:
                        texto_perm = texto_otros

                if texto_perm:
                    if inc and isinstance(inc, str) and inc.strip():
                        return f"{texto_perm} | {inc}"
                    else:
                        return texto_perm
                else:
                    return inc

            resumen["Motivo"] = resumen.apply(combinar_motivo, axis=1)

            # Mostrar:
            # - filas con incidencias
            # - filas con permisos (aunque no haya incidencia)
            resumen_filtrado = resumen[resumen["Motivo"].notna()].copy()

            if resumen_filtrado.empty:
                st.success("🎉 No hay incidencias ni permisos relevantes en el rango seleccionado.")
                st.stop()

            # Orden final: por Fecha y Nombre Completo
            resumen_filtrado = resumen_filtrado.sort_values(
                ["Fecha", "Nombre Completo"], ascending=[True, True]
            )

            # Columnas visibles
            resumen_filtrado["Horas permiso"] = (
                resumen_filtrado["horas_perm_vac"] + resumen_filtrado["horas_perm_otros"]
            ).apply(horas_a_hhmm)
            resumen_filtrado["Horas totales"] = resumen_filtrado["horas_totales"].apply(horas_a_hhmm)

            resumen_filtrado = resumen_filtrado[[
                "Fecha",
                "Nombre Completo",
                "Departamento",
                "Total trabajado",
                "Horas permiso",
                "Horas totales",
                "Numero de fichajes",
                "Permiso",
                "Motivo"
            ]]

            st.subheader("📄 Registros: incidencias y/o permisos")

            fechas = resumen_filtrado["Fecha"].unique()

            for f_dia in fechas:
                st.markdown(f"### 📅 Fecha {f_dia}")
                sub = resumen_filtrado[resumen_filtrado["Fecha"] == f_dia]

                st.data_editor(
                    sub,
                    use_container_width=True,
                    hide_index=True,
                    disabled=True,
                    num_rows="fixed"
                )

            csv_bytes = resumen_filtrado.to_csv(index=False).encode("utf-8")
            st.download_button(
                "⬇ Descargar CSV (incidencias + permisos + cuadre)",
                csv_bytes,
                "fichajes_validaciones_permisos_cuadre.csv",
                "text/csv"
            )
