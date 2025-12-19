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
import random

# ==========================================
# CONFIG (Rápido y Seguro)
# ==========================================

API_URL_BASE = "https://sincronizaciones.crecepersonas.es/api"
API_TOKEN = st.secrets["API_TOKEN"]
APP_KEY_B64 = st.secrets["APP_KEY_B64"]

CPU = multiprocessing.cpu_count()
MAX_WORKERS = min(32, CPU * 5)  # seguro y rápido

# Timeouts (connect, read)
TIMEOUT_GET = (5, 25)
TIMEOUT_POST = (5, 25)

# Retries suaves para errores transitorios (sin reventar API)
RETRY_MAX = 2
RETRY_BACKOFF_BASE = 0.6  # segundos


# ==========================================
# SEGURIDAD: utilidades (sin logs de PII)
# ==========================================

def _safe_mask_nif(nif: str) -> str:
    try:
        s = (nif or "").strip().upper()
        if len(s) <= 4:
            return "***"
        return s[:2] + "***" + s[-2:]
    except Exception:
        return "***"


def _request_with_retries(session: requests.Session, method: str, url: str, *,
                          headers=None, data=None, timeout=None) -> requests.Response:
    """
    Reintentos controlados solo ante errores transitorios (429/5xx y timeouts).
    No loguea cuerpo/headers sensibles.
    """
    last_exc = None
    for attempt in range(RETRY_MAX + 1):
        try:
            resp = session.request(
                method=method,
                url=url,
                headers=headers,
                data=data,
                timeout=timeout
            )

            # Si 2xx -> OK
            if 200 <= resp.status_code < 300:
                return resp

            # 4xx no transitorios (excepto 429)
            if resp.status_code == 429 or 500 <= resp.status_code < 600:
                # backoff con jitter
                if attempt < RETRY_MAX:
                    sleep_s = (RETRY_BACKOFF_BASE * (2 ** attempt)) + random.random() * 0.25
                    time.sleep(sleep_s)
                    continue

            # Resto: lanzar error
            resp.raise_for_status()
            return resp

        except (requests.Timeout, requests.ConnectionError) as e:
            last_exc = e
            if attempt < RETRY_MAX:
                sleep_s = (RETRY_BACKOFF_BASE * (2 ** attempt)) + random.random() * 0.25
                time.sleep(sleep_s)
                continue
            raise
        except Exception as e:
            last_exc = e
            raise

    if last_exc:
        raise last_exc


def _get_session() -> requests.Session:
    """
    Session por ejecución (no cachear globalmente entre reruns si no quieres).
    """
    s = requests.Session()
    # Opcional: puedes fijar un User-Agent genérico
    s.headers.update({"Accept": "application/json"})
    return s


def _auth_headers() -> dict:
    return {"Accept": "application/json", "Authorization": f"Bearer {API_TOKEN}"}


# ==========================================
# DESCIFRADO CRECE
# ==========================================

def decrypt_crece_payload(payload_b64: str, app_key_b64: str) -> str:
    """
    Descifra el payload cifrado con AES-CBC.
    IMPORTANTE: no loguear nunca payload_b64 ni decrypted.
    """
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
    try:
        h, m = map(int, hhmm.split(":"))
        return h + m / 60
    except Exception:
        return 0.0


# ==========================================
# API EXPORTACIÓN DEPARTAMENTOS
# ==========================================

def api_exportar_departamentos(session: requests.Session):
    url = f"{API_URL_BASE}/exportacion/departamentos"
    headers = _auth_headers()

    resp = _request_with_retries(session, "GET", url, headers=headers, timeout=TIMEOUT_GET)

    payload_b64 = resp.text.strip().strip('"')
    if not payload_b64:
        return pd.DataFrame(columns=["departamento_id", "departamento_nombre"])

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

def api_exportar_empleados_completos(session: requests.Session):
    url = f"{API_URL_BASE}/exportacion/empleados"
    headers = _auth_headers()
    data = {"solo_nif": 0}

    resp = _request_with_retries(session, "POST", url, headers=headers, data=data, timeout=TIMEOUT_POST)

    payload_b64 = resp.text.strip().strip('"')
    if not payload_b64:
        return pd.DataFrame(columns=["nif", "nombre_completo", "departamento_id"])

    decrypted = decrypt_crece_payload(payload_b64, APP_KEY_B64)
    empleados = json.loads(decrypted)

    lista = []
    for e in empleados:
        nombre = e.get("name") or e.get("nombre") or ""
        primer_apellido = e.get("primer_apellido") or ""
        segundo_apellido = e.get("segundo_apellido") or ""

        if not (primer_apellido or segundo_apellido) and e.get("apellidos"):
            partes = str(e["apellidos"]).split(" ")
            primer_apellido = partes[0] if len(partes) > 0 else ""
            segundo_apellido = " ".join(partes[1:]) if len(partes) > 1 else ""

        nombre_completo = f"{nombre} {primer_apellido} {segundo_apellido}".strip()

        lista.append({
            "nif": e.get("nif"),
            "nombre_completo": nombre_completo,
            "departamento_id": e.get("departamento"),
        })

    df_emp = pd.DataFrame(lista)
    if not df_emp.empty:
        df_emp["nif"] = df_emp["nif"].astype(str).str.upper().str.strip()
    return df_emp


# ==========================================
# API EXPORTACIÓN DE FICHAJES
# ==========================================

def api_exportar_fichajes(session: requests.Session, nif: str, fi: str, ff: str):
    url = f"{API_URL_BASE}/exportacion/fichajes"
    headers = _auth_headers()

    data = {
        "fecha_inicio": fi,
        "fecha_fin": ff,
        "nif": nif,
        "order": "desc",
    }

    try:
        resp = _request_with_retries(session, "POST", url, headers=headers, data=data, timeout=(5, 20))

        payload_b64 = resp.text.strip().strip('"')
        if not payload_b64:
            return []

        decrypted = decrypt_crece_payload(payload_b64, APP_KEY_B64)
        return json.loads(decrypted)

    except Exception:
        # Silencioso para no romper el proceso ni filtrar datos
        return []


# ==========================================
# API EXPORTACIÓN DE VACACIONES/PERMISOS
# ==========================================

def api_exportar_vacaciones(session: requests.Session, fi: str, ff: str):
    """
    Ampliamos el rango ±7 días para capturar solapes, recortaremos luego.
    """
    url = f"{API_URL_BASE}/exportacion/vacaciones"
    headers = _auth_headers()

    fi_ext = (datetime.strptime(fi, "%Y-%m-%d") - timedelta(days=7)).strftime("%Y-%m-%d")
    ff_ext = (datetime.strptime(ff, "%Y-%m-%d") + timedelta(days=7)).strftime("%Y-%m-%d")

    data = {"fecha_inicio": fi_ext, "fecha_fin": ff_ext}

    try:
        resp = _request_with_retries(session, "POST", url, headers=headers, data=data, timeout=(5, 30))
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


def obtener_permisos_por_dia(session: requests.Session, fi: str, ff: str):
    vacaciones = api_exportar_vacaciones(session, fi, ff)
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
        except Exception:
            continue

        current = max(f_ini, rango_ini)
        last = min(f_fin, rango_fin)
        if current > last:
            continue

        tipo = map_tipo_vacaciones(v.get("tipo"))
        estado = map_estado_vacaciones(v.get("estado"))
        # consideramos válidos pendientes/aprobados/solicitud cancelación/pendientes admin (como ya tenías)
        valido = v.get("estado") in (0, 1, 5, 6)

        while current <= last:
            filas.append({
                "Fecha": current.strftime("%Y-%m-%d"),
                "nif": str(nif).upper().strip(),
                "Permiso": f"{tipo} ({estado})",
                "valido_permiso": bool(valido),
            })
            current += timedelta(days=1)

    if not filas:
        return pd.DataFrame(columns=["Fecha", "nif", "Permiso", "valido_permiso"])

    dfp = pd.DataFrame(filas)
    dfp["nif"] = dfp["nif"].astype(str).str.upper().str.strip()

    dfp = dfp.groupby(["Fecha", "nif"], as_index=False).agg(
        Permiso=("Permiso", lambda s: " + ".join(sorted(set(s)))),
        valido_permiso=("valido_permiso", "max")
    )

    return dfp


# ==========================================
# CÁLCULO DE HORAS POR DÍA (corregido)
# ==========================================

def calcular_horas(df: pd.DataFrame) -> pd.DataFrame:
    """
    Calcula horas trabajadas por pares entrada->salida, y acumulado diario.
    Corrección: evitamos SettingWithCopy y construimos filas de salida explícitas.
    """
    if df.empty:
        df["horas_trabajadas"] = 0.0
        df["horas_acumuladas"] = 0.0
        return df

    out_rows = []

    # Asegurar columnas
    if "horas_trabajadas" not in df.columns:
        df["horas_trabajadas"] = 0.0
    if "horas_acumuladas" not in df.columns:
        df["horas_acumuladas"] = 0.0

    for nif in df["nif"].unique():
        sub_emp = df[df["nif"] == nif].copy()

        for fecha_dia in sub_emp["fecha_dia"].unique():
            sub = sub_emp[sub_emp["fecha_dia"] == fecha_dia].copy()
            sub = sub.sort_values("fecha_dt").reset_index(drop=True)

            horas_acum = 0.0
            i = 0

            while i < len(sub):
                row_i = sub.loc[i].copy()
                row_i["horas_trabajadas"] = 0.0
                row_i["horas_acumuladas"] = horas_acum

                # Intentar emparejar con siguiente
                if i < len(sub) - 1:
                    row_j = sub.loc[i + 1].copy()
                    row_j["horas_trabajadas"] = 0.0
                    row_j["horas_acumuladas"] = horas_acum

                    if row_i.get("direccion") == "entrada" and row_j.get("direccion") == "salida":
                        total_seconds = (row_j["fecha_dt"] - row_i["fecha_dt"]).total_seconds()
                        # defensivo: ignorar pares negativos o absurdos
                        if total_seconds > 0:
                            horas = total_seconds / 3600.0
                            row_i["horas_trabajadas"] = horas
                            horas_acum += horas
                            row_i["horas_acumuladas"] = horas_acum
                            row_j["horas_acumuladas"] = horas_acum

                        out_rows.append(row_i.to_dict())
                        out_rows.append(row_j.to_dict())
                        i += 2
                        continue

                # Si no empareja, se añade solo y avanza 1
                out_rows.append(row_i.to_dict())
                i += 1

    out_df = pd.DataFrame(out_rows)
    return out_df.sort_values(["fecha_dt", "nif"]).reset_index(drop=True)


# ==========================================
# REGLAS DE JORNADA
# ==========================================

def calcular_minimos(depto: str, dia: int):
    depto = (depto or "").upper().strip()
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

# (Opcional) Debug seguro: NO muestra PII ni tokens
with st.expander("⚙️ Diagnóstico (seguro)", expanded=False):
    debug_seguro = st.checkbox("Activar diagnóstico seguro", value=False)
    st.caption("Muestra solo contadores y estados. No imprime tokens, payloads ni datos personales.")

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

        session = _get_session()

        # 1) Empleados y departamentos
        try:
            departamentos_df = api_exportar_departamentos(session)
        except Exception:
            departamentos_df = pd.DataFrame(columns=["departamento_id", "departamento_nombre"])

        try:
            empleados_df = api_exportar_empleados_completos(session)
        except Exception:
            empleados_df = pd.DataFrame(columns=["nif", "nombre_completo", "departamento_id"])

        if empleados_df.empty:
            st.warning("No se pudieron cargar empleados. Revisa credenciales o disponibilidad de la API.")
            st.stop()

        empleados_df = empleados_df.merge(departamentos_df, on="departamento_id", how="left")

        # Asegurar NIF normalizado
        empleados_df["nif"] = empleados_df["nif"].astype(str).str.upper().str.strip()

        if debug_seguro:
            st.info(f"Empleados cargados: {len(empleados_df)} | Departamentos: {len(departamentos_df)}")

        # 2) Fichajes paralelos (no mostramos errores ni PII)
        fichajes = []
        errores_fichajes = 0

        # Nota: cada thread usa su propia Session (requests.Session no es thread-safe)
        def _worker_fichajes(nif_local, fi_local, ff_local):
            s_local = _get_session()
            return api_exportar_fichajes(s_local, nif_local, fi_local, ff_local)

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as exe:
            futures = {
                exe.submit(_worker_fichajes, e["nif"], fi, ff): e
                for _, e in empleados_df.iterrows()
            }
            for f in as_completed(futures):
                emp = futures[f]
                try:
                    resp = f.result()
                except Exception:
                    resp = []
                if not resp:
                    # puede ser normal (sin fichajes) o error; no distinguimos para no exponer
                    # pero contamos error solo si hubo excepción (ya capturada arriba).
                    pass

                # Montaje de filas
                for x in resp:
                    try:
                        fichajes.append({
                            "nif": emp["nif"],
                            "nombre_completo": emp["nombre_completo"],
                            "departamento_nombre": emp["departamento_nombre"],
                            "id": x.get("id"),
                            "direccion": x.get("direccion"),
                            "fecha": x.get("fecha"),
                        })
                    except Exception:
                        continue

        if debug_seguro:
            st.info(f"Registros de fichajes recibidos: {len(fichajes)}")

        # 3) Construcción de resumen base
        if fichajes:
            df = pd.DataFrame(fichajes)
            df["nif"] = df["nif"].astype(str).str.upper().str.strip()
            df["fecha_dt"] = pd.to_datetime(df["fecha"], errors="coerce")
            df = df.dropna(subset=["fecha_dt"]).copy()
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

        if not resumen.empty:
            resumen["nif"] = resumen["nif"].astype(str).str.upper().str.strip()

        # 4) Permisos (solo texto + válido/no válido)
        permisos = obtener_permisos_por_dia(_get_session(), fi, ff)

        if debug_seguro:
            st.info(f"Registros de permisos por día recibidos: {len(permisos)}")

        # Añadir días con permisos sin fichajes
        if not permisos.empty:
            permisos["nif"] = permisos["nif"].astype(str).str.upper().str.strip()

            faltantes = permisos.merge(
                resumen[["nif", "Fecha"]] if not resumen.empty else permisos[["nif", "Fecha"]].head(0),
                on=["nif", "Fecha"],
                how="left",
                indicator=True
            )
            faltantes = faltantes[faltantes["_merge"] == "left_only"][["nif", "Fecha"]]

            if not faltantes.empty:
                faltantes = faltantes.merge(
                    empleados_df[["nif", "nombre_completo", "departamento_nombre"]],
                    on="nif",
                    how="left"
                )
                faltantes["horas"] = 0
                faltantes["Numero de fichajes"] = 0
                faltantes["Total trabajado"] = "00:00"
                faltantes = faltantes.rename(columns={
                    "nombre_completo": "Nombre",
                    "departamento_nombre": "Departamento"
                })
                resumen = pd.concat([resumen, faltantes], ignore_index=True)

        # Merge permisos al resumen
        resumen = resumen.merge(permisos, on=["nif", "Fecha"], how="left")

        if resumen.empty:
            st.info("No se encontraron fichajes ni permisos en el rango seleccionado.")
            st.stop()

        # ==========================================
        # CÁLCULO DE HORAS TOTALES Y VALIDACIONES
        # ==========================================

        resumen["horas_dec"] = resumen["Total trabajado"].apply(hhmm_to_dec)
        resumen["dia"] = pd.to_datetime(resumen["Fecha"]).dt.weekday

        # Minimos
        resumen[["min_horas", "min_fichajes"]] = resumen.apply(
            lambda r: pd.Series(calcular_minimos(r.get("Departamento"), r["dia"])),
            axis=1
        )

        # ✅ CAMBIO CRÍTICO: NO INVENTAMOS HORAS DE PERMISO
        # Solo mostramos el permiso como texto. Si no existe endpoint horario, horas_permiso=0.
        resumen["horas_permiso"] = 0.0
        resumen["horas_totales"] = resumen["horas_dec"] + resumen["horas_permiso"]

        # Validaciones (con regla de "permiso sin horas" -> marcar revisar)
        def validar(r):
            min_h, min_f = r["min_horas"], r["min_fichajes"]
            if pd.isna(min_h) or pd.isna(min_f):
                return None  # no validamos deptos sin reglas

            motivo = []

            # Si hay permiso válido pero sin detalle horario, avisamos (no cuadra automáticamente)
            per = r.get("Permiso")
            valido = bool(r.get("valido_permiso")) if not pd.isna(r.get("valido_permiso")) else False
            if per and str(per).strip() and valido:
                motivo.append("Permiso registrado (sin detalle horario en API) → revisar si computa horas")

            if r["horas_totales"] < min_h:
                motivo.append(
                    f"Horas insuficientes (mín {min_h}h, tiene {r['horas_totales']:.2f}h)"
                )

            if r["Numero de fichajes"] < min_f:
                motivo.append(
                    f"Fichajes insuficientes (mín {min_f}, tiene {r['Numero de fichajes']})"
                )

            # Mantengo tu lógica de "excesivos" pero corrigiendo condición:
            # si tiene MÁS que el mínimo, podemos avisar de exceso si te interesa.
            if r["Numero de fichajes"] > min_f:
                motivo.append(
                    f"Fichajes por encima del mínimo (mín {min_f}, tiene {r['Numero de fichajes']})"
                )

            return "; ".join(motivo) if motivo else None

        resumen["Motivo"] = resumen.apply(validar, axis=1)

        resumen_final = resumen[resumen["Motivo"].notna()].copy()

        if resumen_final.empty:
            st.success("🎉 No hay incidencias que mostrar.")
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
        for f_dia in fechas:
            st.markdown(f"### 📅 {f_dia}")
            sub = resumen_final[resumen_final["Fecha"] == f_dia]

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
