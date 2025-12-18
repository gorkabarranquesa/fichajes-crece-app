import base64
import json
import math
import requests
import pandas as pd
import streamlit as st

from datetime import datetime, date, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


# ============================================================
# CONFIG
# ============================================================

API_URL_BASE = "https://sincronizaciones.crecepersonas.es/api"

API_TOKEN = st.secrets["API_TOKEN"]
APP_KEY_B64 = st.secrets["APP_KEY_B64"]

MAX_WORKERS = 1000  # solicitado


# ============================================================
# HELPERS: CRYPTO / TIME
# ============================================================

def decrypt_crece_payload(payload_b64: str, app_key_b64: str) -> str:
    """
    Descifra el formato Laravel-like que devuelve CRECE:
    - respuesta: base64( json {iv, value, mac, tag} )
    - iv/value en base64
    - clave: APP_KEY en base64 (AES-256-CBC)
    """
    json_raw = base64.b64decode(payload_b64).decode("utf-8")
    payload = json.loads(json_raw)

    iv = base64.b64decode(payload["iv"])
    ct = base64.b64decode(payload["value"])
    key = base64.b64decode(app_key_b64)

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


def seconds_to_hhmm(seconds: float) -> str:
    if seconds is None or (isinstance(seconds, float) and math.isnan(seconds)):
        return "00:00"
    seconds = max(0, float(seconds))
    total_min = int(round(seconds / 60.0))
    h = total_min // 60
    m = total_min % 60
    return f"{h:02d}:{m:02d}"


def hhmm_from_hours(hours: float) -> str:
    if hours is None or (isinstance(hours, float) and math.isnan(hours)):
        return "00:00"
    return seconds_to_hhmm(hours * 3600.0)


# ============================================================
# HTTP (SESSION)
# ============================================================

@st.cache_resource
def get_session() -> requests.Session:
    s = requests.Session()
    # Seguridad: verify=True por defecto (HTTPS). No tocar.
    # Reutiliza conexiones (más rápido).
    return s


def crece_headers() -> dict:
    return {
        "Accept": "application/json",
        "Authorization": f"Bearer {API_TOKEN}",
    }


def post_and_decrypt(session: requests.Session, url: str, data: dict, timeout: int = 30):
    resp = session.post(url, headers=crece_headers(), data=data, timeout=timeout)
    resp.raise_for_status()
    payload_b64 = safe_strip_quotes(resp.text)
    if not payload_b64:
        return None
    decrypted = decrypt_crece_payload(payload_b64, APP_KEY_B64)
    return json.loads(decrypted)


def get_and_decrypt(session: requests.Session, url: str, timeout: int = 30):
    resp = session.get(url, headers=crece_headers(), timeout=timeout)
    resp.raise_for_status()
    payload_b64 = safe_strip_quotes(resp.text)
    if not payload_b64:
        return None
    decrypted = decrypt_crece_payload(payload_b64, APP_KEY_B64)
    return json.loads(decrypted)


# ============================================================
# EXPORTACIONES BÁSICAS
# ============================================================

@st.cache_data(ttl=60 * 30, show_spinner=False)
def api_exportar_departamentos_cached():
    session = get_session()
    url = f"{API_URL_BASE}/exportacion/departamentos"
    data = get_and_decrypt(session, url, timeout=30)  # GET según manual
    if not data:
        return pd.DataFrame(columns=["departamento_id", "departamento_nombre"])

    rows = [{"departamento_id": d.get("id"), "departamento_nombre": d.get("nombre")} for d in data]
    return pd.DataFrame(rows)


@st.cache_data(ttl=60 * 30, show_spinner=False)
def api_exportar_empleados_cached():
    """
    Devuelve NIF + nombre/apellidos + departamento_id.
    """
    session = get_session()
    url = f"{API_URL_BASE}/exportacion/empleados"
    data = post_and_decrypt(session, url, data={"solo_nif": 0}, timeout=60)  # POST según manual
    if not data:
        return pd.DataFrame(columns=["nif", "nombre", "primer_apellido", "segundo_apellido", "nombre_completo", "departamento_id"])

    rows = []
    for e in data:
        nombre = e.get("name") or e.get("nombre") or ""
        pa = e.get("primer_apellido") or ""
        sa = e.get("segundo_apellido") or ""

        # fallback si viene "apellidos"
        if not (pa or sa) and e.get("apellidos"):
            parts = str(e.get("apellidos")).split()
            pa = parts[0] if len(parts) > 0 else ""
            sa = " ".join(parts[1:]) if len(parts) > 1 else ""

        nombre_completo = f"{nombre} {pa} {sa}".strip()

        rows.append({
            "nif": e.get("nif"),
            "nombre": nombre,
            "primer_apellido": pa,
            "segundo_apellido": sa,
            "nombre_completo": nombre_completo,
            "departamento_id": e.get("departamento"),
        })

    df = pd.DataFrame(rows)
    df = df.dropna(subset=["nif"])
    df["nif"] = df["nif"].astype(str)
    return df


def api_exportar_fichajes_un_nif(nif: str, fi: str, ff: str):
    """
    Devuelve lista de fichajes (descifrada) para un nif.
    En error: [].
    """
    session = get_session()
    url = f"{API_URL_BASE}/exportacion/fichajes"
    data = {
        "fecha_inicio": fi,
        "fecha_fin": ff,
        "nif": nif,
        "order": "desc",
    }
    try:
        raw = post_and_decrypt(session, url, data=data, timeout=25)
        if not raw:
            return []
        return raw
    except Exception:
        return []


# ============================================================
# PERMISOS / VACACIONES
# ============================================================

def api_exportar_vacaciones(fi: str, ff: str, nifs: list[str] | None = None):
    """
    Exportación /exportacion/vacaciones (cubre vacaciones/asuntos propios, NO permisos horarios tipo hospitalización)
    """
    session = get_session()
    url = f"{API_URL_BASE}/exportacion/vacaciones"
    data = {"fecha_inicio": fi, "fecha_fin": ff}
    if nifs:
        data["nifs"] = json.dumps(nifs)  # algunos backends esperan array; json string suele funcionar
    try:
        raw = post_and_decrypt(session, url, data=data, timeout=60)
        return raw if raw else []
    except Exception:
        return []


def try_api_exportar_permisos(fi: str, ff: str, nifs: list[str] | None = None):
    """
    El manual NO documenta exportación de permisos, pero en vuestra instancia puede existir.
    Probamos rutas típicas sin romper la app.
    Debe devolver permisos con fecha_inicio/fecha_fin con H:i:s para calcular horas.
    """
    session = get_session()

    candidate_paths = [
        "/exportacion/permisos",
        "/exportacion/permiso",
        "/exportacion/permisos-horas",
        "/exportacion/ausencias",
        "/exportacion/incidencias",
    ]

    payload = {"fecha_inicio": fi, "fecha_fin": ff}
    if nifs:
        payload["nifs"] = json.dumps(nifs)

    for p in candidate_paths:
        url = f"{API_URL_BASE}{p}"
        try:
            raw = post_and_decrypt(session, url, data=payload, timeout=60)
            if isinstance(raw, list):
                return raw, p
        except Exception:
            continue

    return None, None


def permisos_por_dia(fi: str, ff: str, empleados_df: pd.DataFrame):
    """
    Devuelve:
      - df_permisos: Fecha, nif, Horas permiso (seconds), Permiso (texto)
      - flag_permisos_horarios: bool (si hemos conseguido permisos con horas por día)
      - source: endpoint usado (si existe)
    """
    nifs = empleados_df["nif"].dropna().astype(str).tolist()

    # 1) Intentar permisos horarios (si existe en vuestra API)
    permisos_raw, endpoint = try_api_exportar_permisos(fi, ff, nifs=nifs)

    if permisos_raw:
        rows = []
        rango_ini = datetime.strptime(fi, "%Y-%m-%d").date()
        rango_fin = datetime.strptime(ff, "%Y-%m-%d").date()

        for it in permisos_raw:
            # Intentos robustos de localizar nif y fechas
            usuario = it.get("usuario") or {}
            nif = (
                it.get("nif")
                or usuario.get("Nif")
                or usuario.get("nif")
                or usuario.get("NIF")
            )
            if not nif:
                continue
            nif = str(nif)

            f_ini = it.get("fecha_inicio") or it.get("inicio") or it.get("from")
            f_fin = it.get("fecha_fin") or it.get("fin") or it.get("hasta") or it.get("to")
            if not f_ini or not f_fin:
                continue

            # Permiso name
            tipo_obj = it.get("tipo_obj") or it.get("tipo") or {}
            permiso_nombre = None
            if isinstance(tipo_obj, dict):
                permiso_nombre = tipo_obj.get("nombre") or tipo_obj.get("descripcion")
            if not permiso_nombre and isinstance(it.get("tipo"), (int, str)):
                permiso_nombre = f"Tipo {it.get('tipo')}"
            if not permiso_nombre:
                permiso_nombre = "Permiso"

            # Estado (si existe)
            estado = it.get("estado")
            if estado is not None:
                permiso_nombre = f"{permiso_nombre} (estado {estado})"

            # Parse datetimes
            dt_ini = pd.to_datetime(f_ini, errors="coerce")
            dt_fin = pd.to_datetime(f_fin, errors="coerce")
            if pd.isna(dt_ini) or pd.isna(dt_fin):
                continue
            if dt_fin <= dt_ini:
                continue

            # repartir horas por día (solape)
            start_date = max(dt_ini.date(), rango_ini)
            end_date = min(dt_fin.date(), rango_fin)

            cur = start_date
            while cur <= end_date:
                day_start = datetime.combine(cur, datetime.min.time())
                day_end = datetime.combine(cur, datetime.max.time()).replace(microsecond=0)

                seg_start = max(dt_ini.to_pydatetime(), day_start)
                seg_end = min(dt_fin.to_pydatetime(), day_end)

                if seg_end > seg_start:
                    seconds = (seg_end - seg_start).total_seconds()
                    rows.append({
                        "Fecha": cur.strftime("%Y-%m-%d"),
                        "nif": nif,
                        "permiso_seconds": seconds,
                        "Permiso": permiso_nombre
                    })
                cur += timedelta(days=1)

        if rows:
            dfp = pd.DataFrame(rows)
            dfp = dfp.groupby(["Fecha", "nif"], as_index=False).agg(
                permiso_seconds=("permiso_seconds", "sum"),
                Permiso=("Permiso", lambda s: " + ".join(sorted(set(map(str, s)))))
            )
            return dfp, True, endpoint

        # Si endpoint existía pero no hay filas, devolvemos vacío pero “horario disponible”
        return pd.DataFrame(columns=["Fecha", "nif", "permiso_seconds", "Permiso"]), True, endpoint

    # 2) Fallback: vacaciones/asuntos propios (NO permisos horarios)
    vac = api_exportar_vacaciones(fi, ff, nifs=nifs)
    if not vac:
        return pd.DataFrame(columns=["Fecha", "nif", "permiso_seconds", "Permiso"]), False, None

    # Las vacaciones exportadas van por días (días_laborables). NO hay horas por día en el manual.
    # Para no inventar horas (y evitar “8:30” falsas), aquí SOLO marcamos el texto del permiso,
    # y dejamos horas en 0.
    rows = []
    rango_ini = datetime.strptime(fi, "%Y-%m-%d").date()
    rango_fin = datetime.strptime(ff, "%Y-%m-%d").date()

    tipo_map = {
        1: "Vacaciones",
        2: "Asuntos propios",
        8: "Asuntos propios (año anterior)",
        9: "Vacaciones (año anterior)",
        10: "Vacaciones (año siguiente)",
    }
    estado_map = {
        0: "Pendientes",
        1: "Aprobadas",
        2: "Denegadas",
        3: "Canceladas empleado",
        4: "Denegación extraordinaria",
        5: "Solicitada cancelación",
        6: "Pendientes administrador",
    }

    for v in vac:
        usuario = v.get("usuario") or {}
        nif = usuario.get("Nif") or usuario.get("nif") or v.get("nif")
        if not nif:
            continue
        nif = str(nif)

        f_ini = v.get("fecha_inicio")
        f_fin = v.get("fecha_fin")
        if not f_ini or not f_fin:
            continue

        try:
            d_ini = datetime.strptime(f_ini, "%Y-%m-%d").date()
            d_fin = datetime.strptime(f_fin, "%Y-%m-%d").date()
        except Exception:
            continue

        d_ini = max(d_ini, rango_ini)
        d_fin = min(d_fin, rango_fin)

        tipo_txt = tipo_map.get(v.get("tipo"), f"Tipo {v.get('tipo')}")
        estado_txt = estado_map.get(v.get("estado"), f"Estado {v.get('estado')}")
        label = f"{tipo_txt} ({estado_txt})"

        cur = d_ini
        while cur <= d_fin:
            rows.append({
                "Fecha": cur.strftime("%Y-%m-%d"),
                "nif": nif,
                "permiso_seconds": 0.0,  # no inventamos horas
                "Permiso": label
            })
            cur += timedelta(days=1)

    if not rows:
        return pd.DataFrame(columns=["Fecha", "nif", "permiso_seconds", "Permiso"]), False, None

    dfp = pd.DataFrame(rows)
    dfp = dfp.groupby(["Fecha", "nif"], as_index=False).agg(
        permiso_seconds=("permiso_seconds", "sum"),
        Permiso=("Permiso", lambda s: " + ".join(sorted(set(map(str, s)))))
    )
    return dfp, False, None


# ============================================================
# CÁLCULO DE TRABAJO POR DÍA (ENTRADA->SALIDA)
# ============================================================

def calcular_trabajo_diario(df_fichajes: pd.DataFrame) -> pd.DataFrame:
    """
    Entrada: df con columnas [nif, nombre_completo, departamento_nombre, fecha_dt, fecha_dia, direccion, id]
    Salida: resumen diario con:
      [nif, Nombre Completo, Departamento, Fecha, worked_seconds, Numero de fichajes]
    """
    if df_fichajes.empty:
        return pd.DataFrame(columns=[
            "nif", "Nombre Completo", "Departamento", "Fecha",
            "worked_seconds", "Numero de fichajes"
        ])

    df = df_fichajes.copy()
    df = df.sort_values(["nif", "fecha_dt"], ascending=[True, True])

    def work_seconds_for_group(g: pd.DataFrame) -> float:
        # g ordenado por fecha_dt
        times = g["fecha_dt"].tolist()
        dirs = g["direccion"].astype(str).str.lower().tolist()
        total = 0.0
        i = 0
        n = len(g)
        while i < n - 1:
            if dirs[i] == "entrada" and dirs[i + 1] == "salida":
                dt1 = times[i]
                dt2 = times[i + 1]
                if pd.notna(dt1) and pd.notna(dt2) and dt2 > dt1:
                    total += (dt2 - dt1).total_seconds()
                i += 2
            else:
                i += 1
        return total

    # Número de fichajes = número de registros del día (count)
    agg = df.groupby(["nif", "fecha_dia"], as_index=False).agg(
        worked_seconds=("fecha_dt", lambda _: 0.0),
        Numero_de_fichajes=("id", "count"),
        nombre_completo=("nombre_completo", "first"),
        departamento_nombre=("departamento_nombre", "first"),
    )

    # Recalcular worked_seconds con apply por grupo (más exacto)
    worked = df.groupby(["nif", "fecha_dia"], sort=False).apply(work_seconds_for_group).reset_index()
    worked.columns = ["nif", "fecha_dia", "worked_seconds"]
    agg = agg.drop(columns=["worked_seconds"]).merge(worked, on=["nif", "fecha_dia"], how="left")
    agg["worked_seconds"] = agg["worked_seconds"].fillna(0.0)

    agg = agg.rename(columns={
        "fecha_dia": "Fecha",
        "nombre_completo": "Nombre Completo",
        "departamento_nombre": "Departamento",
        "Numero_de_fichajes": "Numero de fichajes",
    })

    return agg[["nif", "Nombre Completo", "Departamento", "Fecha", "worked_seconds", "Numero de fichajes"]]


# ============================================================
# REGLAS DE VALIDACIÓN
# ============================================================

def calcular_minimos(depto: str, weekday: int):
    """
    weekday: 0=Lunes ... 6=Domingo
    """
    d = (depto or "").strip().upper()

    if d in ["ESTRUCTURA", "MOI"]:
        if weekday in [0, 1, 2, 3]:
            return 8.5, 4
        if weekday == 4:
            return 6.5, 2
        return None, None

    if d == "MOD":
        if weekday in [0, 1, 2, 3, 4]:
            return 8.0, 2
        return None, None

    return None, None


def validar_fila(row) -> str | None:
    """
    - Solo devuelve motivo si NO cumple o si “fichajes excesivos cumpliendo horas”.
    - Si depto/día sin reglas -> None
    """
    depto = (row.get("Departamento") or "").strip().upper()
    weekday = int(row.get("weekday"))
    min_h, min_f = calcular_minimos(depto, weekday)
    if min_h is None or min_f is None:
        return None

    horas_totales = float(row.get("horas_totales", 0.0))
    fich = int(row.get("Numero de fichajes", 0))

    motivos = []

    if horas_totales < min_h:
        motivos.append(f"Horas totales insuficientes (mín {min_h}h, tiene {horas_totales:.2f}h)")
    if fich < min_f:
        motivos.append(f"Fichajes insuficientes (mín {min_f}, tiene {fich})")

    # Aviso extra: cumple horas pero tiene MÁS fichajes que el mínimo
    if horas_totales >= min_h and fich > min_f:
        motivos.append(f"Fichajes excesivos (mín {min_f}, tiene {fich})")

    return "; ".join(motivos) if motivos else None


# ============================================================
# UI
# ============================================================

st.set_page_config(page_title="Fichajes CRECE", layout="wide")
st.title("📊 Fichajes CRECE Personas")

hoy = date.today()

col1, col2 = st.columns(2)
with col1:
    fecha_inicio = st.date_input("Fecha inicio", value=hoy, max_value=hoy)
with col2:
    fecha_fin = st.date_input("Fecha fin", value=hoy, max_value=hoy)

st.write("---")

if st.button("▶ Obtener resumen (incidencias)"):
    if fecha_inicio > fecha_fin:
        st.error("❌ La fecha inicio no puede ser posterior a la fecha fin.")
        st.stop()
    if fecha_fin > hoy:
        st.error("❌ La fecha fin no puede ser mayor que hoy.")
        st.stop()

    fi = fecha_inicio.strftime("%Y-%m-%d")
    ff = fecha_fin.strftime("%Y-%m-%d")

    with st.spinner("Cargando empleados y departamentos…"):
        departamentos_df = api_exportar_departamentos_cached()
        empleados_df = api_exportar_empleados_cached()

        empleados_df = empleados_df.merge(
            departamentos_df,
            on="departamento_id",
            how="left"
        )

        # normalizamos nombres
        empleados_df["departamento_nombre"] = empleados_df["departamento_nombre"].fillna("")
        empleados_df["nombre_completo"] = empleados_df["nombre_completo"].fillna("")
        empleados_df = empleados_df.dropna(subset=["nif"])
        empleados_df["nif"] = empleados_df["nif"].astype(str)

    # 1) Fichajes en paralelo
    with st.spinner("Obteniendo fichajes…"):
        fichajes_rows = []

        # Control de saturación: MAX_WORKERS muy alto puede empeorar si el servidor limita.
        # Respetamos tu requisito, pero ajustamos a un límite razonable si el entorno es pequeño.
        # (Si realmente quieres 1000 sí o sí, elimina el min()).
        workers = min(MAX_WORKERS, max(50, len(empleados_df)))
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {
                ex.submit(api_exportar_fichajes_un_nif, row["nif"], fi, ff): row
                for _, row in empleados_df.iterrows()
            }

            for fut in as_completed(futures):
                emp = futures[fut]
                fichajes = fut.result() or []
                for f in fichajes:
                    fichajes_rows.append({
                        "nif": emp["nif"],
                        "nombre_completo": emp["nombre_completo"],
                        "departamento_nombre": emp["departamento_nombre"],
                        "id": f.get("id"),
                        "fecha": f.get("fecha"),
                        "direccion": f.get("direccion"),
                    })

        if fichajes_rows:
            df_f = pd.DataFrame(fichajes_rows)
            df_f["fecha_dt"] = pd.to_datetime(df_f["fecha"], format="%Y-%m-%d %H:%M:%S", errors="coerce")
            df_f = df_f.dropna(subset=["fecha_dt"])
            df_f["fecha_dia"] = df_f["fecha_dt"].dt.strftime("%Y-%m-%d")
        else:
            df_f = pd.DataFrame(columns=["nif", "nombre_completo", "departamento_nombre", "id", "fecha_dt", "fecha_dia", "direccion"])

    # 2) Resumen diario de trabajo
    resumen = calcular_trabajo_diario(df_f)

    # 3) Permisos por día (ideal: permisos horarios; fallback: vacaciones sin horas)
    with st.spinner("Obteniendo permisos/vacaciones…"):
        df_perm, permisos_horarios_disponibles, endpoint_perm = permisos_por_dia(fi, ff, empleados_df)

    if not permisos_horarios_disponibles:
        st.warning(
            "⚠️ En el manual no existe exportación de permisos horarios (solo vacaciones/asuntos propios). "
            "He añadido vacaciones/asuntos propios como texto, pero 'Horas permiso' será 00:00 "
            "para permisos tipo 'Hospitalización familiar' / 'bolsa de horas' si no existe un endpoint de exportación en vuestra instancia."
        )
    else:
        st.caption(f"Permisos horarios obtenidos desde: {endpoint_perm}")

    # 4) Asegurar que salen también días con permiso aunque no haya fichajes
    if not df_perm.empty:
        # unir datos de empleado
        meta = empleados_df[["nif", "nombre_completo", "departamento_nombre"]].copy()
        meta = meta.rename(columns={"nombre_completo": "Nombre Completo", "departamento_nombre": "Departamento"})
        df_perm2 = df_perm.merge(meta, on="nif", how="left")

        # filas resumen existentes
        if resumen.empty:
            resumen = pd.DataFrame(columns=["nif", "Nombre Completo", "Departamento", "Fecha", "worked_seconds", "Numero de fichajes"])

        claves_res = resumen[["nif", "Fecha"]].drop_duplicates()
        claves_perm = df_perm2[["nif", "Fecha"]].drop_duplicates()

        faltan = claves_perm.merge(claves_res, on=["nif", "Fecha"], how="left", indicator=True)
        faltan = faltan[faltan["_merge"] == "left_only"][["nif", "Fecha"]]

        if not faltan.empty:
            faltan = faltan.merge(meta, on="nif", how="left")
            faltan["worked_seconds"] = 0.0
            faltan["Numero de fichajes"] = 0
            resumen = pd.concat([resumen, faltan], ignore_index=True)

    # 5) Merge permisos a resumen
    if resumen.empty:
        st.info("No se encontraron fichajes ni permisos en el rango seleccionado.")
        st.stop()

    if not df_perm.empty:
        resumen = resumen.merge(df_perm, on=["nif", "Fecha"], how="left")
    else:
        resumen["permiso_seconds"] = 0.0
        resumen["Permiso"] = None

    resumen["permiso_seconds"] = resumen["permiso_seconds"].fillna(0.0)

    # 6) Totales y validación
    resumen["Total trabajado"] = resumen["worked_seconds"].apply(seconds_to_hhmm)
    resumen["Horas permiso"] = resumen["permiso_seconds"].apply(seconds_to_hhmm)
    resumen["Horas totales"] = (resumen["worked_seconds"] + resumen["permiso_seconds"]).apply(seconds_to_hhmm)

    resumen["horas_totales"] = (resumen["worked_seconds"] + resumen["permiso_seconds"]) / 3600.0
    resumen["weekday"] = pd.to_datetime(resumen["Fecha"]).dt.weekday

    resumen["Motivo"] = resumen.apply(validar_fila, axis=1)

    # Solo incumplimientos (según tu regla)
    out = resumen[resumen["Motivo"].notna()].copy()

    if out.empty:
        st.success("🎉 No hay incidencias en el rango seleccionado.")
        st.stop()

    # Ordenación: Fecha asc, luego Nombre Completo asc
    out = out.sort_values(["Fecha", "Nombre Completo"], ascending=[True, True])

    # 7) Columnas finales (las que pides ahora + motivo)
    out = out[[
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

    st.subheader("📄 Incidencias (solo registros que NO cumplen)")

    # Tablas por fecha
    for f_dia in out["Fecha"].unique():
        st.markdown(f"### 📅 Fecha {f_dia}")
        sub = out[out["Fecha"] == f_dia].copy()

        # Tabla solo lectura (sin añadir filas)
        st.data_editor(
            sub,
            use_container_width=True,
            hide_index=True,
            disabled=True,
            num_rows="fixed"
        )

    # CSV
    csv_bytes = out.to_csv(index=False).encode("utf-8")
    st.download_button(
        "⬇ Descargar CSV (incidencias)",
        csv_bytes,
        file_name="fichajes_incidencias.csv",
        mime="text/csv"
    )
