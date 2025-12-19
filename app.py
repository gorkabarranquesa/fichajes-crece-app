import base64
import json
import multiprocessing
from datetime import date, datetime, timedelta
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

CPU = multiprocessing.cpu_count()
MAX_WORKERS = max(8, min(24, CPU * 3))  # rápido sin saturar API

HTTP_TIMEOUT = (5, 25)  # (connect, read)

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
    # Deliberadamente no logueamos detalles (evita filtraciones)
    return None


# ============================================================
# DESCIFRADO CRECE (AES-CBC)
# ============================================================

def decrypt_crece_payload(payload_b64: str, app_key_b64: str) -> str:
    json_raw = base64.b64decode(payload_b64).decode("utf-8")
    payload = json.loads(json_raw)

    iv = base64.b64decode(payload["iv"])
    ct = base64.b64decode(payload["value"])
    key = base64.b64decode(app_key_b64)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ct), AES.block_size)
    return decrypted.decode("utf-8")


def _extract_payload_b64(resp: requests.Response) -> str:
    return (resp.text or "").strip().strip('"').strip()


# ============================================================
# FORMATEOS TIEMPO
# ============================================================

def horas_a_hhmm(horas: float) -> str:
    if horas is None or pd.isna(horas):
        return "00:00"
    total_min = int(round(float(horas) * 60))
    h = total_min // 60
    m = total_min % 60
    return f"{h:02d}:{m:02d}"


def segundos_a_hhmm(seg: float) -> str:
    if seg is None or pd.isna(seg):
        return "00:00"
    seg = max(0, int(round(float(seg))))
    m = seg // 60
    h = m // 60
    mm = m % 60
    return f"{h:02d}:{mm:02d}"


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
    # PII -> NO cache
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


@st.cache_data(show_spinner=False, ttl=3600)
def api_exportar_tipos_fichaje() -> dict:
    """
    Devuelve dict: {tipo_id: {descuenta_tiempo, entrada, turno_nocturno}}
    Cache 1h (no PII).
    """
    url = f"{API_URL_BASE}/exportacion/tipos-fichaje"
    try:
        resp = _SESSION.post(url, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()

        payload_b64 = _extract_payload_b64(resp)
        decrypted = decrypt_crece_payload(payload_b64, APP_KEY_B64)
        tipos = json.loads(decrypted)

        out = {}
        if isinstance(tipos, list):
            for t in tipos:
                tid = t.get("id")
                if tid is None:
                    continue
                out[int(tid)] = {
                    "descuenta_tiempo": int(t.get("descuenta_tiempo") or 0),
                    "entrada": int(t.get("entrada") or 0),
                    "turno_nocturno": int(t.get("turno_nocturno") or 0),
                    "nombre": t.get("nombre") or "",
                }
        return out
    except Exception as e:
        _safe_fail(e)
        return {}


def api_exportar_fichajes(nif: str, fi: str, ff: str) -> list:
    url = f"{API_URL_BASE}/exportacion/fichajes"
    data = {
        "fecha_inicio": fi,
        "fecha_fin": ff,
        "nif": nif,
        "order": "asc",  # mejor para calcular tramos
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


def api_exportar_vacaciones(fi: str, ff: str, nifs: list[str]) -> list:
    """
    Vacaciones/Asuntos propios por días (NO horas).
    Permite filtrar por nifs (opcional según manual).
    """
    url = f"{API_URL_BASE}/exportacion/vacaciones"
    data = {
        "fecha_inicio": fi,
        "fecha_fin": ff,
        "nifs": nifs,  # según manual es opcional; si falla lo gestionamos
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
        # Intento sin nifs por si ese parámetro no está habilitado en vuestra instancia
        try:
            data2 = {"fecha_inicio": fi, "fecha_fin": ff}
            resp2 = _SESSION.post(url, data=data2, timeout=HTTP_TIMEOUT)
            resp2.raise_for_status()
            payload_b64 = _extract_payload_b64(resp2)
            if not payload_b64:
                return []
            decrypted = decrypt_crece_payload(payload_b64, APP_KEY_B64)
            out = json.loads(decrypted)
            return out if isinstance(out, list) else []
        except Exception as e2:
            _safe_fail(e2)
            return []


# ============================================================
# LÓGICA: asignar "día" (manejo básico turno nocturno)
# ============================================================

def ajustar_fecha_dia(fecha_dt: pd.Timestamp, turno_nocturno: int) -> str:
    """
    Heurística conservadora:
    - Si turno_nocturno=1 y el fichaje es de madrugada, lo asociamos al día anterior.
    Esto suele acercar el resultado a “cambio de día” que aplica CRECE.
    """
    if turno_nocturno == 1 and fecha_dt.hour < 6:
        return (fecha_dt.date() - timedelta(days=1)).strftime("%Y-%m-%d")
    return fecha_dt.date().strftime("%Y-%m-%d")


# ============================================================
# CÁLCULO TIEMPO TRABAJADO (con descuento_tiempo y nocturno)
# ============================================================

def calcular_tiempos(df: pd.DataFrame, tipos_map: dict) -> pd.DataFrame:
    """
    Devuelve df con:
    - segundos_sumados: suma de tramos "entrada->salida" normales
    - segundos_descontados: suma de tramos cuya entrada tiene descuenta_tiempo=1
    - segundos_neto: sumados - descontados

    Nota: usamos la propiedad del TIPO del fichaje de entrada del tramo.
    """
    if df.empty:
        return df

    df = df.copy()
    df["segundos_sumados"] = 0
    df["segundos_descontados"] = 0
    df["segundos_neto"] = 0

    rows_out = []

    for nif in df["nif"].unique():
        sub_emp = df[df["nif"] == nif].copy()

        for fecha_dia in sub_emp["fecha_dia"].unique():
            sub = sub_emp[sub_emp["fecha_dia"] == fecha_dia].copy()
            sub = sub.sort_values("fecha_dt")

            sumados = 0
            descontados = 0

            i = 0
            n = len(sub)

            while i < n:
                row_i = sub.iloc[i].copy()
                row_i["segundos_sumados"] = sumados
                row_i["segundos_descontados"] = descontados
                row_i["segundos_neto"] = sumados - descontados

                if i < n - 1:
                    row_j = sub.iloc[i + 1].copy()

                    if row_i.get("direccion") == "entrada" and row_j.get("direccion") == "salida":
                        delta = (row_j["fecha_dt"] - row_i["fecha_dt"]).total_seconds()
                        if delta < 0:
                            rows_out.append(row_i)
                            i += 1
                            continue

                        tipo_id = row_i.get("tipo")
                        props = tipos_map.get(int(tipo_id), {}) if tipo_id is not None else {}

                        if int(props.get("descuenta_tiempo", 0)) == 1:
                            descontados += int(round(delta))
                        else:
                            sumados += int(round(delta))

                        row_i["segundos_sumados"] = sumados
                        row_i["segundos_descontados"] = descontados
                        row_i["segundos_neto"] = sumados - descontados
                        rows_out.append(row_i)

                        row_j = row_j.copy()
                        row_j["segundos_sumados"] = sumados
                        row_j["segundos_descontados"] = descontados
                        row_j["segundos_neto"] = sumados - descontados
                        rows_out.append(row_j)

                        i += 2
                        continue

                rows_out.append(row_i)
                i += 1

    out = pd.DataFrame(rows_out).sort_values(["fecha_dt", "nif"], kind="mergesort")
    return out


# ============================================================
# VACACIONES -> bandera por día (sin horas)
# ============================================================

def map_tipo_vacaciones(tipo: int) -> str:
    mapping = {
        1: "Vacaciones",
        2: "Asuntos propios",
        8: "Asuntos propios año anterior",
        9: "Vacaciones año anterior",
        10: "Vacaciones año siguiente",
    }
    return mapping.get(int(tipo) if tipo is not None else -1, f"Tipo {tipo}")


def expandir_vacaciones_a_dias(vacs: list, fi: str, ff: str) -> pd.DataFrame:
    if not vacs:
        return pd.DataFrame(columns=["nif", "Fecha", "Vacaciones_detalle", "Tiene vacaciones"])

    rango_ini = datetime.strptime(fi, "%Y-%m-%d").date()
    rango_fin = datetime.strptime(ff, "%Y-%m-%d").date()

    filas = []
    for v in vacs:
        usuario = v.get("usuario", {}) or {}
        nif = usuario.get("Nif") or usuario.get("nif")
        if not nif:
            continue
        nif = str(nif).upper().strip()

        try:
            f_ini = datetime.strptime(v["fecha_inicio"], "%Y-%m-%d").date()
            f_fin = datetime.strptime(v["fecha_fin"], "%Y-%m-%d").date()
        except Exception:
            continue

        current = max(f_ini, rango_ini)
        last = min(f_fin, rango_fin)
        if current > last:
            continue

        texto = map_tipo_vacaciones(v.get("tipo")) + f" (estado {v.get('estado')})"
        while current <= last:
            filas.append(
                {
                    "nif": nif,
                    "Fecha": current.strftime("%Y-%m-%d"),
                    "Vacaciones_detalle": texto,
                    "Tiene vacaciones": True,
                }
            )
            current += timedelta(days=1)

    if not filas:
        return pd.DataFrame(columns=["nif", "Fecha", "Vacaciones_detalle", "Tiene vacaciones"])

    dfv = pd.DataFrame(filas)
    dfv = dfv.groupby(["nif", "Fecha"], as_index=False).agg(
        Vacaciones_detalle=("Vacaciones_detalle", lambda s: " + ".join(sorted(set(s)))),
        Tiene_vacaciones=("Tiene vacaciones", "max"),
    )
    dfv = dfv.rename(columns={"Tiene_vacaciones": "Tiene vacaciones"})
    return dfv


# ============================================================
# REGLAS DE JORNADA (validación base)
# ============================================================

def calcular_minimos(depto: str, dia: int):
    depto = (depto or "").upper().strip()

    if depto in ["ESTRUCTURA", "MOI"]:
        if dia in [0, 1, 2, 3]:  # L-J
            return 8.5, 4
        if dia == 4:  # V
            return 6.5, 2
        return None, None

    if depto == "MOD":
        if dia in [0, 1, 2, 3, 4]:  # L-V
            return 8.0, 2
        return None, None

    return None, None


def validar_incidencia(r):
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
# UI STREAMLIT (mínima)
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

if st.button("Consultar"):
    if fecha_inicio > fecha_fin:
        st.error("❌ La fecha inicio no puede ser posterior a la fecha fin.")
        st.stop()

    if fecha_fin > hoy:
        st.error("❌ La fecha fin no puede ser mayor que hoy.")
        st.stop()

    fi = fecha_inicio.strftime("%Y-%m-%d")
    ff = fecha_fin.strftime("%Y-%m-%d")

    with st.spinner("Procesando…"):
        try:
            tipos_map = api_exportar_tipos_fichaje()
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

        # Fichajes en paralelo (si un empleado falla, se continúa)
        fichajes_rows = []
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
                                "Nombre": emp["nombre_completo"],
                                "Departamento": emp.get("departamento_nombre"),
                                "id": x.get("id"),
                                "tipo": x.get("tipo"),
                                "direccion": x.get("direccion"),
                                "fecha": x.get("fecha"),
                            }
                        )
                    except Exception:
                        continue

        if not fichajes_rows:
            st.info("No se encontraron fichajes en el rango seleccionado.")
            st.stop()

        df = pd.DataFrame(fichajes_rows)
        df["nif"] = df["nif"].astype(str).str.upper().str.strip()
        df["fecha_dt"] = pd.to_datetime(df["fecha"], errors="coerce")
        df = df.dropna(subset=["fecha_dt"])

        # día ajustado (turno nocturno si aplica)
        def _dia_row(r):
            props = tipos_map.get(int(r["tipo"]), {}) if pd.notna(r.get("tipo")) else {}
            return ajustar_fecha_dia(r["fecha_dt"], int(props.get("turno_nocturno", 0)))

        df["fecha_dia"] = df.apply(_dia_row, axis=1)

        # cálculo tiempos netos
        df = calcular_tiempos(df, tipos_map)

        # nº fichajes por día
        df["Numero"] = df.groupby(["nif", "fecha_dia"])["id"].transform("count")

        # resumen diario (neto)
        resumen = (
            df.groupby(["nif", "Nombre", "Departamento", "fecha_dia"], as_index=False)
            .agg(
                segundos_neto=("segundos_neto", "max"),
                fichajes=("Numero", "max"),
            )
        )
        resumen = resumen.rename(
            columns={
                "fecha_dia": "Fecha",
                "fichajes": "Numero de fichajes",
            }
        )

        resumen["Total trabajado"] = resumen["segundos_neto"].apply(segundos_a_hhmm)
        resumen["horas_dec"] = resumen["Total trabajado"].apply(hhmm_to_dec)
        resumen["dia"] = pd.to_datetime(resumen["Fecha"]).dt.weekday

        resumen[["min_horas", "min_fichajes"]] = resumen.apply(
            lambda r: pd.Series(calcular_minimos(r.get("Departamento"), int(r["dia"]))),
            axis=1,
        )

        resumen["Incidencia"] = resumen.apply(validar_incidencia, axis=1)

        # Vacaciones (bandera por día, sin horas)
        nifs = resumen["nif"].dropna().astype(str).str.upper().str.strip().unique().tolist()
        vacs = api_exportar_vacaciones(fi, ff, nifs)
        df_vac = expandir_vacaciones_a_dias(vacs, fi, ff)

        resumen = resumen.merge(df_vac, on=["nif", "Fecha"], how="left")
        resumen["Tiene vacaciones"] = resumen["Tiene vacaciones"].fillna(False)

        # Mostrar solo lo necesario: incidencias o vacaciones
        salida = resumen[(resumen["Incidencia"].notna()) | (resumen["Tiene vacaciones"] == True)].copy()

        if salida.empty:
            st.success("🎉 No hay incidencias ni vacaciones en el rango seleccionado.")
            st.stop()

        salida["Vacaciones_detalle"] = salida["Vacaciones_detalle"].fillna("")

        salida = salida[
            [
                "Fecha",
                "Nombre",
                "Departamento",
                "Total trabajado",
                "Numero de fichajes",
                "Tiene vacaciones",
                "Vacaciones_detalle",
                "Incidencia",
            ]
        ].sort_values(["Fecha", "Nombre"], kind="mergesort")

    st.subheader("📄 Resultado")

    for f_dia in salida["Fecha"].unique():
        st.markdown(f"### 📅 {f_dia}")
        sub = salida[salida["Fecha"] == f_dia]
        st.data_editor(
            sub,
            use_container_width=True,
            hide_index=True,
            disabled=True,
            num_rows="fixed",
        )

    csv = salida.to_csv(index=False).encode("utf-8")
    st.download_button(
        "⬇ Descargar CSV",
        csv,
        "fichajes_resultado.csv",
        "text/csv",
    )
