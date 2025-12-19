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
MAX_WORKERS = max(8, min(24, CPU * 3))
HTTP_TIMEOUT = (5, 25)

_SESSION = requests.Session()
_SESSION.headers.update(
    {"Accept": "application/json", "Authorization": f"Bearer {API_TOKEN}"}
)

# ============================================================
# SEGURIDAD: no loguear detalles (PII, tokens, payloads)
# ============================================================

def _safe_fail(_exc: Exception) -> None:
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

def segundos_a_hhmm(seg: float) -> str:
    if seg is None or pd.isna(seg):
        return ""
    seg = max(0, int(round(float(seg))))
    total_min = seg // 60
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
    url = f"{API_URL_BASE}/exportacion/departamentos"
    resp = _SESSION.get(url, timeout=HTTP_TIMEOUT)
    resp.raise_for_status()

    payload_b64 = _extract_payload_b64(resp)
    decrypted = decrypt_crece_payload(payload_b64, APP_KEY_B64)
    departamentos = json.loads(decrypted)

    return pd.DataFrame(
        [{"departamento_id": d.get("id"), "departamento_nombre": d.get("nombre")}
         for d in (departamentos or [])]
    )


def api_exportar_empleados_completos() -> pd.DataFrame:
    url = f"{API_URL_BASE}/exportacion/empleados"
    data = {"solo_nif": 0}

    resp = _SESSION.post(url, data=data, timeout=HTTP_TIMEOUT)
    resp.raise_for_status()

    payload_b64 = _extract_payload_b64(resp)
    decrypted = decrypt_crece_payload(payload_b64, APP_KEY_B64)
    empleados = json.loads(decrypted)

    lista = []
    for e in (empleados or []):
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

    df = pd.DataFrame(lista)
    if not df.empty:
        df["nif"] = df["nif"].astype(str).str.upper().str.strip()
    return df


@st.cache_data(show_spinner=False, ttl=3600)
def api_exportar_tipos_fichaje() -> dict:
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
                    "turno_nocturno": int(t.get("turno_nocturno") or 0),
                }
        return out
    except Exception as e:
        _safe_fail(e)
        return {}


def api_exportar_fichajes(nif: str, fi: str, ff: str) -> list:
    url = f"{API_URL_BASE}/exportacion/fichajes"
    data = {"fecha_inicio": fi, "fecha_fin": ff, "nif": nif, "order": "asc"}

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


def _parse_tiempo_trabajado_payload(parsed) -> pd.DataFrame:
    filas = []

    def add_row(nif_key: str, obj):
        nif_key = (str(nif_key) or "").upper().strip()
        if not nif_key:
            return

        if isinstance(obj, dict):
            filas.append(
                {
                    "nif": str(obj.get("nif") or nif_key).upper().strip(),
                    "tiempoEfectivo_seg": obj.get("tiempoEfectivo"),
                    "tiempoContabilizado_seg": obj.get("tiempoContabilizado"),
                }
            )
            return

        if isinstance(obj, list):
            if len(obj) > 0 and isinstance(obj[0], dict):
                for it in obj:
                    filas.append(
                        {
                            "nif": str(it.get("nif") or nif_key).upper().strip(),
                            "tiempoEfectivo_seg": it.get("tiempoEfectivo"),
                            "tiempoContabilizado_seg": it.get("tiempoContabilizado"),
                        }
                    )
                return

            nums = [x for x in obj if isinstance(x, (int, float)) or (isinstance(x, str) and str(x).isdigit())]
            tef = nums[-2] if len(nums) >= 2 else None
            tco = nums[-1] if len(nums) >= 2 else None
            filas.append(
                {"nif": nif_key, "tiempoEfectivo_seg": tef, "tiempoContabilizado_seg": tco}
            )
            return

        filas.append({"nif": nif_key, "tiempoEfectivo_seg": None, "tiempoContabilizado_seg": None})

    if isinstance(parsed, dict):
        for k, v in parsed.items():
            add_row(k, v)
    elif isinstance(parsed, list):
        for it in parsed:
            if isinstance(it, dict):
                nk = it.get("nif") or it.get("email") or it.get("num_empleado") or ""
                add_row(nk, it)

    df = pd.DataFrame(filas)
    if df.empty:
        return pd.DataFrame(columns=["nif", "tiempoEfectivo_seg", "tiempoContabilizado_seg"])
    df["nif"] = df["nif"].astype(str).str.upper().str.strip()
    return df


def api_exportar_tiempo_trabajado(desde: str, hasta: str, nifs=None, emails=None, nums_empleado=None, nums_ss=None) -> pd.DataFrame:
    url = f"{API_URL_BASE}/exportacion/tiempo-trabajado"

    payload = [("desde", desde), ("hasta", hasta)]

    def add_array(key: str, values):
        if not values:
            return
        for v in values:
            if v is None:
                continue
            s = str(v).strip()
            if s:
                payload.append((key, s))

    add_array("nif[]", nifs)
    add_array("email[]", emails)
    add_array("num_empleado[]", nums_empleado)
    add_array("num_seg_social[]", nums_ss)

    try:
        resp = _SESSION.post(url, data=payload, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()

        payload_b64 = _extract_payload_b64(resp)
        if not payload_b64:
            return pd.DataFrame(columns=["nif", "tiempoEfectivo_seg", "tiempoContabilizado_seg"])

        decrypted = decrypt_crece_payload(payload_b64, APP_KEY_B64)
        parsed = json.loads(decrypted)
        return _parse_tiempo_trabajado_payload(parsed)

    except Exception as e:
        _safe_fail(e)
        return pd.DataFrame(columns=["nif", "tiempoEfectivo_seg", "tiempoContabilizado_seg"])



# ============================================================
# DÍA (turno nocturno)
# ============================================================

def ajustar_fecha_dia(fecha_dt: pd.Timestamp, turno_nocturno: int) -> str:
    if turno_nocturno == 1 and fecha_dt.hour < 6:
        return (fecha_dt.date() - timedelta(days=1)).strftime("%Y-%m-%d")
    return fecha_dt.date().strftime("%Y-%m-%d")


# ============================================================
# TIEMPO POR FICHAJES (neto)
# ============================================================

def calcular_tiempos_neto(df: pd.DataFrame, tipos_map: dict) -> pd.DataFrame:
    rows_out = []
    if df.empty:
        return pd.DataFrame(columns=["nif", "Fecha", "segundos_neto"])

    for nif in df["nif"].unique():
        sub_emp = df[df["nif"] == nif].copy()
        for fecha_dia in sub_emp["fecha_dia"].unique():
            sub = sub_emp[sub_emp["fecha_dia"] == fecha_dia].copy()
            sub = sub.sort_values("fecha_dt")

            sumados = 0
            descontados = 0

            i = 0
            n = len(sub)
            while i < n - 1:
                a = sub.iloc[i]
                b = sub.iloc[i + 1]
                if a.get("direccion") == "entrada" and b.get("direccion") == "salida":
                    delta = (b["fecha_dt"] - a["fecha_dt"]).total_seconds()
                    if delta >= 0:
                        props = tipos_map.get(int(a.get("tipo")), {}) if a.get("tipo") is not None else {}
                        if int(props.get("descuenta_tiempo", 0)) == 1:
                            descontados += int(round(delta))
                        else:
                            sumados += int(round(delta))
                    i += 2
                else:
                    i += 1

            rows_out.append(
                {"nif": nif, "Fecha": fecha_dia, "segundos_neto": max(0, sumados - descontados)}
            )

    return pd.DataFrame(rows_out)


# ============================================================
# REGLAS DE JORNADA
# ============================================================

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


def validar_incidencia(r):
    min_h = r.get("min_horas")
    min_f = r.get("min_fichajes")
    if pd.isna(min_h) or pd.isna(min_f):
        return None

    # DEFENSIVO: nunca KeyError
    num_fich = r.get("Numero de fichajes", 0)
    try:
        num_fich = int(num_fich) if not pd.isna(num_fich) else 0
    except Exception:
        num_fich = 0

    horas_val = r.get("horas_dec_validacion", 0.0)
    try:
        horas_val = float(horas_val) if not pd.isna(horas_val) else 0.0
    except Exception:
        horas_val = 0.0

    motivo = []
    if horas_val < float(min_h):
        motivo.append(f"Horas insuficientes (mín {min_h}h, tiene {horas_val:.2f}h)")
    if num_fich < int(min_f):
        motivo.append(f"Fichajes insuficientes (mín {min_f}, tiene {num_fich})")
    if horas_val >= float(min_h) and num_fich > int(min_f):
        motivo.append(f"Fichajes excesivos (mín {min_f}, tiene {num_fich})")

    return "; ".join(motivo) if motivo else None


# ============================================================
# UI
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

        # Fichajes en paralelo
        fichajes_rows = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as exe:
            futures = {exe.submit(api_exportar_fichajes, r["nif"], fi, ff): r for _, r in empleados_df.iterrows()}
            for fut in as_completed(futures):
                emp = futures[fut]
                for x in (fut.result() or []):
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

        # día ajustado por nocturno
        def _dia_row(r):
            props = tipos_map.get(int(r["tipo"]), {}) if pd.notna(r.get("tipo")) else {}
            return ajustar_fecha_dia(r["fecha_dt"], int(props.get("turno_nocturno", 0)))

        df["fecha_dia"] = df.apply(_dia_row, axis=1)

        # Número de fichajes por día
        df["Numero"] = df.groupby(["nif", "fecha_dia"])["id"].transform("count")

        conteo = (
            df.groupby(["nif", "Nombre", "Departamento", "fecha_dia"], as_index=False)
            .agg(Numero=("Numero", "max"))
            .rename(columns={"fecha_dia": "Fecha", "Numero": "Numero de fichajes"})
        )

        # Tiempo neto por marcajes
        neto = calcular_tiempos_neto(df, tipos_map)
        resumen = conteo.merge(neto, on=["nif", "Fecha"], how="left")
        resumen["segundos_neto"] = resumen["segundos_neto"].fillna(0)
        resumen["Total trabajado"] = resumen["segundos_neto"].apply(segundos_a_hhmm)

        # Tiempo contabilizado: rango completo y por día (doble intento)
        nifs = resumen["nif"].dropna().astype(str).str.upper().str.strip().unique().tolist()

        df_tc_rango = api_exportar_tiempo_trabajado(fi, ff, nifs)
        if not df_tc_rango.empty:
            df_tc_rango["Tiempo Contabilizado (rango)"] = df_tc_rango["tiempoContabilizado_seg"].apply(segundos_a_hhmm)
            df_tc_rango = df_tc_rango[["nif", "Tiempo Contabilizado (rango)"]]
        else:
            df_tc_rango = pd.DataFrame(columns=["nif", "Tiempo Contabilizado (rango)"])

        resumen = resumen.merge(df_tc_rango, on="nif", how="left")

        tc_rows = []
        d0 = datetime.strptime(fi, "%Y-%m-%d").date()
        d1 = datetime.strptime(ff, "%Y-%m-%d").date()

        cur = d0
        while cur <= d1:
            desde = cur.strftime("%Y-%m-%d")

            df_tc = api_exportar_tiempo_trabajado(desde, desde, nifs)
            if df_tc.empty or df_tc["tiempoContabilizado_seg"].isna().all():
                hasta = (cur + timedelta(days=1)).strftime("%Y-%m-%d")
                df_tc = api_exportar_tiempo_trabajado(desde, hasta, nifs)

            if not df_tc.empty:
                df_tc["Fecha"] = desde
                tc_rows.append(df_tc)
            cur += timedelta(days=1)

        if tc_rows:
            tc = pd.concat(tc_rows, ignore_index=True)
            tc["Tiempo Contabilizado"] = tc["tiempoContabilizado_seg"].apply(segundos_a_hhmm)
            tc = tc[["nif", "Fecha", "Tiempo Contabilizado"]]
        else:
            tc = pd.DataFrame(columns=["nif", "Fecha", "Tiempo Contabilizado"])

        resumen = resumen.merge(tc, on=["nif", "Fecha"], how="left")
        resumen["Tiempo Contabilizado"] = resumen["Tiempo Contabilizado"].fillna("")
        resumen["Tiempo Contabilizado (rango)"] = resumen["Tiempo Contabilizado (rango)"].fillna("")

        # Validación
        resumen["dia"] = pd.to_datetime(resumen["Fecha"]).dt.weekday
        resumen[["min_horas", "min_fichajes"]] = resumen.apply(
            lambda r: pd.Series(calcular_minimos(r.get("Departamento"), int(r["dia"]))),
            axis=1,
        )

        resumen["horas_dec_marcajes"] = resumen["Total trabajado"].apply(hhmm_to_dec)
        resumen["horas_dec_contabilizado"] = resumen["Tiempo Contabilizado"].apply(hhmm_to_dec)

        resumen["horas_dec_validacion"] = resumen["horas_dec_marcajes"]
        mask_tc = resumen["Tiempo Contabilizado"].astype(str).str.strip().ne("")
        resumen.loc[mask_tc, "horas_dec_validacion"] = resumen.loc[mask_tc, "horas_dec_contabilizado"]

        resumen["Incidencia"] = resumen.apply(validar_incidencia, axis=1)

        salida = resumen[resumen["Incidencia"].notna()].copy()
        if salida.empty:
            st.success("🎉 No hay incidencias en el rango seleccionado.")
            st.stop()

        salida = salida[
            [
                "Fecha",
                "Nombre",
                "Departamento",
                "Total trabajado",
                "Tiempo Contabilizado",
                "Tiempo Contabilizado (rango)",
                "Numero de fichajes",
                "Incidencia",
            ]
        ].sort_values(["Fecha", "Nombre"], kind="mergesort")

    st.subheader("📄 Incidencias")
    for f_dia in salida["Fecha"].unique():
        st.markdown(f"### 📅 {f_dia}")
        sub = salida[salida["Fecha"] == f_dia]
        st.data_editor(sub, use_container_width=True, hide_index=True, disabled=True, num_rows="fixed")

    csv = salida.to_csv(index=False).encode("utf-8")
    st.download_button("⬇ Descargar CSV", csv, "fichajes_incidencias.csv", "text/csv")
