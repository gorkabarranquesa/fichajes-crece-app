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

# Tolerancia RRHH (±5 min). Aplicamos para "mínimo de horas"
TOLERANCIA_MINUTOS = 5
TOLERANCIA_HORAS = TOLERANCIA_MINUTOS / 60.0

_SESSION = requests.Session()
_SESSION.headers.update({"Accept": "application/json", "Authorization": f"Bearer {API_TOKEN}"})


# ============================================================
# SEGURIDAD: no loguear detalles (PII, tokens, payloads)
# ============================================================

def _safe_fail(_exc: Exception) -> None:
    return None


# ============================================================
# NORMALIZACIÓN NOMBRES (para reglas especiales)
# ============================================================

def norm_name(s: str) -> str:
    if s is None:
        return ""
    # uppercase + colapsar espacios
    return " ".join(str(s).upper().strip().split())


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
# FORMATEOS TIEMPO (TRUNCADO A MINUTO: estilo CRECE)
# ============================================================

def segundos_a_hhmm(seg: float) -> str:
    """
    TRUNCADO a minuto (floor), NO round.
    Evita el +1 minuto por segundos residuales.
    """
    if seg is None or pd.isna(seg):
        return ""
    try:
        seg_i = int(float(seg))
    except Exception:
        return ""
    if seg_i < 0:
        seg_i = 0

    total_min = seg_i // 60  # truncado
    h = total_min // 60
    m = total_min % 60
    return f"{h:02d}:{m:02d}"


def hhmm_to_min(hhmm: str) -> int:
    if not isinstance(hhmm, str) or ":" not in hhmm:
        return 0
    try:
        h, m = map(int, hhmm.split(":"))
        return max(0, h * 60 + m)
    except Exception:
        return 0


def hhmm_to_dec(hhmm: str) -> float:
    return hhmm_to_min(hhmm) / 60.0


def diferencia_hhmm(tc_hhmm: str, tt_hhmm: str) -> str:
    """
    Diferencia = Tiempo Contabilizado - Total trabajado
    - Devuelve "" si son iguales o falta alguno
    - Devuelve +HH:MM o -HH:MM
    """
    tc_hhmm = (tc_hhmm or "").strip()
    tt_hhmm = (tt_hhmm or "").strip()
    if not tc_hhmm or not tt_hhmm:
        return ""

    tc_min = hhmm_to_min(tc_hhmm)
    tt_min = hhmm_to_min(tt_hhmm)

    if tc_min == tt_min:
        return ""

    diff = tc_min - tt_min
    sign = "+" if diff > 0 else "-"
    diff = abs(diff)

    h = diff // 60
    m = diff % 60
    return f"{sign}{h:02d}:{m:02d}"


# ============================================================
# REGLAS ESPECIALES RRHH (NOMBRE + DEPTO)
# ============================================================
# Nota: usa el nombre completo tal cual lo muestra la app (normalizado a MAYÚSCULAS y espacios).
# Si en CRECE el nombre viene diferente, ajustamos aquí sin tocar el resto del código.

SPECIAL_RULES = {
    # 2) MOD David Rodriguez: 09:30-14:00 => 4.5h, 2 fichajes
    ("MOD", norm_name("DAVID RODRIGUEZ VAZQUEZ")): {"min_horas": 4.5, "min_fichajes": 2},

    # 3) MOI Debora, Etor y Miriam: mínimo 2 fichajes
    ("MOI", norm_name("DEBORA")): {"min_fichajes": 2},
    ("MOI", norm_name("ETOR")): {"min_fichajes": 2},

    # 4) MOI Miriam: 09:00-14:30 => 5.5h y 2 fichajes
    ("MOI", norm_name("MIRIAM")): {"min_horas": 5.5, "min_fichajes": 2},
}


def _lookup_special(depto_norm: str, nombre_norm: str):
    """
    Intenta casar primero por (depto, nombre completo) y luego por (depto, primer nombre)
    """
    # 1) por nombre completo
    key_full = (depto_norm, nombre_norm)
    if key_full in SPECIAL_RULES:
        return SPECIAL_RULES[key_full]

    # 2) por primer token (p.ej. "MIRIAM", "ETOR")
    first = (nombre_norm.split(" ")[0] if nombre_norm else "")
    key_first = (depto_norm, first)
    return SPECIAL_RULES.get(key_first)


# ============================================================
# REGLAS BASE DE JORNADA
# ============================================================

def calcular_minimos(depto: str, dia: int, nombre: str):
    """
    Devuelve (min_horas, min_fichajes) con overrides por reglas especiales.
    """
    depto_norm = (depto or "").upper().strip()
    nombre_norm = norm_name(nombre)

    min_h, min_f = None, None

    # BASE
    if depto_norm in ["ESTRUCTURA", "MOI"]:
        if dia in [0, 1, 2, 3]:       # L-J
            min_h, min_f = 8.5, 4
        elif dia == 4:                # V
            min_h, min_f = 6.5, 2
        else:
            min_h, min_f = None, None

    elif depto_norm == "MOD":
        if dia in [0, 1, 2, 3, 4]:    # L-V
            min_h, min_f = 8.0, 2
        else:
            min_h, min_f = None, None

    # OVERRIDES ESPECIALES (si aplica)
    special = _lookup_special(depto_norm, nombre_norm)
    if special:
        if "min_horas" in special and min_h is not None:
            min_h = float(special["min_horas"])
        if "min_fichajes" in special and min_f is not None:
            min_f = int(special["min_fichajes"])

    return min_h, min_f


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
    # PII -> NO cache
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

    def add_row(key: str, val):
        k = (str(key) or "").upper().strip()
        if not k:
            return

        if isinstance(val, dict):
            filas.append(
                {
                    "nif": str(val.get("nif") or k).upper().strip(),
                    "tiempoEfectivo_seg": val.get("tiempoEfectivo"),
                    "tiempoContabilizado_seg": val.get("tiempoContabilizado"),
                }
            )
            return

        if isinstance(val, list) and len(val) >= 4:
            filas.append(
                {
                    "nif": k,
                    "tiempoEfectivo_seg": val[-2],
                    "tiempoContabilizado_seg": val[-1],
                }
            )
            return

        filas.append({"nif": k, "tiempoEfectivo_seg": None, "tiempoContabilizado_seg": None})

    if isinstance(parsed, dict):
        for k, v in parsed.items():
            add_row(k, v)

    df = pd.DataFrame(filas)
    if df.empty:
        return pd.DataFrame(columns=["nif", "tiempoEfectivo_seg", "tiempoContabilizado_seg"])
    df["nif"] = df["nif"].astype(str).str.upper().str.strip()
    return df


def api_exportar_tiempo_trabajado(desde: str, hasta: str, nifs=None) -> pd.DataFrame:
    """
    MISMA FORMA que te funciona:
    - POST con nif[] repetido.
    - desde/hasta por día (intento mismo día; fallback día+1).
    """
    url = f"{API_URL_BASE}/exportacion/tiempo-trabajado"
    payload = [("desde", desde), ("hasta", hasta)]

    if nifs:
        for v in nifs:
            s = str(v).strip() if v is not None else ""
            if s:
                payload.append(("nif[]", s))

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
# TIEMPO POR FICHAJES (neto) - segundos enteros
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
                        delta_i = int(delta)  # truncado
                        props = tipos_map.get(int(a.get("tipo")), {}) if a.get("tipo") is not None else {}
                        if int(props.get("descuenta_tiempo", 0)) == 1:
                            descontados += delta_i
                        else:
                            sumados += delta_i
                    i += 2
                else:
                    i += 1

            rows_out.append({"nif": nif, "Fecha": fecha_dia, "segundos_neto": max(0, sumados - descontados)})

    return pd.DataFrame(rows_out)


# ============================================================
# VALIDACIÓN (con tolerancia ±5 minutos en horas)
# ============================================================

def validar_incidencia(r) -> str:
    min_h = r.get("min_horas")
    min_f = r.get("min_fichajes")
    if pd.isna(min_h) or pd.isna(min_f):
        return ""

    try:
        num_fich = int(r.get("Numero de fichajes", 0) or 0)
    except Exception:
        num_fich = 0

    try:
        horas_val = float(r.get("horas_dec_validacion", 0.0) or 0.0)
    except Exception:
        horas_val = 0.0

    motivo = []

    # 1) Tolerancia ±5 min -> para "insuficientes" permitimos min_h - 5 min
    umbral_inferior = float(min_h) - TOLERANCIA_HORAS
    if horas_val < umbral_inferior:
        motivo.append(
            f"Horas insuficientes (mín {min_h}h, tolerancia {TOLERANCIA_MINUTOS}m, tiene {horas_val:.2f}h)"
        )

    # 2) Fichajes (sin tolerancia)
    if num_fich < int(min_f):
        motivo.append(f"Fichajes insuficientes (mín {min_f}, tiene {num_fich})")

    # 3) Fichajes excesivos (misma regla que ya teníais)
    if horas_val >= umbral_inferior and num_fich > int(min_f):
        motivo.append(f"Fichajes excesivos (mín {min_f}, tiene {num_fich})")

    return "; ".join(motivo)


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

        # Nº fichajes por día
        df["Numero"] = df.groupby(["nif", "fecha_dia"])["id"].transform("count")
        conteo = (
            df.groupby(["nif", "Nombre", "Departamento", "fecha_dia"], as_index=False)
            .agg(Numero=("Numero", "max"))
            .rename(columns={"fecha_dia": "Fecha", "Numero": "Numero de fichajes"})
        )

        # Tiempo neto por marcajes (segundos)
        neto = calcular_tiempos_neto(df, tipos_map)
        resumen = conteo.merge(neto, on=["nif", "Fecha"], how="left")
        resumen["segundos_neto"] = resumen["segundos_neto"].fillna(0)

        resumen["Total trabajado"] = resumen["segundos_neto"].apply(segundos_a_hhmm)

        # ============================================================
        # TIEMPO CONTABILIZADO (POR DÍA) - MISMA FORMA
        # Intento 1: (desde=dia, hasta=dia) / Fallback: (hasta=dia+1)
        # ============================================================

        nifs = resumen["nif"].dropna().astype(str).str.upper().str.strip().unique().tolist()

        tc_rows = []
        d0 = datetime.strptime(fi, "%Y-%m-%d").date()
        d1 = datetime.strptime(ff, "%Y-%m-%d").date()

        cur = d0
        while cur <= d1:
            desde = cur.strftime("%Y-%m-%d")

            df_tc = api_exportar_tiempo_trabajado(desde, desde, nifs=nifs)
            if df_tc.empty or df_tc["tiempoContabilizado_seg"].isna().all():
                hasta = (cur + timedelta(days=1)).strftime("%Y-%m-%d")
                df_tc = api_exportar_tiempo_trabajado(desde, hasta, nifs=nifs)

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

        # Diferencia (solo si distinto)
        resumen["Diferencia"] = resumen.apply(
            lambda r: diferencia_hhmm(r.get("Tiempo Contabilizado", ""), r.get("Total trabajado", "")),
            axis=1
        )

        # Validación: si hay contabilizado, valida con contabilizado; si no, con marcajes
        resumen["horas_dec_marcajes"] = resumen["Total trabajado"].apply(hhmm_to_dec)
        resumen["horas_dec_contabilizado"] = resumen["Tiempo Contabilizado"].apply(hhmm_to_dec)

        resumen["horas_dec_validacion"] = resumen["horas_dec_marcajes"]
        mask_tc = resumen["Tiempo Contabilizado"].astype(str).str.strip().ne("")
        resumen.loc[mask_tc, "horas_dec_validacion"] = resumen.loc[mask_tc, "horas_dec_contabilizado"]

        resumen["dia"] = pd.to_datetime(resumen["Fecha"]).dt.weekday

        # Minimos por depto+día + especiales por persona
        resumen[["min_horas", "min_fichajes"]] = resumen.apply(
            lambda r: pd.Series(calcular_minimos(r.get("Departamento"), int(r["dia"]), r.get("Nombre"))),
            axis=1,
        )

        resumen["Incidencia"] = resumen.apply(validar_incidencia, axis=1)

        # ✅ SOLO QUIEN NO CUMPLE
        salida = resumen[resumen["Incidencia"].astype(str).str.strip().ne("")].copy()

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
                "Diferencia",
                "Numero de fichajes",
                "Incidencia",
            ]
        ].sort_values(["Fecha", "Nombre"], kind="mergesort")

    # Vista mínima (sin subheader)
    for f_dia in salida["Fecha"].unique():
        st.markdown(f"### 📅 {f_dia}")
        sub = salida[salida["Fecha"] == f_dia]
        st.data_editor(sub, use_container_width=True, hide_index=True, disabled=True, num_rows="fixed")

    csv = salida.to_csv(index=False).encode("utf-8")
    st.download_button("⬇ Descargar CSV", csv, "fichajes_incidencias.csv", "text/csv")
