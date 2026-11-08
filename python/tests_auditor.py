# -*- coding: utf-8 -*-
"""
Pruebas del Auditor de Seguridad Web
====================================
Uso:
    python tests_auditor.py            # pruebas locales (sin salir a Internet)
    python tests_auditor.py --online   # incluye una auditoría real de la URL por defecto

Las pruebas locales levantan un servidor HTTP propio en un puerto libre y
ejecutan contra él el núcleo `auditor_core.exe`, además de comprobar la
puntuación, las exportaciones y (si hay pantalla) la construcción de la GUI.

Copyright (c) 2026 Juan Ramon Martin <zeronet75@gmail.com>
Licencia MIT (ver el archivo LICENSE).
"""

import csv
import json
import os
import socket
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

import auditor  # noqa: E402

# Las pruebas comprueban textos concretos: se fija el idioma español.
auditor.i18n.initialize("es_ES")

FALLOS = []


def comprobar(condicion, descripcion):
    if condicion:
        print("  OK    " + descripcion)
    else:
        FALLOS.append(descripcion)
        print("  FALLO " + descripcion)


# ==========================================
# Servidor HTTP de pruebas
# ==========================================
class ManejadorPrueba(BaseHTTPRequestHandler):
    # HTTP/1.0 evita que el servidor de pruebas mantenga conexiones abiertas
    # (el núcleo cierra el socket al terminar y eso generaría avisos inofensivos).
    protocol_version = "HTTP/1.0"

    def handle(self):
        try:
            super().handle()
        except (ConnectionResetError, BrokenPipeError):
            pass

    def _responder(self, codigo, cabeceras=None, cuerpo=b""):
        self.send_response(codigo)
        for nombre, valor in (cabeceras or []):
            self.send_header(nombre, valor)
        self.send_header("Content-Length", str(len(cuerpo)))
        self.end_headers()
        if cuerpo:
            self.wfile.write(cuerpo)

    def do_GET(self):
        p = self.path
        puerto = self.server.server_address[1]

        if p == "/ok":
            self._responder(200, [
                ("Content-Type", "text/html"),
                ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
                ("Content-Security-Policy", "default-src 'self'"),
                ("X-Frame-Options", "DENY"),
                ("X-Content-Type-Options", "nosniff"),
                ("Referrer-Policy", "strict-origin-when-cross-origin"),
                ("Permissions-Policy", "geolocation=(), camera=()"),
                ("Cross-Origin-Opener-Policy", "same-origin"),
                ("Set-Cookie", "sesion=abc; Secure; HttpOnly; SameSite=Strict"),
                ("Server", "servidor-prueba/1.0"),
            ], b"<html>ok</html>")
        elif p == "/debil":
            self._responder(200, [
                ("Strict-Transport-Security", "max-age=0"),
                ("Content-Security-Policy", "default-src *; script-src 'unsafe-inline' 'unsafe-eval'"),
                ("X-Frame-Options", "ALLOWALL"),
                ("X-Content-Type-Options", "sniff"),
                ("Referrer-Policy", "unsafe-url"),
            ])
        elif p == "/cookie-insegura":
            self._responder(200, [("Set-Cookie", "seguimiento=xyz; Path=/")])
        elif p == "/cors-abierto":
            self._responder(200, [
                ("Access-Control-Allow-Origin", "*"),
                ("Access-Control-Allow-Credentials", "true"),
            ])
        elif p == "/rel":
            self._responder(302, [("Location", "final.html")])
        elif p == "/final.html":
            self._responder(200, [("X-Frame-Options", "SAMEORIGIN")])
        elif p == "/dir/rel":
            self._responder(302, [("Location", "otra.html")])
        elif p == "/dir/otra.html":
            self._responder(200, [("X-Frame-Options", "SAMEORIGIN")])
        elif p == "/proto":
            self._responder(302, [("Location", "//127.0.0.1:{}/dir/otra.html".format(puerto))])
        elif p == "/query":
            self._responder(302, [("Location", "?x=1")])
        elif p == "/loop":
            self._responder(302, [("Location", "/loop")])
        else:
            self._responder(404, [("Content-Type", "text/plain")], b"no existe")

    def log_message(self, formato, *args):
        pass


def arrancar_servidor():
    servidor = ThreadingHTTPServer(("127.0.0.1", 0), ManejadorPrueba)
    hilo = threading.Thread(target=servidor.serve_forever, daemon=True)
    hilo.start()
    return servidor, servidor.server_address[1]


def ejecutar_nucleo(url):
    """Ejecuta el núcleo y devuelve (json_dict, codigo_salida)."""
    ruta = os.path.join(BASE_DIR, auditor.NOMBRE_CORE)
    proceso = auditor.subprocess.run([ruta, url], capture_output=True, text=True,
                                     encoding="utf-8", errors="replace", timeout=60)
    datos = None
    if proceso.stdout.strip():
        try:
            datos = json.loads(proceso.stdout)
        except json.JSONDecodeError:
            datos = None
    return datos, proceso.returncode


# ==========================================
# Pruebas
# ==========================================
def probar_idiomas():
    print("\n[0] Sistema de idiomas")
    idiomas = auditor.i18n.available()
    comprobar(len(idiomas) == 16, "16 idiomas en el menú ({})".format(len(idiomas)))
    nativos = [nombre for _, nombre in idiomas]
    for esperado in ("English", "Español", "हिन्दी", "Bahasa Indonesia", "Tiếng Việt",
                     "العربية", "日本語", "中文 (简体)", "中文 (繁體)", "Русский"):
        comprobar(esperado in nativos, "nombre nativo: " + esperado)

    auditor.i18n.set_language("es_ES")
    comprobar(auditor.T("form.analyze") == "Analizar Web", "es_ES: Analizar Web")
    auditor.i18n.set_language("en_US")
    comprobar(auditor.T("form.analyze") == "Analyze Web", "en_US: Analyze Web")
    comprobar(auditor.T("clave.inexistente") == "clave.inexistente", "clave ausente -> clave")
    comprobar(auditor.T_or("clave.inexistente", "respaldo") == "respaldo", "fallback a texto de respaldo")
    texto = auditor.T("status.summary", ok=1, total=2, grade="A", pct=90, points="9.0", max="10")
    comprobar("Result" in texto and "1" in texto and "2" in texto, "placeholders en la cadena")

    auditor.i18n.set_language("ja_JP")
    comprobar(auditor.T("form.analyze") == "サイトを分析", "ja_JP: サイトを分析")
    auditor.i18n.set_language("zh_CN")
    comprobar(auditor.T("tab.report") == "分析报告", "zh_CN: 分析报告")

    auditor.i18n.save_language("es_ES")
    comprobar(auditor.i18n.load_saved_language() == "es_ES", "la selección se guarda en disco")
    auditor.i18n.set_language("es_ES")


def probar_normalizacion():
    print("\n[1] Validación y normalización de URLs")
    casos = [
        ("ejemplo.com", "https://ejemplo.com/"),
        ("  https://Ejemplo.COM/ruta?x=1  ", "https://ejemplo.com/ruta?x=1"),
        ("http://192.168.1.10:8080/", "http://192.168.1.10:8080/"),
        ("ftp://ejemplo.com", None),
        ("", None),
        ("https://", None),
        ("https://ejemplo.com:99999/", None),
        ("ejemplo.com/ruta con espacio", None),
    ]
    for entrada, esperado in casos:
        obtenido, error = auditor.normalizar_url(entrada)
        comprobar(obtenido == esperado, "normalizar_url({!r}) -> {!r} ({})".format(entrada, obtenido, error))


def probar_nombres_archivo():
    print("\n[2] Nombres de archivo seguros")
    nombre = auditor.nombre_archivo_seguro("https://www.example.com/index.html?x=1&y=2", "Informe", ".pdf")
    comprobar(all(c not in nombre for c in '\\/:*?"<>|'), "sin caracteres inválidos: " + nombre)
    comprobar(len(nombre) < 120, "longitud razonable")


def probar_puntuacion():
    print("\n[3] Puntuación por peso y calidad")
    fuerte = [{"peso": 4, "criticidad": "CRÍTICA", "aplicable": True, "presente": True, "penalizacion": 0},
              {"peso": 2, "criticidad": "MEDIA", "aplicable": True, "presente": True, "penalizacion": 0}]
    debil = [{"peso": 4, "criticidad": "CRÍTICA", "aplicable": True, "presente": True, "penalizacion": 50},
             {"peso": 2, "criticidad": "MEDIA", "aplicable": True, "presente": False, "penalizacion": 0}]
    informativa = [{"peso": 0, "criticidad": "INFORMATIVA", "aplicable": True, "presente": False},
                   {"peso": 4, "criticidad": "CRÍTICA", "aplicable": True, "presente": True, "penalizacion": 0}]
    no_aplica = [{"peso": 4, "criticidad": "CRÍTICA", "aplicable": False, "presente": False},
                 {"peso": 2, "criticidad": "MEDIA", "aplicable": True, "presente": True, "penalizacion": 0}]
    antiguo = [{"criticidad": "CRITICA", "presente": True}, {"criticidad": "MEDIA", "presente": False}]

    _, _, pct_fuerte, nota_fuerte = auditor.evaluar_puntuacion(fuerte)
    _, _, pct_debil, nota_debil = auditor.evaluar_puntuacion(debil)
    _, max_info, pct_info, _ = auditor.evaluar_puntuacion(informativa)
    _, max_na, pct_na, _ = auditor.evaluar_puntuacion(no_aplica)
    _, _, pct_antiguo, _ = auditor.evaluar_puntuacion(antiguo)

    comprobar(pct_fuerte == 100 and nota_fuerte == "A+", "todo correcto da 100% y A+")
    comprobar(round(pct_debil) == 33 and nota_debil == "D", "cabecera débil y ausente bajan la nota ({:.0f}%)".format(pct_debil))
    comprobar(max_info == 4 and pct_info == 100, "las informativas (peso 0) no puntúan")
    comprobar(max_na == 2 and pct_na == 100, "las comprobaciones no aplicables no puntúan")
    comprobar(round(pct_antiguo) == 67, "registros antiguos sin peso siguen calculándose ({:.0f}%)".format(pct_antiguo))

    comprobar(auditor.estado_item({"aplicable": True, "presente": True, "penalizacion": 0, "peso": 4})[0] == "CONFIGURADA", "estado CONFIGURADA")
    comprobar(auditor.estado_item({"aplicable": True, "presente": True, "penalizacion": 40, "peso": 4})[0] == "DÉBIL", "estado DÉBIL")
    comprobar(auditor.estado_item({"aplicable": True, "presente": False, "peso": 4, "header": "X-Frame-Options"})[0] == "AUSENTE",
              "estado AUSENTE en cabeceras")
    comprobar(auditor.estado_item({"aplicable": True, "presente": False, "peso": 4, "header": ""})[0] == "NO CUMPLE",
              "estado NO CUMPLE en comprobaciones de transporte")
    comprobar(auditor.estado_item({"aplicable": False, "presente": True, "peso": 4})[0] == "NO APLICA", "estado NO APLICA")
    comprobar(auditor.estado_item({"aplicable": True, "presente": False, "peso": 0})[0].startswith("INFORMATIVA"), "estado INFORMATIVA")


def probar_nucleo(puerto):
    print("\n[4] Núcleo nativo (auditor_core.exe) contra servidor local")
    base = "http://127.0.0.1:{}".format(puerto)
    ruta = os.path.join(BASE_DIR, auditor.NOMBRE_CORE)
    if not os.path.exists(ruta):
        comprobar(False, "no se encontró " + auditor.NOMBRE_CORE)
        return None

    datos, codigo = ejecutar_nucleo(base + "/ok")
    comprobar(codigo == 0 and datos and datos.get("ok") is True, "análisis correcto de /ok")
    if datos:
        comprobar(datos.get("status_code") == 200 and "servidor-prueba" in datos.get("server", ""), "código 200 y cabecera Server")
        comprobar(len(datos.get("evaluacion", [])) == 13, "se devuelven las 13 comprobaciones")
        cookies = [i for i in datos["evaluacion"] if i["id"] == "cookies"][0]
        comprobar(cookies["presente"] and cookies["penalizacion"] == 0, "cookie con Secure/HttpOnly/SameSite puntúa bien")
        cors = [i for i in datos["evaluacion"] if i["id"] == "cors"][0]
        comprobar(cors["aplicable"] is False, "CORS no aplicable si no envía la cabecera")
        tls = [i for i in datos["evaluacion"] if i["id"] == "tls"][0]
        comprobar(tls["aplicable"] is False, "TLS no aplicable sobre HTTP")
        https = [i for i in datos["evaluacion"] if i["id"] == "https"][0]
        comprobar(https["presente"] is False and https["penalizacion"] == 100, "HTTP sin cifrar se penaliza al máximo")

    datos, _ = ejecutar_nucleo(base + "/debil")
    if datos:
        csp = [i for i in datos["evaluacion"] if i["id"] == "content-security-policy"][0]
        hsts = [i for i in datos["evaluacion"] if i["id"] == "strict-transport-security"][0]
        xcto = [i for i in datos["evaluacion"] if i["id"] == "x-content-type-options"][0]
        comprobar(csp["presente"] and csp["penalizacion"] >= 40, "CSP con unsafe-inline/eval se marca débil")
        comprobar(hsts["penalizacion"] >= 60, "HSTS con max-age=0 se marca débil")
        comprobar(xcto["penalizacion"] >= 60, "X-Content-Type-Options distinto de nosniff se marca débil")

    datos, _ = ejecutar_nucleo(base + "/cookie-insegura")
    if datos:
        cookies = [i for i in datos["evaluacion"] if i["id"] == "cookies"][0]
        comprobar(cookies["aplicable"] and cookies["presente"] is False and cookies["penalizacion"] >= 60,
                  "cookie sin Secure/HttpOnly se detecta")

    datos, _ = ejecutar_nucleo(base + "/cors-abierto")
    if datos:
        cors = [i for i in datos["evaluacion"] if i["id"] == "cors"][0]
        comprobar(cors["aplicable"] and cors["penalizacion"] >= 90, "CORS '*' con credenciales es crítico")

    datos, _ = ejecutar_nucleo(base + "/rel")
    comprobar(datos and datos.get("url", "").endswith("/final.html"), "redirección relativa resuelta: " + str(datos and datos.get("url")))
    datos, _ = ejecutar_nucleo(base + "/dir/rel")
    comprobar(datos and datos.get("url", "").endswith("/dir/otra.html"), "redirección relativa al directorio")
    datos, _ = ejecutar_nucleo(base + "/proto")
    comprobar(datos and datos.get("url", "").endswith("/dir/otra.html"), "redirección con //host")
    datos, _ = ejecutar_nucleo(base + "/query")
    comprobar(bool(datos) and datos.get("url", "").endswith("?x=1") and datos.get("status_code") == 404,
              "redirección ?query resuelta: " + str(datos and datos.get("url")))

    datos, codigo = ejecutar_nucleo(base + "/loop")
    comprobar(codigo == 2 and datos and "bucle" in datos.get("mensaje", ""), "bucle de redirecciones detectado")
    datos, codigo = ejecutar_nucleo(base + "/no-existe")
    comprobar(codigo == 2 and datos and "404" in datos.get("mensaje", ""), "404 explicado con claridad")
    datos, codigo = ejecutar_nucleo("https://no-existe-abc-12345.invalid/")
    comprobar(codigo == 2 and datos and "dominio" in datos.get("mensaje", "").lower(), "error DNS explicado con claridad")
    return datos


def probar_gui():
    print("\n[5] Interfaz gráfica y exportaciones")
    try:
        import tkinter as tk
        root = tk.Tk()
        root.withdraw()
    except Exception as exc:
        print("  (omitido: no hay entorno gráfico: {})".format(exc))
        return

    mensajes = []

    class FalsoMessagebox:
        @staticmethod
        def showinfo(*a, **k): mensajes.append(a)
        @staticmethod
        def showerror(*a, **k): mensajes.append(a)
        @staticmethod
        def showwarning(*a, **k): mensajes.append(a)
        @staticmethod
        def askyesno(*a, **k): return True

    original = auditor.messagebox
    auditor.messagebox = FalsoMessagebox
    historial_original = auditor.CONFIG_FILE
    copia_original = auditor.COPIA_HISTORIAL
    auditor.CONFIG_FILE = os.path.join(tempfile.mkdtemp(), "historial.json")
    auditor.COPIA_HISTORIAL = os.path.join(tempfile.mkdtemp(), "historial.bak.json")
    try:
        app = auditor.AuditorSeguridadGUI(root)
        resultado = {
            "url": "https://ejemplo.com/?a=1&b=2", "status_code": 200, "reason": "OK",
            "server": "nginx", "fecha": "2026-01-01 10:00:00", "https": True, "tls_protocolo": "TLS 1.3",
            "presentes": 2, "total": 3,
            "evaluacion": [
                {"id": "https", "header": "", "nombre": "HTTPS obligatorio", "desc": "a < b & c",
                 "criticidad": "CRÍTICA", "peso": 4, "aplicable": True, "presente": True,
                 "penalizacion": 0, "valor": "301 -> https://ejemplo.com", "aviso": ""},
                {"id": "x-frame-options", "header": "X-Frame-Options", "nombre": "X-Frame-Options",
                 "desc": "Anti clickjacking", "criticidad": "MEDIA", "peso": 2, "aplicable": True,
                 "presente": True, "penalizacion": 20, "valor": "SAMEORIGIN", "aviso": "Valor aceptable"},
                {"id": "csp", "header": "Content-Security-Policy", "nombre": "CSP",
                 "desc": "Anti XSS", "criticidad": "CRÍTICA", "peso": 4, "aplicable": False,
                 "presente": False, "penalizacion": 0, "valor": "No aplica", "aviso": ""},
            ],
        }
        app.completar_puntuacion(resultado)
        app.mostrar_informe_pantalla(resultado)
        root.update()
        comprobar(len(app._etiquetas_wrap) > 0, "tarjetas del informe dibujadas")
        comprobar(resultado["calificacion"] in ("A+", "A", "B", "C", "D", "F"), "nota calculada: {}".format(resultado["calificacion"]))

        app.ultimo_resultado = resultado
        destino = tempfile.mkdtemp()
        import tkinter.filedialog as fd
        original_fd = fd.asksaveasfilename
        try:
            for extension, funcion in ((".pdf", app.exportar_pdf), (".json", app.exportar_json), (".csv", app.exportar_csv)):
                ruta = os.path.join(destino, "informe" + extension)
                fd.asksaveasfilename = lambda **k: ruta
                funcion()
                comprobar(os.path.exists(ruta) and os.path.getsize(ruta) > 100,
                          "exportación {} ({} bytes)".format(extension, os.path.getsize(ruta) if os.path.exists(ruta) else 0))
        finally:
            fd.asksaveasfilename = original_fd

        # El CSV debe abrirse correctamente y contener las columnas nuevas.
        with open(os.path.join(destino, "informe.csv"), encoding="utf-8-sig") as f:
            filas = list(csv.reader(f, delimiter=";"))
        comprobar(filas[0][:5] == [auditor.T("csv.col.check"), auditor.T("csv.col.state"),
                                   auditor.T("csv.col.criticality"), auditor.T("csv.col.weight"),
                                   auditor.T("csv.col.quality")], "CSV con columnas de calidad")

        app.guardar_en_historial(resultado)
        comprobar(len(app.historial) == 1 and os.path.exists(auditor.CONFIG_FILE), "historial guardado en disco")

        # Segunda auditoría: debe quedar copia del historial anterior y poder restaurarse.
        resultado2 = dict(resultado)
        resultado2["fecha"] = "2026-01-02 10:00:00"
        app.guardar_en_historial(resultado2)
        comprobar(os.path.exists(auditor.COPIA_HISTORIAL), "copia de seguridad del historial creada")
        app.historial = app.historial[:1]
        app.restaurar_copia_historial()
        comprobar(len(app.historial) == 2, "restauración de registros desde la copia")

        app.acerca_de()
        comprobar(mensajes and auditor.AUTOR in mensajes[-1][1] and auditor.CORREO in mensajes[-1][1],
                  "diálogo 'Acerca de' con autor y correo")
        root.destroy()
    finally:
        auditor.messagebox = original
        auditor.CONFIG_FILE = historial_original
        auditor.COPIA_HISTORIAL = copia_original


def probar_online():
    print("\n[6] Auditoría real")
    url = "https://www.wikipedia.org"
    datos, codigo = ejecutar_nucleo(url)
    comprobar(codigo == 0 and datos and datos.get("ok"), "auditoría de {}".format(url))
    if datos:
        comprobar(datos.get("https") is True and datos.get("tls_protocolo"), "TLS detectado: {}".format(datos.get("tls_protocolo")))
        comprobar(datos.get("puntos_max", 0) > 0, "puntuación ponderada presente")


def main():
    print("=" * 60)
    print(" PRUEBAS DEL AUDITOR DE SEGURIDAD WEB")
    print("=" * 60)

    probar_idiomas()
    probar_normalizacion()
    probar_nombres_archivo()
    probar_puntuacion()
    servidor, puerto = arrancar_servidor()
    try:
        probar_nucleo(puerto)
    finally:
        servidor.shutdown()
        servidor.server_close()

    probar_gui()

    if "--online" in sys.argv:
        probar_online()

    print("\n" + "=" * 60)
    if FALLOS:
        print(" RESULTADO: {} FALLOS".format(len(FALLOS)))
        for fallo in FALLOS:
            print("  - " + fallo)
        return 1
    print(" RESULTADO: TODAS LAS PRUEBAS OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
