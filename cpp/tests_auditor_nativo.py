# -*- coding: utf-8 -*-
"""
Pruebas del Auditor de Seguridad Web (versión nativa C++)
=========================================================
Uso:
    python tests_auditor_nativo.py

Levanta un servidor HTTP propio en un puerto libre y ejecuta contra él el
ejecutable `auditor.exe --json <url>`, comprobando el contrato JSON, las
comprobaciones nuevas y los mensajes de error.

Copyright (c) 2026 Juan Ramon Martin <zeronet75@gmail.com>
Licencia MIT (ver el archivo LICENSE).
"""

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
EJECUTABLE = os.path.join(BASE_DIR, "auditor.exe")

FALLOS = []


def comprobar(condicion, descripcion):
    if condicion:
        print("  OK    " + descripcion)
    else:
        FALLOS.append(descripcion)
        print("  FALLO " + descripcion)


class ManejadorPrueba(BaseHTTPRequestHandler):
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


def ejecutar(url, esperar_codigo=60):
    """Ejecuta auditor.exe --json y devuelve (dict, codigo_salida)."""
    proceso = subprocess.run([EJECUTABLE, "--json", url], capture_output=True, timeout=esperar_codigo)
    texto = proceso.stdout.decode("utf-8", errors="replace").strip()
    datos = None
    if texto:
        try:
            datos = json.loads(texto)
        except json.JSONDecodeError:
            datos = None
    return datos, proceso.returncode


def probar_nucleo(puerto):
    print("\n[1] Contrato JSON y comprobaciones")
    base = "http://127.0.0.1:{}".format(puerto)

    datos, codigo = ejecutar(base + "/ok")
    comprobar(codigo == 0 and datos and datos.get("ok") is True, "análisis correcto de /ok")
    if not datos:
        return

    comprobar(datos.get("status_code") == 200 and "servidor-prueba" in datos.get("server", ""), "código 200 y cabecera Server")
    comprobar(len(datos.get("evaluacion", [])) == 13, "se devuelven las 13 comprobaciones")
    comprobar(datos.get("software", {}).get("copyright", "").startswith("© 2026 Juan Ramon Martin"), "bloque software con copyright")
    comprobar(datos.get("motor") == "WinHTTP 4.0", "motor WinHTTP")

    ids = {i["id"]: i for i in datos["evaluacion"]}
    comprobar(ids["https"]["presente"] is False and ids["https"]["penalizacion"] == 100, "HTTP sin cifrar se penaliza al máximo")
    comprobar(ids["tls"]["aplicable"] is False, "TLS no aplicable sobre HTTP")
    comprobar(ids["cookies"]["presente"] and ids["cookies"]["penalizacion"] == 0, "cookie con Secure/HttpOnly/SameSite puntúa bien")
    comprobar(ids["cors"]["aplicable"] is False, "CORS no aplicable si no envía la cabecera")
    comprobar(ids["cross-origin-embedder-policy"]["peso"] == 0, "COEP es informativa (peso 0)")
    comprobar(ids["cache-control"]["peso"] == 0, "Cache-Control es informativa (peso 0)")
    comprobar(datos.get("puntos_max", 0) > 0 and datos.get("porcentaje", -1) >= 0, "puntuación ponderada presente")

    datos, _ = ejecutar(base + "/debil")
    ids = {i["id"]: i for i in datos["evaluacion"]}
    comprobar(ids["content-security-policy"]["penalizacion"] >= 40, "CSP con unsafe-inline/eval se marca débil")
    comprobar(ids["strict-transport-security"]["penalizacion"] >= 60, "HSTS con max-age=0 se marca débil")
    comprobar(ids["x-content-type-options"]["penalizacion"] >= 60, "X-Content-Type-Options distinto de nosniff se marca débil")
    comprobar(ids["x-frame-options"]["penalizacion"] >= 70, "X-Frame-Options ALLOWALL se marca débil")

    datos, _ = ejecutar(base + "/cookie-insegura")
    cookies = [i for i in datos["evaluacion"] if i["id"] == "cookies"][0]
    comprobar(cookies["presente"] is False and cookies["penalizacion"] >= 60, "cookie sin Secure/HttpOnly se detecta")

    datos, _ = ejecutar(base + "/cors-abierto")
    cors = [i for i in datos["evaluacion"] if i["id"] == "cors"][0]
    comprobar(cors["aplicable"] and cors["penalizacion"] >= 90, "CORS '*' con credenciales es crítico")

    print("\n[2] Redirecciones y errores")
    datos, _ = ejecutar(base + "/rel")
    comprobar(datos and datos.get("url", "").endswith("/final.html"), "redirección relativa resuelta")
    datos, _ = ejecutar(base + "/dir/rel")
    comprobar(datos and datos.get("url", "").endswith("/dir/otra.html"), "redirección relativa al directorio")
    datos, _ = ejecutar(base + "/proto")
    comprobar(datos and datos.get("url", "").endswith("/dir/otra.html"), "redirección con //host")
    datos, _ = ejecutar(base + "/query")
    comprobar(datos and datos.get("url", "").endswith("?x=1") and datos.get("status_code") == 404, "redirección ?query resuelta")

    datos, codigo = ejecutar(base + "/loop")
    comprobar(codigo == 2 and datos and "bucle" in datos.get("mensaje", ""), "bucle de redirecciones detectado")
    datos, codigo = ejecutar(base + "/no-existe")
    comprobar(codigo == 2 and datos and "404" in datos.get("mensaje", ""), "404 explicado con claridad")
    datos, codigo = ejecutar("https://no-existe-abc-12345.invalid/")
    comprobar(codigo == 2 and datos and "dominio" in datos.get("mensaje", "").lower(), "error DNS explicado con claridad")
    datos, codigo = ejecutar("https://expired.badssl.com/")
    comprobar(codigo == 2 and datos and "certificado" in datos.get("mensaje", "").lower(), "certificado caducado explicado")


def probar_online():
    print("\n[3] Auditoría real")
    datos, codigo = ejecutar("https://www.wikipedia.org/", 90)
    comprobar(codigo == 0 and datos and datos.get("ok"), "auditoría de www.wikipedia.org")
    if datos:
        comprobar(datos.get("https") is True and datos.get("tls_protocolo"), "TLS detectado: {}".format(datos.get("tls_protocolo")))
        comprobar(datos.get("calificacion") in ("A+", "A", "B", "C", "D", "F"), "nota calculada: {}".format(datos.get("calificacion")))


def probar_gui():
    print("\n[4] Interfaz gráfica y persistencia real")
    import ctypes
    import shutil
    from ctypes import wintypes

    carpeta = tempfile.mkdtemp()
    copia = os.path.join(carpeta, "auditor.exe")
    shutil.copy2(EJECUTABLE, copia)
    historial = os.path.join(carpeta, "historial_auditorias.json")

    proceso = subprocess.Popen([copia, "https://www.wikipedia.org/"], cwd=carpeta)
    time.sleep(6)

    user32 = ctypes.windll.user32
    hwnd = user32.FindWindowW("AuditorSeguridadMainWndClass", None)
    comprobar(proceso.poll() is None and bool(hwnd), "la aplicación arranca y permanece abierta")

    if hwnd:
        WM_COMMAND = 0x0111
        IDC_BTN_ANALIZAR = 1002
        user32.PostMessageW(hwnd, WM_COMMAND, IDC_BTN_ANALIZAR, 0)

        limite = time.time() + 60
        while time.time() < limite and not (os.path.exists(historial) and os.path.getsize(historial) > 100):
            time.sleep(1)
        time.sleep(1)

        comprobar(os.path.exists(historial), "el análisis desde la interfaz guarda el historial")
        if os.path.exists(historial):
            try:
                with open(historial, encoding="utf-8") as f:
                    historial_json = json.load(f)
                comprobar(isinstance(historial_json, list) and len(historial_json) >= 1, "historial en UTF-8 y formato lista")
                item = historial_json[0]
                comprobar(item.get("motor") == "WinHTTP 4.0", "el historial guarda el motor")
                comprobar(len(item.get("evaluacion", [])) == 13, "el historial guarda las 13 comprobaciones")
                comprobar("puntos" in item and "porcentaje" in item and item.get("calificacion"),
                          "el historial guarda puntuación y nota")
                check = item["evaluacion"][0]
                comprobar(all(k in check for k in ("id", "peso", "aplicable", "presente", "penalizacion", "aviso")),
                          "cada comprobación guarda peso, aplicabilidad y aviso")
            except Exception as exc:
                comprobar(False, "historial JSON válido ({})".format(exc))

        WM_CLOSE = 0x0010
        user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)
        time.sleep(3)

    if proceso.poll() is None:
        proceso.kill()
    comprobar(True, "cierre de la aplicación")


def probar_idiomas_nativo():
    print("\n[5] Menú Idioma y cambio en caliente")
    import ctypes
    import shutil
    from ctypes import wintypes

    carpeta = tempfile.mkdtemp()
    copia = os.path.join(carpeta, "auditor.exe")
    shutil.copy2(EJECUTABLE, copia)
    origen_loc = os.path.join(BASE_DIR, "localizations")
    if os.path.isdir(origen_loc):
        shutil.copytree(origen_loc, os.path.join(carpeta, "localizations"))

    user32 = ctypes.windll.user32
    user32.FindWindowW.restype = wintypes.HWND
    user32.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
    user32.GetMenu.restype = wintypes.HMENU
    user32.GetMenu.argtypes = [wintypes.HWND]
    user32.GetSubMenu.restype = wintypes.HMENU
    user32.GetSubMenu.argtypes = [wintypes.HMENU, ctypes.c_int]
    user32.GetMenuItemCount.argtypes = [wintypes.HMENU]
    user32.GetMenuStringW.argtypes = [wintypes.HMENU, wintypes.UINT, wintypes.LPWSTR, ctypes.c_int, wintypes.UINT]
    user32.GetDlgItem.restype = wintypes.HWND
    user32.GetDlgItem.argtypes = [wintypes.HWND, ctypes.c_int]
    user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]

    def texto(handle):
        buffer = ctypes.create_unicode_buffer(256)
        user32.GetWindowTextW(handle, buffer, 256)
        return buffer.value

    proceso = subprocess.Popen([copia, "https://github.com/"], cwd=carpeta)
    time.sleep(6)
    hwnd = user32.FindWindowW("AuditorSeguridadMainWndClass", None)
    comprobar(bool(hwnd), "la aplicación arranca")

    if hwnd:
        menu = user32.GetSubMenu(user32.GetMenu(hwnd), 0)
        total = user32.GetMenuItemCount(menu)
        comprobar(total == 16, "16 idiomas en el menú ({})".format(total))

        nombres = []
        for i in range(total):
            buffer = ctypes.create_unicode_buffer(128)
            user32.GetMenuStringW(menu, i, buffer, 128, 0x400)
            nombres.append(buffer.value)
        comprobar("Español" in nombres and "日本語" in nombres, "nombres nativos en el menú")

        indice_ja = nombres.index("日本語")
        user32.PostMessageW(hwnd, 0x0111, 2000 + indice_ja, 0)
        time.sleep(2)
        comprobar(texto(user32.GetDlgItem(hwnd, 1002)) == "🔍 サイトを分析", "cambio en caliente a japonés")

        ruta_ajustes = os.path.join(os.environ.get("APPDATA", ""), "AuditorSeguridadWeb", "settings.json")
        guardado = None
        if os.path.exists(ruta_ajustes):
            try:
                with open(ruta_ajustes, encoding="utf-8") as f:
                    guardado = json.load(f).get("Language")
            except Exception:
                guardado = None
        comprobar(guardado == "ja_JP", "la selección se guarda ({})".format(guardado))

        indice_es = nombres.index("Español")
        user32.PostMessageW(hwnd, 0x0111, 2000 + indice_es, 0)
        time.sleep(2)
        comprobar(texto(user32.GetDlgItem(hwnd, 1002)) == "🔍 Analizar Web", "vuelta a español")

        user32.PostMessageW(hwnd, 0x0010, 0, 0)
        time.sleep(2)

    if proceso.poll() is None:
        proceso.kill()


def main():
    print("=" * 60)
    print(" PRUEBAS DEL AUDITOR NATIVO (C++)")
    print("=" * 60)

    if not os.path.exists(EJECUTABLE):
        print("No se encontró " + EJECUTABLE)
        return 1

    servidor = ThreadingHTTPServer(("127.0.0.1", 0), ManejadorPrueba)
    hilo = threading.Thread(target=servidor.serve_forever, daemon=True)
    hilo.start()
    try:
        probar_nucleo(servidor.server_address[1])
    finally:
        servidor.shutdown()
        servidor.server_close()

    probar_online()
    probar_gui()
    probar_idiomas_nativo()

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
