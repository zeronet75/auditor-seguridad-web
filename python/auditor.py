# -*- coding: utf-8 -*-
"""
Auditor Profesional de Seguridad HTTP
=====================================
Aplicación de escritorio (Tkinter) que analiza las cabeceras y el transporte
de una página web, calcula una nota de seguridad y permite guardar el historial
y exportar el informe a PDF, JSON o CSV.

El análisis HTTP real lo realiza el módulo nativo `auditor_core.exe` (WinHTTP),
que devuelve un objeto JSON por la salida estándar. Este programa se encarga de
la interfaz, la puntuación, la persistencia y la exportación.

La nota se calcula con dos criterios:
  - peso de cada comprobación (4 CRÍTICA ... 1 BAJA; 0 = informativa, no puntúa)
  - calidad del valor configurado (una cabecera presente pero débil resta puntos)

Copyright (c) 2026 Juan Ramon Martin <zeronet75@gmail.com>
Licencia MIT (ver el archivo LICENSE).
"""

import os
import re
import sys
import csv
import json
import queue
import shutil
import datetime
import threading
import subprocess
import traceback
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from urllib.parse import urlsplit, urlunsplit, quote
from xml.sax.saxutils import escape as escapar_xml

import i18n
from i18n import T, T_or

# ReportLab solo es necesario para exportar a PDF: si falta, el resto sigue funcionando.
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    REPORTLAB_DISPONIBLE = True
except Exception:  # ImportError o cualquier problema de instalación
    REPORTLAB_DISPONIBLE = False

# ==========================================
# 1. CONFIGURACIÓN DE RUTAS Y CONSTANTES
# ==========================================
# Determina si el script se está ejecutando como un ejecutable compilado (PyInstaller) o como script de Python.
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Rutas globales para el archivo de historial, el registro de errores y la URL por defecto.
CONFIG_FILE = os.path.join(BASE_DIR, "historial_auditorias.json")
COPIA_HISTORIAL = os.path.join(BASE_DIR, "historial_auditorias.bak.json")
LOG_FILE = os.path.join(BASE_DIR, "auditor_errores.log")
DEFAULT_URL = ""   # Sin web por defecto: el usuario introduce la suya

MAX_HISTORIAL = 30          # Registros que se conservan en el historial
TIMEOUT_ANALISIS = 40       # Segundos máximos para una auditoría individual (incluye sondas TLS)
TIMEOUT_LOTE = 30           # Segundos máximos por URL en modo por lotes
NOMBRE_CORE = "auditor_core.exe"

# Datos de autoría (se muestran en la interfaz y en los informes exportados).
AUTOR = "Juan Ramon Martin"
CORREO = "zeronet75@gmail.com"
VERSION_APP = "4.1"
COPYRIGHT = "© 2026 Juan Ramon Martin"

# Pesos de respaldo para registros antiguos, que no guardaban el campo "peso".
PESOS_CRITICIDAD = {"CRÍTICA": 4, "CRITICA": 4, "ALTA": 3, "MEDIA": 2, "BAJA": 1, "INFORMATIVA": 0}


def soporta_emojis():
    """Decide si se pueden usar emojis en la interfaz (Windows 10+ y Tk moderno)."""
    if os.environ.get("AUDITOR_SIN_EMOJIS") == "1":
        return False
    if sys.platform != "win32":
        return True
    try:
        return sys.getwindowsversion().build >= 10240
    except Exception:
        return False


SOPORTA_EMOJIS = soporta_emojis()


def ico(emoji, alternativo=""):
    """Devuelve el emoji o su alternativa de texto según el sistema."""
    return emoji if SOPORTA_EMOJIS else alternativo


def ruta_recurso(nombre):
    """Busca un recurso junto al ejecutable y, en compilaciones onefile, dentro del paquete."""
    candidatos = [os.path.join(BASE_DIR, nombre)]
    if hasattr(sys, "_MEIPASS"):
        candidatos.append(os.path.join(sys._MEIPASS, nombre))
    for ruta in candidatos:
        if os.path.exists(ruta):
            return ruta
    return candidatos[0]


def normalizar_url(texto):
    """
    Valida y normaliza una dirección introducida por el usuario.
    Devuelve (url_normalizada, error). Si hay error, la url es None.
    """
    if texto is None:
        return None, "Introduce una dirección URL."

    url = texto.strip().strip('"').strip("'").strip("<>").strip()
    if not url:
        return None, "Introduce una dirección URL."
    if any(c.isspace() for c in url):
        return None, "La dirección contiene espacios; revisa que esté bien escrita."

    # Si no se indica esquema se asume HTTPS (igual que hacen los navegadores).
    if "://" not in url:
        url = "https://" + url

    partes = urlsplit(url)
    esquema = partes.scheme.lower()
    if esquema not in ("http", "https"):
        return None, "Solo se admiten direcciones http:// o https://."

    host = partes.hostname or ""
    if not host:
        return None, "La dirección no indica ningún dominio."
    if not re.match(r"^[A-Za-z0-9._\-\[\]:]+$", host):
        return None, "El dominio introducido no es válido."

    try:
        partes.port  # Fuerza la validación del puerto
    except ValueError:
        return None, "El puerto indicado no es válido."

    # Se codifican los caracteres especiales de la ruta y la consulta sin romper la URL.
    ruta = quote(partes.path or "/", safe="/%:@!$&'()*+,;=-._~")
    consulta = quote(partes.query, safe="=&%:@!$'()*+,;/?-._~")
    return urlunsplit((esquema, partes.netloc.lower(), ruta, consulta, "")), None


def nombre_archivo_seguro(url, prefijo, extension):
    """Genera un nombre de archivo válido en Windows a partir de una URL."""
    limpio = re.sub(r"^[A-Za-z][A-Za-z0-9+.-]*://", "", url or "sitio")
    limpio = re.sub(r"[^A-Za-z0-9._-]+", "_", limpio).strip("._-") or "sitio"
    return "{}_{}{}".format(prefijo, limpio[:80], extension)


def peso_item(item):
    """Peso de una comprobación (tolera registros antiguos sin el campo 'peso')."""
    peso = item.get("peso")
    if peso is None:
        peso = PESOS_CRITICIDAD.get(str(item.get("criticidad", "")).upper(), 2)
    try:
        return int(peso)
    except (TypeError, ValueError):
        return 0


def calidad_item(item):
    """Calidad (0-100) de una comprobación según su estado y su penalización."""
    if not item.get("aplicable", True) or not item.get("presente"):
        return 0
    try:
        penalizacion = float(item.get("penalizacion", 0) or 0)
    except (TypeError, ValueError):
        penalizacion = 0.0
    return int(round(max(0.0, 100.0 - penalizacion)))


def evaluar_puntuacion(evaluacion):
    """
    Calcula la puntuación global ponderada.
    Devuelve (puntos, puntos_max, porcentaje, nota).
    Las comprobaciones informativas (peso 0) y las no aplicables no puntúan.
    """
    puntos = 0.0
    maximo = 0.0
    for item in evaluacion or []:
        if not isinstance(item, dict):
            continue
        peso = peso_item(item)
        if not item.get("aplicable", True) or peso <= 0:
            continue
        puntos += peso * (calidad_item(item) / 100.0)
        maximo += peso

    if maximo <= 0:
        return 0.0, 0.0, 0.0, "F"
    porcentaje = (puntos / maximo) * 100
    return puntos, maximo, porcentaje, nota_desde_porcentaje(porcentaje)


def nota_desde_porcentaje(porcentaje):
    """Convierte un porcentaje de calidad en la nota A+/A/B/C/D/F."""
    if porcentaje >= 95:
        return "A+"
    if porcentaje >= 85:
        return "A"
    if porcentaje >= 70:
        return "B"
    if porcentaje >= 50:
        return "C"
    if porcentaje >= 30:
        return "D"
    return "F"


def estado_item(item):
    """Devuelve (texto_estado, color, icono) para dibujar la tarjeta de una comprobación."""
    if not item.get("aplicable", True):
        return T("state.not_applicable"), "#6c757d", "○"
    if peso_item(item) <= 0:
        if item.get("presente"):
            return T("state.info_on"), "#0d6efd", "ℹ"
        return T("state.info_off"), "#6c757d", "○"
    if not item.get("presente"):
        # Las comprobaciones de transporte (sin cabecera HTTP asociada) no "faltan": no se cumplen.
        return (T("state.failed") if not item.get("header") else T("state.missing")), "#dc3545", "☒"
    if calidad_item(item) < 100:
        return T("state.weak"), "#fd7e14", "⚠"
    return T("state.configured"), "#0a8042", "☑"


def crit_item(item):
    """Criticidad traducida a partir del texto que envía el núcleo."""
    criticidad = str(item.get("criticidad", "")).upper()
    clave = {
        "CRÍTICA": "crit.critical", "CRITICA": "crit.critical",
        "ALTA": "crit.high", "MEDIA": "crit.medium",
        "BAJA": "crit.low", "INFORMATIVA": "crit.info",
    }.get(criticidad)
    return T(clave) if clave else item.get("criticidad", "-")


def nombre_item(item):
    """Nombre de la comprobación (traducido por id, con el texto del núcleo como respaldo)."""
    clave = "check.{}.name".format(item.get("id", ""))
    return T_or(clave, item.get("nombre", ""))


def desc_item(item):
    """Descripción de la comprobación (traducida por id, con el texto del núcleo como respaldo)."""
    clave = "check.{}.desc".format(item.get("id", ""))
    return T_or(clave, item.get("desc", ""))


def aviso_item(item):
    """Observación traducida; si el núcleo no manda clave se usa su texto."""
    texto = item.get("aviso") or ""
    clave = item.get("aviso_clave") or ""
    if not clave:
        return texto
    return T_or("aviso." + clave, texto)


def valor_item(item):
    """Valor traducido cuando el núcleo manda clave y argumentos (transporte)."""
    texto = item.get("valor", "")
    clave = item.get("valor_clave") or ""
    if not clave:
        return texto
    args = item.get("valor_args") or {}
    if not isinstance(args, dict):
        args = {}
    return T_or(clave, texto, **args)


class AuditorSeguridadGUI:
    """Clase principal que gestiona la interfaz gráfica y la lógica de la aplicación de auditoría web."""

    def __init__(self, root):
        self.root = root
        if not i18n.is_initialized():
            i18n.initialize(i18n.load_saved_language())
        self.root.title(T("app.title"))
        self.root.geometry("1020x780")
        self.root.minsize(900, 680)

        # Cola de eventos: los hilos de trabajo nunca tocan Tk directamente.
        self.cola_eventos = queue.Queue()
        self.analizando = False
        self.cerrando = False
        self.mapa_iids = {}
        self._etiquetas_wrap = []
        self._ancho_canvas = 900

        # Cualquier error no controlado queda registrado en disco en lugar de perderse.
        self.root.report_callback_exception = self.registrar_error_no_controlado
        self.root.protocol("WM_DELETE_WINDOW", self.cerrar_aplicacion)

        # Carga el icono gráfico de la aplicación (escudo) si se encuentra disponible en el directorio.
        icon_path = ruta_recurso("escudo.ico")
        if os.path.exists(icon_path):
            try:
                self.root.iconbitmap(icon_path)
            except Exception:
                pass

        # Configuración del motor de estilos de la interfaz (Theming con ttk).
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.configurar_estilos()

        # Inicialización del historial de auditorías y variables de estado.
        self.historial = self.cargar_historial()
        self.ultimo_resultado = None

        # Construcción visual de los componentes de la interfaz.
        self.crear_interfaz()

        # Arranca el bucle que traslada los resultados de los hilos a la interfaz.
        self.root.after(120, self.procesar_cola)

    def configurar_estilos(self):
        """Define los estilos personalizados (fuentes, colores y bordes) para los widgets de ttk."""
        self.style.configure(".", font=("Segoe UI", 10))
        self.style.configure("Header.TFrame", background="#18346a")
        self.style.configure("Title.TLabel", font=("Segoe UI", 16, "bold"), foreground="white", background="#18346a")
        self.style.configure("Subtitle.TLabel", font=("Segoe UI", 10), foreground="#d7e1f5", background="#18346a")
        self.style.configure("MainBtn.TButton", font=("Segoe UI", 10, "bold"), padding=6)
        self.style.configure("Card.TFrame", background="#ffffff", relief="solid", borderwidth=1)

    def crear_interfaz(self):
        """Construye la estructura general de la ventana (Menú, Cabecera, Formulario URL, Pestañas principales)."""
        self.construir_barra_menu()

        # --- Cabecera superior institucional ---
        header_frame = ttk.Frame(self.root, style="Header.TFrame")
        header_frame.pack(fill=tk.X, ipadx=10, ipady=12)

        self.lbl_titulo = ttk.Label(header_frame, text=ico("🛡️ ", "") + T("app.title"), style="Title.TLabel")
        self.lbl_titulo.pack(anchor="w", padx=20)
        self.lbl_subtitulo = ttk.Label(header_frame, text=T("app.subtitle"), style="Subtitle.TLabel")
        self.lbl_subtitulo.pack(anchor="w", padx=20)

        # Copyright del autor: visible en la cabecera y con acceso a "Acerca de".
        self.lbl_copyright = ttk.Label(header_frame, text="{} · {}".format(COPYRIGHT, CORREO),
                                       style="Subtitle.TLabel", cursor="hand2")
        self.lbl_copyright.pack(anchor="e", padx=20)
        self.lbl_copyright.bind("<Button-1>", lambda e: self.acerca_de())

        # --- Panel de Entrada / Formulario URL ---
        self.input_frame = ttk.LabelFrame(self.root, text=" {} ".format(T("form.title")), padding=12)
        self.input_frame.pack(fill=tk.X, padx=20, pady=12)

        self.lbl_url = ttk.Label(self.input_frame, text=T("form.url"))
        self.lbl_url.grid(row=0, column=0, sticky="w", padx=5, pady=5)

        # Obtiene las URLs recientes del historial para autocompletar el campo desplegable.
        urls_recientes = list(dict.fromkeys([item["url"] for item in self.historial if item.get("url")]))[:10]

        self.url_var = tk.StringVar(value=urls_recientes[0] if urls_recientes else "")
        self.combo_url = ttk.Combobox(self.input_frame, textvariable=self.url_var, values=urls_recientes, font=("Segoe UI", 10))
        self.combo_url.grid(row=0, column=1, sticky="ew", padx=5, pady=5)
        self.combo_url.bind("<Return>", lambda e: self.iniciar_hilo_analisis())
        self.input_frame.columnconfigure(1, weight=1)

        # Botones de acción principales (Analizar, Lotes, Exportar)
        self.btn_analizar = ttk.Button(self.input_frame, text=ico("🔍 ", "") + T("form.analyze"), command=self.iniciar_hilo_analisis, style="MainBtn.TButton")
        self.btn_analizar.grid(row=0, column=2, padx=5, pady=5)

        self.btn_lotes = ttk.Button(self.input_frame, text=ico("📂 ", "") + T("form.batch"), command=self.auditoria_por_lotes)
        self.btn_lotes.grid(row=0, column=3, padx=5, pady=5)

        self.btn_exportar = ttk.Button(self.input_frame, text=ico("💾 ", "") + T("form.export") + " ▾", command=self.mostrar_menu_exportacion, state=tk.DISABLED)
        self.btn_exportar.grid(row=0, column=4, padx=5, pady=5)

        # Menú contextual desplegable para las opciones de exportación (PDF, JSON, CSV)
        self.menu_exportar = tk.Menu(self.root, tearoff=0)
        self.rellenar_menu_exportar()

        # --- Contenedor de Pestañas (Notebook) ---
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 15))

        self.tab_informe = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_informe, text=ico("📊 ", "") + T("tab.report"))

        self.tab_historial = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_historial, text=ico("📜 ", "") + T("tab.history"))

        self.construir_tab_informe()
        self.construir_tab_historial()

    def construir_barra_menu(self):
        """Barra de menús: Idioma (16 idiomas) y Ayuda."""
        self.barra_menu = tk.Menu(self.root)

        self.idioma_var = tk.StringVar(value=i18n.current())
        self.menu_idioma = tk.Menu(self.barra_menu, tearoff=0)
        for codigo, nombre in i18n.available():
            self.menu_idioma.add_radiobutton(
                label=nombre, value=codigo, variable=self.idioma_var,
                command=lambda c=codigo: self.cambiar_idioma(c))
        self.barra_menu.add_cascade(label=T("menu.language"), menu=self.menu_idioma)

        self.menu_ayuda = tk.Menu(self.barra_menu, tearoff=0)
        self.menu_ayuda.add_command(label=T("menu.help.about"), command=self.acerca_de)
        self.barra_menu.add_cascade(label=T("menu.help"), menu=self.menu_ayuda)

        self.root.config(menu=self.barra_menu)

    def rellenar_menu_exportar(self):
        """(Re)escribe las opciones del menú de exportación en el idioma activo."""
        self.menu_exportar.delete(0, tk.END)
        self.menu_exportar.add_command(label=T("form.export.pdf"), command=self.exportar_pdf)
        self.menu_exportar.add_command(label=T("form.export.json"), command=self.exportar_json)
        self.menu_exportar.add_command(label=T("form.export.csv"), command=self.exportar_csv)

    def cambiar_idioma(self, codigo):
        """Cambia el idioma en caliente y guarda la preferencia."""
        i18n.set_language(codigo)
        i18n.save_language(i18n.current())
        self.idioma_var.set(i18n.current())
        self.aplicar_idioma()

    def aplicar_idioma(self):
        """Reaplica todos los textos visibles sin reiniciar la aplicación."""
        self.root.title(T("app.title"))
        self.lbl_titulo.config(text=ico("🛡️ ", "") + T("app.title"))
        self.lbl_subtitulo.config(text=T("app.subtitle"))
        self.input_frame.config(text=" {} ".format(T("form.title")))
        self.lbl_url.config(text=T("form.url"))
        self.btn_analizar.config(text=(T("form.analyzing") if self.analizando else ico("🔍 ", "") + T("form.analyze")))
        self.btn_lotes.config(text=ico("📂 ", "") + T("form.batch"))
        self.btn_exportar.config(text=ico("💾 ", "") + T("form.export") + " ▾")
        self.rellenar_menu_exportar()

        self.barra_menu.entryconfig(0, label=T("menu.language"))
        self.barra_menu.entryconfig(1, label=T("menu.help"))
        self.menu_ayuda.entryconfig(0, label=T("menu.help.about"))

        self.notebook.tab(0, text=ico("📊 ", "") + T("tab.report"))
        self.notebook.tab(1, text=ico("📜 ", "") + T("tab.history"))

        self.btn_borrar_item.config(text=ico("🗑️ ", "") + T("hist.delete"))
        self.btn_limpiar_todo.config(text=ico("🧹 ", "") + T("hist.clear"))
        self.btn_restaurar.config(text=ico("♻️ ", "") + T("hist.restore"))
        self.tree_historial.heading("fecha", text=T("hist.date"))
        self.tree_historial.heading("url", text=T("hist.url"))
        self.tree_historial.heading("estado", text=T("hist.status"))
        self.tree_historial.heading("calificacion", text=T("hist.grade"))
        self.actualizar_tabla_historial()

        if self.ultimo_resultado:
            self.mostrar_informe_pantalla(self.ultimo_resultado)
        else:
            self.lbl_estado_general.config(text=T("status.ready"))
            self.lbl_detalles_servidor.config(text=T("status.hint"))

    def mostrar_menu_exportacion(self):
        """Despliega el menú flotante de exportación justo debajo del botón correspondiente."""
        try:
            x = self.btn_exportar.winfo_rootx()
            y = self.btn_exportar.winfo_rooty() + self.btn_exportar.winfo_height()
            self.menu_exportar.tk_popup(x, y)
        finally:
            self.menu_exportar.grab_release()

    def acerca_de(self):
        """Muestra la información de autoría y versión del programa."""
        messagebox.showinfo(
            T("about.title"),
            T("about.text", version=VERSION_APP, author=AUTOR, email=CORREO, copyright=COPYRIGHT)
        )

    def construir_tab_informe(self):
        """Construye la interfaz de la pestaña de informes con soporte para desplazamiento mediante ratón y teclado."""
        self.frame_resumen = ttk.Frame(self.tab_informe, padding=10)
        self.frame_resumen.pack(fill=tk.X)

        self.lbl_estado_general = ttk.Label(self.frame_resumen, text=T("status.ready"), font=("Segoe UI", 11, "bold"))
        self.lbl_estado_general.pack(anchor="w")

        self.lbl_detalles_servidor = ttk.Label(self.frame_resumen, text=T("status.hint"), foreground="#555555")
        self.lbl_detalles_servidor.pack(anchor="w", pady=(2, 0))

        canvas_container = ttk.Frame(self.tab_informe)
        canvas_container.pack(fill=tk.BOTH, expand=True, pady=10)

        # Canvas con barra de desplazamiento vertical interactiva
        self.canvas = tk.Canvas(canvas_container, highlightthickness=0, bg="#e2e2e2", takefocus=1)
        scrollbar = ttk.Scrollbar(canvas_container, orient="vertical", command=self.canvas.yview)

        self.scrollable_frame = ttk.Frame(self.canvas, padding=10)
        self.canvas_window = self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")

        self.scrollable_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))

        def _on_canvas_configure(event):
            self.canvas.itemconfig(self.canvas_window, width=event.width)
            # El ancho real del lienzo define el ajuste de línea de las tarjetas.
            self._ancho_canvas = event.width
            self._aplicar_wrap()

        self.canvas.bind("<Configure>", _on_canvas_configure)
        self.canvas.configure(yscrollcommand=scrollbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Navegación por teclado (flechas, RePág, AvPág) cuando el lienzo tiene el foco.
        self.canvas.bind("<Up>", lambda e: self.canvas.yview_scroll(-3, "units"))
        self.canvas.bind("<Down>", lambda e: self.canvas.yview_scroll(3, "units"))
        self.canvas.bind("<Prior>", lambda e: self.canvas.yview_scroll(-1, "pages"))
        self.canvas.bind("<Next>", lambda e: self.canvas.yview_scroll(1, "pages"))

        # La rueda del ratón se atiende globalmente pero solo actúa sobre el informe,
        # así no se rompe el desplazamiento de otros widgets (por ejemplo el desplegable de URLs).
        self.root.bind_all("<MouseWheel>", self._on_mousewheel, add="+")

    def _pertenece_al_canvas(self, widget):
        """Comprueba si un widget está dentro del lienzo del informe."""
        while widget is not None:
            if widget is self.canvas:
                return True
            widget = getattr(widget, "master", None)
        return False

    def _on_mousewheel(self, event):
        """Maneja el desplazamiento vertical del informe mediante la rueda del ratón."""
        try:
            widget = self.root.winfo_containing(self.root.winfo_pointerx(), self.root.winfo_pointery())
        except (tk.TclError, KeyError):
            return
        if not self._pertenece_al_canvas(widget):
            return

        delta = getattr(event, "delta", 0) or 0
        if delta == 0:
            return
        pasos = int(-delta / 120) or (-1 if delta > 0 else 1)
        self.canvas.yview_scroll(pasos, "units")

    def _aplicar_wrap(self):
        """Ajusta el ancho de las etiquetas del informe al tamaño real de la ventana."""
        ancho = max(240, self._ancho_canvas - 80)
        for etiqueta in list(self._etiquetas_wrap):
            try:
                etiqueta.configure(wraplength=ancho)
            except tk.TclError:
                # La etiqueta ya no existe (informe regenerado).
                try:
                    self._etiquetas_wrap.remove(etiqueta)
                except ValueError:
                    pass

    def construir_tab_historial(self):
        """Construye la tabla (Treeview) para visualizar y gestionar el historial de auditorías pasadas."""
        frame_hist = ttk.Frame(self.tab_historial, padding=10)
        frame_hist.pack(fill=tk.BOTH, expand=True)

        columns = ("fecha", "url", "estado", "calificacion")

        tree_frame = ttk.Frame(frame_hist)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        self.tree_historial = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="browse")

        self.tree_historial.heading("fecha", text=T("hist.date"))
        self.tree_historial.heading("url", text=T("hist.url"))
        self.tree_historial.heading("estado", text=T("hist.status"))
        self.tree_historial.heading("calificacion", text=T("hist.grade"))

        self.tree_historial.column("fecha", width=160, anchor="center")
        self.tree_historial.column("url", width=430, anchor="w")
        self.tree_historial.column("estado", width=120, anchor="center")
        self.tree_historial.column("calificacion", width=150, anchor="center")

        scroll_tree = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree_historial.yview)
        self.tree_historial.configure(yscrollcommand=scroll_tree.set)

        self.tree_historial.pack(side="left", fill="both", expand=True)
        scroll_tree.pack(side="right", fill="y")

        # Botones de control del historial (Borrar registro seleccionado o limpiar todo)
        btn_frame = ttk.Frame(frame_hist)
        btn_frame.pack(fill=tk.X)

        self.btn_borrar_item = ttk.Button(btn_frame, text=ico("🗑️ ", "") + T("hist.delete"), command=self.borrar_item_seleccionado)
        self.btn_borrar_item.pack(side="left", padx=(0, 10))

        self.btn_limpiar_todo = ttk.Button(btn_frame, text=ico("🧹 ", "") + T("hist.clear"), command=self.limpiar_todo_historial)
        self.btn_limpiar_todo.pack(side="left")

        self.btn_restaurar = ttk.Button(btn_frame, text=ico("♻️ ", "") + T("hist.restore"), command=self.restaurar_copia_historial)
        self.btn_restaurar.pack(side="left", padx=(10, 0))

        # Enlaces de eventos del ratón y teclado sobre el Treeview
        self.tree_historial.bind("<Double-1>", self.cargar_analisis_desde_historial)
        self.tree_historial.bind("<Return>", self.cargar_analisis_desde_historial)
        self.tree_historial.bind("<Delete>", lambda e: self.borrar_item_seleccionado())
        self.actualizar_tabla_historial()

    # ==========================================
    # 2. COLA DE EVENTOS (hilos -> interfaz)
    # ==========================================
    def procesar_cola(self):
        """Atiende los mensajes enviados por los hilos de análisis (único punto que toca la GUI)."""
        if self.cerrando:
            return
        try:
            while True:
                tipo, datos = self.cola_eventos.get_nowait()
                if tipo == "progreso":
                    self.lbl_estado_general.config(text=datos, foreground="#555555")
                elif tipo == "exito":
                    self.finalizar_analisis_exitoso(datos)
                elif tipo == "error":
                    self.finalizar_con_error(datos)
                elif tipo == "lote_fin":
                    self.finalizar_lote(datos)
        except queue.Empty:
            pass
        except tk.TclError:
            return
        self.root.after(120, self.procesar_cola)

    def borrar_item_seleccionado(self):
        """Elimina el registro de auditoría seleccionado en el historial tras confirmación."""
        seleccion = self.tree_historial.selection()
        if not seleccion:
            messagebox.showwarning(T("dlg.attention"), T("hist.select_first"))
            return

        idx = self.mapa_iids.get(seleccion[0])
        if idx is None or idx >= len(self.historial):
            self.actualizar_tabla_historial()
            return

        if messagebox.askyesno(T("hist.confirm_delete_title"), T("hist.confirm_delete")):
            del self.historial[idx]
            self.guardar_historial_disco()
            self.actualizar_tabla_historial()

    def limpiar_todo_historial(self):
        """Vacía por completo el historial de auditorías guardado."""
        if not self.historial:
            messagebox.showinfo(T("dlg.attention"), T("hist.empty"))
            return

        if messagebox.askyesno(T("hist.confirm_clear_title"), T("hist.confirm_clear")):
            self.historial.clear()
            self.guardar_historial_disco()
            self.actualizar_tabla_historial()

    def restaurar_copia_historial(self):
        """Recupera los registros de la copia de seguridad que ya no estén en el historial actual."""
        if not os.path.exists(COPIA_HISTORIAL):
            messagebox.showinfo(T("dlg.info"), T("hist.no_backup"))
            return

        try:
            with open(COPIA_HISTORIAL, "r", encoding="utf-8") as f:
                copia = json.load(f)
        except Exception as e:
            messagebox.showerror(T("dlg.error"), T("hist.backup_read_error", error=e))
            return

        if not isinstance(copia, list):
            messagebox.showerror(T("dlg.error"), T("hist.backup_invalid"))
            return

        claves = {(item.get("fecha"), item.get("url")) for item in self.historial}
        nuevos = [item for item in copia
                  if isinstance(item, dict) and item.get("url") and (item.get("fecha"), item.get("url")) not in claves]

        if not nuevos:
            messagebox.showinfo(T("dlg.info"), T("hist.backup_nothing"))
            return

        if messagebox.askyesno(T("hist.restore_title"), T("hist.restore_question", count=len(nuevos))):
            self.historial = (self.historial + nuevos)[:MAX_HISTORIAL]
            self.guardar_historial_disco()
            self.actualizar_tabla_historial()
            messagebox.showinfo(T("dlg.info"), T("hist.restored", count=len(nuevos)))

    # ==========================================
    # 3. LÓGICA DE AUDITORÍA Y SUBPROCESOS
    # ==========================================
    def iniciar_hilo_analisis(self):
        """Valida la URL introducida y lanza un hilo independiente para ejecutar el análisis sin bloquear la GUI."""
        if self.analizando:
            return

        url, error = normalizar_url(self.url_var.get())
        if error:
            messagebox.showwarning(T("dlg.attention"), error)
            return

        self.url_var.set(url)
        self.analizando = True
        self.btn_analizar.config(state=tk.DISABLED, text=T("form.analyzing"))
        self.btn_lotes.config(state=tk.DISABLED)
        self.lbl_estado_general.config(text=T("status.analyzing", url=url), foreground="#555555")

        threading.Thread(target=self.ejecutar_analisis_con_cpp, args=(url,), daemon=True).start()

    def consultar_nucleo(self, url, timeout):
        """
        Ejecuta `auditor_core.exe` y devuelve (resultado, mensaje_de_error).
        Todo el diagnóstico real (DNS, TLS, HTTP, tiempo de espera) viene del núcleo.
        """
        ruta_core = ruta_recurso(NOMBRE_CORE)
        if not os.path.exists(ruta_core):
            return None, T("err.core_missing", name=NOMBRE_CORE)

        startupinfo = None
        creacion = 0
        if os.name == 'nt':
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            creacion = 0x08000000  # CREATE_NO_WINDOW: evita que parpadee una consola

        try:
            proceso = subprocess.run(
                [ruta_core, url],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                startupinfo=startupinfo,
                creationflags=creacion
            )
        except subprocess.TimeoutExpired:
            return None, T("err.timeout", seconds=timeout)
        except OSError as exc:
            return None, T("err.core_start", error=exc)

        texto = (proceso.stdout or "").strip()
        datos = None
        if texto:
            try:
                datos = json.loads(texto)
            except json.JSONDecodeError:
                datos = None

        # El núcleo comunica el motivo exacto del fallo dentro del JSON.
        if isinstance(datos, dict) and datos.get("ok") is False:
            clave = "err.net." + str(datos.get("error") or "unknown")
            mensaje = T_or(clave, datos.get("mensaje") or T("err.generic"))
            if datos.get("error") == "http" and datos.get("status_code"):
                mensaje = T("err.http_code", code=datos.get("status_code"))
            return None, mensaje

        if proceso.returncode != 0 or not isinstance(datos, dict):
            detalle = (proceso.stderr or "").strip()
            mensaje = T("err.generic")
            if detalle:
                mensaje += "\n\n" + T("err.detail", detail=detalle)
            return None, mensaje

        # Comprobación mínima del contrato del núcleo.
        if not isinstance(datos.get("evaluacion"), list) or not datos["evaluacion"]:
            return None, T("err.incomplete")

        status_code = datos.get("status_code") or 0
        if status_code < 200 or status_code >= 400:
            motivo = datos.get("reason") or ""
            return None, T("err.http", code=status_code, reason=motivo).replace("  ", " ")

        # Normalización defensiva de los campos usados por la interfaz.
        datos.setdefault("url", url)
        datos.setdefault("server", T("value.server_hidden"))
        datos.setdefault("presentes", sum(1 for i in datos["evaluacion"] if i.get("presente")))
        datos.setdefault("total", len(datos["evaluacion"]))
        return datos, None

    def completar_puntuacion(self, res):
        """Añade a un resultado la puntuación, el porcentaje y la nota de seguridad."""
        puntos, puntos_max, porcentaje, nota = evaluar_puntuacion(res.get("evaluacion"))
        res["puntos"] = round(puntos, 2)
        res["puntos_max"] = round(puntos_max, 2)
        res["porcentaje"] = round(porcentaje, 1)
        res["calificacion"] = nota
        return res

    def calcular_calificacion(self, evaluacion):
        """Devuelve solo la nota (A+, A, B, C, D, F) de una lista de comprobaciones."""
        return evaluar_puntuacion(evaluacion)[3]

    def ejecutar_analisis_con_cpp(self, url):
        """Hilo de trabajo: analiza la URL y deja el resultado en la cola de eventos."""
        datos, error = self.consultar_nucleo(url, TIMEOUT_ANALISIS)
        if error:
            self.cola_eventos.put(("error", error))
            return

        datos["fecha"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.completar_puntuacion(datos)
        self.cola_eventos.put(("exito", datos))

    def finalizar_analisis_exitoso(self, res):
        """Procesa y actualiza la interfaz cuando una auditoría finaliza con éxito."""
        self.ultimo_resultado = res
        self.mostrar_informe_pantalla(res)
        self.guardar_en_historial(res)
        self.btn_exportar.config(state=tk.NORMAL)
        self.restaurar_controles()
        self.recordar_url(res.get("url", ""))

    def finalizar_con_error(self, mensaje):
        """Restaura la interfaz y muestra el motivo real del fallo."""
        self.restaurar_controles()
        self.lbl_estado_general.config(text=T("status.failed"), foreground="#dc3545")
        self.lbl_detalles_servidor.config(text=mensaje)
        messagebox.showerror(T("err.connection_title"), mensaje)

    def restaurar_controles(self):
        """Restaura el estado original de los botones tras finalizar un análisis."""
        self.analizando = False
        self.btn_analizar.config(state=tk.NORMAL, text=ico("🔍 ", "") + T("form.analyze"))
        self.btn_lotes.config(state=tk.NORMAL)

    def recordar_url(self, url):
        """Coloca la última URL analizada al principio del desplegable."""
        if not url:
            return
        valores_actuales = [v for v in self.combo_url["values"] if v != url]
        valores_actuales.insert(0, url)
        self.combo_url["values"] = valores_actuales[:10]

    def mostrar_informe_pantalla(self, res):
        """Dibuja de forma dinámica las tarjetas con el resultado detallado de cada comprobación."""
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()
        self._etiquetas_wrap = []

        evaluacion = [i for i in res.get("evaluacion", []) if isinstance(i, dict)]
        aplicables = [i for i in evaluacion if i.get("aplicable", True) and peso_item(i) > 0]
        superadas = [i for i in aplicables if i.get("presente") and calidad_item(i) >= 100]
        puntos, puntos_max, porcentaje, nota = evaluar_puntuacion(evaluacion)

        color_resumen = "#0a8042" if nota in ["A+", "A"] else ("#fd7e14" if nota in ["B", "C"] else "#dc3545")
        self.lbl_estado_general.config(
            text=T("status.summary", ok=len(superadas), total=len(aplicables), grade=nota,
                   pct=int(round(porcentaje)), points="{:.1f}".format(puntos), max="{:.0f}".format(puntos_max)),
            foreground=color_resumen
        )

        detalles = T("status.http", status=res.get("status_code", "?"), reason=res.get("reason", ""),
                     server=res.get("server", "?"), date=res.get("fecha", "-"))
        protocolo = res.get("tls_protocolo")
        if protocolo:
            detalles += T("status.tls", protocol=protocolo)
        if res.get("https") is False:
            detalles += T("status.insecure")
        self.lbl_detalles_servidor.config(text=detalles)

        for item in evaluacion:
            estado_txt, color_txt, icono = estado_item(item)
            peso = peso_item(item)

            card = ttk.Frame(self.scrollable_frame, padding=10, style="Card.TFrame")
            card.pack(fill=tk.X, expand=True, pady=6)

            top_line = ttk.Frame(card)
            top_line.pack(fill=tk.X)

            lbl_title = tk.Label(top_line, text="{} {}".format(icono, nombre_item(item)),
                                 font=("Segoe UI", 11, "bold"), fg=color_txt, bg="#ffffff")
            lbl_title.pack(side=tk.LEFT)

            if peso > 0 and item.get("aplicable", True):
                texto_badge = T("card.state", state=estado_txt, crit=crit_item(item),
                                quality=calidad_item(item))
            else:
                texto_badge = T("card.state_simple", state=estado_txt, crit=crit_item(item))

            lbl_badge = tk.Label(top_line, text=texto_badge, font=("Segoe UI", 9, "bold"),
                                 fg="#ffffff", bg=color_txt, padx=8, pady=2)
            lbl_badge.pack(side=tk.RIGHT)

            lbl_desc = tk.Label(card, text=desc_item(item), font=("Segoe UI", 9, "italic"),
                                fg="#555555", bg="#ffffff", anchor="w", justify=tk.LEFT)
            lbl_desc.pack(fill=tk.X, pady=(4, 4))

            if item.get("presente") and peso > 0:
                val_bg = "#ecf6ef" if calidad_item(item) >= 100 else "#fff4e0"
            else:
                val_bg = "#ffebee" if peso > 0 and item.get("aplicable", True) else "#f1f3f5"

            clave_valor = "card.value" if item.get("header") else "card.detail"
            lbl_val = tk.Label(card, text=T(clave_valor, value=valor_item(item)), font=("Consolas", 9),
                               fg="#333333", bg=val_bg, anchor="w", justify=tk.LEFT, padx=6, pady=4)
            lbl_val.pack(fill=tk.X)

            self._etiquetas_wrap.append(lbl_desc)
            self._etiquetas_wrap.append(lbl_val)

            # Observación sobre la calidad del valor (presente pero mal configurado).
            aviso = aviso_item(item).strip()
            if aviso:
                lbl_aviso = tk.Label(card, text=T("card.aviso", text=aviso), font=("Segoe UI", 9),
                                     fg="#8a5a00", bg="#fff4d6", anchor="w", justify=tk.LEFT, padx=6, pady=4)
                lbl_aviso.pack(fill=tk.X, pady=(4, 0))
                self._etiquetas_wrap.append(lbl_aviso)

        self._aplicar_wrap()
        self.canvas.yview_moveto(0)

    # ==========================================
    # 4. GESTIÓN DE PERSISTENCIA E HISTORIAL
    # ==========================================
    def _item_historial(self, res):
        """Construye la entrada de historial a partir de un resultado completo."""
        nota = res.get("calificacion", "N/A")
        porcentaje = res.get("porcentaje")
        if porcentaje is None:
            porcentaje = evaluar_puntuacion(res.get("evaluacion"))[2]
        return {
            "fecha": res.get("fecha", ""),
            "url": res.get("url", ""),
            "status": "{} {}".format(res.get("status_code", ""), res.get("reason", "")).strip() or "N/A",
            "calificacion": T("hist.grade_value", grade=nota, pct=int(round(porcentaje))),
            "grade": nota,
            "pct": int(round(porcentaje)),
            "detalle_completo": res
        }

    def guardar_en_historial(self, res):
        """Añade un nuevo resultado al historial general y lo persiste en disco."""
        self.historial.insert(0, self._item_historial(res))
        self.historial = self.historial[:MAX_HISTORIAL]
        self.guardar_historial_disco()
        self.actualizar_tabla_historial()

    def actualizar_tabla_historial(self):
        """Refresca los elementos visuales de la tabla del historial."""
        for item in self.tree_historial.get_children():
            self.tree_historial.delete(item)

        self.mapa_iids = {}
        for idx, elem in enumerate(self.historial):
            nota = elem.get("calificacion", "")
            if elem.get("grade") is not None:
                nota = T("hist.grade_value", grade=elem.get("grade"), pct=elem.get("pct", 0))
            iid = self.tree_historial.insert("", tk.END, values=(
                elem.get("fecha", ""), elem.get("url", ""), elem.get("status", ""), nota
            ))
            self.mapa_iids[iid] = idx

    def cargar_analisis_desde_historial(self, event=None):
        """Recupera y muestra en pantalla los detalles completos de un análisis previo al hacer doble clic en el historial."""
        seleccion = self.tree_historial.selection()
        if not seleccion:
            return

        idx = self.mapa_iids.get(seleccion[0])
        if idx is None or idx >= len(self.historial):
            self.actualizar_tabla_historial()
            return

        item_hist = self.historial[idx]
        detalle = item_hist.get("detalle_completo")
        if not isinstance(detalle, dict) or not detalle.get("evaluacion"):
            messagebox.showinfo(T("dlg.info"), T("hist.old_no_detail"))
            return

        self.ultimo_resultado = detalle
        self.url_var.set(detalle.get("url", ""))
        self.mostrar_informe_pantalla(detalle)
        self.btn_exportar.config(state=tk.NORMAL)
        self.notebook.select(0)

    def cargar_historial(self):
        """Lee y carga el archivo JSON con el historial de auditorías guardadas previamente en disco."""
        if not os.path.exists(CONFIG_FILE):
            return []
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            return []
        if not isinstance(data, list):
            return []

        # Se descartan entradas corruptas o de versiones antiguas incompletas.
        historial = []
        for elem in data:
            if isinstance(elem, dict) and elem.get("url"):
                historial.append({
                    "fecha": elem.get("fecha", ""),
                    "url": elem.get("url", ""),
                    "status": elem.get("status", ""),
                    "calificacion": elem.get("calificacion", ""),
                    "detalle_completo": elem.get("detalle_completo") if isinstance(elem.get("detalle_completo"), dict) else None,
                })
        return historial[:MAX_HISTORIAL]

    def guardar_historial_disco(self):
        """Escribe el historial en disco (escritura atómica) conservando una copia de seguridad."""
        temporal = CONFIG_FILE + ".tmp"
        try:
            # Copia de seguridad del historial anterior por si hubiera que recuperarlo.
            if os.path.exists(CONFIG_FILE):
                try:
                    shutil.copy2(CONFIG_FILE, COPIA_HISTORIAL)
                except OSError:
                    pass
            with open(temporal, "w", encoding="utf-8") as f:
                json.dump(self.historial, f, ensure_ascii=False, indent=4)
            os.replace(temporal, CONFIG_FILE)
        except Exception as e:
            try:
                if os.path.exists(temporal):
                    os.remove(temporal)
            except OSError:
                pass
            messagebox.showerror(T("dlg.error"), T("hist.save_error", error=e))

    def registrar_error_no_controlado(self, tipo, valor, tb):
        """Guarda en disco cualquier error inesperado de la interfaz (la app compilada no tiene consola)."""
        detalle = "".join(traceback.format_exception(tipo, valor, tb))
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write("\n[{}]\n{}\n".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), detalle))
        except Exception:
            pass
        if not self.cerrando:
            messagebox.showerror(T("err.unexpected_title"), T("err.unexpected", error=valor))

    def cerrar_aplicacion(self):
        """Cierra la ventana de forma ordenada aunque haya un análisis en curso."""
        self.cerrando = True
        try:
            self.root.destroy()
        except tk.TclError:
            pass

    # ==========================================
    # 5. AUDITORÍA POR LOTES Y EXPORTACIÓN
    # ==========================================
    def auditoria_por_lotes(self):
        """Permite seleccionar un archivo de texto con múltiples URLs para analizarlas secuencialmente en segundo plano."""
        if self.analizando:
            return

        filepath = filedialog.askopenfilename(
            title=T("batch.select_file"),
            filetypes=[(T("batch.filter_text"), "*.txt"), (T("batch.filter_all"), "*.*")]
        )
        if not filepath:
            return

        try:
            urls = self.leer_archivo_lotes(filepath)
        except Exception as e:
            messagebox.showerror(T("dlg.error"), T("batch.read_error", error=e))
            return

        if not urls:
            messagebox.showwarning(T("form.batch"), T("batch.empty"))
            return

        self.analizando = True
        self.btn_analizar.config(state=tk.DISABLED)
        self.btn_lotes.config(state=tk.DISABLED)
        self.lbl_estado_general.config(text=T("batch.progress", current=0, total=len(urls), url=""), foreground="#555555")

        threading.Thread(target=self.procesar_lotes, args=(urls,), daemon=True).start()
        messagebox.showinfo(T("batch.title"), T("batch.started"))

    def leer_archivo_lotes(self, filepath):
        """Lee el archivo de URLs tolerando distintas codificaciones (UTF-8, ANSI/Windows-1252)."""
        contenido = None
        for codificacion in ("utf-8-sig", "cp1252", "latin-1"):
            try:
                with open(filepath, "r", encoding=codificacion) as f:
                    contenido = f.read()
                break
            except UnicodeDecodeError:
                continue
        if contenido is None:
            raise ValueError("No se pudo interpretar el texto del archivo.")

        urls = []
        vistos = set()
        for linea in contenido.splitlines():
            limpia = linea.strip().strip('"').strip("'")
            if not limpia or limpia.startswith("#"):
                continue
            normalizada, error = normalizar_url(limpia)
            if normalizada and normalizada not in vistos:
                vistos.add(normalizada)
                urls.append(normalizada)
        return urls

    def procesar_lotes(self, urls):
        """Hilo de trabajo: audita cada URL y publica el progreso y el resumen final."""
        resultados = []
        fallos = []
        total = len(urls)

        for i, u in enumerate(urls, start=1):
            self.cola_eventos.put(("progreso", T("batch.progress", current=i, total=total, url=u)))
            datos, error = self.consultar_nucleo(u, TIMEOUT_LOTE)
            if error:
                fallos.append((u, error))
                continue
            datos["url"] = datos.get("url") or u
            datos["fecha"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.completar_puntuacion(datos)
            resultados.append(datos)

        self.cola_eventos.put(("lote_fin", {"ok": resultados, "fallos": fallos, "total": total}))

    def finalizar_lote(self, payload):
        """Vuelca los resultados del lote en el historial y muestra un resumen al usuario."""
        resultados = payload.get("ok", [])
        fallos = payload.get("fallos", [])
        total = payload.get("total", 0)

        if resultados:
            nuevos = [self._item_historial(r) for r in resultados]
            self.historial = (nuevos + self.historial)[:MAX_HISTORIAL]
            self.guardar_historial_disco()
            self.actualizar_tabla_historial()

            self.ultimo_resultado = resultados[-1]
            self.mostrar_informe_pantalla(self.ultimo_resultado)
            self.btn_exportar.config(state=tk.NORMAL)
            for r in resultados:
                self.recordar_url(r.get("url", ""))

        self.restaurar_controles()

        if resultados:
            resumen = T("batch.finished", ok=len(resultados), total=total)
        else:
            resumen = T("batch.none", total=total)

        if fallos:
            resumen += "\n\n" + T("batch.failures")
            for u, motivo in fallos[:8]:
                resumen += "\n- {}: {}".format(u, motivo)
            if len(fallos) > 8:
                resumen += "\n" + T("batch.more", count=len(fallos) - 8)

        if resultados:
            messagebox.showinfo(T("batch.finished_title"), resumen)
        else:
            messagebox.showerror(T("form.batch"), resumen)

    def exportar_json(self):
        """Exporta el último resultado de la auditoría en formato JSON estructurado."""
        if not self.ultimo_resultado:
            return
        filepath = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[(T("export.file_json"), "*.json")],
            initialfile=nombre_archivo_seguro(self.ultimo_resultado.get("url", ""), "informe_seguridad", ".json")
        )
        if filepath:
            try:
                exportacion = dict(self.ultimo_resultado)
                exportacion["software"] = {
                    "nombre": "Auditor de Seguridad HTTP",
                    "version": VERSION_APP,
                    "autor": AUTOR,
                    "contacto": CORREO,
                    "copyright": COPYRIGHT,
                }
                with open(filepath, "w", encoding="utf-8") as f:
                    json.dump(exportacion, f, ensure_ascii=False, indent=4)
                messagebox.showinfo(T("dlg.success"), T("export.json_ok"))
            except Exception as e:
                messagebox.showerror(T("dlg.error"), T("export.failed", error=e))

    def exportar_csv(self):
        """Exporta el desglose del análisis en formato tabular compatible con hojas de cálculo (CSV)."""
        if not self.ultimo_resultado:
            return
        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[(T("export.file_csv"), "*.csv")],
            initialfile=nombre_archivo_seguro(self.ultimo_resultado.get("url", ""), "informe_seguridad", ".csv")
        )
        if filepath:
            try:
                # utf-8-sig permite que Excel muestre bien los acentos; ';' es el separador de la configuración regional española.
                with open(filepath, "w", newline="", encoding="utf-8-sig") as f:
                    writer = csv.writer(f, delimiter=";")
                    writer.writerow([T("csv.col.check"), T("csv.col.state"), T("csv.col.criticality"),
                                     T("csv.col.weight"), T("csv.col.quality"), T("csv.col.value"),
                                     T("csv.col.note"), T("csv.col.description")])
                    for item in self.ultimo_resultado.get("evaluacion", []):
                        if not isinstance(item, dict):
                            continue
                        writer.writerow([
                            nombre_item(item),
                            estado_item(item)[0],
                            crit_item(item),
                            peso_item(item),
                            calidad_item(item),
                            valor_item(item),
                            aviso_item(item),
                            desc_item(item)
                        ])
                messagebox.showinfo(T("dlg.success"), T("export.csv_ok"))
            except Exception as e:
                messagebox.showerror(T("dlg.error"), T("export.failed", error=e))

    def exportar_pdf(self):
        """Genera y compila un informe profesional en formato PDF utilizando la librería ReportLab."""
        if not self.ultimo_resultado:
            return
        if not REPORTLAB_DISPONIBLE:
            messagebox.showerror(T("export.reportlab_missing_title"), T("export.reportlab_missing"))
            return

        filepath = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[(T("export.file_pdf"), "*.pdf")],
            title=T("export.save_pdf"),
            initialfile=nombre_archivo_seguro(self.ultimo_resultado.get("url", ""), "Informe_Seguridad", ".pdf")
        )

        if not filepath:
            return

        try:
            doc = SimpleDocTemplate(filepath, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36,
                                    title=T("pdf.title"),
                                    author="{} <{}>".format(AUTOR, CORREO),
                                    subject=T("pdf.title"))
            styles = getSampleStyleSheet()

            title_style = ParagraphStyle("DocTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=18,
                                         textColor=colors.HexColor("#18346a"), alignment=0, spaceAfter=10)
            h2_style = ParagraphStyle("Header2", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=12,
                                      textColor=colors.HexColor("#2c3e50"), spaceBefore=10, spaceAfter=6)
            normal_style = ParagraphStyle("Norm", parent=styles["Normal"], fontName="Helvetica", fontSize=9, leading=12)
            code_style = ParagraphStyle("CodeStyle", parent=styles["Normal"], fontName="Courier", fontSize=8.5, leading=10,
                                        textColor=colors.HexColor("#222222"), wordWrap="CJK")

            def texto(valor, estilo=normal_style):
                # Se escapan < > & para que ReportLab no interprete el valor como marcado.
                return Paragraph(escapar_xml(str(valor if valor is not None else "")), estilo)

            story = []

            story.append(Paragraph(escapar_xml(T("pdf.title")), title_style))
            story.append(Spacer(1, 6))

            res = self.ultimo_resultado
            evaluacion = [i for i in res.get("evaluacion", []) if isinstance(i, dict)]
            aplicables = [i for i in evaluacion if i.get("aplicable", True) and peso_item(i) > 0]
            superadas = [i for i in aplicables if i.get("presente") and calidad_item(i) >= 100]
            puntos, puntos_max, porcentaje, nota = evaluar_puntuacion(evaluacion)

            meta = [
                (T("pdf.site"), res.get("url", "-")),
                (T("pdf.date"), res.get("fecha", "-")),
                (T("pdf.status"), "{} {}".format(res.get("status_code", "-"), res.get("reason", "")).strip()),
                (T("pdf.server"), res.get("server", "-")),
                (T("pdf.crypto"), "{} (TLS: {})".format(
                    T("pdf.crypto_https") if res.get("https", True) else T("pdf.crypto_http"),
                    res.get("tls_protocolo") or T("pdf.tls_unavailable"))),
                (T("pdf.grade"), T("pdf.grade_value", grade=nota, pct=int(round(porcentaje)),
                                   points="{:.1f}".format(puntos), max="{:.0f}".format(puntos_max),
                                   ok=len(superadas), total=len(aplicables))),
            ]
            for etiqueta, valor in meta:
                story.append(Paragraph("<b>{}:</b> {}".format(escapar_xml(etiqueta), escapar_xml(str(valor))), normal_style))
            story.append(Spacer(1, 15))

            story.append(Paragraph(escapar_xml(T("pdf.section")), h2_style))

            data = [[T("pdf.col.check"), T("pdf.col.state"), T("pdf.col.criticality"), T("pdf.col.value")]]

            for item in evaluacion:
                estado_txt, color_estado, _ = estado_item(item)
                color = {"#0a8042": "green", "#fd7e14": "#c46a00", "#dc3545": "red",
                         "#0d6efd": "#0d6efd", "#6c757d": "#6c757d"}.get(color_estado, "#333333")
                if item.get("aplicable", True) and peso_item(item) > 0:
                    estado_html = "<font color='{}'><b>{}</b></font><br/>{}".format(
                        color, escapar_xml(estado_txt),
                        escapar_xml(T("pdf.quality", quality=calidad_item(item))))
                else:
                    estado_html = "<font color='{}'>{}</font>".format(color, escapar_xml(estado_txt))
                estado_p = Paragraph(estado_html, normal_style)

                cabecera = "<b>{}</b><br/><font color='#555555'>{}</font>".format(
                    escapar_xml(nombre_item(item)), escapar_xml(desc_item(item)))
                aviso = aviso_item(item).strip()
                if aviso:
                    cabecera += "<br/><font color='#b8860b'>{}</font>".format(
                        escapar_xml(T("pdf.observation", text=aviso)))
                header_p = Paragraph(cabecera, normal_style)

                crit_p = texto(crit_item(item))
                val_p = texto(valor_item(item), code_style)

                data.append([header_p, estado_p, crit_p, val_p])

            table = Table(data, colWidths=[175, 85, 70, 210], repeatRows=1)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#18346a")),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#f8f9fa")),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
            ]))

            story.append(table)
            story.append(Spacer(1, 14))
            story.append(texto(T("pdf.note"),
                               ParagraphStyle("Nota", parent=normal_style, fontSize=8, textColor=colors.HexColor("#666666"))))
            story.append(Spacer(1, 10))
            story.append(texto("{} — {} · {}".format(COPYRIGHT, CORREO, T("app.title")),
                               ParagraphStyle("Firma", parent=normal_style, fontSize=8.5,
                                              textColor=colors.HexColor("#18346a"))))

            def pie_pagina(canvas, documento):
                canvas.saveState()
                canvas.setFont("Helvetica", 7.5)
                canvas.setFillColor(colors.HexColor("#666666"))
                canvas.drawString(36, 26, "{} · {}".format(COPYRIGHT, CORREO))
                canvas.setFont("Helvetica", 7)
                canvas.drawString(36, 16, T("pdf.footer", version=VERSION_APP))
                canvas.setFont("Helvetica", 7.5)
                canvas.drawRightString(letter[0] - 36, 26, T("pdf.page", page=documento.page))
                canvas.restoreState()

            doc.build(story, onFirstPage=pie_pagina, onLaterPages=pie_pagina)

            messagebox.showinfo(T("dlg.success"), T("export.pdf_ok_path", path=filepath))

        except Exception as e:
            messagebox.showerror(T("export.pdf_title"), T("export.pdf_failed", error=e))


# ==========================================
# 6. PUNTO DE ENTRADA DE LA APLICACIÓN
# ==========================================
if __name__ == "__main__":
    root = tk.Tk()
    app = AuditorSeguridadGUI(root)
    # Permite abrir la aplicación con una URL ya puesta: python auditor.py https://ejemplo.com
    if len(sys.argv) > 1:
        app.url_var.set(sys.argv[1])
    root.mainloop()
