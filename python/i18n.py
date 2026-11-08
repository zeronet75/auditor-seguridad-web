# -*- coding: utf-8 -*-
"""
Gestor de idiomas del Auditor de Seguridad Web.

- Un JSON por idioma en la carpeta `localizations/`.
- Claves estables; fallback: idioma actual -> en_US -> clave original.
- Placeholders con nombre: {count}, {path}, {url}...
- La selección se guarda en %APPDATA%\\AuditorSeguridadWeb\\settings.json

Copyright (c) 2026 Juan Ramon Martin <zeronet75@gmail.com>
Licencia MIT (ver el archivo LICENSE).
"""

import json
import os
import re
import sys

DEFAULT_LANGUAGE = "en_US"

# Orden del menú (los idiomas que no estén en la lista se añaden al final).
LANGUAGE_ORDER = [
    "en_US", "ar_AR", "de_DE", "es_ES", "fr_FR", "hi_IN", "id_ID",
    "it_IT", "ja_JP", "ko_KR", "pt_BR", "ru_RU", "tr_TR", "vi_VN",
    "zh_CN", "zh_TW",
]

_PLACEHOLDER = re.compile(r"\{([A-Za-z0-9_]+)\}")
_DEBUG = bool(os.environ.get("AUDITOR_L10N_DEBUG"))


def _base_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def _settings_path():
    appdata = os.environ.get("APPDATA")
    if appdata:
        return os.path.join(appdata, "AuditorSeguridadWeb", "settings.json")
    return os.path.join(_base_dir(), "settings.json")


def _normalize(code):
    if not code:
        return DEFAULT_LANGUAGE
    return str(code).strip().replace("-", "_")


# Idioma de interfaz de Windows (LCID primario -> código de catálogo)
_WINDOWS_LANG = {
    0x01: "ar_AR", 0x04: "zh_CN", 0x07: "de_DE", 0x09: "en_US", 0x0A: "es_ES",
    0x0C: "fr_FR", 0x10: "it_IT", 0x11: "ja_JP", 0x12: "ko_KR", 0x16: "pt_BR",
    0x19: "ru_RU", 0x1F: "tr_TR", 0x21: "id_ID", 0x2A: "vi_VN", 0x39: "hi_IN",
}


def _system_language():
    """Código de idioma del sistema (Windows UI o locale como respaldo)."""
    try:
        import ctypes
        lcid = ctypes.windll.kernel32.GetUserDefaultUILanguage()
        if (lcid & 0x3FF) == 0x04:
            return "zh_TW" if lcid == 0x0404 else "zh_CN"
        codigo = _WINDOWS_LANG.get(lcid & 0x3FF)
        if codigo:
            return codigo
    except Exception:
        pass
    try:
        import locale
        idioma = (locale.getlocale()[0] or "").replace("-", "_")
        if idioma:
            return idioma
    except Exception:
        pass
    return ""


class L10n:
    """Catálogo de textos y idioma activo."""

    def __init__(self, folder=None):
        self.folder = folder or os.path.join(_base_dir(), "localizations")
        self.catalogs = {}
        self.names = {}
        self.code = DEFAULT_LANGUAGE
        self._current = {}
        self._fallback = {}
        self.load()

    # ------------------------------------------------------------------
    def load(self):
        """Lee todos los *.json de la carpeta de localizaciones."""
        self.catalogs = {}
        self.names = {}
        if not os.path.isdir(self.folder):
            return
        for nombre in sorted(os.listdir(self.folder)):
            if not nombre.lower().endswith(".json"):
                continue
            ruta = os.path.join(self.folder, nombre)
            try:
                with open(ruta, "r", encoding="utf-8-sig") as f:
                    data = json.load(f)
                if not isinstance(data, dict):
                    continue
                codigo = os.path.splitext(nombre)[0]
                textos = {k: v for k, v in data.items() if isinstance(v, str)}
                nativo = (textos.get("Language") or codigo).strip() or codigo
                self.catalogs[codigo] = textos
                self.names[codigo] = nativo
            except Exception as exc:  # un JSON roto no debe tumbar la app
                print("[l10n] no se pudo leer {}: {}".format(nombre, exc),
                      file=sys.stderr)

    # ------------------------------------------------------------------
    def available(self):
        """[(codigo, nombre_nativo)] en el orden del menú."""
        codigos = [c for c in LANGUAGE_ORDER if c in self.catalogs]
        codigos += sorted(c for c in self.catalogs if c not in LANGUAGE_ORDER)
        return [(c, self.names.get(c, c)) for c in codigos]

    def language_name(self, code):
        return self.names.get(_normalize(code), code)

    def is_available(self, code):
        return _normalize(code) in self.catalogs

    # ------------------------------------------------------------------
    def resolve_startup(self, saved):
        """Guardado -> idioma del sistema -> inglés."""
        if self.is_available(saved):
            return _normalize(saved)

        sistema = _system_language()
        if self.is_available(sistema):
            return _normalize(sistema)

        neutral = (sistema.split("_")[0] if sistema else "").lower()
        if neutral:
            for codigo in self.catalogs:
                if codigo.lower().startswith(neutral + "_") or codigo.lower() == neutral:
                    return codigo
        return DEFAULT_LANGUAGE

    def set_language(self, code):
        """Activa un idioma. Devuelve el código realmente aplicado."""
        codigo = _normalize(code)
        if codigo not in self.catalogs:
            codigo = DEFAULT_LANGUAGE if DEFAULT_LANGUAGE in self.catalogs else next(
                iter(self.catalogs), DEFAULT_LANGUAGE)
        self.code = codigo
        self._current = self.catalogs.get(codigo, {})
        self._fallback = self.catalogs.get(DEFAULT_LANGUAGE, {})
        return codigo

    # ------------------------------------------------------------------
    def tr(self, key, **kwargs):
        """Traduce una clave; si falta, usa inglés; si tampoco, la clave."""
        if not key:
            return ""
        valor = self._current.get(key)
        if not valor:
            valor = self._fallback.get(key)
        if not valor:
            if _DEBUG:
                print("[l10n] clave no encontrada: {}".format(key), file=sys.stderr)
            return key
        return self._format(valor, key, kwargs)

    def tr_or(self, key, default, **kwargs):
        """Como tr(), pero si la clave no existe devuelve `default`."""
        valor = self._current.get(key) or self._fallback.get(key)
        if not valor:
            return default
        return self._format(valor, key, kwargs)

    def _format(self, texto, key, kwargs):
        if not kwargs:
            return texto

        def reemplazar(match):
            nombre = match.group(1)
            if nombre in kwargs:
                valor = kwargs[nombre]
                return "" if valor is None else str(valor)
            if _DEBUG:
                print("[l10n] placeholder sin valor: {}.{}".format(key, nombre),
                      file=sys.stderr)
            return match.group(0)

        return _PLACEHOLDER.sub(reemplazar, texto)


# ----------------------------------------------------------------------
# Instancia global y atajos
# ----------------------------------------------------------------------
_instancia = None


def initialize(saved_code=None, folder=None):
    global _instancia
    _instancia = L10n(folder)
    _instancia.set_language(_instancia.resolve_startup(saved_code))
    return _instancia


def instance():
    global _instancia
    if _instancia is None:
        initialize()
    return _instancia


def is_initialized():
    return _instancia is not None


def T(key, **kwargs):
    return instance().tr(key, **kwargs)


def T_or(key, default, **kwargs):
    return instance().tr_or(key, default, **kwargs)


def available():
    return instance().available()


def current():
    return instance().code


def language_name(code):
    return instance().language_name(code)


def set_language(code):
    return instance().set_language(code)


# ----------------------------------------------------------------------
# Preferencias (compartidas por la versión Python y la nativa)
# ----------------------------------------------------------------------
def load_saved_language():
    try:
        with open(_settings_path(), "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data.get("Language") or None
    except Exception:
        pass
    return None


def save_language(code):
    ruta = _settings_path()
    try:
        data = {}
        if os.path.exists(ruta):
            try:
                with open(ruta, "r", encoding="utf-8") as f:
                    actual = json.load(f)
                if isinstance(actual, dict):
                    data = actual
            except Exception:
                data = {}
        data["Language"] = _normalize(code)
        os.makedirs(os.path.dirname(ruta), exist_ok=True)
        with open(ruta, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return True
    except Exception:
        return False
