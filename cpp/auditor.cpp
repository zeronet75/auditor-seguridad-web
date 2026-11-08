/**
 * ============================================================================
 * AUDITOR PROFESIONAL DE SEGURIDAD HTTP (VERSIÓN NATIVA C++)
 * ============================================================================
 * Descripción: Aplicación de escritorio desarrollada con Win32 API y C++ nativo
 * para auditar cabeceras de seguridad HTTP, el transporte TLS, las cookies y
 * CORS; gestiona un historial de análisis en formato JSON y exporta informes
 * detallados (PDF, JSON, CSV).
 *
 * Motor HTTP: WinHTTP (validación real de certificados, sin caché ni cookies).
 *
 * La nota de seguridad se calcula con dos criterios:
 *   - peso de cada comprobación (4 CRÍTICA ... 1 BAJA; 0 = informativa)
 *   - calidad del valor configurado (una cabecera presente pero débil resta)
 *
 * Modo de consola (para pruebas y automatización):
 *   auditor.exe --json https://ejemplo.com
 *
 * Copyright (c) 2026 Juan Ramon Martin <zeronet75@gmail.com>
 * Licencia MIT (ver el archivo LICENSE).
 * ============================================================================
 */

#define NOMINMAX
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <windowsx.h>
#include <winhttp.h>
#include <commctrl.h>
#include <shellapi.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <ctime>
#include <cmath>
#include <cwchar>
#include <cstring>
#include <iomanip>
#include <map>
#include <utility>
#include <set>
#include <algorithm>
#include <thread>

// Enlaces a librerías nativas requeridas por el sistema de Windows
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// ============================================================================
// 1. IDENTIFICADORES, CONSTANTES Y MENSAJES PERSONALIZADOS
// ============================================================================
#define IDC_URL_ENTRY        1001
#define IDC_BTN_ANALIZAR     1002
#define IDC_BTN_EXPORTAR     1003
#define IDC_BTN_LOTES        1004
#define IDC_TAB_CONTROL      1005
#define IDC_HIST_TREE        1006
#define IDC_BTN_BORRAR_ITEM  1007
#define IDC_BTN_LIMPIAR_TODO 1008
#define IDC_BTN_RESTAURAR    1009

// Mensajes personalizados para comunicación entre hilos secundarios y la ventana principal
#define WM_ANALISIS_COMPLETO (WM_APP + 1)   // LPARAM: AnalisisResultado*
#define WM_ANALISIS_ERROR    (WM_APP + 2)   // LPARAM: std::wstring* (mensaje de error)
#define WM_LOTES_COMPLETO    (WM_APP + 3)   // LPARAM: std::wstring* (resumen)

// Constantes globales de configuración, autoría y URLs por defecto
const wchar_t DEFAULT_URL[] = L"";   // Sin web por defecto: el usuario introduce la suya
const wchar_t AUTOR[] = L"Juan Ramon Martin";
const wchar_t CORREO[] = L"zeronet75@gmail.com";
const wchar_t COPYRIGHT[] = L"© 2026 Juan Ramon Martin";
const wchar_t VERSION_APP[] = L"4.1";

// ============================================================================
// 2. ESTRUCTURAS DE DATOS
// ============================================================================
// Estructura que define la metadata de cada cabecera HTTP a evaluar
struct CabeceraMeta {
    std::wstring key;
    std::wstring nombre;
    std::wstring desc;
    std::wstring criticidad;
    int peso;
};

// Estructura que almacena el resultado individual de una comprobación
struct CabeceraResultado {
    std::wstring id;
    std::wstring clave;        // Nombre real de la cabecera (vacío en comprobaciones de transporte)
    std::wstring nombre;
    std::wstring desc;
    std::wstring criticidad;
    int peso = 0;
    bool aplicable = true;
    bool presente = false;
    std::wstring valor;
    std::wstring aviso;
    std::wstring avisoClave;
    std::wstring valorClave;
    std::vector<std::pair<std::wstring, std::wstring>> valorArgs;
    int penalizacion = 0;
};

// Estructura que agrupa el resultado completo de la auditoría de un sitio web
struct AnalisisResultado {
    std::wstring fecha;
    std::wstring url;
    std::wstring urlSolicitada;
    int statusCode = 0;
    std::wstring reason;
    std::wstring server;
    bool https = false;
    std::wstring tlsProtocolo;
    long long tlsDias = -1;
    int presentes = 0;
    int aplicables = 0;
    int total = 0;
    double puntos = 0.0;
    double puntosMax = 0.0;
    double porcentaje = 0.0;
    std::wstring calificacion;
    std::wstring motor = L"WinHTTP 4.0";
    std::vector<CabeceraResultado> evaluacion;
};

// Cabecera HTTP recibida tal cual
struct CabeceraCruda {
    std::wstring nombre;
    std::wstring valor;
};

// Respuesta HTTP de una petición (con redirecciones y datos TLS)
struct RespuestaHttp {
    bool ok = false;
    int status = 0;
    std::wstring razon;
    std::wstring urlFinal;
    std::vector<CabeceraCruda> cabeceras;
    bool https = false;
    std::wstring protocoloTls;
    std::wstring emisorTls;
    long long diasCertificado = -1;
    bool aceptaTlsObsoleto = false;
    std::wstring errorCodigo;
    std::wstring errorMensaje;
};

// ============================================================================
// 3. VARIABLES GLOBALES Y GESTIÓN DE FUENTES
// ============================================================================
HWND hEditUrl, hBtnAnalizar, hBtnExportar, hBtnLotes, hTabControl, hHistTree, hPanelInformeScroll, hGrpBox, hLblUrl;
HWND hBtnBorrarItem, hBtnLimpiarTodo, hBtnRestaurar;
HWND hMainWnd;
HMENU hMenuExportar = NULL;
AnalisisResultado g_ultimoResultado;
bool g_tieneResultado = false;
std::vector<AnalisisResultado> g_historialCompleto;
HICON hIconEscudo = NULL;
bool g_analizando = false;
bool g_loteEnCurso = false;
std::wstring g_rutaPdfForzada;   // Solo para el modo consola de pruebas (--pdf)
std::wstring g_urlInicial;       // URL con la que se abre la interfaz (auditor.exe <url>)
bool g_irAlPrincipio = false;    // Fuerza el informe arriba en el siguiente repintado

// Punteros a fuentes tipográficas globales de la interfaz
HFONT hFontBase = NULL;
HFONT hFontBold = NULL;
HFONT hFontItalic = NULL;
HFONT hFontHeader = NULL;
HFONT hFontSubHeader = NULL;
HFONT hFontConsolas = NULL;

// Lista de cabeceras de seguridad HTTP evaluadas (Estándar OWASP)
// peso 0 = informativa: se muestra pero no puntúa.
std::vector<CabeceraMeta> g_cabecerasAEvaluar = {
    { L"Strict-Transport-Security", L"Strict-Transport-Security (HSTS)", L"Obliga a realizar conexiones cifradas HTTPS, evitando ataques Man-in-the-Middle.", L"ALTA", 3 },
    { L"Content-Security-Policy", L"Content-Security-Policy (CSP)", L"Previene inyecciones de código malicioso como Cross-Site Scripting (XSS) y datos no autorizados.", L"CRÍTICA", 4 },
    { L"X-Frame-Options", L"X-Frame-Options", L"Protege la web contra ataques de Clickjacking impidiendo su carga no autorizada en iframes.", L"MEDIA", 2 },
    { L"X-Content-Type-Options", L"X-Content-Type-Options", L"Inhabilita el MIME-Sniffing obligando al navegador a respetar el tipo de contenido declarado.", L"MEDIA", 2 },
    { L"Referrer-Policy", L"Referrer-Policy", L"Controla y limita la fuga de información sensible enviada en los enlaces salientes.", L"MEDIA", 2 },
    { L"Permissions-Policy", L"Permissions-Policy", L"Restringe el acceso no autorizado del navegador a funciones de hardware (cámara, micrófono, GPS).", L"ALTA", 3 },
    { L"Cross-Origin-Opener-Policy", L"Cross-Origin-Opener-Policy (COOP)", L"Aísla el contexto de navegación de la ventana frente a otros documentos externos.", L"MEDIA", 2 },
    { L"Cross-Origin-Embedder-Policy", L"Cross-Origin-Embedder-Policy (COEP)", L"Impide que una página cargue recursos cruzados que no hayan dado permiso explícito. No es necesaria en webs normales.", L"INFORMATIVA", 0 },
    { L"Cache-Control", L"Cache-Control", L"Controla las políticas de almacenamiento en caché para evitar la fuga de datos sensibles.", L"INFORMATIVA", 0 }
};

// ============================================================================
// 4. UTILIDADES GENERALES
// ============================================================================

// Crea fuentes tipográficas personalizadas con suavizado ClearType
HFONT CrearFuenteSuave(int tamano, int peso, bool italica = false, const wchar_t* nombre = L"Segoe UI") {
    return CreateFont(-tamano, 0, 0, 0, peso, italica ? TRUE : FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, nombre);
}

// Inicializa las fuentes globales utilizadas en toda la aplicación
void InicializarFuentesGlobales() {
    hFontBase = CrearFuenteSuave(13, FW_NORMAL);
    hFontBold = CrearFuenteSuave(13, FW_BOLD);
    hFontItalic = CrearFuenteSuave(12, FW_NORMAL, true);
    hFontHeader = CrearFuenteSuave(17, FW_BOLD);
    hFontSubHeader = CrearFuenteSuave(12, FW_NORMAL);
    hFontConsolas = CrearFuenteSuave(12, FW_NORMAL, false, L"Consolas");
}

// Obtiene la fecha y hora actual en formato de cadena de texto
std::wstring FormatearDecimal(double valor, int decimales) {
    wchar_t buf[32];
    if (decimales <= 0) swprintf_s(buf, L"%.0f", valor);
    else if (decimales == 1) swprintf_s(buf, L"%.1f", valor);
    else swprintf_s(buf, L"%.2f", valor);
    return buf;
}

std::wstring ObtenerFechaActual() {
    time_t t = time(0);
    tm ahora;
    localtime_s(&ahora, &t);
    wchar_t buf[80];
    wcsftime(buf, sizeof(buf) / sizeof(wchar_t), L"%Y-%m-%d %H:%M:%S", &ahora);
    return buf;
}

// Carpeta donde se encuentra el ejecutable (para el historial y las copias)
std::wstring CarpetaPrograma() {
    wchar_t ruta[MAX_PATH] = { 0 };
    GetModuleFileNameW(NULL, ruta, MAX_PATH);
    std::wstring p = ruta;
    size_t barra = p.find_last_of(L"\\/");
    return (barra == std::wstring::npos) ? L"." : p.substr(0, barra);
}

std::wstring RutaHistorial() { return CarpetaPrograma() + L"\\historial_auditorias.json"; }
std::wstring RutaCopiaHistorial() { return CarpetaPrograma() + L"\\historial_auditorias.bak.json"; }

std::wstring Trim(const std::wstring& s) {
    size_t inicio = 0, fin = s.size();
    while (inicio < fin && iswspace(s[inicio])) ++inicio;
    while (fin > inicio && iswspace(s[fin - 1])) --fin;
    return s.substr(inicio, fin - inicio);
}

std::wstring Minusculas(const std::wstring& s) {
    std::wstring r = s;
    for (auto& c : r) c = (wchar_t)towlower(c);
    return r;
}

std::string AUtf8(const std::wstring& texto) {
    if (texto.empty()) return std::string();
    int tam = WideCharToMultiByte(CP_UTF8, 0, texto.c_str(), (int)texto.size(), NULL, 0, NULL, NULL);
    std::string salida(tam, '\0');
    WideCharToMultiByte(CP_UTF8, 0, texto.c_str(), (int)texto.size(), &salida[0], tam, NULL, NULL);
    return salida;
}

std::wstring DesdeUtf8(const std::string& texto) {
    if (texto.empty()) return std::wstring();
    int tam = MultiByteToWideChar(CP_UTF8, 0, texto.c_str(), (int)texto.size(), NULL, 0);
    if (tam <= 0) return std::wstring();
    std::wstring salida(tam, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, texto.c_str(), (int)texto.size(), &salida[0], tam);
    return salida;
}

// Escribe un texto en UTF-8 (sin BOM)
bool EscribirArchivoUtf8(const std::wstring& ruta, const std::wstring& texto, bool conBom = false) {
    std::ofstream f(ruta, std::ios::binary | std::ios::trunc);
    if (!f.is_open()) return false;
    if (conBom) {
        const unsigned char bom[3] = { 0xEF, 0xBB, 0xBF };
        f.write((const char*)bom, 3);
    }
    std::string utf8 = AUtf8(texto);
    f.write(utf8.data(), (std::streamsize)utf8.size());
    return f.good();
}

// Lee un archivo de texto tolerando UTF-8 (con o sin BOM) y ANSI
std::wstring LeerArchivoTexto(const std::wstring& ruta) {
    std::ifstream f(ruta, std::ios::binary);
    if (!f.is_open()) return L"";
    std::string crudo((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    if (crudo.size() >= 3 && (unsigned char)crudo[0] == 0xEF && (unsigned char)crudo[1] == 0xBB && (unsigned char)crudo[2] == 0xBF) {
        crudo.erase(0, 3);
    }
    std::wstring texto = DesdeUtf8(crudo);
    if (texto.empty() && !crudo.empty()) {
        int tam = MultiByteToWideChar(CP_ACP, 0, crudo.c_str(), (int)crudo.size(), NULL, 0);
        if (tam > 0) {
            texto.resize(tam);
            MultiByteToWideChar(CP_ACP, 0, crudo.c_str(), (int)crudo.size(), &texto[0], tam);
        }
    }
    return texto;
}

// Escapa una cadena para JSON
std::wstring EscaparJson(const std::wstring& val) {
    std::wstring salida;
    salida.reserve(val.size() + 16);
    for (wchar_t c : val) {
        switch (c) {
            case L'"':  salida += L"\\\""; break;
            case L'\\': salida += L"\\\\"; break;
            case L'\n': salida += L"\\n";  break;
            case L'\r': salida += L"\\r";  break;
            case L'\t': salida += L"\\t";  break;
            default:
                if (c < 0x20) {
                    wchar_t buf[8];
                    swprintf_s(buf, L"\\u%04x", (unsigned)c);
                    salida += buf;
                } else {
                    salida += c;
                }
        }
    }
    return salida;
}

// ============================================================================
// 5. LECTOR JSON (para el historial, compatible con versiones anteriores)
// ============================================================================
struct JsonValor {
    enum Tipo { NULO, BOOLEANO, NUMERO, TEXTO, LISTA, OBJETO } tipo = NULO;
    bool booleano = false;
    double numero = 0.0;
    std::wstring texto;
    std::vector<JsonValor> lista;
    std::vector<std::pair<std::wstring, JsonValor>> objeto;

    const JsonValor* Buscar(const wchar_t* clave) const {
        for (const auto& kv : objeto) {
            if (kv.first == clave) return &kv.second;
        }
        return nullptr;
    }
    std::wstring Texto(const wchar_t* clave, const wchar_t* def = L"") const {
        const JsonValor* v = Buscar(clave);
        return (v && v->tipo == TEXTO) ? v->texto : std::wstring(def);
    }
    int Entero(const wchar_t* clave, int def = 0) const {
        const JsonValor* v = Buscar(clave);
        return (v && v->tipo == NUMERO) ? (int)v->numero : def;
    }
    double Decimal(const wchar_t* clave, double def = 0.0) const {
        const JsonValor* v = Buscar(clave);
        return (v && v->tipo == NUMERO) ? v->numero : def;
    }
    bool Bool(const wchar_t* clave, bool def = false) const {
        const JsonValor* v = Buscar(clave);
        return (v && v->tipo == BOOLEANO) ? v->booleano : def;
    }
};

class JsonParser {
public:
    explicit JsonParser(const std::wstring& texto) : s(texto) {}

    bool Parsear(JsonValor& salida) {
        SaltarEspacios();
        if (!LeerValor(salida)) return false;
        SaltarEspacios();
        return true;
    }

private:
    const std::wstring& s;
    size_t i = 0;

    void SaltarEspacios() { while (i < s.size() && iswspace(s[i])) ++i; }

    bool LeerValor(JsonValor& v) {
        SaltarEspacios();
        if (i >= s.size()) return false;
        wchar_t c = s[i];
        if (c == L'{') return LeerObjeto(v);
        if (c == L'[') return LeerLista(v);
        if (c == L'"') { v.tipo = JsonValor::TEXTO; return LeerCadena(v.texto); }
        if (c == L't' || c == L'f') return LeerBooleano(v);
        if (c == L'n') {
            if (s.compare(i, 4, L"null") == 0) { i += 4; v.tipo = JsonValor::NULO; return true; }
            return false;
        }
        return LeerNumero(v);
    }

    bool LeerCadena(std::wstring& salida) {
        if (i >= s.size() || s[i] != L'"') return false;
        ++i;
        while (i < s.size()) {
            wchar_t c = s[i++];
            if (c == L'"') return true;
            if (c != L'\\') { salida += c; continue; }
            if (i >= s.size()) return false;
            wchar_t esc = s[i++];
            switch (esc) {
                case L'"':  salida += L'"';  break;
                case L'\\': salida += L'\\'; break;
                case L'/':  salida += L'/';  break;
                case L'b':  salida += L'\b'; break;
                case L'f':  salida += L'\f'; break;
                case L'n':  salida += L'\n'; break;
                case L'r':  salida += L'\r'; break;
                case L't':  salida += L'\t'; break;
                case L'u': {
                    if (i + 4 > s.size()) return false;
                    unsigned cp = (unsigned)wcstoul(s.substr(i, 4).c_str(), nullptr, 16);
                    i += 4;
                    if (cp >= 0xD800 && cp <= 0xDBFF && i + 6 <= s.size() && s[i] == L'\\' && s[i + 1] == L'u') {
                        unsigned bajo = (unsigned)wcstoul(s.substr(i + 2, 4).c_str(), nullptr, 16);
                        i += 6;
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (bajo - 0xDC00);
                    }
                    if (cp <= 0xFFFF) {
                        salida += (wchar_t)cp;
                    } else {
                        salida += (wchar_t)(0xD800 + ((cp - 0x10000) >> 10));
                        salida += (wchar_t)(0xDC00 + ((cp - 0x10000) & 0x3FF));
                    }
                    break;
                }
                default: return false;
            }
        }
        return false;
    }

    bool LeerNumero(JsonValor& v) {
        size_t inicio = i;
        if (i < s.size() && (s[i] == L'-' || s[i] == L'+')) ++i;
        while (i < s.size() && (iswdigit(s[i]) || s[i] == L'.' || s[i] == L'e' || s[i] == L'E' || s[i] == L'-' || s[i] == L'+')) ++i;
        if (inicio == i) return false;
        v.tipo = JsonValor::NUMERO;
        v.numero = wcstod(s.substr(inicio, i - inicio).c_str(), nullptr);
        return true;
    }

    bool LeerBooleano(JsonValor& v) {
        if (s.compare(i, 4, L"true") == 0) { i += 4; v.tipo = JsonValor::BOOLEANO; v.booleano = true; return true; }
        if (s.compare(i, 5, L"false") == 0) { i += 5; v.tipo = JsonValor::BOOLEANO; v.booleano = false; return true; }
        return false;
    }

    bool LeerLista(JsonValor& v) {
        ++i;  // '['
        v.tipo = JsonValor::LISTA;
        SaltarEspacios();
        if (i < s.size() && s[i] == L']') { ++i; return true; }
        while (true) {
            JsonValor elem;
            if (!LeerValor(elem)) return false;
            v.lista.push_back(elem);
            SaltarEspacios();
            if (i >= s.size()) return false;
            if (s[i] == L',') { ++i; continue; }
            if (s[i] == L']') { ++i; return true; }
            return false;
        }
    }

    bool LeerObjeto(JsonValor& v) {
        ++i;  // '{'
        v.tipo = JsonValor::OBJETO;
        SaltarEspacios();
        if (i < s.size() && s[i] == L'}') { ++i; return true; }
        while (true) {
            SaltarEspacios();
            std::wstring clave;
            if (!LeerCadena(clave)) return false;
            SaltarEspacios();
            if (i >= s.size() || s[i] != L':') return false;
            ++i;
            JsonValor valor;
            if (!LeerValor(valor)) return false;
            v.objeto.emplace_back(clave, valor);
            SaltarEspacios();
            if (i >= s.size()) return false;
            if (s[i] == L',') { ++i; continue; }
            if (s[i] == L'}') { ++i; return true; }
            return false;
        }
    }
};

// ============================================================================
// 5b. LOCALIZACIÓN (JSON en localizations/, fallback a en_US)
// ============================================================================
namespace L10n {
    const std::wstring DEFECTO = L"en_US";

    std::map<std::wstring, std::map<std::wstring, std::wstring>> g_catalogos;
    std::vector<std::pair<std::wstring, std::wstring>> g_idiomas;   // código, nombre nativo
    std::wstring g_actual = DEFECTO;
    std::wstring g_carpeta;

    std::wstring Carpeta() {
        if (!g_carpeta.empty()) return g_carpeta;
        std::wstring local = CarpetaPrograma() + L"\\localizations";
        g_carpeta = local;
        return g_carpeta;
    }

    std::wstring RutaAjustes() {
        wchar_t appdata[MAX_PATH] = { 0 };
        DWORD n = GetEnvironmentVariableW(L"APPDATA", appdata, MAX_PATH);
        if (n == 0 || n >= MAX_PATH)
            return CarpetaPrograma() + L"\\settings.json";
        return std::wstring(appdata) + L"\\AuditorSeguridadWeb\\settings.json";
    }

    void Cargar() {
        g_catalogos.clear();
        g_idiomas.clear();
        std::wstring patron = Carpeta() + L"\\*.json";
        WIN32_FIND_DATAW datos;
        HANDLE busqueda = FindFirstFileW(patron.c_str(), &datos);
        if (busqueda == INVALID_HANDLE_VALUE) return;

        do {
            if (datos.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            std::wstring archivo = datos.cFileName;
            size_t punto = archivo.find_last_of(L'.');
            if (punto == std::wstring::npos) continue;
            std::wstring codigo = archivo.substr(0, punto);

            std::wstring contenido = LeerArchivoTexto(Carpeta() + L"\\" + archivo);
            if (contenido.empty()) continue;
            JsonValor raiz;
            JsonParser parser(contenido);
            if (!parser.Parsear(raiz) || raiz.tipo != JsonValor::OBJETO) continue;

            std::map<std::wstring, std::wstring> textos;
            for (const auto& kv : raiz.objeto) {
                if (kv.second.tipo == JsonValor::TEXTO)
                    textos[kv.first] = kv.second.texto;
            }
            std::wstring nativo = codigo;
            auto it = textos.find(L"Language");
            if (it != textos.end() && !it->second.empty()) nativo = it->second;
            g_catalogos[codigo] = textos;
            g_idiomas.emplace_back(codigo, nativo);
        } while (FindNextFileW(busqueda, &datos));
        FindClose(busqueda);

        std::sort(g_idiomas.begin(), g_idiomas.end(),
                  [](const std::pair<std::wstring, std::wstring>& a,
                     const std::pair<std::wstring, std::wstring>& b) {
                      return a.first < b.first;
                  });
    }

    const std::vector<std::pair<std::wstring, std::wstring>>& Idiomas() {
        if (g_idiomas.empty()) Cargar();
        return g_idiomas;
    }

    bool Disponible(const std::wstring& codigo) {
        if (g_catalogos.empty()) Cargar();
        return g_catalogos.find(codigo) != g_catalogos.end();
    }

    std::wstring Normalizar(std::wstring codigo) {
        for (auto& c : codigo) if (c == L'-') c = L'_';
        return codigo;
    }

    std::wstring Nombre(const std::wstring& codigo) {
        for (const auto& i : Idiomas())
            if (i.first == codigo) return i.second;
        return codigo;
    }

    std::wstring ResolverInicio() {
        std::wstring guardado;
        std::wstring contenido = LeerArchivoTexto(RutaAjustes());
        if (!contenido.empty()) {
            JsonValor raiz;
            JsonParser parser(contenido);
            if (parser.Parsear(raiz) && raiz.tipo == JsonValor::OBJETO)
                guardado = raiz.Texto(L"Language");
        }
        guardado = Normalizar(guardado);
        if (Disponible(guardado)) return guardado;

        LANGID lang = GetUserDefaultUILanguage();
        WORD primario = PRIMARYLANGID(lang);
        std::wstring porIdioma;
        switch (primario) {
            case LANG_SPANISH: porIdioma = L"es_ES"; break;
            case LANG_GERMAN: porIdioma = L"de_DE"; break;
            case LANG_FRENCH: porIdioma = L"fr_FR"; break;
            case LANG_ITALIAN: porIdioma = L"it_IT"; break;
            case LANG_JAPANESE: porIdioma = L"ja_JP"; break;
            case LANG_KOREAN: porIdioma = L"ko_KR"; break;
            case LANG_PORTUGUESE: porIdioma = L"pt_BR"; break;
            case LANG_RUSSIAN: porIdioma = L"ru_RU"; break;
            case LANG_TURKISH: porIdioma = L"tr_TR"; break;
            case LANG_ARABIC: porIdioma = L"ar_AR"; break;
            case LANG_HINDI: porIdioma = L"hi_IN"; break;
            case LANG_INDONESIAN: porIdioma = L"id_ID"; break;
            case LANG_VIETNAMESE: porIdioma = L"vi_VN"; break;
            case LANG_CHINESE:
                porIdioma = (SUBLANGID(lang) == SUBLANG_CHINESE_TRADITIONAL ||
                             SUBLANGID(lang) == SUBLANG_CHINESE_HONGKONG)
                                ? L"zh_TW" : L"zh_CN";
                break;
        }
        if (Disponible(porIdioma)) return porIdioma;
        return DEFECTO;
    }

    std::wstring Aplicar(const std::wstring& codigo) {
        std::wstring elegido = Normalizar(codigo);
        if (!Disponible(elegido)) elegido = DEFECTO;
        g_actual = elegido;
        return g_actual;
    }

    void Guardar(const std::wstring& codigo) {
        std::wstring ruta = RutaAjustes();
        size_t barra = ruta.find_last_of(L'\\');
        if (barra != std::wstring::npos)
            CreateDirectoryW(ruta.substr(0, barra).c_str(), NULL);
        std::wstring json = L"{\n  \"Language\": \"" + codigo + L"\"\n}\n";
        EscribirArchivoUtf8(ruta, json);
    }

    const std::map<std::wstring, std::wstring>& Catalogo(const std::wstring& codigo) {
        static const std::map<std::wstring, std::wstring> vacio;
        auto it = g_catalogos.find(codigo);
        return (it == g_catalogos.end()) ? vacio : it->second;
    }

    std::wstring Sustituir(const std::wstring& texto, const std::wstring& clave,
                           const std::vector<std::pair<std::wstring, std::wstring>>& args) {
        std::wstring salida;
        for (size_t i = 0; i < texto.size();) {
            if (texto[i] != L'{') { salida += texto[i++]; continue; }
            size_t fin = texto.find(L'}', i);
            if (fin == std::wstring::npos) { salida += texto[i++]; continue; }
            std::wstring nombre = texto.substr(i + 1, fin - i - 1);
            bool sustituido = false;
            for (const auto& a : args) {
                if (a.first == nombre) { salida += a.second; sustituido = true; break; }
            }
            if (!sustituido) {
                salida += texto.substr(i, fin - i + 1);
                if (false) {
                    std::wstring aviso = L"[l10n] placeholder sin valor: " + clave + L"." + nombre + L"\n";
                    OutputDebugStringW(aviso.c_str());
                }
            }
            i = fin + 1;
        }
        return salida;
    }

    std::wstring Tr(const std::wstring& clave,
                    const std::vector<std::pair<std::wstring, std::wstring>>& args = {}) {
        if (g_catalogos.empty()) Cargar();
        const auto& actualCat = Catalogo(g_actual);
        const auto& defectoCat = Catalogo(DEFECTO);
        auto it = actualCat.find(clave);
        if (it != actualCat.end()) return Sustituir(it->second, clave, args);
        it = defectoCat.find(clave);
        if (it != defectoCat.end()) return Sustituir(it->second, clave, args);
        OutputDebugStringW((L"[l10n] clave no encontrada: " + clave + L"\n").c_str());
        return clave;
    }

    std::wstring TrOr(const std::wstring& clave, const std::wstring& defecto,
                      const std::vector<std::pair<std::wstring, std::wstring>>& args = {}) {
        if (g_catalogos.empty()) Cargar();
        const auto& actualCat = Catalogo(g_actual);
        const auto& defectoCat = Catalogo(DEFECTO);
        auto it = actualCat.find(clave);
        if (it != actualCat.end()) return Sustituir(it->second, clave, args);
        it = defectoCat.find(clave);
        if (it != defectoCat.end()) return Sustituir(it->second, clave, args);
        return defecto;
    }
}

// ============================================================================
// 6. PUNTUACIÓN Y EVALUACIÓN DE CADA COMPROBACIÓN
// ============================================================================

// Nota (A+, A, B, C, D, F) a partir del porcentaje de calidad
std::wstring NotaDesdePorcentaje(double porcentaje) {
    if (porcentaje >= 95.0) return L"A+";
    if (porcentaje >= 85.0) return L"A";
    if (porcentaje >= 70.0) return L"B";
    if (porcentaje >= 50.0) return L"C";
    if (porcentaje >= 30.0) return L"D";
    return L"F";
}

// Peso de una comprobación (tolera registros antiguos sin el campo "peso")
int PesoDesdeCriticidad(const std::wstring& criticidad) {
    std::wstring c = Minusculas(criticidad);
    if (c == L"crítica" || c == L"critica") return 4;
    if (c == L"alta") return 3;
    if (c == L"media") return 2;
    if (c == L"baja") return 1;
    if (c == L"informativa") return 0;
    return 2;
}

// Calidad (0-100) de una comprobación según su estado y penalización
int CalidadItem(const CabeceraResultado& item) {
    if (!item.presente || !item.aplicable) return 0;
    int calidad = 100 - item.penalizacion;
    return calidad < 0 ? 0 : calidad;
}

// Calcula la puntuación ponderada global del análisis
void CalcularPuntuacion(AnalisisResultado& r) {
    double puntos = 0.0, maximo = 0.0;
    int presentes = 0, aplicables = 0;

    for (const auto& item : r.evaluacion) {
        if (!item.aplicable || item.peso <= 0) continue;
        aplicables++;
        double calidad = 0.0;
        if (item.presente) {
            calidad = 1.0 - (item.penalizacion / 100.0);
            if (calidad < 0.0) calidad = 0.0;
            if (item.penalizacion < 60) presentes++;
        }
        puntos += item.peso * calidad;
        maximo += item.peso;
    }

    r.puntos = puntos;
    r.puntosMax = maximo;
    r.aplicables = aplicables;
    r.presentes = presentes;
    r.total = (int)r.evaluacion.size();
    r.porcentaje = (maximo > 0.0) ? (puntos / maximo) * 100.0 : 0.0;
    r.calificacion = NotaDesdePorcentaje(r.porcentaje);
}

bool Contiene(const std::wstring& texto, const wchar_t* aguja) {
    return Minusculas(texto).find(Minusculas(aguja)) != std::wstring::npos;
}

// Devuelve una observación cuando el valor está presente pero mal configurado
std::wstring GenerarAviso(const std::wstring& clave, const std::wstring& valor, bool https, int& penalizacion) {
    penalizacion = 0;
    std::wstring v = Minusculas(valor);

    if (clave == L"Strict-Transport-Security") {
        if (!https) {
            penalizacion = 60;
            return L"HSTS solo protege las conexiones HTTPS y el sitio se ha consultado por HTTP.";
        }
        size_t p = v.find(L"max-age");
        if (p == std::wstring::npos) {
            penalizacion = 70;
            return L"No declara max-age; los navegadores ignoran la política.";
        }
        size_t igual = v.find(L'=', p);
        if (igual != std::wstring::npos) {
            long long segundos = _wtoi64(v.c_str() + igual + 1);
            if (segundos <= 0) {
                penalizacion = 60;
                return L"max-age=0 desactiva HSTS en la práctica.";
            }
            if (segundos < 15552000) {
                penalizacion = 30;
                return L"max-age inferior a 6 meses (recomendado 15552000 o más).";
            }
        }
        if (v.find(L"includesubdomains") == std::wstring::npos) {
            penalizacion = 10;
            return L"No incluye includeSubDomains; los subdominios no quedan protegidos.";
        }
        return L"";
    }

    if (clave == L"Content-Security-Policy") {
        bool inlinePermitido = v.find(L"unsafe-inline") != std::wstring::npos;
        bool evalPermitido = v.find(L"unsafe-eval") != std::wstring::npos;
        bool comodin = v.find(L" *") != std::wstring::npos || v.find(L"*;") != std::wstring::npos ||
                       v.find(L"* ") != std::wstring::npos;
        if (inlinePermitido && evalPermitido) {
            penalizacion = 40;
            return L"Permite 'unsafe-inline' y 'unsafe-eval'; reduce mucho la protección frente a XSS.";
        }
        if (inlinePermitido) {
            penalizacion = 30;
            return L"Permite 'unsafe-inline'; reduce la protección frente a XSS.";
        }
        if (evalPermitido) {
            penalizacion = 20;
            return L"Permite 'unsafe-eval'; permite ejecutar código generado en tiempo de ejecución.";
        }
        if (comodin) {
            penalizacion = 40;
            return L"Incluye el comodín '*' y admite recursos de cualquier origen.";
        }
        return L"";
    }

    if (clave == L"X-Frame-Options") {
        if (v.find(L"allowall") != std::wstring::npos) {
            penalizacion = 70;
            return L"ALLOWALL desactiva la protección frente a Clickjacking.";
        }
        if (v.find(L"allow-from") != std::wstring::npos) {
            penalizacion = 50;
            return L"ALLOW-FROM ya no lo admiten los navegadores modernos; usa CSP frame-ancestors.";
        }
        if (v != L"deny" && v != L"sameorigin") {
            penalizacion = 50;
            return L"Valor no reconocido; debería ser DENY o SAMEORIGIN.";
        }
        return L"";
    }

    if (clave == L"X-Content-Type-Options") {
        if (v != L"nosniff") {
            penalizacion = 60;
            return L"El único valor válido es nosniff.";
        }
        return L"";
    }

    if (clave == L"Referrer-Policy") {
        if (v.find(L"unsafe-url") != std::wstring::npos) {
            penalizacion = 50;
            return L"unsafe-url envía la URL completa a sitios externos.";
        }
        if (v.find(L"no-referrer-when-downgrade") != std::wstring::npos) {
            penalizacion = 15;
            return L"Configuración heredada; se recomienda strict-origin-when-cross-origin.";
        }
        return L"";
    }

    if (clave == L"Permissions-Policy") {
        if (valor.find(L'*') != std::wstring::npos) {
            penalizacion = 40;
            return L"El comodín '*' deja las funciones abiertas a cualquier origen.";
        }
        return L"";
    }

    if (clave == L"Cross-Origin-Opener-Policy") {
        if (v.find(L"unsafe-none") != std::wstring::npos) {
            penalizacion = 40;
            return L"unsafe-none no aísla la ventana frente a otros orígenes.";
        }
        return L"";
    }

    if (clave == L"Cross-Origin-Embedder-Policy") {
        if (v.find(L"unsafe-none") != std::wstring::npos) {
            penalizacion = 0;
            return L"unsafe-none permite cargar recursos cruzados sin permiso explícito.";
        }
        return L"";
    }

    if (clave == L"Cache-Control") {
        if (v.find(L"no-store") == std::wstring::npos && v.find(L"no-cache") == std::wstring::npos &&
            v.find(L"private") == std::wstring::npos && v.find(L"must-revalidate") == std::wstring::npos) {
            penalizacion = 0;
            return L"Permite almacenar la respuesta en caché; revísalo si sirve contenido sensible.";
        }
        return L"";
    }

    return L"";
}

bool TieneCabecera(const std::vector<CabeceraCruda>& lista, const std::wstring& nombre, std::wstring& valor) {
    std::wstring objetivo = Minusculas(nombre);
    bool encontrada = false;
    for (const auto& cab : lista) {
        if (Minusculas(cab.nombre) == objetivo) {
            if (!encontrada) { valor = cab.valor; encontrada = true; }
            else { valor += L", " + cab.valor; }
        }
    }
    return encontrada;
}

std::vector<std::wstring> TodasLasCabeceras(const std::vector<CabeceraCruda>& lista, const std::wstring& nombre) {
    std::vector<std::wstring> valores;
    std::wstring objetivo = Minusculas(nombre);
    for (const auto& cab : lista) {
        if (Minusculas(cab.nombre) == objetivo) valores.push_back(cab.valor);
    }
    return valores;
}

CabeceraResultado EvaluarCabecera(const CabeceraMeta& meta, const RespuestaHttp& resp) {
    CabeceraResultado c;
    c.id = Minusculas(meta.key);
    c.clave = meta.key;
    c.nombre = meta.nombre;
    c.desc = meta.desc;
    c.criticidad = meta.criticidad;
    c.peso = meta.peso;
    c.aplicable = true;
    c.presente = false;
    c.valor = L"No configurada";

    std::wstring valor;
    if (TieneCabecera(resp.cabeceras, meta.key, valor)) {
        c.presente = true;
        c.valor = valor.empty() ? L"(cabecera enviada sin valor)" : valor;
        c.aviso = GenerarAviso(meta.key, c.valor, resp.https, c.penalizacion);
    } else if (meta.key == L"Strict-Transport-Security" && !resp.https) {
        c.aviso = L"El sitio se ha consultado por HTTP sin cifrar.";
    }
    return c;
}

CabeceraResultado EvaluarCookies(const RespuestaHttp& resp) {
    CabeceraResultado c;
    c.id = L"cookies";
    c.nombre = L"Cookies seguras (Secure / HttpOnly / SameSite)";
    c.desc = L"Impide que las cookies viajen sin cifrar, sean leídas por JavaScript o se envíen en peticiones cruzadas.";
    c.criticidad = L"ALTA";
    c.peso = 3;

    std::vector<std::wstring> galletas = TodasLasCabeceras(resp.cabeceras, L"Set-Cookie");
    if (galletas.empty()) {
        c.aplicable = false;
        c.presente = true;
        c.valorClave = L"value.no_cookies";
        c.valor = L"La web no envía cookies en esta respuesta";
        return c;
    }

    int sinSecure = 0, sinHttpOnly = 0, sinSameSite = 0;
    for (const auto& galleta : galletas) {
        bool secure = false, httpOnly = false, sameSite = false;
        std::wstringstream partes(galleta);
        std::wstring trozo;
        bool primero = true;
        while (std::getline(partes, trozo, L';')) {
            std::wstring atributo = Minusculas(Trim(trozo));
            if (primero) { primero = false; continue; }
            if (atributo == L"secure") secure = true;
            else if (atributo == L"httponly") httpOnly = true;
            else if (atributo.rfind(L"samesite", 0) == 0) sameSite = true;
        }
        if (!secure) sinSecure++;
        if (!httpOnly) sinHttpOnly++;
        if (!sameSite) sinSameSite++;
    }

    if (sinSecure > 0)   c.penalizacion = (std::max)(c.penalizacion, 60);
    if (sinHttpOnly > 0) c.penalizacion = (std::max)(c.penalizacion, 50);
    if (sinSameSite > 0) c.penalizacion = (std::max)(c.penalizacion, 25);

    wchar_t valor[256];
    swprintf_s(valor, L"%zu cookies | sin Secure: %d | sin HttpOnly: %d | sin SameSite: %d",
               galletas.size(), sinSecure, sinHttpOnly, sinSameSite);
    c.valor = valor;
    c.presente = (c.penalizacion == 0);
    c.valorClave = L"value.cookies";
    c.valorArgs = { { L"total", std::to_wstring(galletas.size()) },
                    { L"secure", std::to_wstring(sinSecure) },
                    { L"httponly", std::to_wstring(sinHttpOnly) },
                    { L"samesite", std::to_wstring(sinSameSite) } };

    if (sinSecure > 0)        c.aviso = L"Hay cookies que se enviarían también por HTTP sin cifrar.";
    else if (sinHttpOnly > 0) c.aviso = L"Hay cookies legibles desde JavaScript (riesgo si existe XSS).";
    else if (sinSameSite > 0) c.aviso = L"Hay cookies sin SameSite; pueden viajar en peticiones de otros sitios (CSRF).";

    return c;
}

CabeceraResultado EvaluarCors(const RespuestaHttp& resp) {
    CabeceraResultado c;
    c.id = L"cors";
    c.nombre = L"CORS (Access-Control-Allow-Origin)";
    c.desc = L"Controla qué páginas externas pueden leer las respuestas del servidor desde el navegador.";
    c.criticidad = L"MEDIA";
    c.peso = 2;

    std::wstring origen, credenciales;
    bool tieneOrigen = TieneCabecera(resp.cabeceras, L"Access-Control-Allow-Origin", origen);
    bool tieneCredenciales = TieneCabecera(resp.cabeceras, L"Access-Control-Allow-Credentials", credenciales);

    if (!tieneOrigen) {
        c.aplicable = false;
        c.presente = true;
        c.valorClave = L"value.no_cors";
        c.valor = L"No se envía cabecera Access-Control-Allow-Origin";
        return c;
    }

    std::wstring cred = Minusculas(Trim(credenciales));
    c.valorClave = L"value.cors";
    c.valor = L"Access-Control-Allow-Origin: " + origen;
    if (tieneCredenciales) c.valor += L" | Credenciales: " + (credenciales.empty() ? L"?" : credenciales);
    c.valorArgs = { { L"origin", origen },
                    { L"credentials", tieneCredenciales ? (credenciales.empty() ? L"?" : credenciales) : L"-" } };

    if (origen == L"*") {
        if (cred == L"true") {
            c.penalizacion = 90;
            c.aviso = L"Permite cualquier origen con credenciales: cualquier web podría leer datos autenticados.";
        } else {
            c.penalizacion = 30;
            c.aviso = L"Permite cualquier origen (*); revisa si expone información privada.";
        }
    }
    c.presente = (c.penalizacion == 0);
    return c;
}

// ============================================================================
// 7. MOTOR HTTP (WINHTTP), REDIRECCIONES Y TLS
// ============================================================================
std::wstring EsquemaDeUrl(int nScheme) {
    return (nScheme == INTERNET_SCHEME_HTTP) ? L"http://" : L"https://";
}

std::wstring SufijoPuerto(int nScheme, INTERNET_PORT puerto) {
    if (nScheme == INTERNET_SCHEME_HTTP && puerto != INTERNET_DEFAULT_HTTP_PORT)
        return L":" + std::to_wstring(puerto);
    if (nScheme == INTERNET_SCHEME_HTTPS && puerto != INTERNET_DEFAULT_HTTPS_PORT)
        return L":" + std::to_wstring(puerto);
    return L"";
}

std::wstring NormalizarRuta(const std::wstring& ruta) {
    bool barraFinal = !ruta.empty() && ruta.back() == L'/';
    std::vector<std::wstring> partes;
    std::wstring actual;
    for (wchar_t ch : ruta) {
        if (ch == L'/') {
            if (!actual.empty()) { partes.push_back(actual); actual.clear(); }
        } else {
            actual += ch;
        }
    }
    if (!actual.empty()) partes.push_back(actual);

    std::vector<std::wstring> salida;
    for (const auto& p : partes) {
        if (p == L".") continue;
        if (p == L"..") { if (!salida.empty()) salida.pop_back(); continue; }
        salida.push_back(p);
    }

    std::wstring resultado = L"/";
    for (size_t i = 0; i < salida.size(); ++i) {
        resultado += salida[i];
        if (i + 1 < salida.size()) resultado += L"/";
    }
    if (barraFinal && resultado.size() > 1) resultado += L"/";
    return resultado;
}

std::wstring ResolverRedireccion(const std::wstring& base, const std::wstring& location) {
    std::wstring loc = Trim(location);
    if (loc.empty()) return L"";
    std::wstring locMin = Minusculas(loc);

    if (locMin.rfind(L"http://", 0) == 0 || locMin.rfind(L"https://", 0) == 0) return loc;

    URL_COMPONENTS uc = { 0 };
    uc.dwStructSize = sizeof(uc);
    wchar_t host[512] = { 0 }, ruta[4096] = { 0 };
    uc.lpszHostName = host;  uc.dwHostNameLength = 512;
    uc.lpszUrlPath = ruta;   uc.dwUrlPathLength = 4096;
    if (!WinHttpCrackUrl(base.c_str(), 0, 0, &uc)) return L"";

    std::wstring origen = EsquemaDeUrl(uc.nScheme) + std::wstring(host) + SufijoPuerto(uc.nScheme, uc.nPort);

    if (loc.rfind(L"//", 0) == 0) {
        std::wstring esquema = (uc.nScheme == INTERNET_SCHEME_HTTP) ? L"http:" : L"https:";
        return esquema + loc;
    }
    if (loc[0] == L'/') return origen + loc;
    if (loc[0] == L'?') return origen + std::wstring(ruta) + loc;
    if (loc[0] == L'#') {
        size_t almohadilla = base.find(L'#');
        return (almohadilla == std::wstring::npos) ? base : base.substr(0, almohadilla);
    }

    std::wstring directorio(ruta);
    size_t barra = directorio.find_last_of(L'/');
    directorio = (barra == std::wstring::npos) ? L"/" : directorio.substr(0, barra + 1);
    return origen + NormalizarRuta(directorio + loc);
}

void ClasificarError(DWORD codigo, RespuestaHttp& r) {
    switch (codigo) {
        case ERROR_WINHTTP_NAME_NOT_RESOLVED:
            r.errorCodigo = L"dns";
            r.errorMensaje = L"No se pudo resolver el dominio: revisa que la dirección esté escrita correctamente.";
            break;
        case ERROR_WINHTTP_CANNOT_CONNECT:
            r.errorCodigo = L"conexion";
            r.errorMensaje = L"No se pudo conectar con el servidor: el puerto está cerrado o el host no responde.";
            break;
        case ERROR_WINHTTP_TIMEOUT:
            r.errorCodigo = L"timeout";
            r.errorMensaje = L"El servidor tarda demasiado en responder o ha cortado la conexión.";
            break;
        case ERROR_WINHTTP_SECURE_CERT_DATE_INVALID:
            r.errorCodigo = L"tls";
            r.errorMensaje = L"El certificado TLS está caducado o aún no es válido.";
            break;
        case ERROR_WINHTTP_SECURE_CERT_CN_INVALID:
            r.errorCodigo = L"tls";
            r.errorMensaje = L"El certificado TLS no corresponde al dominio consultado.";
            break;
        case ERROR_WINHTTP_SECURE_INVALID_CA:
            r.errorCodigo = L"tls";
            r.errorMensaje = L"El certificado TLS lo emite una autoridad desconocida.";
            break;
        case ERROR_WINHTTP_SECURE_CERT_REV_FAILED:
            r.errorCodigo = L"tls";
            r.errorMensaje = L"No se pudo comprobar la revocación del certificado TLS.";
            break;
        case ERROR_WINHTTP_SECURE_CERT_REVOKED:
            r.errorCodigo = L"tls";
            r.errorMensaje = L"El certificado TLS está revocado.";
            break;
        case ERROR_WINHTTP_SECURE_INVALID_CERT:
            r.errorCodigo = L"tls";
            r.errorMensaje = L"El certificado TLS no es de confianza.";
            break;
        case ERROR_WINHTTP_SECURE_FAILURE:
        case ERROR_WINHTTP_SECURE_CHANNEL_ERROR:
            r.errorCodigo = L"tls";
            r.errorMensaje = L"Falló la negociación TLS con el servidor (protocolo o cifrado no admitido).";
            break;
        case ERROR_WINHTTP_INVALID_URL:
        case ERROR_WINHTTP_UNRECOGNIZED_SCHEME:
            r.errorCodigo = L"url";
            r.errorMensaje = L"La dirección indicada no es una URL válida.";
            break;
        case ERROR_WINHTTP_CONNECTION_ERROR:
            r.errorCodigo = L"conexion";
            r.errorMensaje = L"El servidor ha cerrado la conexión inesperadamente.";
            break;
        case ERROR_WINHTTP_REDIRECT_FAILED:
            r.errorCodigo = L"redireccion";
            r.errorMensaje = L"El servidor devuelve redirecciones repetidas o no seguras (por ejemplo de HTTPS a HTTP).";
            break;
        default: {
            r.errorCodigo = L"red";
            wchar_t buf[256] = { 0 };
            swprintf_s(buf, L"No se pudo completar la petición HTTP (código WinHTTP %lu).", (unsigned long)codigo);
            r.errorMensaje = buf;
            break;
        }
    }
}

bool ConsultarTexto(HINTERNET hRequest, DWORD consulta, std::wstring& salida) {
    DWORD tam = 0;
    WinHttpQueryHeaders(hRequest, consulta, WINHTTP_HEADER_NAME_BY_INDEX, NULL, &tam, WINHTTP_NO_HEADER_INDEX);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || tam == 0) return false;

    std::vector<wchar_t> buffer(tam / sizeof(wchar_t) + 2, 0);
    DWORD tamReal = (DWORD)(buffer.size() * sizeof(wchar_t));
    if (!WinHttpQueryHeaders(hRequest, consulta, WINHTTP_HEADER_NAME_BY_INDEX, buffer.data(), &tamReal, WINHTTP_NO_HEADER_INDEX))
        return false;
    salida = Trim(buffer.data());
    return true;
}

std::vector<CabeceraCruda> ParsearCabeceras(const std::wstring& crudo) {
    std::vector<CabeceraCruda> lista;
    size_t pos = 0;
    bool primeraLinea = true;

    while (pos < crudo.size()) {
        size_t fin = crudo.find(L"\r\n", pos);
        std::wstring linea = crudo.substr(pos, (fin == std::wstring::npos) ? std::wstring::npos : fin - pos);
        pos = (fin == std::wstring::npos) ? crudo.size() : fin + 2;

        if (primeraLinea) { primeraLinea = false; continue; }
        if (linea.empty()) continue;

        if ((linea[0] == L' ' || linea[0] == L'\t') && !lista.empty()) {
            lista.back().valor += L" " + Trim(linea);
            continue;
        }

        size_t dosPuntos = linea.find(L':');
        if (dosPuntos == std::wstring::npos) continue;

        CabeceraCruda cab;
        cab.nombre = Trim(linea.substr(0, dosPuntos));
        cab.valor = Trim(linea.substr(dosPuntos + 1));
        if (!cab.nombre.empty()) lista.push_back(cab);
    }
    return lista;
}

long long DiasHasta(const FILETIME& destino) {
    ULARGE_INTEGER objetivo, ahora;
    objetivo.LowPart = destino.dwLowDateTime;
    objetivo.HighPart = destino.dwHighDateTime;
    FILETIME ahoraFt;
    GetSystemTimeAsFileTime(&ahoraFt);
    ahora.LowPart = ahoraFt.dwLowDateTime;
    ahora.HighPart = ahoraFt.dwHighDateTime;
    if (objetivo.QuadPart <= ahora.QuadPart) return -1;
    return (long long)((objetivo.QuadPart - ahora.QuadPart) / 864000000000ULL);
}

std::wstring UnirLineas(const std::wstring& texto) {
    std::wstringstream ss(texto);
    std::wstring linea, resultado;
    while (std::getline(ss, linea)) {
        linea = Trim(linea);
        if (linea.empty()) continue;
        if (!resultado.empty()) resultado += L", ";
        resultado += linea;
    }
    if (resultado.size() > 120) resultado = resultado.substr(0, 117) + L"...";
    return resultado;
}

void ObtenerInfoTls(HINTERNET hRequest, RespuestaHttp& r) {
    WINHTTP_CERTIFICATE_INFO info = { 0 };
    DWORD tam = sizeof(info);
    if (WinHttpQueryOption(hRequest, WINHTTP_OPTION_SECURITY_CERTIFICATE_STRUCT, &info, &tam)) {
        if (info.lpszProtocolName) r.protocoloTls = UnirLineas(info.lpszProtocolName);
        if (info.lpszIssuerInfo) r.emisorTls = UnirLineas(info.lpszIssuerInfo);
        r.diasCertificado = DiasHasta(info.ftExpiry);
        if (info.lpszSubjectInfo) LocalFree(info.lpszSubjectInfo);
        if (info.lpszIssuerInfo) LocalFree(info.lpszIssuerInfo);
        if (info.lpszProtocolName) LocalFree(info.lpszProtocolName);
        if (info.lpszSignatureAlgName) LocalFree(info.lpszSignatureAlgName);
        if (info.lpszEncryptionAlgName) LocalFree(info.lpszEncryptionAlgName);
    }
}

// WinHTTP no informa de la versión negociada: se repite el saludo restringiendo protocolos.
#ifndef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1
#define WINHTTP_FLAG_SECURE_PROTOCOL_SSL3   0x00000020
#define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1   0x00000080
#define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_1 0x00000200
#define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 0x00000800
#endif
#define PROTOCOLO_TLS1_3 0x00002000

bool HandshakeConProtocolo(const std::wstring& url, DWORD mascara) {
    URL_COMPONENTS uc = { 0 };
    uc.dwStructSize = sizeof(uc);
    wchar_t host[512] = { 0 }, ruta[4096] = { 0 };
    uc.lpszHostName = host;  uc.dwHostNameLength = 512;
    uc.lpszUrlPath = ruta;   uc.dwUrlPathLength = 4096;
    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &uc)) return false;

    std::wstring rutaCompleta = std::wstring(ruta) + (uc.lpszExtraInfo ? uc.lpszExtraInfo : L"");
    if (rutaCompleta.empty()) rutaCompleta = L"/";

    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AuditorSeguridadWeb/4.0",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;
    WinHttpSetTimeouts(hSession, 8000, 8000, 8000, 10000);
    WinHttpSetOption(hSession, WINHTTP_OPTION_SECURE_PROTOCOLS, &mascara, sizeof(mascara));

    bool ok = false;
    HINTERNET hConnect = WinHttpConnect(hSession, host, uc.nPort, 0);
    if (hConnect) {
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", rutaCompleta.c_str(), NULL,
                                                WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                                WINHTTP_FLAG_SECURE);
        if (hRequest) {
            DWORD politica = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
            WinHttpSetOption(hRequest, WINHTTP_OPTION_REDIRECT_POLICY, &politica, sizeof(politica));
            ok = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
                 WinHttpReceiveResponse(hRequest, NULL);
            WinHttpCloseHandle(hRequest);
        }
        WinHttpCloseHandle(hConnect);
    }
    WinHttpCloseHandle(hSession);
    return ok;
}

std::wstring DetectarProtocolo(const std::wstring& url, bool& aceptaObsoleto) {
    aceptaObsoleto = false;
    std::wstring version;
    if (HandshakeConProtocolo(url, PROTOCOLO_TLS1_3))                          version = L"TLS 1.3";
    else if (HandshakeConProtocolo(url, WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2))  version = L"TLS 1.2";
    else if (HandshakeConProtocolo(url, WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_1))  version = L"TLS 1.1";
    else if (HandshakeConProtocolo(url, WINHTTP_FLAG_SECURE_PROTOCOL_TLS1))    version = L"TLS 1.0";
    else                                                                       version = L"desconocido";

    aceptaObsoleto = HandshakeConProtocolo(url, WINHTTP_FLAG_SECURE_PROTOCOL_TLS1 |
                                                WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_1);
    return version;
}

// Cuando WinHTTP rechaza el certificado solo informa de "SECURE_FAILURE": se
// repite la petición ignorando los errores para describir el problema real.
bool DiagnosticarCertificado(HINTERNET hSession, const std::wstring& url, std::wstring& mensaje) {
    URL_COMPONENTS uc = { 0 };
    uc.dwStructSize = sizeof(uc);
    wchar_t host[512] = { 0 }, ruta[4096] = { 0 };
    uc.lpszHostName = host;  uc.dwHostNameLength = 512;
    uc.lpszUrlPath = ruta;   uc.dwUrlPathLength = 4096;
    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &uc)) return false;
    if (uc.nScheme != INTERNET_SCHEME_HTTPS) return false;

    std::wstring rutaCompleta = std::wstring(ruta) + (uc.lpszExtraInfo ? uc.lpszExtraInfo : L"");
    if (rutaCompleta.empty()) rutaCompleta = L"/";

    HINTERNET hConnect = WinHttpConnect(hSession, host, uc.nPort, 0);
    if (!hConnect) return false;

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", rutaCompleta.c_str(), NULL,
                                            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                            WINHTTP_FLAG_SECURE);
    if (!hRequest) { WinHttpCloseHandle(hConnect); return false; }

    DWORD ignorar = SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &ignorar, sizeof(ignorar));

    bool ok = false;
    if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
        WinHttpReceiveResponse(hRequest, NULL)) {
        RespuestaHttp diag;
        ObtenerInfoTls(hRequest, diag);

        if (diag.diasCertificado < 0 && !diag.emisorTls.empty()) {
            mensaje = L"El certificado TLS no es válido: ya ha caducado.";
        } else if (diag.diasCertificado >= 0 && diag.emisorTls.empty()) {
            mensaje = L"El certificado TLS no es de confianza: no se reconoce su autoridad emisora.";
        } else if (diag.diasCertificado >= 0) {
            mensaje = L"El certificado TLS no corresponde a este dominio (emisor: " + diag.emisorTls + L").";
        }
        ok = true;
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    return ok;
}

void ClasificarFallo(DWORD codigo, HINTERNET hSession, const std::wstring& url, RespuestaHttp& r) {
    ClasificarError(codigo, r);
    bool esTls = (codigo == ERROR_WINHTTP_SECURE_FAILURE ||
                  codigo == ERROR_WINHTTP_SECURE_CHANNEL_ERROR ||
                  codigo == ERROR_WINHTTP_SECURE_CERT_DATE_INVALID ||
                  codigo == ERROR_WINHTTP_SECURE_CERT_CN_INVALID ||
                  codigo == ERROR_WINHTTP_SECURE_INVALID_CA ||
                  codigo == ERROR_WINHTTP_SECURE_INVALID_CERT);
    if (!esTls) return;

    std::wstring detalle;
    if (DiagnosticarCertificado(hSession, url, detalle) && !detalle.empty()) {
        r.errorCodigo = L"tls";
        r.errorMensaje = detalle;
    }
}

bool HacerPeticion(HINTERNET hSession, const std::wstring& urlInicial, int maxRedirecciones, RespuestaHttp& r) {
    std::wstring url = urlInicial;
    std::set<std::wstring> visitadas;
    HINTERNET hConnect = NULL, hRequest = NULL;
    bool salir = false;

    for (int salto = 0; salto <= maxRedirecciones && !salir; ++salto) {
        if (visitadas.count(Minusculas(url))) {
            r.errorCodigo = L"redireccion";
            r.errorMensaje = L"La web entra en un bucle de redirecciones.";
            break;
        }
        visitadas.insert(Minusculas(url));

        URL_COMPONENTS uc = { 0 };
        uc.dwStructSize = sizeof(uc);
        wchar_t host[512] = { 0 }, ruta[4096] = { 0 };
        uc.lpszHostName = host;  uc.dwHostNameLength = 512;
        uc.lpszUrlPath = ruta;   uc.dwUrlPathLength = 4096;

        if (!WinHttpCrackUrl(url.c_str(), 0, 0, &uc)) {
            r.errorCodigo = L"url";
            r.errorMensaje = L"La dirección no se pudo interpretar (demasiado larga o con caracteres no válidos).";
            break;
        }

        bool esHttps = (uc.nScheme == INTERNET_SCHEME_HTTPS);
        INTERNET_PORT puerto = uc.nPort;

        if (hConnect) { WinHttpCloseHandle(hConnect); hConnect = NULL; }
        hConnect = WinHttpConnect(hSession, host, puerto, 0);
        if (!hConnect) { ClasificarError(GetLastError(), r); break; }

        std::wstring rutaCompleta = std::wstring(ruta) + (uc.lpszExtraInfo ? uc.lpszExtraInfo : L"");
        if (rutaCompleta.empty()) rutaCompleta = L"/";

        if (hRequest) { WinHttpCloseHandle(hRequest); hRequest = NULL; }
        hRequest = WinHttpOpenRequest(hConnect, L"GET", rutaCompleta.c_str(), NULL,
                                      WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                      esHttps ? WINHTTP_FLAG_SECURE : 0);
        if (!hRequest) { ClasificarError(GetLastError(), r); break; }

        DWORD politica = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_REDIRECT_POLICY, &politica, sizeof(politica));

        WinHttpAddRequestHeaders(hRequest,
            L"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            L"(KHTML, like Gecko) Chrome/124.0 Safari/537.36\r\n"
            L"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            L"Accept-Language: es-ES,es;q=0.9,en;q=0.8\r\n",
            (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);

        if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
            ClasificarFallo(GetLastError(), hSession, url, r);
            break;
        }
        if (!WinHttpReceiveResponse(hRequest, NULL)) {
            ClasificarFallo(GetLastError(), hSession, url, r);
            break;
        }

        DWORD status = 0, tamStatus = sizeof(status);
        if (!WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                 WINHTTP_HEADER_NAME_BY_INDEX, &status, &tamStatus, WINHTTP_NO_HEADER_INDEX)) {
            ClasificarError(GetLastError(), r);
            break;
        }

        std::wstring razon;
        ConsultarTexto(hRequest, WINHTTP_QUERY_STATUS_TEXT, razon);

        r.status = (int)status;
        r.razon = razon;
        r.urlFinal = url;
        r.https = esHttps;
        r.protocoloTls.clear();
        r.emisorTls.clear();
        r.diasCertificado = -1;
        if (esHttps) ObtenerInfoTls(hRequest, r);

        if (status >= 300 && status < 400 && status != 304 && salto < maxRedirecciones) {
            std::wstring destino;
            if (ConsultarTexto(hRequest, WINHTTP_QUERY_LOCATION, destino) && !destino.empty()) {
                std::wstring siguiente = ResolverRedireccion(url, destino);
                if (siguiente.empty()) {
                    r.errorCodigo = L"redireccion";
                    r.errorMensaje = L"El servidor devolvió una redirección que no se pudo interpretar.";
                    break;
                }
                url = siguiente;
                continue;
            }
        }

        std::wstring crudo;
        if (!ConsultarTexto(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF, crudo)) {
            r.errorCodigo = L"red";
            r.errorMensaje = L"El servidor respondió pero no se pudieron leer sus cabeceras.";
            break;
        }
        r.cabeceras = ParsearCabeceras(crudo);
        r.ok = true;
        salir = true;
    }

    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    return r.ok;
}

CabeceraResultado EvaluarTls(const RespuestaHttp& resp) {
    CabeceraResultado c;
    c.id = L"tls";
    c.nombre = L"Cifrado TLS y validez del certificado";
    c.desc = L"Evalúa la versión de TLS negociada, si se admiten versiones obsoletas y los días que le quedan al certificado.";
    c.criticidad = L"CRÍTICA";
    c.peso = 4;

    if (!resp.https) {
        c.aplicable = false;
        c.valorClave = L"value.no_https";
        c.valor = L"El sitio no usa HTTPS";
        return c;
    }

    std::wstring protocolo = resp.protocoloTls.empty() ? L"desconocido" : resp.protocoloTls;
    std::vector<std::wstring> avisos;

    if (protocolo == L"TLS 1.0" || protocolo == L"TLS 1.1" || protocolo == L"SSL 3.0") {
        c.penalizacion = 70;
        avisos.push_back(L"La versión de TLS negociada está obsoleta; debería ser TLS 1.2 o superior.");
    }
    if (resp.aceptaTlsObsoleto) {
        c.penalizacion = (std::max)(c.penalizacion, 30);
        avisos.push_back(L"El servidor completa el saludo TLS 1.0/1.1; debería rechazar versiones obsoletas.");
    }
    if (resp.diasCertificado >= 0 && resp.diasCertificado < 30) {
        c.penalizacion = (std::max)(c.penalizacion, resp.diasCertificado < 7 ? 80 : 40);
        avisos.push_back(L"El certificado caduca en menos de 30 días.");
    }

    std::wstring valor = L"Protocolo: " + protocolo;
    if (resp.diasCertificado >= 0) valor += L" | Certificado válido " + std::to_wstring(resp.diasCertificado) + L" días más";
    if (!resp.emisorTls.empty()) valor += L" | Emisor: " + resp.emisorTls;
    if (resp.aceptaTlsObsoleto) valor += L" | Acepta TLS 1.0/1.1";
    c.valor = valor;
    c.presente = (c.penalizacion == 0);
    c.valorClave = L"value.tls_ok";
    c.valorArgs = { { L"protocol", protocolo },
                    { L"days", resp.diasCertificado >= 0 ? std::to_wstring(resp.diasCertificado) : L"-" },
                    { L"issuer", resp.emisorTls },
                    { L"legacy", resp.aceptaTlsObsoleto ? L"1" : L"0" } };

    for (size_t i = 0; i < avisos.size(); ++i) {
        if (i) c.aviso += L" ";
        c.aviso += avisos[i];
    }
    return c;
}

CabeceraResultado EvaluarRedireccionHttps(HINTERNET hSession, const RespuestaHttp& resp) {
    CabeceraResultado c;
    c.id = L"https";
    c.nombre = L"HTTPS obligatorio (redirección desde HTTP)";
    c.desc = L"Comprueba que el sitio no sirve contenido por HTTP sin cifrar y que redirige a HTTPS.";
    c.criticidad = L"CRÍTICA";
    c.peso = 4;

    if (!resp.https) {
        c.presente = false;
        c.penalizacion = 100;
        c.valorClave = L"value.insecure_site";
        c.valor = L"La web se sirve por HTTP sin cifrar";
        c.aviso = L"Todo el tráfico viaja sin cifrar y puede ser leído o modificado.";
        return c;
    }

    URL_COMPONENTS uc = { 0 };
    uc.dwStructSize = sizeof(uc);
    wchar_t host[512] = { 0 }, ruta[4096] = { 0 };
    uc.lpszHostName = host;  uc.dwHostNameLength = 512;
    uc.lpszUrlPath = ruta;   uc.dwUrlPathLength = 4096;
    if (!WinHttpCrackUrl(resp.urlFinal.c_str(), 0, 0, &uc) || uc.nPort != INTERNET_DEFAULT_HTTPS_PORT) {
        c.aplicable = false;
        c.valorClave = L"value.https_nonstandard";
        c.valor = L"No se puede comprobar: el sitio usa un puerto HTTPS no estándar";
        return c;
    }

    std::wstring rutaHttp = std::wstring(ruta) + (uc.lpszExtraInfo ? uc.lpszExtraInfo : L"");
    std::wstring urlHttp = L"http://" + std::wstring(host) + L":" + std::to_wstring(INTERNET_DEFAULT_HTTP_PORT) + rutaHttp;

    RespuestaHttp sonda;
    if (!HacerPeticion(hSession, urlHttp, 0, sonda)) {
        if (sonda.errorCodigo == L"conexion" || sonda.errorCodigo == L"dns" || sonda.errorCodigo == L"timeout") {
            c.presente = true;
            c.valorClave = L"value.http_closed";
            c.valor = L"El puerto 80 no responde: solo se sirve contenido por HTTPS";
            return c;
        }
        c.presente = false;
        c.penalizacion = 40;
        c.valorClave = L"value.http_probe_failed";
        c.valor = L"No se pudo comprobar la versión HTTP del sitio";
        c.aviso = sonda.errorMensaje;
        return c;
    }

    std::wstring ubicacion;
    TieneCabecera(sonda.cabeceras, L"Location", ubicacion);

    if (sonda.status >= 300 && sonda.status < 400) {
        if (Minusculas(ubicacion).rfind(L"https://", 0) == 0) {
            c.presente = true;
            c.valorClave = L"value.http_redirect";
            c.valorArgs = { { L"status", std::to_wstring(sonda.status) }, { L"url", ubicacion } };
            c.valor = L"HTTP responde " + std::to_wstring(sonda.status) + L" y redirige a " + ubicacion;
            return c;
        }
        c.presente = false;
        c.penalizacion = 60;
        c.valorClave = L"value.http_redirect";
        c.valorArgs = { { L"status", std::to_wstring(sonda.status) }, { L"url", ubicacion } };
        c.valor = L"HTTP responde " + std::to_wstring(sonda.status) + L" y redirige a " + ubicacion;
        c.aviso = L"La redirección no lleva a HTTPS.";
        return c;
    }

    if (sonda.status >= 400) {
        c.aplicable = false;
        c.presente = true;
        c.valorClave = L"value.http_unknown";
        c.valorArgs = { { L"status", std::to_wstring(sonda.status) } };
        c.valor = L"HTTP responde " + std::to_wstring(sonda.status) + L"; no se puede determinar si redirige";
        return c;
    }

    c.presente = false;
    c.penalizacion = 100;
    c.valorClave = L"value.http_no_redirect";
    c.valorArgs = { { L"status", std::to_wstring(sonda.status) } };
    c.valor = L"HTTP responde " + std::to_wstring(sonda.status) + L" sin redirigir a HTTPS";
    c.aviso = L"El contenido también se sirve sin cifrar; fuerza la redirección a HTTPS.";
    return c;
}

// ============================================================================
// 8. ANÁLISIS COMPLETO DE UNA URL
// ============================================================================
bool AnalizarUrl(const std::wstring& urlEntrada, AnalisisResultado& res, std::wstring& error) {
    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AuditorSeguridadWeb/4.0",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        hSession = WinHttpOpen(L"AuditorSeguridadWeb/4.0", WINHTTP_ACCESS_TYPE_NO_PROXY,
                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    }
    if (!hSession) {
        error = L"No se pudo inicializar el motor HTTP del sistema.";
        return false;
    }
    WinHttpSetTimeouts(hSession, 8000, 8000, 8000, 12000);

    RespuestaHttp resp;
    bool peticionOk = HacerPeticion(hSession, urlEntrada, 5, resp);

    res = AnalisisResultado();
    res.fecha = ObtenerFechaActual();
    res.urlSolicitada = urlEntrada;

    if (!peticionOk) {
        error = resp.errorMensaje.empty() ? L"No se pudo completar la auditoría." : resp.errorMensaje;
        WinHttpCloseHandle(hSession);
        return false;
    }

    // La URL final y el código se conservan también cuando la respuesta es un error HTTP.
    res.url = resp.urlFinal;
    res.statusCode = resp.status;
    res.reason = resp.razon;

    if (resp.status < 200 || resp.status >= 400) {
        wchar_t buf[512];
        swprintf_s(buf, L"El servidor respondió HTTP %d (%s). Comprueba que la dirección exista.",
                   resp.status, resp.razon.empty() ? L"Sin descripción" : resp.razon.c_str());
        error = buf;
        WinHttpCloseHandle(hSession);
        return false;
    }

    res.https = resp.https;

    if (resp.https) {
        resp.protocoloTls = DetectarProtocolo(resp.urlFinal, resp.aceptaTlsObsoleto);
        res.tlsProtocolo = resp.protocoloTls;
        res.tlsDias = resp.diasCertificado;
    }

    std::wstring servidor = L"Oculto / Protegido", valorServer;
    if (TieneCabecera(resp.cabeceras, L"Server", valorServer) && !valorServer.empty()) servidor = valorServer;
    res.server = servidor;

    res.evaluacion.push_back(EvaluarRedireccionHttps(hSession, resp));
    res.evaluacion.push_back(EvaluarTls(resp));
    for (const auto& meta : g_cabecerasAEvaluar) res.evaluacion.push_back(EvaluarCabecera(meta, resp));
    res.evaluacion.push_back(EvaluarCookies(resp));
    res.evaluacion.push_back(EvaluarCors(resp));

    CalcularPuntuacion(res);

    WinHttpCloseHandle(hSession);
    return true;
}

// ============================================================================
// 9. PERSISTENCIA DEL HISTORIAL (JSON, con copia de seguridad)
// ============================================================================
std::wstring JsonDeResultado(const AnalisisResultado& r, bool incluirSoftware);

void GuardarHistorialDisco() {
    // Copia de seguridad del historial anterior
    std::wstring actual = RutaHistorial();
    if (GetFileAttributesW(actual.c_str()) != INVALID_FILE_ATTRIBUTES) {
        CopyFileW(actual.c_str(), RutaCopiaHistorial().c_str(), FALSE);
    }

    std::wstringstream js;
    js << L"[\n";
    for (size_t i = 0; i < g_historialCompleto.size(); ++i) {
        js << JsonDeResultado(g_historialCompleto[i], false);
        if (i + 1 < g_historialCompleto.size()) js << L",";
        js << L"\n";
    }
    js << L"]\n";
    EscribirArchivoUtf8(RutaHistorial(), js.str());
}

void CargarHistorialEnTabla() {
    ListView_DeleteAllItems(hHistTree);
    g_historialCompleto.clear();

    std::wstring contenido = LeerArchivoTexto(RutaHistorial());
    if (!contenido.empty()) {
        JsonValor raiz;
        JsonParser parser(contenido);
        if (parser.Parsear(raiz) && raiz.tipo == JsonValor::LISTA) {
            for (const auto& obj : raiz.lista) {
                if (obj.tipo != JsonValor::OBJETO) continue;
                AnalisisResultado item;
                item.fecha = obj.Texto(L"fecha");
                item.url = obj.Texto(L"url");
                if (item.url.empty()) continue;
                item.urlSolicitada = obj.Texto(L"url_solicitada", item.url.c_str());
                item.statusCode = obj.Entero(L"status_code", 0);
                item.reason = obj.Texto(L"reason");
                item.server = obj.Texto(L"server");
                item.https = obj.Bool(L"https", false);
                item.tlsProtocolo = obj.Texto(L"tls_protocolo");
                item.tlsDias = obj.Entero(L"tls_dias_certificado", -1);
                item.presentes = obj.Entero(L"presentes", 0);
                item.aplicables = obj.Entero(L"aplicables", 0);
                item.total = obj.Entero(L"total", 0);
                item.puntos = obj.Decimal(L"puntos", 0.0);
                item.puntosMax = obj.Decimal(L"puntos_max", 0.0);
                item.porcentaje = obj.Decimal(L"porcentaje", -1.0);
                item.calificacion = obj.Texto(L"calificacion");
                item.motor = obj.Texto(L"motor", L"WinHTTP 4.0");

                const JsonValor* evs = obj.Buscar(L"evaluacion");
                if (evs && evs->tipo == JsonValor::LISTA) {
                    for (const auto& ev : evs->lista) {
                        if (ev.tipo != JsonValor::OBJETO) continue;
                        CabeceraResultado c;
                        c.id = ev.Texto(L"id");
                        c.clave = ev.Texto(L"header");
                        if (c.clave.empty()) c.clave = ev.Texto(L"key");   // registros antiguos
                        c.nombre = ev.Texto(L"nombre");
                        c.desc = ev.Texto(L"desc");
                        c.criticidad = ev.Texto(L"criticidad");
                        int peso = ev.Entero(L"peso", -1);
                        c.peso = (peso < 0) ? PesoDesdeCriticidad(c.criticidad) : peso;
                        c.aplicable = ev.Bool(L"aplicable", true);
                        c.presente = ev.Bool(L"presente", false);
                        c.penalizacion = ev.Entero(L"penalizacion", 0);
                        c.valor = ev.Texto(L"valor");
                        c.aviso = ev.Texto(L"aviso");
                        item.evaluacion.push_back(c);
                    }
                }

                // Registros antiguos sin puntuación: se recalcula con los pesos equivalentes.
                if (item.calificacion.empty() || item.puntosMax <= 0.0) {
                    CalcularPuntuacion(item);
                }
                g_historialCompleto.push_back(item);
            }
        }
    }

    if (g_historialCompleto.size() > 30) g_historialCompleto.resize(30);

    int index = 0;
    for (const auto& elem : g_historialCompleto) {
        LVITEM lvi = { 0 };
        lvi.mask = LVIF_TEXT;
        lvi.iItem = index;
        lvi.pszText = (LPWSTR)elem.fecha.c_str();
        ListView_InsertItem(hHistTree, &lvi);
        ListView_SetItemText(hHistTree, index, 1, (LPWSTR)elem.url.c_str());

        wchar_t statusBuf[96];
        swprintf_s(statusBuf, L"%d %s", elem.statusCode, elem.reason.c_str());
        ListView_SetItemText(hHistTree, index, 2, statusBuf);

        std::wstring nota = L10n::Tr(L"hist.grade_value", { { L"grade", elem.calificacion }, { L"pct", std::to_wstring((int)std::lround(elem.porcentaje)) } });
        ListView_SetItemText(hHistTree, index, 3, (LPWSTR)nota.c_str());

        index++;
    }
}

// ============================================================================
// 10. EXPORTACIÓN (JSON, CSV, PDF)
// ============================================================================
std::wstring JsonDeResultado(const AnalisisResultado& r, bool incluirSoftware) {
    std::wstringstream js;
    js << L"{\n";
    js << L"  \"ok\": true,\n";
    js << L"  \"motor\": \"" << EscaparJson(r.motor) << L"\",\n";
    js << L"  \"url\": \"" << EscaparJson(r.url) << L"\",\n";
    js << L"  \"url_solicitada\": \"" << EscaparJson(r.urlSolicitada.empty() ? r.url : r.urlSolicitada) << L"\",\n";
    js << L"  \"status_code\": " << r.statusCode << L",\n";
    js << L"  \"reason\": \"" << EscaparJson(r.reason) << L"\",\n";
    js << L"  \"server\": \"" << EscaparJson(r.server) << L"\",\n";
    js << L"  \"https\": " << (r.https ? L"true" : L"false") << L",\n";
    js << L"  \"tls_protocolo\": \"" << EscaparJson(r.tlsProtocolo) << L"\",\n";
    js << L"  \"tls_dias_certificado\": " << r.tlsDias << L",\n";
    js << L"  \"presentes\": " << r.presentes << L",\n";
    js << L"  \"aplicables\": " << r.aplicables << L",\n";
    js << L"  \"total\": " << r.total << L",\n";
    js << L"  \"fecha\": \"" << EscaparJson(r.fecha) << L"\",\n";
    js << L"  \"calificacion\": \"" << EscaparJson(r.calificacion) << L"\",\n";
    js << L"  \"porcentaje\": " << std::fixed << std::setprecision(1) << r.porcentaje << L",\n";
    js << L"  \"puntos\": " << std::fixed << std::setprecision(2) << r.puntos << L",\n";
    js << L"  \"puntos_max\": " << std::fixed << std::setprecision(2) << r.puntosMax << L",\n";

    if (incluirSoftware) {
        js << L"  \"software\": {\n";
        js << L"    \"nombre\": \"Auditor de Seguridad HTTP\",\n";
        js << L"    \"version\": \"" << VERSION_APP << L"\",\n";
        js << L"    \"autor\": \"" << AUTOR << L"\",\n";
        js << L"    \"contacto\": \"" << CORREO << L"\",\n";
        js << L"    \"copyright\": \"" << EscaparJson(COPYRIGHT) << L"\"\n";
        js << L"  },\n";
    }

    js << L"  \"evaluacion\": [\n";
    for (size_t i = 0; i < r.evaluacion.size(); ++i) {
        const auto& ev = r.evaluacion[i];
        js << L"    {\n";
        js << L"      \"id\": \"" << EscaparJson(ev.id) << L"\",\n";
        js << L"      \"header\": \"" << EscaparJson(ev.clave) << L"\",\n";
        js << L"      \"nombre\": \"" << EscaparJson(ev.nombre) << L"\",\n";
        js << L"      \"desc\": \"" << EscaparJson(ev.desc) << L"\",\n";
        js << L"      \"criticidad\": \"" << EscaparJson(ev.criticidad) << L"\",\n";
        js << L"      \"peso\": " << ev.peso << L",\n";
        js << L"      \"aplicable\": " << (ev.aplicable ? L"true" : L"false") << L",\n";
        js << L"      \"presente\": " << (ev.presente ? L"true" : L"false") << L",\n";
        js << L"      \"penalizacion\": " << ev.penalizacion << L",\n";
        js << L"      \"valor\": \"" << EscaparJson(ev.valor) << L"\",\n";
        js << L"      \"aviso\": \"" << EscaparJson(ev.aviso) << L"\"\n";
        js << L"    }" << (i + 1 < r.evaluacion.size() ? L"," : L"") << L"\n";
    }
    js << L"  ]\n";
    js << L"}";
    return js.str();
}

// Texto de estado mostrado en la interfaz y en los informes
void EstadoDeItem(const CabeceraResultado& item, std::wstring& texto, COLORREF& color) {
    if (!item.aplicable) { texto = L10n::Tr(L"state.not_applicable"); color = RGB(108, 117, 125); return; }
    if (item.peso <= 0) {
        texto = item.presente ? L10n::Tr(L"state.info_on") : L10n::Tr(L"state.info_off");
        color = item.presente ? RGB(13, 110, 253) : RGB(108, 117, 125);
        return;
    }
    if (!item.presente) {
        texto = item.clave.empty() ? L10n::Tr(L"state.failed") : L10n::Tr(L"state.missing");
        color = RGB(220, 53, 69);
        return;
    }
    if (CalidadItem(item) < 100) { texto = L10n::Tr(L"state.weak"); color = RGB(253, 126, 20); return; }
    texto = L10n::Tr(L"state.configured");
    color = RGB(10, 128, 66);
}

// Clave de traducción de los avisos generados por la aplicación (texto -> clave)
std::wstring ClaveAviso(const std::wstring& texto) {
    static const std::map<std::wstring, std::wstring> mapa = {
        { L"HSTS solo protege las conexiones HTTPS y el sitio se ha consultado por HTTP.", L"hsts.http" },
        { L"No declara max-age; los navegadores ignoran la política.", L"hsts.no_max_age" },
        { L"max-age=0 desactiva HSTS en la práctica.", L"hsts.zero" },
        { L"max-age inferior a 6 meses (recomendado 15552000 o más).", L"hsts.short" },
        { L"No incluye includeSubDomains; los subdominios no quedan protegidos.", L"hsts.no_subdomains" },
        { L"Permite 'unsafe-inline' y 'unsafe-eval'; reduce mucho la protección frente a XSS.", L"csp.inline_eval" },
        { L"Permite 'unsafe-inline'; reduce la protección frente a XSS.", L"csp.inline" },
        { L"Permite 'unsafe-eval'; permite ejecutar código generado en tiempo de ejecución.", L"csp.eval" },
        { L"Incluye el comodín '*' y admite recursos de cualquier origen.", L"csp.wildcard" },
        { L"ALLOWALL desactiva la protección frente a Clickjacking.", L"xfo.allowall" },
        { L"ALLOW-FROM ya no lo admiten los navegadores modernos; usa CSP frame-ancestors.", L"xfo.allowfrom" },
        { L"Valor no reconocido; debería ser DENY o SAMEORIGIN.", L"xfo.invalid" },
        { L"El único valor válido es nosniff.", L"xcto.not_nosniff" },
        { L"unsafe-url envía la URL completa a sitios externos.", L"referrer.unsafe" },
        { L"Configuración heredada; se recomienda strict-origin-when-cross-origin.", L"referrer.legacy" },
        { L"El comodín '*' deja las funciones abiertas a cualquier origen.", L"permissions.wildcard" },
        { L"unsafe-none no aísla la ventana frente a otros orígenes.", L"coop.unsafe_none" },
        { L"unsafe-none permite cargar recursos cruzados sin permiso explícito.", L"coep.unsafe_none" },
        { L"Permite almacenar la respuesta en caché; revísalo si sirve contenido sensible.", L"cache.permissive" },
        { L"La versión de TLS negociada está obsoleta; debería ser TLS 1.2 o superior.", L"tls.obsolete" },
        { L"El servidor completa el saludo TLS 1.0/1.1; debería rechazar versiones obsoletas.", L"tls.legacy" },
        { L"El certificado caduca en menos de 30 días.", L"tls.expiring" },
        { L"Hay cookies que se enviarían también por HTTP sin cifrar.", L"cookies.no_secure" },
        { L"Hay cookies legibles desde JavaScript (riesgo si existe XSS).", L"cookies.no_httponly" },
        { L"Hay cookies sin SameSite; pueden viajar en peticiones de otros sitios (CSRF).", L"cookies.no_samesite" },
        { L"Permite cualquier origen con credenciales: cualquier web podría leer datos autenticados.", L"cors.wildcard_credentials" },
        { L"Permite cualquier origen (*); revisa si expone información privada.", L"cors.wildcard" },
        { L"Todo el tráfico viaja sin cifrar y puede ser leído o modificado.", L"https.insecure" },
        { L"El contenido también se sirve sin cifrar; fuerza la redirección a HTTPS.", L"https.no_redirect" },
        { L"La redirección no lleva a HTTPS.", L"https.no_redirect" },
    };
    auto it = mapa.find(texto);
    return (it == mapa.end()) ? L"" : it->second;
}

std::wstring NombreItem(const CabeceraResultado& item) {
    return L10n::TrOr(L"check." + item.id + L".name", item.nombre);
}

std::wstring DescItem(const CabeceraResultado& item) {
    return L10n::TrOr(L"check." + item.id + L".desc", item.desc);
}

std::wstring AvisoItem(const CabeceraResultado& item) {
    std::wstring clave = item.avisoClave;
    if (clave.empty()) clave = ClaveAviso(item.aviso);
    if (clave.empty()) return item.aviso;
    return L10n::TrOr(L"aviso." + clave, item.aviso);
}

std::wstring ValorItem(const CabeceraResultado& item) {
    if (item.valorClave.empty()) return item.valor;
    std::vector<std::pair<std::wstring, std::wstring>> args = item.valorArgs;
    if (item.valorClave == L"value.tls_ok") {
        std::wstring legacy;
        for (const auto& a : item.valorArgs) if (a.first == L"legacy" && a.second == L"1") legacy = L"1";
        args.erase(std::remove_if(args.begin(), args.end(),
                                  [](const std::pair<std::wstring, std::wstring>& a) { return a.first == L"legacy"; }),
                   args.end());
        args.emplace_back(L"legacy", legacy.empty() ? L"" : (L" | " + L10n::Tr(L"value.tls_legacy")));
    }
    return L10n::TrOr(item.valorClave, item.valor, args);
}

std::wstring CritItem(const CabeceraResultado& item) {
    std::wstring c = item.criticidad;
    for (auto& ch : c) ch = (wchar_t)towupper(ch);
    if (c == L"CRÍTICA" || c == L"CRITICA") return L10n::Tr(L"crit.critical");
    if (c == L"ALTA") return L10n::Tr(L"crit.high");
    if (c == L"MEDIA") return L10n::Tr(L"crit.medium");
    if (c == L"BAJA") return L10n::Tr(L"crit.low");
    if (c == L"INFORMATIVA") return L10n::Tr(L"crit.info");
    return item.criticidad;
}

void ExportarJSON() {
    if (!g_tieneResultado) return;
    wchar_t szFileName[MAX_PATH] = L"informe_seguridad.json";
    OPENFILENAME ofn = { 0 };
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hMainWnd;
    ofn.lpstrFilter = L"Archivos JSON (*.json)\0*.json\0Todos los archivos (*.*)\0*.*\0";
    ofn.lpstrFile = szFileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_EXPLORER | OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;
    ofn.lpstrDefExt = L"json";

    if (!GetSaveFileName(&ofn)) return;

    if (!EscribirArchivoUtf8(szFileName, JsonDeResultado(g_ultimoResultado, true) + L"\n")) {
        MessageBox(hMainWnd, L10n::Tr(L"err.write_file").c_str(), L10n::Tr(L"dlg.error").c_str(), MB_OK | MB_ICONERROR);
        return;
    }
    MessageBox(hMainWnd, L10n::Tr(L"export.json_ok").c_str(), L10n::Tr(L"dlg.success").c_str(), MB_OK | MB_ICONINFORMATION);
}

// Escapa un campo CSV entre comillas
std::wstring CampoCSV(const std::wstring& valor) {
    std::wstring v = valor;
    size_t pos = 0;
    while ((pos = v.find(L'"', pos)) != std::wstring::npos) {
        v.insert(pos, L"\"");   // duplica la comilla
        pos += 2;
    }
    return L"\"" + v + L"\"";
}

void ExportarCSV() {
    if (!g_tieneResultado) return;
    wchar_t szFileName[MAX_PATH] = L"informe_seguridad.csv";
    OPENFILENAME ofn = { 0 };
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hMainWnd;
    ofn.lpstrFilter = L"Archivos CSV (*.csv)\0*.csv\0Todos los archivos (*.*)\0*.*\0";
    ofn.lpstrFile = szFileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_EXPLORER | OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;
    ofn.lpstrDefExt = L"csv";

    if (!GetSaveFileName(&ofn)) return;

    std::wstringstream csv;
    csv << L"Comprobacion;Estado;Criticidad;Peso;Calidad %;Valor Detectado;Observacion;Descripcion\n";
    for (const auto& ev : g_ultimoResultado.evaluacion) {
        std::wstring estado;
        COLORREF color;
        EstadoDeItem(ev, estado, color);

        std::wstring valor = ev.valor;
        std::replace(valor.begin(), valor.end(), L'\r', L' ');
        std::replace(valor.begin(), valor.end(), L'\n', L' ');

        csv << CampoCSV(ev.nombre) << L";"
            << CampoCSV(estado) << L";"
            << CampoCSV(ev.criticidad) << L";"
            << ev.peso << L";"
            << CalidadItem(ev) << L";"
            << CampoCSV(valor) << L";"
            << CampoCSV(ev.aviso) << L";"
            << CampoCSV(ev.desc) << L"\n";
    }

    if (!EscribirArchivoUtf8(szFileName, csv.str(), true)) {
        MessageBox(hMainWnd, L10n::Tr(L"err.write_file").c_str(), L10n::Tr(L"dlg.error").c_str(), MB_OK | MB_ICONERROR);
        return;
    }
    MessageBox(hMainWnd, L10n::Tr(L"export.csv_ok").c_str(), L10n::Tr(L"dlg.success").c_str(), MB_OK | MB_ICONINFORMATION);
}

// Genera un archivo PDF nativo utilizando la impresora virtual "Microsoft Print to PDF"
void ExportarPDFNativo() {
    if (!g_tieneResultado) return;

    wchar_t szFileName[MAX_PATH] = L"Informe_Seguridad.pdf";
    std::wstring rutaSalida;

    if (!g_rutaPdfForzada.empty()) {
        rutaSalida = g_rutaPdfForzada;
    } else {
        OPENFILENAME ofn = { 0 };
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = hMainWnd;
        ofn.lpstrFilter = L"Archivos PDF (*.pdf)\0*.pdf\0Todos los archivos (*.*)\0*.*\0";
        ofn.lpstrFile = szFileName;
        ofn.nMaxFile = MAX_PATH;
        ofn.Flags = OFN_EXPLORER | OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;
        ofn.lpstrDefExt = L"pdf";

        if (!GetSaveFileName(&ofn)) return;
        rutaSalida = szFileName;
    }

    HDC hdcPrinter = CreateDC(L"WINSPOOL", L"Microsoft Print to PDF", NULL, NULL);
    if (!hdcPrinter) {
        if (g_rutaPdfForzada.empty())
            MessageBox(hMainWnd, L10n::Tr(L"err.pdf_printer").c_str(), L10n::Tr(L"export.pdf_title").c_str(), MB_OK | MB_ICONERROR);
        return;
    }

    std::wstring tituloPdf = L10n::Tr(L"pdf.title");
    DOCINFO di = { sizeof(DOCINFO) };
    di.lpszDocName = tituloPdf.c_str();
    di.lpszOutput = rutaSalida.c_str();

    if (StartDoc(hdcPrinter, &di) > 0) {
        StartPage(hdcPrinter);
        SetBkMode(hdcPrinter, TRANSPARENT);

        int pageW = GetDeviceCaps(hdcPrinter, HORZRES);
        int pageH = GetDeviceCaps(hdcPrinter, VERTRES);
        int logPixelsY = GetDeviceCaps(hdcPrinter, LOGPIXELSY);

        auto PtToPx = [logPixelsY](double pt) -> int {
            return -MulDiv((int)(pt * 10), logPixelsY, 720);
        };

        HFONT hFontPdfTitle = CreateFont(PtToPx(18), 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Arial");
        HFONT hFontPdfH2 = CreateFont(PtToPx(12), 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Arial");
        HFONT hFontPdfNorm = CreateFont(PtToPx(9.5), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Arial");
        HFONT hFontPdfBold = CreateFont(PtToPx(9.5), 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Arial");
        HFONT hFontPdfSmall = CreateFont(PtToPx(8), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Arial");
        HFONT hFontPdfCode = CreateFont(PtToPx(8.5), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Courier New");

        int marginX = MulDiv(24, logPixelsY, 72);
        int maxBottomY = pageH - MulDiv(34, logPixelsY, 72);
        int y = MulDiv(28, logPixelsY, 72);
        int padX = MulDiv(12, logPixelsY, 72);

        // Pie de página con el copyright del autor
        auto DibujarPie = [&](int pagina) {
            SelectObject(hdcPrinter, hFontPdfSmall);
            SetTextColor(hdcPrinter, RGB(102, 102, 102));
            std::wstring linea = std::wstring(COPYRIGHT) + L" · " + CORREO;
            TextOut(hdcPrinter, marginX, pageH - MulDiv(26, logPixelsY, 72), linea.c_str(), (int)linea.length());

            std::wstring programa = L10n::Tr(L"pdf.footer", { { L"version", VERSION_APP } });
            TextOut(hdcPrinter, marginX, pageH - MulDiv(16, logPixelsY, 72), programa.c_str(), (int)programa.length());

            wchar_t pag[64];
            std::wstring paginaTxt = L10n::Tr(L"pdf.page", { { L"page", std::to_wstring(pagina) } });
            wcscpy_s(pag, paginaTxt.c_str());
            SIZE sz;
            GetTextExtentPoint32(hdcPrinter, pag, lstrlen(pag), &sz);
            TextOut(hdcPrinter, pageW - marginX - sz.cx, pageH - MulDiv(26, logPixelsY, 72), pag, lstrlen(pag));
        };

        SelectObject(hdcPrinter, hFontPdfTitle);
        SetTextColor(hdcPrinter, RGB(24, 52, 106));
        TextOut(hdcPrinter, marginX, y, tituloPdf.c_str(), (int)tituloPdf.length());
        y += MulDiv(26, logPixelsY, 72);

        auto DibujarMeta = [&](const wchar_t* label, const std::wstring& val) {
            SelectObject(hdcPrinter, hFontPdfBold);
            SetTextColor(hdcPrinter, RGB(30, 30, 30));
            TextOut(hdcPrinter, marginX, y, label, lstrlen(label));
            SIZE sz;
            GetTextExtentPoint32(hdcPrinter, label, lstrlen(label), &sz);
            SelectObject(hdcPrinter, hFontPdfNorm);
            TextOut(hdcPrinter, marginX + sz.cx + 5, y, val.c_str(), (int)val.length());
            y += MulDiv(14, logPixelsY, 72);
        };

        DibujarMeta(L10n::Tr(L"pdf.site").c_str(), g_ultimoResultado.url);
        DibujarMeta(L10n::Tr(L"pdf.date").c_str(), g_ultimoResultado.fecha);

        wchar_t statusBuf[128];
        swprintf_s(statusBuf, L"%d %s", g_ultimoResultado.statusCode, g_ultimoResultado.reason.c_str());
        DibujarMeta(L10n::Tr(L"pdf.status").c_str(), statusBuf);
        DibujarMeta(L10n::Tr(L"pdf.server").c_str(), g_ultimoResultado.server);

        std::wstring cifrado = g_ultimoResultado.https ? L10n::Tr(L"pdf.crypto_https") : L10n::Tr(L"pdf.crypto_http");
        if (!g_ultimoResultado.tlsProtocolo.empty()) cifrado += L" (TLS: " + g_ultimoResultado.tlsProtocolo + L")";
        DibujarMeta(L10n::Tr(L"pdf.crypto").c_str(), cifrado);

        std::wstring reqBuf = L10n::Tr(L"pdf.grade_value", {
            { L"grade", g_ultimoResultado.calificacion },
            { L"pct", std::to_wstring((int)std::lround(g_ultimoResultado.porcentaje)) },
            { L"points", FormatearDecimal(g_ultimoResultado.puntos, 1) },
            { L"max", FormatearDecimal(g_ultimoResultado.puntosMax, 0) },
            { L"ok", std::to_wstring(g_ultimoResultado.presentes) },
            { L"total", std::to_wstring(g_ultimoResultado.aplicables) }
        });
        DibujarMeta(L10n::Tr(L"pdf.grade").c_str(), reqBuf);

        y += MulDiv(12, logPixelsY, 72);

        SelectObject(hdcPrinter, hFontPdfH2);
        SetTextColor(hdcPrinter, RGB(44, 62, 80));
        std::wstring subtitulo = L10n::Tr(L"pdf.section");
        TextOut(hdcPrinter, marginX, y, subtitulo.c_str(), (int)subtitulo.length());
        y += MulDiv(18, logPixelsY, 72);

        int tableW = pageW - (2 * marginX);
        int col1W = (tableW * 34) / 100;
        int col2W = (tableW * 17) / 100;
        int col3W = (tableW * 17) / 100;
        int col4W = tableW - col1W - col2W - col3W;

        int x1 = marginX;
        int x2 = x1 + col1W;
        int x3 = x2 + col2W;
        int x4 = x3 + col3W;

        auto DibujarEncabezadoTabla = [&](int curY) -> int {
            int hHdr = MulDiv(24, logPixelsY, 72);
            RECT hdrRc = { x1, curY, x1 + tableW, curY + hHdr };
            HBRUSH hHdrBg = CreateSolidBrush(RGB(24, 52, 106));
            FillRect(hdcPrinter, &hdrRc, hHdrBg);
            DeleteObject(hHdrBg);

            SelectObject(hdcPrinter, hFontPdfBold);
            SetTextColor(hdcPrinter, RGB(255, 255, 255));

            RECT r1 = { x1 + padX, curY, x2 - padX, curY + hHdr };
            RECT r2 = { x2 + padX, curY, x3 - padX, curY + hHdr };
            RECT r3 = { x3 + padX, curY, x4 - padX, curY + hHdr };
            RECT r4 = { x4 + padX, curY, x1 + tableW - padX, curY + hHdr };

            std::wstring h1 = L10n::Tr(L"pdf.col.check");
            std::wstring h2 = L10n::Tr(L"pdf.col.state");
            std::wstring h3 = L10n::Tr(L"pdf.col.criticality");
            std::wstring h4 = L10n::Tr(L"pdf.col.value");
            DrawText(hdcPrinter, h1.c_str(), -1, &r1, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
            DrawText(hdcPrinter, h2.c_str(), -1, &r2, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
            DrawText(hdcPrinter, h3.c_str(), -1, &r3, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
            DrawText(hdcPrinter, h4.c_str(), -1, &r4, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

            return curY + hHdr;
        };

        y = DibujarEncabezadoTabla(y);
        int pagina = 1;

        for (const auto& item : g_ultimoResultado.evaluacion) {
            std::wstring estado;
            COLORREF colorEstado;
            EstadoDeItem(item, estado, colorEstado);

            std::wstring estadoCompleto = estado;
            if (item.peso <= 0) {
                estadoCompleto = L10n::Tr(L"state.info");
            } else if (item.aplicable) {
                estadoCompleto += L" " + L10n::Tr(L"pdf.quality", { { L"quality", std::to_wstring(CalidadItem(item)) } });
            }

            RECT calcNom = { 0, 0, col1W - (padX * 2), 0 };
            SelectObject(hdcPrinter, hFontPdfBold);
            std::wstring nombrePdfCalc = NombreItem(item);
            DrawText(hdcPrinter, nombrePdfCalc.c_str(), -1, &calcNom, DT_CALCRECT | DT_WORDBREAK);
            int altoNom = calcNom.bottom - calcNom.top;

            RECT calcDesc = { 0, 0, col1W - (padX * 2), 0 };
            SelectObject(hdcPrinter, hFontPdfNorm);
            std::wstring descPdfCalc = DescItem(item);
            DrawText(hdcPrinter, descPdfCalc.c_str(), -1, &calcDesc, DT_CALCRECT | DT_WORDBREAK);
            int altoDesc = calcDesc.bottom - calcDesc.top;

            std::wstring avisoPdf = AvisoItem(item);
            std::wstring textoAviso = avisoPdf.empty() ? L"" : L10n::Tr(L"pdf.observation", { { L"text", avisoPdf } });
            int altoAviso = 0;
            if (!textoAviso.empty()) {
                RECT calcAviso = { 0, 0, col1W - (padX * 2), 0 };
                DrawText(hdcPrinter, textoAviso.c_str(), -1, &calcAviso, DT_CALCRECT | DT_WORDBREAK);
                altoAviso = (calcAviso.bottom - calcAviso.top) + MulDiv(3, logPixelsY, 72);
            }

            RECT calcValRc = { 0, 0, col4W - (padX * 2), 0 };
            SelectObject(hdcPrinter, hFontPdfCode);
            std::wstring valorPdfCalc = ValorItem(item);
            DrawText(hdcPrinter, valorPdfCalc.c_str(), -1, &calcValRc, DT_CALCRECT | DT_WORDBREAK);

            int hCol1 = altoNom + altoDesc + altoAviso + MulDiv(16, logPixelsY, 72);
            int hVal = (calcValRc.bottom - calcValRc.top) + MulDiv(16, logPixelsY, 72);
            int rowH = (std::max)({ hCol1, hVal, MulDiv(30, logPixelsY, 72) });

            if (y + rowH > maxBottomY) {
                DibujarPie(pagina);
                EndPage(hdcPrinter);
                StartPage(hdcPrinter);
                pagina++;
                y = MulDiv(28, logPixelsY, 72);
                y = DibujarEncabezadoTabla(y);
            }

            RECT rowRc = { x1, y, x1 + tableW, y + rowH };
            HBRUSH hRowBg = CreateSolidBrush(RGB(248, 249, 250));
            FillRect(hdcPrinter, &rowRc, hRowBg);
            DeleteObject(hRowBg);

            HPEN hGridPen = CreatePen(PS_SOLID, 1, RGB(204, 204, 204));
            SelectObject(hdcPrinter, hGridPen);
            MoveToEx(hdcPrinter, x1, y, NULL); LineTo(hdcPrinter, x1 + tableW, y);
            MoveToEx(hdcPrinter, x1, y + rowH, NULL); LineTo(hdcPrinter, x1 + tableW, y + rowH);
            MoveToEx(hdcPrinter, x1, y - MulDiv(24, logPixelsY, 72), NULL); LineTo(hdcPrinter, x1, y + rowH);
            MoveToEx(hdcPrinter, x2, y - MulDiv(24, logPixelsY, 72), NULL); LineTo(hdcPrinter, x2, y + rowH);
            MoveToEx(hdcPrinter, x3, y - MulDiv(24, logPixelsY, 72), NULL); LineTo(hdcPrinter, x3, y + rowH);
            MoveToEx(hdcPrinter, x4, y - MulDiv(24, logPixelsY, 72), NULL); LineTo(hdcPrinter, x4, y + rowH);
            MoveToEx(hdcPrinter, x1 + tableW, y - MulDiv(24, logPixelsY, 72), NULL); LineTo(hdcPrinter, x1 + tableW, y + rowH);
            DeleteObject(hGridPen);

            // Columna 1: nombre, descripción y observación
            SelectObject(hdcPrinter, hFontPdfBold);
            SetTextColor(hdcPrinter, RGB(30, 30, 30));
            RECT nomRc = { x1 + padX, y + 4, x2 - padX, y + 4 + altoNom };
            DrawText(hdcPrinter, nombrePdfCalc.c_str(), -1, &nomRc, DT_LEFT | DT_TOP | DT_WORDBREAK);

            SelectObject(hdcPrinter, hFontPdfNorm);
            SetTextColor(hdcPrinter, RGB(80, 80, 80));
            RECT descBox = { x1 + padX, y + 4 + altoNom + 2, x2 - padX, y + 4 + altoNom + 2 + altoDesc };
            DrawText(hdcPrinter, descPdfCalc.c_str(), -1, &descBox, DT_LEFT | DT_TOP | DT_WORDBREAK);

            if (!textoAviso.empty()) {
                SetTextColor(hdcPrinter, RGB(184, 134, 11));
                RECT avisoRc = { x1 + padX, y + 4 + altoNom + 2 + altoDesc + 2, x2 - padX, y + rowH - 4 };
                DrawText(hdcPrinter, textoAviso.c_str(), -1, &avisoRc, DT_LEFT | DT_TOP | DT_WORDBREAK);
            }

            SelectObject(hdcPrinter, hFontPdfBold);
            SetTextColor(hdcPrinter, colorEstado);
            RECT c2Rc = { x2 + padX, y + 4, x3 - padX, y + rowH - 4 };
            DrawText(hdcPrinter, estadoCompleto.c_str(), -1, &c2Rc, DT_LEFT | DT_TOP | DT_WORDBREAK);

            SelectObject(hdcPrinter, hFontPdfNorm);
            SetTextColor(hdcPrinter, RGB(30, 30, 30));
            RECT c3Rc = { x3 + padX, y + 4, x4 - padX, y + rowH - 4 };
            std::wstring critPdf = CritItem(item);
            DrawText(hdcPrinter, critPdf.c_str(), -1, &c3Rc, DT_LEFT | DT_TOP | DT_WORDBREAK);

            SelectObject(hdcPrinter, hFontPdfCode);
            SetTextColor(hdcPrinter, RGB(34, 34, 34));
            RECT c4Rc = { x4 + padX, y + 4, x1 + tableW - padX, y + rowH - 4 };
            DrawText(hdcPrinter, valorPdfCalc.c_str(), -1, &c4Rc, DT_LEFT | DT_TOP | DT_WORDBREAK);

            y += rowH;
        }

        // Nota final y firma del autor
        y += MulDiv(14, logPixelsY, 72);
        SelectObject(hdcPrinter, hFontPdfSmall);
        SetTextColor(hdcPrinter, RGB(102, 102, 102));
        std::wstring nota = L10n::Tr(L"pdf.note");
        TextOut(hdcPrinter, marginX, y, nota.c_str(), (int)nota.length());
        y += MulDiv(12, logPixelsY, 72);

        SelectObject(hdcPrinter, hFontPdfNorm);
        SetTextColor(hdcPrinter, RGB(24, 52, 106));
        std::wstring firma = std::wstring(COPYRIGHT) + L" — " + CORREO;
        TextOut(hdcPrinter, marginX, y, firma.c_str(), (int)firma.length());

        DibujarPie(pagina);
        EndPage(hdcPrinter);

        DeleteObject(hFontPdfTitle);
        DeleteObject(hFontPdfH2);
        DeleteObject(hFontPdfNorm);
        DeleteObject(hFontPdfBold);
        DeleteObject(hFontPdfSmall);
        DeleteObject(hFontPdfCode);

        EndDoc(hdcPrinter);
        if (g_rutaPdfForzada.empty())
            MessageBox(hMainWnd, L10n::Tr(L"export.pdf_ok").c_str(), L10n::Tr(L"dlg.success").c_str(), MB_OK | MB_ICONINFORMATION);
    }
    DeleteDC(hdcPrinter);
}

// ============================================================================
// 11. HISTORIAL: ACCIONES DE USUARIO
// ============================================================================
void BorrarItemSeleccionado() {
    int selIdx = ListView_GetNextItem(hHistTree, -1, LVNI_SELECTED);
    if (selIdx < 0 || selIdx >= (int)g_historialCompleto.size()) {
        MessageBox(hMainWnd, L10n::Tr(L"hist.select_first").c_str(), L10n::Tr(L"dlg.attention").c_str(), MB_OK | MB_ICONWARNING);
        return;
    }

    if (MessageBox(hMainWnd, L10n::Tr(L"hist.confirm_delete").c_str(), L10n::Tr(L"hist.confirm_delete_title").c_str(), MB_YESNO | MB_ICONQUESTION) == IDYES) {
        g_historialCompleto.erase(g_historialCompleto.begin() + selIdx);
        GuardarHistorialDisco();
        CargarHistorialEnTabla();
    }
}

void LimpiarTodoHistorial() {
    if (g_historialCompleto.empty()) {
        MessageBox(hMainWnd, L10n::Tr(L"hist.empty").c_str(), L10n::Tr(L"dlg.attention").c_str(), MB_OK | MB_ICONINFORMATION);
        return;
    }

    if (MessageBox(hMainWnd, L10n::Tr(L"hist.confirm_clear").c_str(), L10n::Tr(L"hist.confirm_clear_title").c_str(), MB_YESNO | MB_ICONWARNING) == IDYES) {
        g_historialCompleto.clear();
        GuardarHistorialDisco();
        CargarHistorialEnTabla();
    }
}

void RestaurarCopiaHistorial() {
    std::wstring contenido = LeerArchivoTexto(RutaCopiaHistorial());
    if (contenido.empty()) {
        MessageBox(hMainWnd, L10n::Tr(L"hist.no_backup").c_str(), L10n::Tr(L"dlg.info").c_str(), MB_OK | MB_ICONINFORMATION);
        return;
    }

    JsonValor raiz;
    JsonParser parser(contenido);
    if (!parser.Parsear(raiz) || raiz.tipo != JsonValor::LISTA) {
        MessageBox(hMainWnd, L10n::Tr(L"hist.backup_invalid").c_str(), L10n::Tr(L"dlg.error").c_str(), MB_OK | MB_ICONERROR);
        return;
    }

    // Recupera solo los registros que ya no estén en el historial actual
    std::set<std::wstring> existentes;
    for (const auto& item : g_historialCompleto) existentes.insert(item.fecha + L"|" + item.url);

    std::vector<AnalisisResultado> nuevos;
    for (const auto& obj : raiz.lista) {
        if (obj.tipo != JsonValor::OBJETO) continue;
        std::wstring fecha = obj.Texto(L"fecha");
        std::wstring url = obj.Texto(L"url");
        if (url.empty() || existentes.count(fecha + L"|" + url)) continue;

        AnalisisResultado item;
        item.fecha = fecha;
        item.url = url;
        item.statusCode = obj.Entero(L"status_code", 0);
        item.reason = obj.Texto(L"reason");
        item.server = obj.Texto(L"server");
        item.porcentaje = obj.Decimal(L"porcentaje", -1.0);
        item.puntos = obj.Decimal(L"puntos", 0.0);
        item.puntosMax = obj.Decimal(L"puntos_max", 0.0);
        item.calificacion = obj.Texto(L"calificacion");

        const JsonValor* evs = obj.Buscar(L"evaluacion");
        if (evs && evs->tipo == JsonValor::LISTA) {
            for (const auto& ev : evs->lista) {
                if (ev.tipo != JsonValor::OBJETO) continue;
                CabeceraResultado c;
                c.id = ev.Texto(L"id");
                c.clave = ev.Texto(L"header");
                if (c.clave.empty()) c.clave = ev.Texto(L"key");
                c.nombre = ev.Texto(L"nombre");
                c.desc = ev.Texto(L"desc");
                c.criticidad = ev.Texto(L"criticidad");
                int peso = ev.Entero(L"peso", -1);
                c.peso = (peso < 0) ? PesoDesdeCriticidad(c.criticidad) : peso;
                c.aplicable = ev.Bool(L"aplicable", true);
                c.presente = ev.Bool(L"presente", false);
                c.penalizacion = ev.Entero(L"penalizacion", 0);
                c.valor = ev.Texto(L"valor");
                c.aviso = ev.Texto(L"aviso");
                item.evaluacion.push_back(c);
            }
        }
        if (item.calificacion.empty()) CalcularPuntuacion(item);
        nuevos.push_back(item);
    }

    if (nuevos.empty()) {
        MessageBox(hMainWnd, L10n::Tr(L"hist.backup_nothing").c_str(), L10n::Tr(L"dlg.info").c_str(), MB_OK | MB_ICONINFORMATION);
        return;
    }

    std::wstring pregunta = L10n::Tr(L"hist.restore_question", { { L"count", std::to_wstring(nuevos.size()) } });
    if (MessageBox(hMainWnd, pregunta.c_str(), L10n::Tr(L"hist.restore_title").c_str(), MB_YESNO | MB_ICONQUESTION) != IDYES) return;

    for (const auto& item : nuevos) g_historialCompleto.push_back(item);
    if (g_historialCompleto.size() > 30) g_historialCompleto.resize(30);
    GuardarHistorialDisco();
    CargarHistorialEnTabla();

    std::wstring recuperados = L10n::Tr(L"hist.restored", { { L"count", std::to_wstring(nuevos.size()) } });
    MessageBox(hMainWnd, recuperados.c_str(), L10n::Tr(L"dlg.info").c_str(), MB_OK | MB_ICONINFORMATION);
}

void MostrarAcercaDe() {
    std::wstring mensaje = L10n::Tr(L"about.text", {
        { L"version", VERSION_APP },
        { L"author", AUTOR },
        { L"email", CORREO },
        { L"copyright", COPYRIGHT }
    });
    MessageBox(hMainWnd, mensaje.c_str(), L10n::Tr(L"about.title").c_str(), MB_OK | MB_ICONINFORMATION);
}

// ============================================================================
// 12. LOTES Y ANÁLISIS EN SEGUNDO PLANO
// ============================================================================
void EjecutarLotesNativo() {
    if (g_analizando || g_loteEnCurso) {
        MessageBox(hMainWnd, L10n::Tr(L"err.busy").c_str(), L10n::Tr(L"form.batch").c_str(), MB_OK | MB_ICONINFORMATION);
        return;
    }

    wchar_t szFileName[MAX_PATH] = L"";
    OPENFILENAME ofn = { 0 };
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hMainWnd;
    ofn.lpstrFilter = L"Archivos de texto (*.txt)\0*.txt\0Todos los archivos (*.*)\0*.*\0";
    ofn.lpstrFile = szFileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST;

    if (!GetOpenFileName(&ofn)) return;

    std::wstring contenido = LeerArchivoTexto(szFileName);
    if (contenido.empty()) {
        MessageBox(hMainWnd, L10n::Tr(L"err.batch_open").c_str(), L10n::Tr(L"dlg.error").c_str(), MB_OK | MB_ICONERROR);
        return;
    }

    std::vector<std::wstring> urlsLote;
    std::wstringstream ss(contenido);
    std::wstring linea;
    while (std::getline(ss, linea)) {
        linea = Trim(linea);
        if (!linea.empty() && linea.find(L'#') != 0) urlsLote.push_back(linea);
    }

    if (urlsLote.empty()) {
        MessageBox(hMainWnd, L10n::Tr(L"batch.empty").c_str(), L10n::Tr(L"dlg.attention").c_str(), MB_OK | MB_ICONWARNING);
        return;
    }

    g_loteEnCurso = true;
    EnableWindow(hBtnLotes, FALSE);
    EnableWindow(hBtnAnalizar, FALSE);

    std::thread([urlsLote]() {
        std::vector<AnalisisResultado> resultados;
        std::vector<std::pair<std::wstring, std::wstring>> fallos;

        for (const auto& rawUrl : urlsLote) {
            std::wstring urlStr = Trim(rawUrl);
            if (!urlStr.empty() && urlStr.front() == L'"' && urlStr.back() == L'"') {
                urlStr = urlStr.substr(1, urlStr.size() - 2);
            }
            if (urlStr.find(L"http://") != 0 && urlStr.find(L"https://") != 0) {
                urlStr = L"https://" + urlStr;
            }

            AnalisisResultado item;
            std::wstring error;
            if (AnalizarUrl(urlStr, item, error)) {
                resultados.push_back(item);
            } else {
                fallos.emplace_back(urlStr, error);
            }
        }

        // El historial solo se toca desde el hilo principal (WM_LOTES_COMPLETO)
        auto* paquete = new std::pair<std::vector<AnalisisResultado>, std::vector<std::pair<std::wstring, std::wstring>>>(resultados, fallos);
        PostMessage(hMainWnd, WM_LOTES_COMPLETO, 0, (LPARAM)paquete);
    }).detach();

    MessageBox(hMainWnd, L10n::Tr(L"batch.started").c_str(), L10n::Tr(L"batch.title").c_str(), MB_OK | MB_ICONINFORMATION);
}

void TareaAnalisisBackground(std::wstring urlStr) {
    AnalisisResultado* res = new AnalisisResultado();
    std::wstring error;

    if (AnalizarUrl(urlStr, *res, error)) {
        PostMessage(hMainWnd, WM_ANALISIS_COMPLETO, 0, (LPARAM)res);
    } else {
        delete res;
        PostMessage(hMainWnd, WM_ANALISIS_ERROR, 0, (LPARAM)new std::wstring(error.empty() ? L"No se pudo completar la auditoría." : error));
    }
}

void EjecutarAnalisis() {
    if (g_analizando || g_loteEnCurso) {
        MessageBox(hMainWnd, L10n::Tr(L"err.busy").c_str(), L10n::Tr(L"dlg.attention").c_str(), MB_OK | MB_ICONINFORMATION);
        return;
    }

    wchar_t urlBuf[1024] = { 0 };
    GetWindowText(hEditUrl, urlBuf, 1024);
    std::wstring urlStr = Trim(urlBuf);

    if (urlStr.empty()) {
        MessageBox(hMainWnd, L10n::Tr(L"err.net.url").c_str(), L10n::Tr(L"dlg.attention").c_str(), MB_OK | MB_ICONWARNING);
        return;
    }

    if (urlStr.find(L"http://") != 0 && urlStr.find(L"https://") != 0) {
        urlStr = L"https://" + urlStr;
        SetWindowText(hEditUrl, urlStr.c_str());
    }

    g_analizando = true;
    EnableWindow(hBtnAnalizar, FALSE);
    EnableWindow(hBtnLotes, FALSE);
    SetWindowText(hBtnAnalizar, L"Analizando...");

    std::thread(TareaAnalisisBackground, urlStr).detach();
}

// ============================================================================
// 13. INTERFAZ GRÁFICA (DIBUJO DEL INFORME Y PROCEDIMIENTOS DE VENTANA)
// ============================================================================
void DibujarIconoEstado(HDC hdc, const RECT& rc, COLORREF color, const CabeceraResultado& item) {
    HBRUSH hFondo = CreateSolidBrush(RGB(255, 255, 255));
    FillRect(hdc, &rc, hFondo);
    DeleteObject(hFondo);

    HPEN hBorde = CreatePen(PS_SOLID, 1, color);
    HGDIOBJ hPenViejo = SelectObject(hdc, hBorde);
    HGDIOBJ hBrushViejo = SelectObject(hdc, GetStockObject(NULL_BRUSH));
    Rectangle(hdc, rc.left, rc.top, rc.right, rc.bottom);
    SelectObject(hdc, hBrushViejo);
    SelectObject(hdc, hPenViejo);
    DeleteObject(hBorde);

    const wchar_t* simbolo = L"?";
    if (!item.aplicable) simbolo = L"·";
    else if (item.peso <= 0) simbolo = L"i";
    else if (!item.presente) simbolo = L"✗";
    else if (CalidadItem(item) < 100) simbolo = L"!";
    else simbolo = L"✓";

    SetTextColor(hdc, color);
    RECT rcTexto = rc;
    DrawText(hdc, simbolo, -1, &rcTexto, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
}

LRESULT CALLBACK InformeScrollPanelProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_LBUTTONDOWN:
        SetFocus(hwnd);
        return 0;

    case WM_KEYDOWN: {
        switch (wParam) {
        case VK_UP:    SendMessage(hwnd, WM_VSCROLL, MAKEWPARAM(SB_LINEUP, 0), 0); break;
        case VK_DOWN:  SendMessage(hwnd, WM_VSCROLL, MAKEWPARAM(SB_LINEDOWN, 0), 0); break;
        case VK_PRIOR: SendMessage(hwnd, WM_VSCROLL, MAKEWPARAM(SB_PAGEUP, 0), 0); break;
        case VK_NEXT:  SendMessage(hwnd, WM_VSCROLL, MAKEWPARAM(SB_PAGEDOWN, 0), 0); break;
        case VK_HOME:  SendMessage(hwnd, WM_VSCROLL, MAKEWPARAM(SB_TOP, 0), 0); break;
        case VK_END:   SendMessage(hwnd, WM_VSCROLL, MAKEWPARAM(SB_BOTTOM, 0), 0); break;
        }
        return 0;
    }

    case WM_VSCROLL: {
        SCROLLINFO siLocal = { sizeof(SCROLLINFO), SIF_ALL };
        GetScrollInfo(hwnd, SB_VERT, &siLocal);
        int curPos = siLocal.nPos;
        switch (LOWORD(wParam)) {
        case SB_LINEUP:     siLocal.nPos -= 25; break;
        case SB_LINEDOWN:   siLocal.nPos += 25; break;
        case SB_PAGEUP:     siLocal.nPos -= (siLocal.nPage > 0 ? (int)siLocal.nPage / 2 : 100); break;
        case SB_PAGEDOWN:   siLocal.nPos += (siLocal.nPage > 0 ? (int)siLocal.nPage / 2 : 100); break;
        case SB_TOP:        siLocal.nPos = siLocal.nMin; break;
        case SB_BOTTOM:     siLocal.nPos = siLocal.nMax; break;
        case SB_THUMBTRACK: siLocal.nPos = siLocal.nTrackPos; break;
        }
        siLocal.fMask = SIF_POS;
        SetScrollInfo(hwnd, SB_VERT, &siLocal, TRUE);
        GetScrollInfo(hwnd, SB_VERT, &siLocal);
        if (siLocal.nPos != curPos) {
            ScrollWindow(hwnd, 0, curPos - siLocal.nPos, NULL, NULL);
            UpdateWindow(hwnd);
        }
        return 0;
    }

    case WM_MOUSEWHEEL: {
        int zDelta = GET_WHEEL_DELTA_WPARAM(wParam);
        SendMessage(hwnd, WM_VSCROLL, zDelta > 0 ? SB_LINEUP : SB_LINEDOWN, 0);
        return 0;
    }

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);

        // Al mostrar un informe nuevo se coloca siempre al principio
        if (g_irAlPrincipio) {
            SCROLLINFO siReset = { sizeof(SCROLLINFO), SIF_POS };
            siReset.nPos = 0;
            SetScrollInfo(hwnd, SB_VERT, &siReset, FALSE);
            g_irAlPrincipio = false;
        }

        SCROLLINFO siLocal = { sizeof(SCROLLINFO), SIF_POS };
        GetScrollInfo(hwnd, SB_VERT, &siLocal);
        int offset = -siLocal.nPos;

        RECT rcClient;
        GetClientRect(hwnd, &rcClient);
        HBRUSH hBg = CreateSolidBrush(RGB(226, 226, 226));
        FillRect(hdc, &rcClient, hBg);
        DeleteObject(hBg);

        SetBkMode(hdc, TRANSPARENT);

        if (!g_tieneResultado) {
            SelectObject(hdc, hFontBold);
            SetTextColor(hdc, RGB(50, 50, 50));
            std::wstring listo = L10n::Tr(L"status.ready");
            TextOut(hdc, 20, 20 + offset, listo.c_str(), (int)listo.length());

            SelectObject(hdc, hFontBase);
            SetTextColor(hdc, RGB(90, 90, 90));
            std::wstring pista = L10n::Tr(L"status.hint");
            TextOut(hdc, 20, 45 + offset, pista.c_str(), (int)pista.length());
        } else {
            std::wstring resStr = L10n::Tr(L"status.summary", {
                { L"ok", std::to_wstring(g_ultimoResultado.presentes) },
                { L"total", std::to_wstring(g_ultimoResultado.aplicables) },
                { L"grade", g_ultimoResultado.calificacion },
                { L"pct", std::to_wstring((int)std::lround(g_ultimoResultado.porcentaje)) },
                { L"points", FormatearDecimal(g_ultimoResultado.puntos, 1) },
                { L"max", FormatearDecimal(g_ultimoResultado.puntosMax, 0) }
            });

            SelectObject(hdc, hFontBold);
            COLORREF colorNota = (g_ultimoResultado.calificacion == L"A+" || g_ultimoResultado.calificacion == L"A")
                ? RGB(10, 128, 66)
                : ((g_ultimoResultado.calificacion == L"B" || g_ultimoResultado.calificacion == L"C") ? RGB(253, 126, 20) : RGB(220, 53, 69));
            SetTextColor(hdc, colorNota);
            TextOut(hdc, 15, 12 + offset, resStr.c_str(), (int)resStr.length());

            std::wstring detStr = L10n::Tr(L"status.http", {
                { L"status", std::to_wstring(g_ultimoResultado.statusCode) },
                { L"reason", g_ultimoResultado.reason },
                { L"server", g_ultimoResultado.server },
                { L"date", g_ultimoResultado.fecha }
            });
            if (!g_ultimoResultado.tlsProtocolo.empty())
                detStr += L10n::Tr(L"status.tls", { { L"protocol", g_ultimoResultado.tlsProtocolo } });
            if (!g_ultimoResultado.https)
                detStr += L10n::Tr(L"status.insecure");
            SelectObject(hdc, hFontBase);
            SetTextColor(hdc, RGB(90, 90, 90));
            TextOut(hdc, 15, 34 + offset, detStr.c_str(), (int)detStr.length());

            int yPos = 65 + offset;
            int cardWidth = rcClient.right - 30;

            for (const auto& item : g_ultimoResultado.evaluacion) {
                std::wstring estadoTxt;
                COLORREF colorEstado;
                EstadoDeItem(item, estadoTxt, colorEstado);

                COLORREF colorFondoValor = RGB(241, 243, 245);
                if (item.aplicable && item.peso > 0) {
                    colorFondoValor = item.presente
                        ? (CalidadItem(item) >= 100 ? RGB(236, 246, 239) : RGB(255, 244, 224))
                        : RGB(255, 235, 238);
                }

                std::wstring valStr = L10n::Tr(item.clave.empty() ? L"card.detail" : L"card.value", { { L"value", ValorItem(item) } });

                // Alturas calculadas del texto
                SelectObject(hdc, hFontConsolas);
                RECT calcValRc = { 0, 0, cardWidth - 36, 0 };
                DrawText(hdc, valStr.c_str(), -1, &calcValRc, DT_CALCRECT | DT_WORDBREAK);
                int valBoxHeight = (calcValRc.bottom - calcValRc.top) + 14;

                SelectObject(hdc, hFontItalic);
                RECT calcDescRc = { 0, 0, cardWidth - 24, 0 };
                std::wstring descTexto = DescItem(item);
                int descHeight = (calcDescRc.bottom - calcDescRc.top) + 4;

                int avisoHeight = 0;
                RECT calcAvisoRc = { 0, 0, cardWidth - 36, 0 };
                std::wstring avisoTexto = AvisoItem(item);
                if (!avisoTexto.empty()) {
                    SelectObject(hdc, hFontBase);
                    std::wstring aviso = L10n::Tr(L"card.aviso", { { L"text", avisoTexto } });
                    DrawText(hdc, aviso.c_str(), -1, &calcAvisoRc, DT_CALCRECT | DT_WORDBREAK);
                    avisoHeight = (calcAvisoRc.bottom - calcAvisoRc.top) + 12;
                }

                int cardHeight = 34 + descHeight + valBoxHeight + avisoHeight + 14;

                RECT cardRc = { 15, yPos, 15 + cardWidth, yPos + cardHeight };
                HBRUSH hCardBg = CreateSolidBrush(RGB(255, 255, 255));
                FillRect(hdc, &cardRc, hCardBg);
                DeleteObject(hCardBg);

                HPEN hBorderPen = CreatePen(PS_SOLID, 1, RGB(180, 180, 180));
                HGDIOBJ hPenViejo = SelectObject(hdc, hBorderPen);
                HGDIOBJ hBrushViejo = SelectObject(hdc, GetStockObject(NULL_BRUSH));
                Rectangle(hdc, cardRc.left, cardRc.top, cardRc.right, cardRc.bottom);
                SelectObject(hdc, hBrushViejo);
                SelectObject(hdc, hPenViejo);
                DeleteObject(hBorderPen);

                RECT headerBoxRc = { cardRc.left + 1, cardRc.top + 1, cardRc.right - 1, cardRc.top + 32 };
                HBRUSH hHeaderBoxBg = CreateSolidBrush(RGB(236, 236, 236));
                FillRect(hdc, &headerBoxRc, hHeaderBoxBg);
                DeleteObject(hHeaderBoxBg);

                RECT checkRc = { cardRc.left + 10, cardRc.top + 7, cardRc.left + 26, cardRc.top + 23 };
                DibujarIconoEstado(hdc, checkRc, colorEstado, item);

                SelectObject(hdc, hFontBold);
                SetTextColor(hdc, colorEstado);
                RECT nomRc = { cardRc.left + 32, cardRc.top + 7, cardRc.right - 200, cardRc.top + 27 };
                std::wstring nombreTexto = NombreItem(item);

                std::wstring badgeText;
                if (item.aplicable && item.peso > 0)
                    badgeText = L10n::Tr(L"card.state", { { L"state", estadoTxt }, { L"crit", CritItem(item) },
                                                           { L"quality", std::to_wstring(CalidadItem(item)) } });
                else
                    badgeText = L10n::Tr(L"card.state_simple", { { L"state", estadoTxt }, { L"crit", CritItem(item) } });
                HFONT hBadgeFont = CrearFuenteSuave(10, FW_BOLD);
                SelectObject(hdc, hBadgeFont);

                SIZE badgeSize;
                GetTextExtentPoint32(hdc, badgeText.c_str(), (int)badgeText.length(), &badgeSize);
                int badgeWidth = badgeSize.cx + 16;

                RECT badgeRc = { cardRc.right - badgeWidth - 8, cardRc.top + 5, cardRc.right - 8, cardRc.top + 25 };
                HBRUSH hBadgeBg = CreateSolidBrush(colorEstado);
                FillRect(hdc, &badgeRc, hBadgeBg);
                DeleteObject(hBadgeBg);

                SetTextColor(hdc, RGB(255, 255, 255));
                DrawText(hdc, badgeText.c_str(), -1, &badgeRc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
                DeleteObject(hBadgeFont);

                SelectObject(hdc, hFontItalic);
                SetTextColor(hdc, RGB(100, 100, 100));
                RECT descRc = { cardRc.left + 12, cardRc.top + 36, cardRc.right - 12, cardRc.top + 36 + descHeight };
                DrawText(hdc, descTexto.c_str(), -1, &descRc, DT_LEFT | DT_TOP | DT_WORDBREAK);

                int yValor = cardRc.top + 36 + descHeight + 2;
                RECT valBoxRc = { cardRc.left + 12, yValor, cardRc.right - 12, yValor + valBoxHeight };
                HBRUSH hValBg = CreateSolidBrush(colorFondoValor);
                FillRect(hdc, &valBoxRc, hValBg);
                DeleteObject(hValBg);

                SelectObject(hdc, hFontConsolas);
                SetTextColor(hdc, RGB(40, 40, 40));
                RECT valTextMargin = { valBoxRc.left + 8, valBoxRc.top + 6, valBoxRc.right - 8, valBoxRc.bottom - 4 };
                DrawText(hdc, valStr.c_str(), -1, &valTextMargin, DT_LEFT | DT_TOP | DT_WORDBREAK);

                if (!avisoTexto.empty()) {
                    int yAviso = yValor + valBoxHeight + 4;
                    RECT avisoBoxRc = { cardRc.left + 12, yAviso, cardRc.right - 12, yAviso + avisoHeight };
                    HBRUSH hAvisoBg = CreateSolidBrush(RGB(255, 244, 214));
                    FillRect(hdc, &avisoBoxRc, hAvisoBg);
                    DeleteObject(hAvisoBg);

                    SelectObject(hdc, hFontBase);
                    SetTextColor(hdc, RGB(138, 90, 0));
                    std::wstring aviso = L10n::Tr(L"card.aviso", { { L"text", avisoTexto } });
                    RECT avisoRc = { avisoBoxRc.left + 8, avisoBoxRc.top + 4, avisoBoxRc.right - 8, avisoBoxRc.bottom - 2 };
                    DrawText(hdc, aviso.c_str(), -1, &avisoRc, DT_LEFT | DT_TOP | DT_WORDBREAK);
                }

                yPos += cardHeight + 12;
            }

            SCROLLINFO siPageInfo = { sizeof(SCROLLINFO), SIF_RANGE | SIF_PAGE };
            siPageInfo.nMin = 0;
            siPageInfo.nMax = yPos - offset + 20;
            siPageInfo.nPage = rcClient.bottom;
            SetScrollInfo(hwnd, SB_VERT, &siPageInfo, TRUE);
        }

        EndPaint(hwnd, &ps);
        return 0;
    }
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

// ----------------------------------------------------------------------------
// Menús e idioma
// ----------------------------------------------------------------------------
HMENU g_menuPrincipal = NULL;
HMENU g_menuIdioma = NULL;
std::vector<std::wstring> g_codigosIdioma;

void RellenarMenuExportar() {
    if (hMenuExportar) DestroyMenu(hMenuExportar);
    hMenuExportar = CreatePopupMenu();
    AppendMenu(hMenuExportar, MF_STRING, 1, L10n::Tr(L"form.export.pdf").c_str());
    AppendMenu(hMenuExportar, MF_STRING, 2, L10n::Tr(L"form.export.json").c_str());
    AppendMenu(hMenuExportar, MF_STRING, 3, L10n::Tr(L"form.export.csv").c_str());
    AppendMenu(hMenuExportar, MF_SEPARATOR, 0, NULL);
    AppendMenu(hMenuExportar, MF_STRING, 4, L10n::Tr(L"menu.help.about").c_str());
}

void ConstruirMenuIdioma(HWND hwnd) {
    if (g_menuPrincipal) DestroyMenu(g_menuPrincipal);
    g_menuPrincipal = CreateMenu();
    g_menuIdioma = CreatePopupMenu();
    g_codigosIdioma.clear();

    for (const auto& idioma : L10n::Idiomas()) {
        AppendMenu(g_menuIdioma, MF_STRING, 2000 + (UINT)g_codigosIdioma.size(), idioma.second.c_str());
        g_codigosIdioma.push_back(idioma.first);
    }
    for (size_t j = 0; j < g_codigosIdioma.size(); ++j) {
        if (g_codigosIdioma[j] == L10n::g_actual) {
            CheckMenuRadioItem(g_menuIdioma, 2000, 2000 + (UINT)g_codigosIdioma.size() - 1,
                               2000 + (UINT)j, MF_BYCOMMAND);
        }
    }
    std::wstring etiqueta = L10n::Tr(L"menu.language");
    AppendMenu(g_menuPrincipal, MF_POPUP, (UINT_PTR)g_menuIdioma, etiqueta.c_str());
    SetMenu(hwnd, g_menuPrincipal);
    DrawMenuBar(hwnd);
}

void ActualizarTextosUI(HWND hwnd) {
    SetWindowText(hwnd, L10n::Tr(L"app.title").c_str());
    SetWindowText(hGrpBox, L10n::Tr(L"form.title").c_str());
    SetWindowText(hLblUrl, L10n::Tr(L"form.url").c_str());

    std::wstring textoAnalizar = g_analizando
        ? L10n::Tr(L"form.analyzing")
        : (L"🔍 " + L10n::Tr(L"form.analyze"));
    SetWindowText(hBtnAnalizar, textoAnalizar.c_str());
    SetWindowText(hBtnLotes, (L"📂 " + L10n::Tr(L"form.batch")).c_str());
    SetWindowText(hBtnExportar, (L"💾 " + L10n::Tr(L"form.export") + L" ▾").c_str());

    std::wstring tab1 = L"📊 " + L10n::Tr(L"tab.report");
    std::wstring tab2 = L"📜 " + L10n::Tr(L"tab.history");
    TCITEM tie = { 0 };
    tie.mask = TCIF_TEXT;
    tie.pszText = (LPWSTR)tab1.c_str();
    TabCtrl_SetItem(hTabControl, 0, &tie);
    tie.pszText = (LPWSTR)tab2.c_str();
    TabCtrl_SetItem(hTabControl, 1, &tie);

    std::wstring col0 = L10n::Tr(L"hist.date");
    std::wstring col1 = L10n::Tr(L"hist.url");
    std::wstring col2 = L10n::Tr(L"hist.status");
    std::wstring col3 = L10n::Tr(L"hist.grade");
    LVCOLUMN col = { 0 };
    col.mask = LVCF_TEXT;
    col.pszText = (LPWSTR)col0.c_str(); ListView_SetColumn(hHistTree, 0, &col);
    col.pszText = (LPWSTR)col1.c_str(); ListView_SetColumn(hHistTree, 1, &col);
    col.pszText = (LPWSTR)col2.c_str(); ListView_SetColumn(hHistTree, 2, &col);
    col.pszText = (LPWSTR)col3.c_str(); ListView_SetColumn(hHistTree, 3, &col);

    SetWindowText(hBtnBorrarItem, (L"🗑️ " + L10n::Tr(L"hist.delete")).c_str());
    SetWindowText(hBtnLimpiarTodo, (L"🧹 " + L10n::Tr(L"hist.clear")).c_str());
    SetWindowText(hBtnRestaurar, (L"♻️ " + L10n::Tr(L"hist.restore")).c_str());

    RellenarMenuExportar();
}

void CambiarIdioma(HWND hwnd, const std::wstring& codigo) {
    L10n::Aplicar(codigo);
    L10n::Guardar(L10n::g_actual);
    ConstruirMenuIdioma(hwnd);
    ActualizarTextosUI(hwnd);
    CargarHistorialEnTabla();
    g_irAlPrincipio = true;
    InvalidateRect(hwnd, NULL, TRUE);
    InvalidateRect(hPanelInformeScroll, NULL, TRUE);
}

LRESULT CALLBACK MainWndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE: {
        InicializarFuentesGlobales();

        hIconEscudo = LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(1));
        if (hIconEscudo) {
            SendMessage(hwnd, WM_SETICON, ICON_BIG, (LPARAM)hIconEscudo);
            SendMessage(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hIconEscudo);
        }

        INITCOMMONCONTROLSEX icex = { sizeof(INITCOMMONCONTROLSEX), ICC_TAB_CLASSES | ICC_LISTVIEW_CLASSES };
        InitCommonControlsEx(&icex);

        hGrpBox = CreateWindow(L"BUTTON", L"", WS_CHILD | WS_VISIBLE | BS_GROUPBOX, 15, 65, 960, 60, hwnd, NULL, NULL, NULL);
        SendMessage(hGrpBox, WM_SETFONT, (WPARAM)hFontBase, TRUE);

        hLblUrl = CreateWindow(L"STATIC", L"", WS_CHILD | WS_VISIBLE, 28, 88, 160, 20, hwnd, NULL, NULL, NULL);
        SendMessage(hLblUrl, WM_SETFONT, (WPARAM)hFontBase, TRUE);

        hEditUrl = CreateWindow(L"EDIT", g_urlInicial.empty() ? L"" : g_urlInicial.c_str(), WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 190, 85, 380, 24, hwnd, (HMENU)IDC_URL_ENTRY, NULL, NULL);
        SendMessage(hEditUrl, WM_SETFONT, (WPARAM)hFontBase, TRUE);
        SendMessage(hEditUrl, EM_SETLIMITTEXT, 1000, 0);

        hBtnAnalizar = CreateWindow(L"BUTTON", L"", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 580, 84, 115, 26, hwnd, (HMENU)IDC_BTN_ANALIZAR, NULL, NULL);
        SendMessage(hBtnAnalizar, WM_SETFONT, (WPARAM)hFontBold, TRUE);

        hBtnLotes = CreateWindow(L"BUTTON", L"", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 705, 84, 85, 26, hwnd, (HMENU)IDC_BTN_LOTES, NULL, NULL);
        SendMessage(hBtnLotes, WM_SETFONT, (WPARAM)hFontBase, TRUE);

        hBtnExportar = CreateWindow(L"BUTTON", L"", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED, 800, 84, 115, 26, hwnd, (HMENU)IDC_BTN_EXPORTAR, NULL, NULL);
        SendMessage(hBtnExportar, WM_SETFONT, (WPARAM)hFontBase, TRUE);

        RellenarMenuExportar();

        hTabControl = CreateWindow(WC_TABCONTROL, L"", WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS, 15, 135, 960, 550, hwnd, (HMENU)IDC_TAB_CONTROL, NULL, NULL);
        SendMessage(hTabControl, WM_SETFONT, (WPARAM)hFontBase, TRUE);

        TCITEM tie = { 0 };
        tie.mask = TCIF_TEXT;
        tie.pszText = (LPWSTR)L"";
        TabCtrl_InsertItem(hTabControl, 0, &tie);
        TabCtrl_InsertItem(hTabControl, 1, &tie);

        WNDCLASS wcPanel = { 0 };
        wcPanel.lpfnWndProc = InformeScrollPanelProc;
        wcPanel.hInstance = GetModuleHandle(NULL);
        wcPanel.lpszClassName = L"InformeScrollPanelClass";
        wcPanel.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        RegisterClass(&wcPanel);

        hPanelInformeScroll = CreateWindow(L"InformeScrollPanelClass", L"", WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_TABSTOP, 20, 165, 950, 470, hwnd, NULL, NULL, NULL);

        hHistTree = CreateWindow(WC_LISTVIEW, L"", WS_CHILD | LVS_REPORT | LVS_SINGLESEL, 20, 165, 950, 470, hwnd, (HMENU)IDC_HIST_TREE, NULL, NULL);
        SendMessage(hHistTree, WM_SETFONT, (WPARAM)hFontBase, TRUE);
        ListView_SetExtendedListViewStyle(hHistTree, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

        LVCOLUMN lvc = { 0 };
        lvc.mask = LVCF_TEXT | LVCF_WIDTH;
        lvc.pszText = (LPWSTR)L"";
        lvc.cx = 160; ListView_InsertColumn(hHistTree, 0, &lvc);
        lvc.cx = 400; ListView_InsertColumn(hHistTree, 1, &lvc);
        lvc.cx = 140; ListView_InsertColumn(hHistTree, 2, &lvc);
        lvc.cx = 190; ListView_InsertColumn(hHistTree, 3, &lvc);

        hBtnBorrarItem = CreateWindow(L"BUTTON", L"", WS_CHILD, 20, 642, 175, 28, hwnd, (HMENU)IDC_BTN_BORRAR_ITEM, NULL, NULL);
        SendMessage(hBtnBorrarItem, WM_SETFONT, (WPARAM)hFontBase, TRUE);

        hBtnLimpiarTodo = CreateWindow(L"BUTTON", L"", WS_CHILD, 205, 642, 160, 28, hwnd, (HMENU)IDC_BTN_LIMPIAR_TODO, NULL, NULL);
        SendMessage(hBtnLimpiarTodo, WM_SETFONT, (WPARAM)hFontBase, TRUE);

        hBtnRestaurar = CreateWindow(L"BUTTON", L"", WS_CHILD, 375, 642, 170, 28, hwnd, (HMENU)IDC_BTN_RESTAURAR, NULL, NULL);
        SendMessage(hBtnRestaurar, WM_SETFONT, (WPARAM)hFontBase, TRUE);

        ActualizarTextosUI(hwnd);
        ConstruirMenuIdioma(hwnd);

        CargarHistorialEnTabla();
        return 0;
    }

    case WM_ANALISIS_COMPLETO: {
        AnalisisResultado* res = (AnalisisResultado*)lParam;
        g_ultimoResultado = *res;
        delete res;
        g_tieneResultado = true;

        g_historialCompleto.insert(g_historialCompleto.begin(), g_ultimoResultado);
        if (g_historialCompleto.size() > 30) g_historialCompleto.pop_back();
        GuardarHistorialDisco();
        CargarHistorialEnTabla();

        g_analizando = false;
        EnableWindow(hBtnExportar, TRUE);
        EnableWindow(hBtnAnalizar, TRUE);
        EnableWindow(hBtnLotes, TRUE);
        ActualizarTextosUI(hwnd);
        g_irAlPrincipio = true;
        InvalidateRect(hPanelInformeScroll, NULL, TRUE);
        return 0;
    }

    case WM_ANALISIS_ERROR: {
        std::wstring* mensaje = (std::wstring*)lParam;
        g_analizando = false;
        EnableWindow(hBtnAnalizar, TRUE);
        EnableWindow(hBtnLotes, TRUE);
        ActualizarTextosUI(hwnd);
        MessageBox(hwnd, mensaje ? mensaje->c_str() : L10n::Tr(L"err.generic").c_str(),
                   L10n::Tr(L"err.connection_title").c_str(), MB_OK | MB_ICONERROR);
        delete mensaje;
        return 0;
    }

    case WM_LOTES_COMPLETO: {
        auto* paquete = (std::pair<std::vector<AnalisisResultado>, std::vector<std::pair<std::wstring, std::wstring>>>*)lParam;
        g_loteEnCurso = false;
        EnableWindow(hBtnAnalizar, TRUE);
        EnableWindow(hBtnLotes, TRUE);

        if (paquete) {
            for (const auto& item : paquete->first) {
                g_historialCompleto.insert(g_historialCompleto.begin(), item);
            }
            if (g_historialCompleto.size() > 30) g_historialCompleto.resize(30);
            if (!paquete->first.empty()) {
                GuardarHistorialDisco();
                CargarHistorialEnTabla();

                g_ultimoResultado = paquete->first.back();
                g_tieneResultado = true;
                EnableWindow(hBtnExportar, TRUE);
                TabCtrl_SetCurSel(hTabControl, 0);
                ShowWindow(hPanelInformeScroll, SW_SHOW);
                ShowWindow(hHistTree, SW_HIDE);
                ShowWindow(hBtnBorrarItem, SW_HIDE);
                ShowWindow(hBtnLimpiarTodo, SW_HIDE);
                ShowWindow(hBtnRestaurar, SW_HIDE);
                g_irAlPrincipio = true;
                InvalidateRect(hPanelInformeScroll, NULL, TRUE);
            }

            std::wstring resumen = L10n::Tr(
                paquete->first.empty() ? L"batch.none" : L"batch.finished",
                { { L"ok", std::to_wstring(paquete->first.size()) },
                  { L"total", std::to_wstring(paquete->first.size() + paquete->second.size()) } });

            if (!paquete->second.empty()) {
                resumen += L"\n\n" + L10n::Tr(L"batch.failures");
                size_t mostrados = 0;
                for (const auto& fallo : paquete->second) {
                    if (mostrados++ >= 8) { resumen += L"\n" + L10n::Tr(L"batch.more", { { L"count", std::to_wstring(paquete->second.size() - 8) } }); break; }
                    resumen += L"\n- " + fallo.first + L": " + fallo.second;
                }
            }

            MessageBox(hwnd, resumen.c_str(),
                       L10n::Tr(paquete->first.empty() ? L"form.batch" : L"batch.finished_title").c_str(),
                       MB_OK | (paquete->first.empty() ? MB_ICONERROR : MB_ICONINFORMATION));
            delete paquete;
        }
        return 0;
    }

    case WM_SIZE: {
        int width = LOWORD(lParam);
        int height = HIWORD(lParam);

        if (width > 0 && height > 0) {
            SetWindowPos(hGrpBox, NULL, 15, 65, width - 30, 60, SWP_NOZORDER);
            SetWindowPos(hEditUrl, NULL, 190, 85, width - 580, 24, SWP_NOZORDER);
            SetWindowPos(hBtnAnalizar, NULL, width - 380, 84, 110, 26, SWP_NOZORDER);
            SetWindowPos(hBtnLotes, NULL, width - 260, 84, 80, 26, SWP_NOZORDER);
            SetWindowPos(hBtnExportar, NULL, width - 170, 84, 110, 26, SWP_NOZORDER);

            SetWindowPos(hTabControl, NULL, 15, 135, width - 30, height - 150, SWP_NOZORDER);

            int histHeight = height - 230;
            if (histHeight < 100) histHeight = 100;

            SetWindowPos(hPanelInformeScroll, NULL, 20, 165, width - 40, histHeight, SWP_NOZORDER);
            SetWindowPos(hHistTree, NULL, 20, 165, width - 40, histHeight, SWP_NOZORDER);
            SetWindowPos(hBtnBorrarItem, NULL, 20, 175 + histHeight, 175, 28, SWP_NOZORDER);
            SetWindowPos(hBtnLimpiarTodo, NULL, 205, 175 + histHeight, 160, 28, SWP_NOZORDER);
            SetWindowPos(hBtnRestaurar, NULL, 375, 175 + histHeight, 170, 28, SWP_NOZORDER);

            InvalidateRect(hwnd, NULL, TRUE);
            InvalidateRect(hPanelInformeScroll, NULL, TRUE);
        }
        return 0;
    }

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);

        RECT rcWindow;
        GetClientRect(hwnd, &rcWindow);

        RECT headerRc = { 0, 0, rcWindow.right, 55 };
        HBRUSH hHeaderBrush = CreateSolidBrush(RGB(24, 52, 106));
        FillRect(hdc, &headerRc, hHeaderBrush);
        DeleteObject(hHeaderBrush);

        if (hIconEscudo) {
            DrawIconEx(hdc, 18, 11, hIconEscudo, 32, 32, 0, NULL, DI_NORMAL);
        }

        SetBkMode(hdc, TRANSPARENT);

        SelectObject(hdc, hFontHeader);
        SetTextColor(hdc, RGB(255, 255, 255));
        RECT textRc = { 62, 8, rcWindow.right - 20, 28 };
        std::wstring tituloVentana = L10n::Tr(L"app.title");
        DrawText(hdc, tituloVentana.c_str(), -1, &textRc, DT_LEFT | DT_TOP | DT_SINGLELINE | DT_NOPREFIX);

        SelectObject(hdc, hFontSubHeader);
        SetTextColor(hdc, RGB(215, 225, 245));
        RECT subTextRc = { 62, 32, rcWindow.right - 20, 50 };
        std::wstring subtituloVentana = L10n::Tr(L"app.subtitle");
        DrawText(hdc, subtituloVentana.c_str(), -1, &subTextRc, DT_LEFT | DT_TOP | DT_SINGLELINE | DT_NOPREFIX);

        // Copyright del autor (clic para ver "Acerca de")
        std::wstring credito = std::wstring(COPYRIGHT) + L" · " + CORREO;
        RECT creditoRc = { rcWindow.right - 380, 32, rcWindow.right - 12, 50 };
        DrawText(hdc, credito.c_str(), -1, &creditoRc, DT_RIGHT | DT_TOP | DT_SINGLELINE | DT_NOPREFIX);

        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_LBUTTONDOWN: {
        int x = GET_X_LPARAM(lParam);
        int y = GET_Y_LPARAM(lParam);
        RECT rcWindow;
        GetClientRect(hwnd, &rcWindow);
        if (y < 55 && x > rcWindow.right - 390) {
            MostrarAcercaDe();
        }
        return 0;
    }

    case WM_COMMAND: {
        int wmId = LOWORD(wParam);
        if (wmId == IDC_BTN_ANALIZAR) {
            EjecutarAnalisis();
        } else if (wmId == IDC_BTN_LOTES) {
            EjecutarLotesNativo();
        } else if (wmId == IDC_BTN_EXPORTAR) {
            RECT rc;
            GetWindowRect(hBtnExportar, &rc);
            TrackPopupMenu(hMenuExportar, TPM_LEFTALIGN | TPM_TOPALIGN, rc.left, rc.bottom, 0, hwnd, NULL);
        } else if (wmId == 1) {
            ExportarPDFNativo();
        } else if (wmId == 2) {
            ExportarJSON();
        } else if (wmId == 3) {
            ExportarCSV();
        } else if (wmId == 4) {
            MostrarAcercaDe();
        } else if (wmId == IDC_BTN_BORRAR_ITEM) {
            BorrarItemSeleccionado();
        } else if (wmId == IDC_BTN_LIMPIAR_TODO) {
            LimpiarTodoHistorial();
        } else if (wmId == IDC_BTN_RESTAURAR) {
            RestaurarCopiaHistorial();
        } else if (wmId >= 2000 && wmId < 2000 + (int)g_codigosIdioma.size()) {
            CambiarIdioma(hwnd, g_codigosIdioma[wmId - 2000]);
        }
        return 0;
    }

    case WM_NOTIFY: {
        LPNMHDR pnmh = (LPNMHDR)lParam;
        if (pnmh->idFrom == IDC_TAB_CONTROL && pnmh->code == TCN_SELCHANGE) {
            int iPage = TabCtrl_GetCurSel(hTabControl);
            ShowWindow(hPanelInformeScroll, iPage == 0 ? SW_SHOW : SW_HIDE);
            ShowWindow(hHistTree, iPage == 1 ? SW_SHOW : SW_HIDE);
            ShowWindow(hBtnBorrarItem, iPage == 1 ? SW_SHOW : SW_HIDE);
            ShowWindow(hBtnLimpiarTodo, iPage == 1 ? SW_SHOW : SW_HIDE);
            ShowWindow(hBtnRestaurar, iPage == 1 ? SW_SHOW : SW_HIDE);
        }
        else if (pnmh->idFrom == IDC_HIST_TREE && pnmh->code == NM_DBLCLK) {
            int selIdx = ListView_GetNextItem(hHistTree, -1, LVNI_SELECTED);
            if (selIdx >= 0 && selIdx < (int)g_historialCompleto.size()) {
                g_ultimoResultado = g_historialCompleto[selIdx];
                g_tieneResultado = true;
                SetWindowText(hEditUrl, g_ultimoResultado.url.c_str());
                EnableWindow(hBtnExportar, TRUE);
                TabCtrl_SetCurSel(hTabControl, 0);
                ShowWindow(hPanelInformeScroll, SW_SHOW);
                ShowWindow(hHistTree, SW_HIDE);
                ShowWindow(hBtnBorrarItem, SW_HIDE);
                ShowWindow(hBtnLimpiarTodo, SW_HIDE);
                ShowWindow(hBtnRestaurar, SW_HIDE);
                g_irAlPrincipio = true;
                InvalidateRect(hPanelInformeScroll, NULL, TRUE);
            }
        }
        else if (pnmh->idFrom == IDC_HIST_TREE && pnmh->code == LVN_KEYDOWN) {
            LPNMLVKEYDOWN pnkd = (LPNMLVKEYDOWN)lParam;
            if (pnkd->wVKey == VK_DELETE) {
                BorrarItemSeleccionado();
            }
        }
        return 0;
    }

    case WM_DESTROY:
        if (hMenuExportar) DestroyMenu(hMenuExportar);
        if (g_menuPrincipal) DestroyMenu(g_menuPrincipal);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

// ============================================================================
// 14. MODO CONSOLA (--json): misma salida que el núcleo, para pruebas
// ============================================================================
void EscribirConsolaUtf8(const std::wstring& texto) {
    std::string utf8 = AUtf8(texto);
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD escrito = 0;
    if (h != NULL && h != INVALID_HANDLE_VALUE) {
        WriteFile(h, utf8.data(), (DWORD)utf8.size(), &escrito, NULL);
    }
}

std::wstring JsonError(const std::wstring& url, const std::wstring& codigo, int status, const std::wstring& mensaje) {
    std::wstringstream js;
    js << L"{\n";
    js << L"  \"ok\": false,\n";
    js << L"  \"url\": \"" << EscaparJson(url) << L"\",\n";
    js << L"  \"error\": \"" << EscaparJson(codigo) << L"\",\n";
    js << L"  \"status_code\": " << status << L",\n";
    js << L"  \"mensaje\": \"" << EscaparJson(mensaje) << L"\"\n";
    js << L"}\n";
    return js.str();
}

int ModoConsolaJson(const std::wstring& urlEntrada) {
    std::wstring url = Trim(urlEntrada);
    if (url.empty()) {
        EscribirConsolaUtf8(JsonError(L"", L"url", 0, L"Indica una URL: auditor.exe --json <url>"));
        return 2;
    }
    if (url.find(L"http://") != 0 && url.find(L"https://") != 0) url = L"https://" + url;

    AnalisisResultado res;
    std::wstring error;
    if (!AnalizarUrl(url, res, error)) {
        std::wstring codigo = (error.find(L"dominio") != std::wstring::npos) ? L"dns" : L"red";
        if (error.find(L"certificado") != std::wstring::npos || error.find(L"TLS") != std::wstring::npos) codigo = L"tls";
        if (error.find(L"HTTP ") != std::wstring::npos) codigo = L"http";
        EscribirConsolaUtf8(JsonError(res.url.empty() ? url : res.url, codigo, res.statusCode, error));
        return 2;
    }

    EscribirConsolaUtf8(JsonDeResultado(res, true) + L"\n");
    return 0;
}

int ModoConsolaPdf(const std::wstring& urlEntrada, const std::wstring& rutaSalida) {
    std::wstring url = Trim(urlEntrada);
    if (url.empty()) {
        EscribirConsolaUtf8(JsonError(L"", L"url", 0, L"Indica una URL: auditor.exe --pdf <url> <salida.pdf>"));
        return 2;
    }
    if (url.find(L"http://") != 0 && url.find(L"https://") != 0) url = L"https://" + url;

    AnalisisResultado res;
    std::wstring error;
    if (!AnalizarUrl(url, res, error)) {
        EscribirConsolaUtf8(JsonError(url, L"red", res.statusCode, error));
        return 2;
    }

    g_ultimoResultado = res;
    g_tieneResultado = true;
    g_rutaPdfForzada = rutaSalida;
    ExportarPDFNativo();
    g_rutaPdfForzada.clear();
    return 0;
}

// ============================================================================
// 15. PUNTO DE ENTRADA PRINCIPAL (WinMain)
// ============================================================================
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Idioma guardado -> idioma del sistema -> inglés (también para los modos de consola)
    L10n::Aplicar(L10n::ResolverInicio());

    // Modo consola para pruebas/automatización: auditor.exe --json <url>
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv) {
        if (argc >= 2 && (_wcsicmp(argv[1], L"--json") == 0 || _wcsicmp(argv[1], L"/json") == 0)) {
            std::wstring url = (argc >= 3) ? argv[2] : DEFAULT_URL;
            LocalFree(argv);
            return ModoConsolaJson(url);
        }
        if (argc >= 4 && (_wcsicmp(argv[1], L"--pdf") == 0 || _wcsicmp(argv[1], L"/pdf") == 0)) {
            std::wstring url = argv[2];
            std::wstring ruta = argv[3];
            LocalFree(argv);
            return ModoConsolaPdf(url, ruta);
        }
        // Uso normal: auditor.exe <url> abre la interfaz con la dirección puesta
        if (argc >= 2 && argv[1][0] != L'-' && argv[1][0] != L'/') {
            g_urlInicial = Trim(argv[1]);
        }
        LocalFree(argv);
    }

    INITCOMMONCONTROLSEX icex = { sizeof(INITCOMMONCONTROLSEX), ICC_TAB_CLASSES | ICC_LISTVIEW_CLASSES };
    InitCommonControlsEx(&icex);

    WNDCLASS wc = { 0 };
    wc.lpfnWndProc = MainWndProc;
    wc.hInstance = hInstance;
    wc.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(1));
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"AuditorSeguridadMainWndClass";

    RegisterClass(&wc);

    hMainWnd = CreateWindow(L"AuditorSeguridadMainWndClass", L"Auditor Profesional de Seguridad HTTP",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1000, 740, NULL, NULL, hInstance, NULL);

    ShowWindow(hMainWnd, nCmdShow);
    UpdateWindow(hMainWnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return (int)msg.wParam;
}
