// ============================================================================
// auditor_core.cpp - Núcleo de auditoría HTTP del Auditor de Seguridad Web
// ----------------------------------------------------------------------------
// Recibe una URL por línea de comandos, descarga SOLO las cabeceras de la
// respuesta (siguiendo redirecciones) y devuelve un objeto JSON por la salida
// estándar con el resultado del análisis.
//
// Motor: WinHTTP (TLS real, sin caché ni cookies del sistema).
//
// Contrato con la interfaz Python:
//   - Código de salida 0 y JSON con "ok": true  -> análisis correcto.
//   - Código de salida 2 y JSON con "ok": false -> fallo controlado; el campo
//     "mensaje" explica el motivo real (DNS, TLS, tiempo de espera, HTTP 404...).
//
// Cada comprobación incluye:
//   peso          -> importancia (4 CRÍTICA ... 0 informativa, no puntúa)
//   aplicable     -> false cuando la comprobación no tiene sentido en ese sitio
//   presente      -> true si está configurada (o no supone un riesgo)
//   penalizacion  -> 0..100 según la calidad del valor configurado
//
// Compilación (x64 Native Tools):
//   cl /O2 /EHsc /utf-8 auditor_core.cpp /link /SUBSYSTEM:CONSOLE winhttp.lib
//
// Copyright (c) 2026 Juan Ramon Martin <zeronet75@gmail.com>
// Licencia MIT (ver el archivo LICENSE).
// ============================================================================
#define NOMINMAX
#define UNICODE
#define _UNICODE
#include <windows.h>
#define SECURITY_WIN32
#include <sspi.h>
#include <schannel.h>
#include <winhttp.h>
#include <string>
#include <vector>
#include <sstream>
#include <set>
#include <algorithm>
#include <cwctype>
#include <io.h>
#include <fcntl.h>

#pragma comment(lib, "winhttp.lib")

// ----------------------------------------------------------------------------
// Estructuras de trabajo
// ----------------------------------------------------------------------------
struct CabeceraMeta {
    std::wstring key;          // Nombre real de la cabecera HTTP
    std::wstring nombre;       // Nombre legible
    std::wstring desc;         // Explicación
    std::wstring criticidad;   // CRÍTICA / ALTA / MEDIA / BAJA / INFORMATIVA
    int peso;                  // Puntos que aporta al cálculo de la nota (0 = no puntúa)
};

struct CabeceraCruda {
    std::wstring nombre;
    std::wstring valor;
};

struct Chequeo {
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
    int penalizacion = 0;      // 0 = valor correcto
};

struct ResultadoPeticion {
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

// Cabeceras evaluadas: peso 0 = informativa (se muestra pero no baja la nota).
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

// ----------------------------------------------------------------------------
// Utilidades de texto y JSON
// ----------------------------------------------------------------------------
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

bool Contiene(const std::wstring& texto, const wchar_t* aguja) {
    return Minusculas(texto).find(Minusculas(aguja)) != std::wstring::npos;
}

// Escapa correctamente cadenas para JSON (comillas, barras y caracteres de control).
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

// ----------------------------------------------------------------------------
// Análisis de las cabeceras recibidas
// ----------------------------------------------------------------------------
std::vector<CabeceraCruda> ParsearCabeceras(const std::wstring& crudo) {
    std::vector<CabeceraCruda> lista;
    size_t pos = 0;
    bool primeraLinea = true;               // La primera línea es "HTTP/1.1 200 OK"

    while (pos < crudo.size()) {
        size_t fin = crudo.find(L"\r\n", pos);
        std::wstring linea = crudo.substr(pos, (fin == std::wstring::npos) ? std::wstring::npos : fin - pos);
        pos = (fin == std::wstring::npos) ? crudo.size() : fin + 2;

        if (primeraLinea) { primeraLinea = false; continue; }
        if (linea.empty()) continue;

        // Continuación de la cabecera anterior (líneas que empiezan por espacio o tabulador)
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

bool TieneCabecera(const std::vector<CabeceraCruda>& lista, const std::wstring& nombre, std::wstring& valor) {
    std::wstring objetivo = Minusculas(nombre);
    bool encontrada = false;
    for (const auto& cab : lista) {
        if (Minusculas(cab.nombre) == objetivo) {
            if (!encontrada) { valor = cab.valor; encontrada = true; }
            else { valor += L", " + cab.valor; }   // Cabeceras repetidas se combinan
        }
    }
    return encontrada;
}

// Todas las apariciones de una cabecera (necesario para Set-Cookie, que no se puede unir con comas).
std::vector<std::wstring> TodasLasCabeceras(const std::vector<CabeceraCruda>& lista, const std::wstring& nombre) {
    std::vector<std::wstring> valores;
    std::wstring objetivo = Minusculas(nombre);
    for (const auto& cab : lista) {
        if (Minusculas(cab.nombre) == objetivo) valores.push_back(cab.valor);
    }
    return valores;
}

// ----------------------------------------------------------------------------
// Evaluación de la calidad de cada cabecera
// ----------------------------------------------------------------------------
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
            penalizacion = 0;   // Informativa: no resta nota
            return L"unsafe-none permite cargar recursos cruzados sin permiso explícito.";
        }
        return L"";
    }

    if (clave == L"Cache-Control") {
        if (v.find(L"no-store") == std::wstring::npos && v.find(L"no-cache") == std::wstring::npos &&
            v.find(L"private") == std::wstring::npos && v.find(L"must-revalidate") == std::wstring::npos) {
            penalizacion = 0;   // Informativa: no resta nota
            return L"Permite almacenar la respuesta en caché; revísalo si sirve contenido sensible.";
        }
        return L"";
    }

    return L"";
}

Chequeo EvaluarCabecera(const CabeceraMeta& meta, const ResultadoPeticion& resp) {
    Chequeo c;
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

Chequeo EvaluarCookies(const ResultadoPeticion& resp) {
    Chequeo c;
    c.id = L"cookies";
    c.nombre = L"Cookies seguras (Secure / HttpOnly / SameSite)";
    c.desc = L"Impide que las cookies viajen sin cifrar, sean leídas por JavaScript o se envíen en peticiones cruzadas.";
    c.criticidad = L"ALTA";
    c.peso = 3;

    std::vector<std::wstring> galletas = TodasLasCabeceras(resp.cabeceras, L"Set-Cookie");
    if (galletas.empty()) {
        c.aplicable = false;
        c.presente = true;
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
            if (primero) { primero = false; continue; }   // "nombre=valor"
            if (atributo == L"secure") secure = true;
            else if (atributo == L"httponly") httpOnly = true;
            else if (atributo.rfind(L"samesite", 0) == 0) sameSite = true;
        }
        if (!secure) sinSecure++;
        if (!httpOnly) sinHttpOnly++;
        if (!sameSite) sinSameSite++;
    }

    if (sinSecure > 0)   c.penalizacion = std::max(c.penalizacion, 60);
    if (sinHttpOnly > 0) c.penalizacion = std::max(c.penalizacion, 50);
    if (sinSameSite > 0) c.penalizacion = std::max(c.penalizacion, 25);

    wchar_t valor[256];
    swprintf_s(valor, L"%zu cookies | sin Secure: %d | sin HttpOnly: %d | sin SameSite: %d",
               galletas.size(), sinSecure, sinHttpOnly, sinSameSite);
    c.valor = valor;
    c.presente = (c.penalizacion == 0);

    if (sinSecure > 0)
        c.aviso = L"Hay cookies que se enviarían también por HTTP sin cifrar.";
    else if (sinHttpOnly > 0)
        c.aviso = L"Hay cookies legibles desde JavaScript (riesgo si existe XSS).";
    else if (sinSameSite > 0)
        c.aviso = L"Hay cookies sin SameSite; pueden viajar en peticiones de otros sitios (CSRF).";

    return c;
}

Chequeo EvaluarCors(const ResultadoPeticion& resp) {
    Chequeo c;
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
        c.valor = L"No se envía cabecera Access-Control-Allow-Origin";
        return c;
    }

    std::wstring cred = Minusculas(Trim(credenciales));
    c.valor = L"Access-Control-Allow-Origin: " + origen;
    if (tieneCredenciales) c.valor += L" | Credenciales: " + (credenciales.empty() ? L"?" : credenciales);

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

// ----------------------------------------------------------------------------
// Composición y resolución de URLs (redirecciones relativas)
// ----------------------------------------------------------------------------
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

// Resuelve "." y ".." en una ruta absoluta.
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

// Convierte una cabecera Location (absoluta o relativa) en una URL absoluta correcta.
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

    // "//otrohost/ruta" -> conserva el esquema actual
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

    // Ruta relativa: se resuelve contra el directorio del documento actual.
    std::wstring directorio(ruta);
    size_t barra = directorio.find_last_of(L'/');
    directorio = (barra == std::wstring::npos) ? L"/" : directorio.substr(0, barra + 1);
    return origen + NormalizarRuta(directorio + loc);
}

// ----------------------------------------------------------------------------
// Mensajes de error de WinHTTP
// ----------------------------------------------------------------------------
void ClasificarError(DWORD codigo, ResultadoPeticion& r) {
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
        case ERROR_WINHTTP_REDIRECT_FAILED:
            r.errorCodigo = L"conexion";
            r.errorMensaje = L"El servidor ha cerrado la conexión inesperadamente.";
            break;
        default:
            r.errorCodigo = L"red";
            {
                wchar_t buf[256] = { 0 };
                swprintf_s(buf, L"No se pudo completar la petición HTTP (código WinHTTP %lu).", (unsigned long)codigo);
                r.errorMensaje = buf;
            }
            break;
    }
}

// Consulta una cabecera completa (sin límite fijo de tamaño).
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

// Los nombres de certificado llegan en varias líneas (US\r\nLet's Encrypt\r\nYE1).
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

std::wstring FechaCorta(const FILETIME& ft) {
    SYSTEMTIME st = { 0 };
    if (!FileTimeToSystemTime(&ft, &st)) return L"";
    wchar_t buf[32];
    swprintf_s(buf, L"%02d/%02d/%04d", st.wDay, st.wMonth, st.wYear);
    return buf;
}

void ObtenerInfoTls(HINTERNET hRequest, ResultadoPeticion& r) {
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

// ----------------------------------------------------------------------------
// Detección de la versión de TLS
// ----------------------------------------------------------------------------
// WinHTTP no informa de la versión negociada, así que se repite el saludo
// restringiendo los protocolos permitidos: la versión más alta que acepte el
// servidor es la que realmente se negocia.
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
    if (HandshakeConProtocolo(url, PROTOCOLO_TLS1_3))      version = L"TLS 1.3";
    else if (HandshakeConProtocolo(url, WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2)) version = L"TLS 1.2";
    else if (HandshakeConProtocolo(url, WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_1)) version = L"TLS 1.1";
    else if (HandshakeConProtocolo(url, WINHTTP_FLAG_SECURE_PROTOCOL_TLS1))   version = L"TLS 1.0";
    else version = L"desconocido";

    // ¿Sigue aceptando protocolos obsoletos aunque negocie uno moderno?
    aceptaObsoleto = HandshakeConProtocolo(url, WINHTTP_FLAG_SECURE_PROTOCOL_TLS1 |
                                                WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_1);
    return version;
}

// Cuando WinHTTP rechaza el certificado solo informa de "SECURE_FAILURE".
// Se repite la petición ignorando los errores de certificado para poder
// describir el problema real (caducado, emisor desconocido, etc.).
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
        ResultadoPeticion diag;
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

// ----------------------------------------------------------------------------
// Petición HTTP con seguimiento de redirecciones
// ----------------------------------------------------------------------------
void ClasificarFallo(DWORD codigo, HINTERNET hSession, const std::wstring& url, ResultadoPeticion& r) {
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

bool HacerPeticion(HINTERNET hSession, const std::wstring& urlInicial, int maxRedirecciones, ResultadoPeticion& r) {
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

        // Las redirecciones se resuelven en este código para poder informar de la URL final.
        DWORD politica = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_REDIRECT_POLICY, &politica, sizeof(politica));

        // User-Agent de navegador normal: algunos servidores bloquean clientes desconocidos.
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

        // Redirección: se resuelve y se repite la petición sobre la nueva URL.
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
            // Sin Location se trata como respuesta final.
        }

        // Cabeceras crudas de la respuesta final
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

// ----------------------------------------------------------------------------
// Comprobaciones de transporte: TLS y redirección HTTP -> HTTPS
// ----------------------------------------------------------------------------
Chequeo EvaluarTls(const ResultadoPeticion& resp) {
    Chequeo c;
    c.id = L"tls";
    c.nombre = L"Cifrado TLS y validez del certificado";
    c.desc = L"Evalúa la versión de TLS negociada, si se admiten versiones obsoletas y los días que le quedan al certificado.";
    c.criticidad = L"CRÍTICA";
    c.peso = 4;

    if (!resp.https) {
        c.aplicable = false;
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
        c.penalizacion = std::max(c.penalizacion, 30);
        avisos.push_back(L"El servidor completa el saludo TLS 1.0/1.1; debería rechazar versiones obsoletas.");
    }
    if (resp.diasCertificado >= 0 && resp.diasCertificado < 30) {
        c.penalizacion = std::max(c.penalizacion, resp.diasCertificado < 7 ? 80 : 40);
        avisos.push_back(L"El certificado caduca en menos de 30 días.");
    }

    std::wstring valor = L"Protocolo: " + protocolo;
    if (resp.diasCertificado >= 0) {
        valor += L" | Certificado válido " + std::to_wstring(resp.diasCertificado) + L" días más";
    }
    if (!resp.emisorTls.empty()) valor += L" | Emisor: " + resp.emisorTls;
    if (resp.aceptaTlsObsoleto) valor += L" | Acepta TLS 1.0/1.1";
    c.valor = valor;
    c.presente = (c.penalizacion == 0);

    for (size_t i = 0; i < avisos.size(); ++i) {
        if (i) c.aviso += L" ";
        c.aviso += avisos[i];
    }
    return c;
}

Chequeo EvaluarRedireccionHttps(HINTERNET hSession, const ResultadoPeticion& resp) {
    Chequeo c;
    c.id = L"https";
    c.nombre = L"HTTPS obligatorio (redirección desde HTTP)";
    c.desc = L"Comprueba que el sitio no sirve contenido por HTTP sin cifrar y que redirige a HTTPS.";
    c.criticidad = L"CRÍTICA";
    c.peso = 4;

    // Si el usuario pidió HTTP y la respuesta final sigue siendo HTTP, el fallo es directo.
    if (!resp.https) {
        c.presente = false;
        c.penalizacion = 100;
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
        c.valor = L"No se puede comprobar: el sitio usa un puerto HTTPS no estándar";
        return c;
    }

    std::wstring rutaHttp = std::wstring(ruta) + (uc.lpszExtraInfo ? uc.lpszExtraInfo : L"");
    std::wstring urlHttp = L"http://" + std::wstring(host) + L":" + std::to_wstring(INTERNET_DEFAULT_HTTP_PORT) + rutaHttp;

    ResultadoPeticion sonda;
    if (!HacerPeticion(hSession, urlHttp, 0, sonda)) {
        // Si el puerto 80 no responde, el contenido solo se puede servir por HTTPS: correcto.
        if (sonda.errorCodigo == L"conexion" || sonda.errorCodigo == L"dns" || sonda.errorCodigo == L"timeout") {
            c.presente = true;
            c.valor = L"El puerto 80 no responde: solo se sirve contenido por HTTPS";
            return c;
        }
        c.presente = false;
        c.penalizacion = 40;
        c.valor = L"No se pudo comprobar la versión HTTP del sitio";
        c.aviso = sonda.errorMensaje;
        return c;
    }

    std::wstring ubicacion, valorUbicacion;
    if (TieneCabecera(sonda.cabeceras, L"Location", ubicacion)) valorUbicacion = ubicacion;

    if (sonda.status >= 300 && sonda.status < 400) {
        if (Minusculas(valorUbicacion).rfind(L"https://", 0) == 0) {
            c.presente = true;
            c.valor = L"HTTP responde " + std::to_wstring(sonda.status) + L" y redirige a " + valorUbicacion;
            return c;
        }
        c.presente = false;
        c.penalizacion = 60;
        c.valor = L"HTTP responde " + std::to_wstring(sonda.status) + L" y redirige a " + valorUbicacion;
        c.aviso = L"La redirección no lleva a HTTPS.";
        return c;
    }

    if (sonda.status >= 400) {
        // El servidor rechaza la petición HTTP (bloqueo de bots, WAF...): no se puede concluir nada.
        c.aplicable = false;
        c.presente = true;
        c.valor = L"HTTP responde " + std::to_wstring(sonda.status) + L"; no se puede determinar si redirige";
        return c;
    }

    c.presente = false;
    c.penalizacion = 100;
    c.valor = L"HTTP responde " + std::to_wstring(sonda.status) + L" sin redirigir a HTTPS";
    c.aviso = L"El contenido también se sirve sin cifrar; fuerza la redirección a HTTPS.";
    return c;
}

// ----------------------------------------------------------------------------
// Salida JSON
// ----------------------------------------------------------------------------
void ImprimirError(const ResultadoPeticion& r, const std::wstring& url) {
    std::wstringstream js;
    js << L"{\n";
    js << L"  \"ok\": false,\n";
    js << L"  \"url\": \"" << EscaparJson(r.urlFinal.empty() ? url : r.urlFinal) << L"\",\n";
    js << L"  \"error\": \"" << EscaparJson(r.errorCodigo.empty() ? L"desconocido" : r.errorCodigo) << L"\",\n";
    js << L"  \"status_code\": " << r.status << L",\n";
    js << L"  \"mensaje\": \"" << EscaparJson(r.errorMensaje.empty() ? L"No se pudo completar la auditoría." : r.errorMensaje) << L"\"\n";
    js << L"}\n";
    wprintf(L"%s", js.str().c_str());
}

int wmain(int argc, wchar_t* argv[]) {
    _setmode(_fileno(stdout), _O_U8TEXT);

    std::wstring urlStr = (argc > 1) ? Trim(argv[1]) : L"https://www.example.com";

    if (urlStr.empty() || (Minusculas(urlStr).rfind(L"http://", 0) != 0 &&
                           Minusculas(urlStr).rfind(L"https://", 0) != 0)) {
        ResultadoPeticion r;
        r.errorCodigo = L"url";
        r.errorMensaje = L"La dirección debe empezar por http:// o https://.";
        ImprimirError(r, urlStr);
        return 2;
    }

    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AuditorSeguridadWeb/4.0",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        hSession = WinHttpOpen(L"AuditorSeguridadWeb/4.0", WINHTTP_ACCESS_TYPE_NO_PROXY,
                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    }
    if (!hSession) {
        ResultadoPeticion r;
        r.errorCodigo = L"red";
        r.errorMensaje = L"No se pudo inicializar el motor HTTP del sistema.";
        ImprimirError(r, urlStr);
        return 2;
    }
    WinHttpSetTimeouts(hSession, 8000, 8000, 8000, 12000);

    ResultadoPeticion resp;
    if (!HacerPeticion(hSession, urlStr, 5, resp)) {
        ImprimirError(resp, urlStr);
        WinHttpCloseHandle(hSession);
        return 2;
    }

    if (resp.status < 200 || resp.status >= 400) {
        ResultadoPeticion err = resp;
        err.errorCodigo = L"http";
        std::wstring razon = resp.razon.empty() ? L"Sin descripción" : resp.razon;
        wchar_t buf[512];
        swprintf_s(buf, L"El servidor respondió HTTP %d (%s). Comprueba que la dirección exista.",
                   resp.status, razon.c_str());
        err.errorMensaje = buf;
        ImprimirError(err, urlStr);
        WinHttpCloseHandle(hSession);
        return 2;
    }

    // Servidor / proxy
    std::wstring servidor = L"Oculto / Protegido", valorServer;
    if (TieneCabecera(resp.cabeceras, L"Server", valorServer) && !valorServer.empty()) servidor = valorServer;

    // Versión real de TLS (requiere repetición del saludo con protocolos restringidos).
    if (resp.https) resp.protocoloTls = DetectarProtocolo(resp.urlFinal, resp.aceptaTlsObsoleto);

    // Comprobaciones: primero transporte, después cabeceras y por último cookies/CORS.
    std::vector<Chequeo> comprobaciones;
    comprobaciones.push_back(EvaluarRedireccionHttps(hSession, resp));
    comprobaciones.push_back(EvaluarTls(resp));
    for (const auto& meta : g_cabecerasAEvaluar) comprobaciones.push_back(EvaluarCabecera(meta, resp));
    comprobaciones.push_back(EvaluarCookies(resp));
    comprobaciones.push_back(EvaluarCors(resp));

    int presentes = 0, aplicables = 0;
    double puntos = 0.0, puntosMax = 0.0;
    for (const auto& c : comprobaciones) {
        if (!c.aplicable || c.peso <= 0) continue;
        aplicables++;
        if (c.presente && c.penalizacion < 60) presentes++;
        double calidad = c.presente ? (1.0 - (c.penalizacion / 100.0)) : 0.0;
        if (calidad < 0.0) calidad = 0.0;
        puntos += c.peso * calidad;
        puntosMax += c.peso;
    }

    std::wstringstream jsonOut;
    jsonOut << L"{\n";
    jsonOut << L"  \"ok\": true,\n";
    jsonOut << L"  \"motor\": \"WinHTTP 4.0\",\n";
    jsonOut << L"  \"url\": \"" << EscaparJson(resp.urlFinal) << L"\",\n";
    jsonOut << L"  \"url_solicitada\": \"" << EscaparJson(urlStr) << L"\",\n";
    jsonOut << L"  \"status_code\": " << resp.status << L",\n";
    jsonOut << L"  \"reason\": \"" << EscaparJson(resp.razon) << L"\",\n";
    jsonOut << L"  \"server\": \"" << EscaparJson(servidor) << L"\",\n";
    jsonOut << L"  \"https\": " << (resp.https ? L"true" : L"false") << L",\n";
    jsonOut << L"  \"tls_protocolo\": \"" << EscaparJson(resp.protocoloTls) << L"\",\n";
    jsonOut << L"  \"tls_dias_certificado\": " << resp.diasCertificado << L",\n";
    jsonOut << L"  \"presentes\": " << presentes << L",\n";
    jsonOut << L"  \"aplicables\": " << aplicables << L",\n";
    jsonOut << L"  \"total\": " << (int)comprobaciones.size() << L",\n";
    jsonOut << L"  \"puntos\": " << puntos << L",\n";
    jsonOut << L"  \"puntos_max\": " << puntosMax << L",\n";
    jsonOut << L"  \"evaluacion\": [\n";

    for (size_t i = 0; i < comprobaciones.size(); ++i) {
        const auto& c = comprobaciones[i];
        jsonOut << L"    {\n";
        jsonOut << L"      \"id\": \"" << EscaparJson(c.id) << L"\",\n";
        jsonOut << L"      \"header\": \"" << EscaparJson(c.clave) << L"\",\n";
        jsonOut << L"      \"nombre\": \"" << EscaparJson(c.nombre) << L"\",\n";
        jsonOut << L"      \"desc\": \"" << EscaparJson(c.desc) << L"\",\n";
        jsonOut << L"      \"criticidad\": \"" << EscaparJson(c.criticidad) << L"\",\n";
        jsonOut << L"      \"peso\": " << c.peso << L",\n";
        jsonOut << L"      \"aplicable\": " << (c.aplicable ? L"true" : L"false") << L",\n";
        jsonOut << L"      \"presente\": " << (c.presente ? L"true" : L"false") << L",\n";
        jsonOut << L"      \"penalizacion\": " << c.penalizacion << L",\n";
        jsonOut << L"      \"valor\": \"" << EscaparJson(c.valor) << L"\",\n";
        jsonOut << L"      \"aviso\": \"" << EscaparJson(c.aviso) << L"\"\n";
        jsonOut << L"    }" << (i + 1 < comprobaciones.size() ? L"," : L"") << L"\n";
    }
    jsonOut << L"  ]\n";
    jsonOut << L"}\n";

    wprintf(L"%s", jsonOut.str().c_str());
    WinHttpCloseHandle(hSession);
    return 0;
}
