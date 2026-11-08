# Localizaciones del Auditor de Seguridad Web

Un archivo JSON por idioma en esta carpeta. El gestor está en:

- Versión Python: `i18n.py` (se carga al arrancar la interfaz).
- Versión nativa: `L10n` dentro de `auditor.cpp`.

## Idiomas incluidos

| Código | Idioma | Archivo |
|---|---|---|
| `en_US` | English (base y fallback) | `en_US.json` |
| `ar_AR` | العربية | `ar_AR.json` |
| `de_DE` | Deutsch | `de_DE.json` |
| `es_ES` | Español | `es_ES.json` |
| `fr_FR` | Français | `fr_FR.json` |
| `hi_IN` | हिन्दी | `hi_IN.json` |
| `id_ID` | Bahasa Indonesia | `id_ID.json` |
| `it_IT` | Italiano | `it_IT.json` |
| `ja_JP` | 日本語 | `ja_JP.json` |
| `ko_KR` | 한국어 | `ko_KR.json` |
| `pt_BR` | Português (Brasil) | `pt_BR.json` |
| `ru_RU` | Русский | `ru_RU.json` |
| `tr_TR` | Türkçe | `tr_TR.json` |
| `vi_VN` | Tiếng Việt | `vi_VN.json` |
| `zh_CN` | 中文 (简体) | `zh_CN.json` |
| `zh_TW` | 中文 (繁體) | `zh_TW.json` |

El menú **Idioma / Language** se construye leyendo los `*.json` de esta
carpeta: para añadir un idioma basta con crear el archivo (no hay que tocar
código) y reiniciar. En la versión nativa el menú se reconstruye al cambiar de
idioma.

## Formato

Claves estables, nunca el texto traducido como clave:

```json
{
  "Language": "Español",
  "form.analyze": "Analizar Web",
  "status.summary": "Resultado: {ok} de {total} comprobaciones · Nota: {grade} ({pct}% de calidad · {points}/{max} puntos)",
  "check.tls.name": "Cifrado TLS y validez del certificado",
  "aviso.csp.inline": "Permite 'unsafe-inline'; reduce la protección frente a XSS."
}
```

- `Language` es el nombre nativo que aparece en el menú.
- El nombre del archivo es el código de idioma (`es_ES`, `pt_BR`, ...).
- Valores de tipo cadena; no se admiten objetos anidados.
- Codificación UTF-8.

## Fallback

1. Idioma actual.
2. `en_US.json`.
3. La propia clave (y un aviso en la salida de depuración).

Así una traducción incompleta nunca deja un hueco vacío ni rompe la interfaz.

## Placeholders

Entre llaves y por nombre: `{count}`, `{path}`, `{url}`, `{grade}`, `{pct}`,
`{ok}`, `{total}`, `{code}`, `{reason}`, `{seconds}`, `{value}`, `{text}`,
`{version}`, `{author}`, `{email}`, `{copyright}`.

```csharp
L10n::Tr(L"status.analyzing", { { L"url", url } })
Tr("status.analyzing", url=url)
```

No se construyen frases concatenando trozos traducidos.

## Criterio de traducción

Se traducen menús, botones, pestañas, estados, diálogos, mensajes de error,
tooltips, informes PDF/CSV y la ayuda.

No se traducen marcas, nombres de cabecera HTTP (`Strict-Transport-Security`,
`Content-Security-Policy`...), siglas (`HTTP`, `HTTPS`, `TLS`, `CSP`, `HSTS`,
`CORS`, `COOP`, `COEP`, `MIT`) ni los valores que devuelve el servidor.

## Persistencia

La elección se guarda en `%APPDATA%\AuditorSeguridadWeb\settings.json`:

```json
{ "Language": "es_ES" }
```

Es el mismo archivo para las dos versiones, así que el idioma elegido en una se
mantiene en la otra. Al arrancar: preferencia guardada → idioma de Windows →
inglés.

## Cobertura

Traducido en los 16 idiomas:

- Menús, formulario, botones, pestañas y menú de exportación.
- Resumen, estados, criticidades, tarjetas y observaciones.
- Historial (columnas, botones y confirmaciones).
- Diálogos de error, lotes y exportación.
- «Acerca de» y cabeceras del PDF/CSV.

Pendiente de revisión nativa (de momento muestran el texto inglés, que es el
fallback):

- Descripciones largas de cada comprobación (`check.*.desc`).
- Avisos de configuración débil (`aviso.*`).
- Valores de transporte (`value.*`), salvo en español e inglés.
- Texto de la nota al pie del PDF y algunos mensajes secundarios.

Para completarlos, copia el texto inglés de `en_US.json` y sustitúyelo en el
archivo del idioma: no hay que tocar el código.

## Pruebas

- `python tests_auditor.py`: 16 idiomas, nombres nativos, fallback, placeholders
  y persistencia.
- `python tests_auditor_nativo.py`: menú con 16 opciones, cambio en caliente,
  persistencia y análisis desde la interfaz.
