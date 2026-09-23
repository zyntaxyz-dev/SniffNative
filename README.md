# SniffNative (tweak iOS) — P4

Observador a nivel nativo con el mismo propósito que el SNIFF Lua, pero donde
Lua no llega: qué endpoints HTTP toca el juego, qué lee como HWID, qué rutas
husmea (jailbreak/entorno) y **qué clases trae el framework de seguridad
(anogs)** en runtime. Todo log+forward; cero bypass, cero bloqueos.

## Estado
- Fuente lista (`Tweak.x`, ~150 líneas). **NO compilado**: en este entorno
  (Windows) no hay toolchain iOS. Se compila en macOS con theos.
- v1 a propósito sin C-hooks (sin substrate en sideload): solo ObjC runtime
  + hooks ObjC. v2 (tras analizar la IPA y el log v1) engancharía métodos
  concretos de anogs con fishhook/Logos.

## Qué aporta vs el SNIFF Lua (directo y complementario)
| SNIFF Lua (PAK) | SniffNative (dylib) |
|---|---|
| Nombres de paquetes juego↔servidor | URLs/cuerpos HTTP reales (tencent, wetest, Bugly, cloud) |
| `ban_info_notify`, TSS-IN | Clases/métodos del framework anogs en runtime (= targets v2) |
| Telemetría UE4 | Fuentes de HWID que lee el juego (IDFV, pasteboard, IDFA) |
| Estable con 1-3 wraps | Chequeos de entorno (rutas jailbreak/ESign que husmea) |

El tweak NO reemplaza el mod PAK (features van en Lua); lo alimenta con
inteligencia nativa: endpoints para vigilar + nombres exactos de anogs.

## Compilar (macOS)
```
# theos: https://theos.dev/docs/installation-macos
brew install ldid xz  # + Xcode command line tools + iOS SDK via theos
git clone --recursive https://github.com/theos/theos $THEOS
cd tweak-ios && make package
# sale: packages/com.mod.sniffnative_1.0_iphoneos-arm64.deb
# extraer el .dylib: dpkg-deb -x <deb> out/  (o ar x + tar)
```

## Inyectar con ESign
1. IPA **desencriptada** (las de App Store traen FairPlay; no sirve cifrada —
   ver `tools/ipa_surface.py`, que reporta `cryptid`).
2. ESign → Apps → Importar IPA → firma con tu certificado.
3. ESign → la app → More/Inject → importar `SniffNative.dylib`
   (o el .deb si tu ESign lo acepta como tweak).
4. Instalar, jugar, recuperar el log: `Documents/sniff_native.log`
   (vía Filza / iTunes File Sharing si la app lo expone / Apple Configurator).

## Leer el log
- `IMAGE [...]` → dónde vive anogs (framework separado o dentro del binario).
- `CLASS ... (+N)` → clases de seguridad con conteo de métodos: de aquí
  salen los hooks v2 (nombres exactos, sin adivinar).
- `HTTP ...` → endpoints de telemetría/detección (cruzar con SNIFF_LOG).
- `HWID ...` → qué identificador usa el juego (guía el FakeHWID).
- `ENV ...` → qué rutas chequea (guía qué ocultar / qué no instalar).

## Límites honestos
- Sin la IPA no hay análisis de anogs todavía (`tools/ipa_surface.py`
  corre en cuanto la pongas en `source-4.6/`).
- Anogs probablemente ofusca/empaqueta su lógica real (los nombres ObjC que
  veamos pueden ser pocos); aun así, URLs + HWID + entorno ya pagan el tweak.
- En sideload sin jailbreak no hay garantías de que todos los hooks
  enganchen (firma/entitlements); el log START + IMAGE lo confirma al arrancar.
