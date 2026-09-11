# 03 — Análisis Dinámico

## Objetivo de esta fase

Ejecutar la muestra en un entorno controlado (emulador Android aislado) e
interceptar su tráfico de red real con Burp Suite, para revelar
comportamiento que el análisis estático no pudo mostrar (recordar que no se
encontraron endpoints en texto plano — ver `02-analisis-estatico.md`).

## Configuración del entorno de intercepción

- **Proxy:** Burp Suite en Kali Linux, listener configurado en todas las
  interfaces (`*:8080`) para aceptar conexiones desde el emulador.
- **Emulador:** se intentó en dos plataformas distintas para descartar
  problemas específicos de una sola herramienta:
  1. **Genymotion** (Android 9, x86) + parche comunitario de ARM Translation
  2. **Android Studio Emulator** (Android 12, x86_64) con Google Play Store
     y traductor de instrucciones ARM oficial de Google

## Instalación y primer intento de ejecución

```bash
adb install magistv.apk
# Success
```

La app se instaló correctamente en ambos entornos. Al intentar abrirla:

**En Genymotion:** la app entra en un bucle de reinicio constante
(crash loop, reinicio cada ~70ms), sin llegar a mostrar interfaz.

**En Android Studio Emulator:** la app sí alcanza a mostrar el splash
screen (logo), pero luego crashea repetidamente en la misma actividad.

## Diagnóstico con logcat

```bash
adb logcat -d | grep -i "fatal signal"
```

**Resultado en Genymotion:**
```
F libc: Fatal signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x1c in tid 11795 (sandroid.mobile), pid 11779
```

**Resultado en Android Studio Emulator:**
```
F libc: Fatal signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x20 in tid 12138 (Thread-2), pid 12120 (sandroid.mobile)
```

El patrón se repite consistentemente en cada reinicio del proceso, siempre
fallando en un hilo secundario llamado **`Thread-2`**, con una dirección de
memoria casi nula (`0x1c` / `0x20`) — típico de un puntero nulo o de una
comprobación deliberada que fuerza un fallo de acceso a memoria.

## Interpretación del hallazgo

El mismo tipo de fallo (`SIGSEGV` en `Thread-2`) ocurre en **dos motores de
traducción de instrucciones ARM completamente independientes**:
- El parche comunitario usado por Genymotion
- El traductor oficial de Google integrado en Android Studio Emulator

Que ambos sistemas, desarrollados de forma independiente, fallen de forma
casi idéntica en el mismo punto es estadísticamente significativo. Esto hace
poco probable que se trate de una simple incompatibilidad de instrucciones, y
refuerza la hipótesis planteada en el análisis estático: el módulo nativo
ofuscado (identificado como paquete `s.h.e.l.l` — ver `02-analisis-estatico.md`)
probablemente **detecta activamente que se ejecuta en un entorno emulado o
traducido** (mediante comprobaciones de CPU, timing, o artefactos del
hipervisor) y **fuerza un fallo deliberado en un hilo dedicado (`Thread-2`)**
como mecanismo de evasión de análisis, en lugar de simplemente no ser
compatible con la traducción de instrucciones.

Este comportamiento se clasifica bajo la técnica **MITRE ATT&CK for Mobile
T1633 — Virtualization/Sandbox Evasion**, documentada formalmente en
`05-iocs-mitre.md`.

## Limitación del laboratorio

Debido a este mecanismo de evasión, no fue posible capturar tráfico de red
en vivo generado por la aplicación (el proxy y Burp Suite se configuraron
correctamente y funcionan, como se verificó con tráfico de control de Google
Play — ver captura de referencia). Esta limitación es en sí misma un
resultado del análisis: confirma la sofisticación del mecanismo de protección
del binario frente a entornos de sandboxing, un indicador de riesgo adicional
más allá del ya identificado en la fase de triage y análisis estático.

Siguiente: [`04-mobsf.md`](04-mobsf.md) — análisis automatizado con
Mobile Security Framework (MobSF), que emplea técnicas adicionales
(incluyendo instrumentación con Frida) para intentar sortear este tipo de
protecciones.
