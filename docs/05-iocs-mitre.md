# 05 — Indicadores de Compromiso (IOCs) y Mapeo MITRE ATT&CK

## Objetivo de esta fase

Consolidar en un solo lugar todos los indicadores técnicos recopilados a lo
largo del análisis, y mapear el comportamiento observado al framework
**MITRE ATT&CK for Mobile**, traduciendo el trabajo manual en un formato
estándar de la industria, útil para un equipo de detección (SOC/Threat Intel).

## Indicadores de Compromiso (IOCs)

### Hashes de archivo

| Tipo | Valor |
|---|---|
| MD5 | `97efaf115590b2b00112a7e70c2260b9` |
| SHA1 | `b4787731cc605dc578a51dc880a588ca8fb9dd8a` |
| SHA256 | `5d19f412085b00a44d52a218bea1f2560cd2d5736f2b77ba00424336f923e824` |
| SSDEEP | `786432:aagZ2vA/jrlEZG1VvZ7Koli8TrnJdJVCKfVpKceuz5fqQ4sh:5gZ2IGZG1VdKoli2JbVDpr9z8u` |
| TLSH | `T1388733CBFB3C592ED8B305738D6A9132BA654D008642BB0B2944B72D68733D89F59FC5` |

### Identificadores de aplicación

| Campo | Valor |
|---|---|
| Nombre de archivo original | `MAGIS_6.4.2_1758895072_latestmodapks.com.apk` |
| Package name | `com.msandroid.mobile` |
| Main Activity | `com.mobile.brasiltv.activity.SplashAty` |
| Nombres de marca asociados | MAGIS, BrasilTV, Magis TV |
| Firebase Project Number | `18767524675` |
| Firebase API Key | `AIzaSyC-sMwGTAhbysLLyN0Zvdi4M5W8tiZ7P90` |

### Artefactos de código

| Tipo | Valor |
|---|---|
| Paquete ofuscado (loader/dropper) | `s.h.e.l.l` (clases `A`, `C`, `N`, `S`) |
| Librería nativa dropper | `lib/armeabi-v7a/libexec.so` (ELF empaquetado dentro de ELF, UPX) |
| Empaquetador detectado | Ijiami |
| Librerías con anti-instrumentación | `libcast-jni.so`, `libcrashlytics-common.so`, `libcrashsdk.so`, `libexec.so`, `libexecmain.so`, `libranger-jni.so` |
| Fault address en crash (Genymotion) | `0x1c` |
| Fault address en crash (Android Studio Emulator) | `0x20` |
| Hilo donde ocurre el crash | `Thread-2` |

### Veredictos de terceros

| Fuente | Veredicto |
|---|---|
| VirusTotal | 5/55 — `PUP/Android.Malct` (AhnLab), `Andr/Xgen-BYE` (Sophos, ZoneAlarm), `AdLibrary:Generisk` (Symantec) |
| Triage Sandbox | Score 7/10 — Defense Evasion (T1633.001) |
| MobSF | Security Score 52/100 |

## Mapeo a MITRE ATT&CK for Mobile

| Táctica | Técnica | Evidencia en este análisis |
|---|---|---|
| **Defense Evasion** | T1406 — Obfuscated Files or Information | Paquete Java ofuscado `s.h.e.l.l`, resource confusion detectado por APKiD |
| **Defense Evasion** | T1027.002 — Software Packing | Empaquetador Ijiami + UPX modificado en múltiples `.so`; ELF embebido en `libexec.so` |
| **Defense Evasion** | T1633 / T1633.001 — Virtualization/Sandbox Evasion (System Checks) | Crash reproducible en dos motores de traducción ARM independientes; confirmado externamente por Triage (comprobación de propiedades QEMU y pipes del emulador) |
| **Defense Evasion** | T1628.002 (relacionado) — Anti-instrumentación | Comprobaciones `anti_hook` sobre syscalls detectadas por APKiD en múltiples librerías nativas |
| **Discovery** | T1424 — Process Discovery | Permiso `GET_TASKS`, deprecado precisamente por su uso para enumerar apps en ejecución |
| **Collection** | T1533 (relacionado) — Data from Local System | Permisos amplios de almacenamiento (`MANAGE_EXTERNAL_STORAGE`, `READ/WRITE_EXTERNAL_STORAGE`), gestionados por el propio módulo ofuscado |
| **Impact / Adware** | (fuera de matriz formal, categoría PUP/Adware) | Integración de AdMob + SDK Umeng (analítica/push de origen chino), uso de `AD_ID` |
| **Persistence** (hipótesis, no confirmada) | T1624 — Event Triggered Execution | Permiso `RECEIVE_BOOT_COMPLETED` combinado con `REQUEST_INSTALL_PACKAGES` — capacidad potencial de reinicio/instalación de componentes adicionales; no se pudo confirmar comportamiento en tiempo de ejecución debido a T1633 |

## Limitaciones reconocidas

Debido al mecanismo de evasión de sandbox (T1633) documentado en la Fase 3,
no fue posible capturar tráfico de red en vivo ni observar directamente el
payload que el dropper (`libexec.so`) descomprime en tiempo de ejecución.
El mapeo de **Command and Control** y **Exfiltration** no pudo completarse
con evidencia de primera mano en este laboratorio; se recomienda como
trabajo futuro el uso de un dispositivo físico real (no virtualizado) o
técnicas de unpacking estático dedicadas (fuera del alcance académico de
este ejercicio).

Siguiente: [`06-conclusion.md`](06-conclusion.md) — veredicto técnico
final y prioridad de recomendaciones.
