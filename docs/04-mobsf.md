# 04 — Análisis Automatizado (MobSF)

## Objetivo de esta fase

Validar y complementar los hallazgos del análisis manual (estático y
dinámico) utilizando Mobile Security Framework (MobSF), una herramienta
automatizada de referencia en la industria para análisis de seguridad móvil.

## Despliegue

```bash
sudo docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

Acceso vía navegador en `http://localhost:8000`, autenticación con


credenciales por defecto (`mobsf`/`mobsf`), y carga del archivo `magistv.apk`
para análisis estático automatizado.

## Resultados generales

- **Security Score:** 52/100 (riesgo medio)
- **Package Name:** `com.msandroid.mobile` — confirma hallazgo de análisis
  estático manual
- **Min SDK:** 19 (Android 4.4) — soporte a versiones muy antiguas de
  Android, ampliando la superficie de ataque a dispositivos sin parches de
  seguridad recientes
- **Firma del APK:** únicamente esquemas v1 y v2 (sin v3/v4) — esquemas de
  firma más antiguos, potencialmente susceptibles a ataques de manipulación
  conocidos (p. ej. Janus)
- **Componentes exportados:** 2/61 actividades, 2/27 servicios, 2/18
  receivers expuestos a otras apps del dispositivo

## Confirmación cruzada de permisos

La tabla de permisos generada por MobSF coincide con la extraída
manualmente en `02-analisis-estatico.md`. De forma notable, MobSF vincula
automáticamente los permisos `READ_EXTERNAL_STORAGE` y
`WRITE_EXTERNAL_STORAGE` a los archivos `s/h/e/l/l/N.java` y
`s/h/e/l/l/S.java` — confirmando, de forma independiente, que es el módulo
ofuscado "shell" identificado manualmente quien gestiona el acceso a
almacenamiento.

## APKiD — Detección de empaquetado (hallazgo clave)

| Archivo | Hallazgo |
|---|---|
| `magistv.apk` (global) | Manipulator: Resources Confusion · Packer: **Ijiami** |
| `lib/armeabi-v7a/libexec.so` | **dropper, packer** — "UPX packed ELF embedded in ELF" |
| `lib/armeabi-v7a/libexecmain.so`, `libcast-jni.so`, `libranger-jni.so` | Packer: UPX (unknown, modified) |
| `lib/arm64-v8a/libcast-jni.so`, `libcrashlytics-common.so`, `libcrashsdk.so`, `libexec.so`, `libexecmain.so`, `libranger-jni.so` | **anti_hook** (syscalls) |

**Interpretación:** `libexec.so` contiene literalmente un ejecutable ELF
comprimido embebido dentro de otro ELF — el patrón técnico de un *dropper*:
un componente cuyo propósito es desempaquetar y ejecutar código adicional en
tiempo de ejecución, fuera del alcance del análisis estático convencional.
Esto explica por qué no se hallaron URLs ni IPs de C2 en texto plano en las
fases anteriores. El uso adicional del empaquetador comercial **Ijiami**
(de origen chino, legítimo en su uso original pero frecuentemente empleado
para ofuscar comportamiento no deseado) y de comprobaciones **anti_hook**
(detección de instrumentación dinámica, p. ej. Frida/Xposed) confirman un
nivel de sofisticación de evasión deliberado y multicapa.

## Behaviour Analysis

| Regla | Comportamiento | Archivos involucrados |
|---|---|---|
| 00013 | Lee un archivo y lo coloca en un stream | `s/h/e/l/l/N.java`, `s/h/e/l/l/S.java` |
| 00022 | Abre un archivo desde una ruta absoluta | `s/h/e/l/l/A.java`, `s/h/e/l/l/S.java` |

Confirma nuevamente que el módulo "shell" es responsable del manejo de
archivos en tiempo de ejecución — consistente con su rol de dropper/loader.

## URLs y dominios embebidos

Las URLs extraídas corresponden en su totalidad a documentación técnica de
librerías open-source legítimas (FFmpeg, OpenSSL, W3C, Mozilla NSS,
Chromium Crashpad, OASIS). La verificación de reputación de dominios
(**Domain Malware Check**) no arrojó ningún dominio malicioso conocido — 
todos con estado `ok`. La única URL atípica, `https://a` encontrada en
`libexec_x86.so`, es consistente con un placeholder o fragmento de URL
ensamblado dinámicamente en tiempo de ejecución dentro del componente
empaquetado, en lugar de una URL de C2 real y estática.

## Firebase Database Analysis

Se identificó configuración de Firebase asociada a la app:
- **Firebase Project Number:** `18767524675`
- **API Key:** `AIzaSyC-sMwGTAhbysLLyN0Zvdi4M5W8tiZ7P90`
- **Estado:** Remote Config deshabilitado (`NO_TEMPLATE`) — no representa
  una vulnerabilidad explotable en este caso, pero ambos valores constituyen
  IOCs útiles para correlacionar esta muestra con otras variantes de la
  misma familia (recordar los múltiples nombres de marca identificados:
  "MAGIS", "BrasilTV", paquete `com.msandroid.mobile`).

## Trackers Detection: 0/432

MobSF no identificó trackers conocidos pese a que el análisis manual
confirmó el uso de AdMob y Umeng (ver `02-analisis-estatico.md`). Esto es
consistente con el patrón general de la muestra: el empaquetado/ofuscación
dificulta también la detección automatizada basada en firmas, no solo el
análisis manual.

Siguiente: [`05-iocs-mitre.md`](05-iocs-mitre.md) — consolidación de
indicadores de compromiso (IOCs) y mapeo completo a MITRE ATT&CK for Mobile.
