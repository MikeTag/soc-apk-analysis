# 02 — Análisis Estático

## Objetivo de esta fase

Inspeccionar el contenido del APK sin ejecutarlo: estructura interna,
permisos declarados y, más adelante, el código descompilado.

## Desempaquetado con apktool

```bash
cd ~/analisis_magis
apktool d magistv.apk -o magis_desempaquetado
```

El comando extrae los recursos, el `AndroidManifest.xml` en formato legible
y el código en formato *smali* (representación intermedia del bytecode
Dalvik), sin necesidad de tener el código fuente original.

## Permisos declarados (AndroidManifest.xml)

```bash
cat magis_desempaquetado/AndroidManifest.xml | grep -i "uses-permission"
```

```
android.permission.INTERNET
android.permission.ACCESS_NETWORK_STATE
android.permission.CHANGE_NETWORK_STATE
android.permission.ACCESS_WIFI_STATE
android.permission.WRITE_EXTERNAL_STORAGE
android.permission.WAKE_LOCK
android.permission.VIBRATE
android.permission.GET_TASKS
android.permission.CAMERA
android.permission.REQUEST_INSTALL_PACKAGES
android.permission.POST_NOTIFICATIONS
android.permission.MANAGE_EXTERNAL_STORAGE
android.permission.READ_EXTERNAL_STORAGE
android.permission.READ_MEDIA_IMAGES
android.permission.READ_MEDIA_AUDIO
android.permission.CHANGE_WIFI_STATE
com.google.android.c2dm.permission.RECEIVE
com.google.android.gms.permission.AD_ID
com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE
android.permission.CHANGE_WIFI_MULTICAST_STATE
android.permission.BLUETOOTH
com.huawei.android.launcher.permission.CHANGE_BADGE
com.vivo.notification.permission.BADGE_ICON
```

## Análisis de permisos de riesgo

| Permiso | Riesgo | Justificación |
|---|---|---|
| `REQUEST_INSTALL_PACKAGES` | 🔴 Alto | Permite instalar otros APKs sin pasar por Play Store — patrón común en *droppers* que despliegan componentes adicionales tras la instalación inicial. |
| `CAMERA` | 🟠 Medio-Alto | Sin justificación funcional aparente en una app de streaming. Posible fingerprinting del dispositivo o sobre-solicitud de permisos. |
| `MANAGE_EXTERNAL_STORAGE` | 🟠 Medio | Acceso amplio a todo el almacenamiento del dispositivo, más allá del acceso segmentado (`READ/WRITE_EXTERNAL_STORAGE`). |
| `GET_TASKS` | 🟠 Medio | Permiso deprecado en versiones modernas de Android por su historial de abuso para monitorear qué apps tiene abiertas el usuario. |
| `com.google.android.gms.permission.AD_ID` | 🟡 Bajo-Medio | Confirma el uso de identificador de publicidad, consistente con el veredicto `AdLibrary:Generisk` de VirusTotal (fase de triage). |
| `BIND_GET_INSTALL_REFERRER_SERVICE` | 🟡 Bajo | Rastrea el origen de instalación; típico de SDKs de tracking/publicidad agresivos. |

## Discrepancia a investigar

VirusTotal etiquetó la muestra con el tag `checks-gps`, pero el manifest **no**
declara `ACCESS_FINE_LOCATION` ni `ACCESS_COARSE_LOCATION`. Esto sugiere que la
app podría estimar la ubicación por medios indirectos (geolocalización por IP
en las peticiones de red) en vez de por GPS del dispositivo — se validará en
el análisis dinámico (`03-analisis-dinamico.md`) revisando el tráfico
capturado en Burp Suite.

## Descompilación con jadx

```bash
jadx /home/kali/analisis_magis/magistv.apk -d /home/kali/analisis_magis/magis_jadx
```

El proceso terminó con 1 error de descompilación (clases que jadx no pudo
reconstruir a Java), algo común en apps con ofuscación agresiva o secciones
cifradas — no impide continuar el análisis con el resto del código.

## Evidencia de ofuscación deliberada

```bash
ls /home/kali/analisis_magis/magis_jadx/sources/
```
```
android  androidx  com  kotlin  s
```

El paquete `s` (una sola letra) se desglosa en:
```bash
find /home/kali/analisis_magis/magis_jadx/sources/s/h -type f
```
```
s/h/e/l/l/N.java
s/h/e/l/l/A.java
s/h/e/l/l/S.java
s/h/e/l/l/C.java
```

**Hallazgo relevante:** la ruta de carpetas `s → h → e → l → l` deletrea
literalmente **"SHELL"**, con clases nombradas con una sola letra (`N`, `A`,
`S`, `C`). Esta es una técnica deliberada de ofuscación para ocultar la
identidad de un módulo — el nombre "shell" en este contexto sugiere un
componente de tipo *loader/packer*, cuya función típica es descifrar y
ejecutar código adicional en tiempo de ejecución.

## Confirmación de librería de publicidad (AdMob)

```bash
find /home/kali/analisis_magis/magis_jadx -iname "*ads*" -o -iname "*advert*" -o -iname "*admob*"
```
```
resources/play-services-ads-identifier.properties
resources/res/drawable/bg_admob_native_ad.xml
```

Confirma el uso de **Google AdMob**, consistente con el veredicto
`AdLibrary:Generisk` obtenido en VirusTotal (fase de triage).

## Búsqueda de URLs embebidas

```bash
grep -rEho "https?://[a-zA-Z0-9./?=_%:-]*" /home/kali/analisis_magis/magis_jadx/resources/ | sort -u
strings /home/kali/analisis_magis/magistv.apk | grep -Eo "https?://[a-zA-Z0-9./?=_%:-]*" | sort -u
```

Solo aparecen URLs legítimas de documentación técnica (esquemas de Android,
Google, Apache License) y un enlace de soporte de Chromecast. **No se
encontraron endpoints propios en texto plano** — consistente con la hipótesis
del módulo "shell": las URLs de control probablemente están cifradas dentro
de los binarios nativos y solo se revelan en tiempo de ejecución (por eso el
análisis dinámico, en el siguiente documento, es indispensable).

## Librerías nativas (.so)

```bash
find /home/kali/analisis_magis/magis_desempaquetado -iname "*.so"
```

| Librería | Función esperada | Evaluación |
|---|---|---|
| `libijkplayer.so`, `libijksdl.so`, `libijkffmpeg.so` | Reproductor de video (FFmpeg) | ✅ Normal para app de streaming |
| `libcrashlytics*.so` | Reporte de errores (Firebase) | ✅ Normal |
| `libcast-jni.so` | Soporte Chromecast | ✅ Normal |
| `libc++_shared.so`, `librsjni*.so` | Librerías de soporte estándar | ✅ Normal |
| **`libexec.so`, `libexecmain.so`, `libexec_x86.so`, `libexecmain_x86.so`** | Nombre sugiere ejecución de código | 🔴 Sospechoso — coincide con el patrón "shell/loader" hallado en el código Java |
| **`libumeng-spy.so`** | SDK de analítica/push (Umeng, origen chino) | 🟠 Tracking adicional no declarado explícitamente al usuario |
| `libed25519.so` | Librería de firma criptográfica | 🟡 Uso no confirmado — posible verificación de licencia/comunicación con servidor propio |

## Conclusión del análisis estático

La evidencia combinada (paquete ofuscado deletreando "SHELL", binarios
nativos con nombres relacionados a ejecución de código, y ausencia de
endpoints en texto plano) apunta a una **arquitectura de tipo packer/loader**,
cuyo propósito habitual es dificultar el análisis estático y cargar
comportamiento adicional únicamente en tiempo de ejecución. Esto se relaciona
con la técnica **T1406 / T1027.002 (Obfuscated Files or Information /
Software Packing)** de MITRE ATT&CK for Mobile — se documentará formalmente
en `05-iocs-mitre.md`.

Siguiente: [`03-analisis-dinamico.md`](03-analisis-dinamico.md) — ejecutar
la muestra en el emulador aislado e interceptar su tráfico real con Burp
Suite para revelar los endpoints que el análisis estático no pudo mostrar.
