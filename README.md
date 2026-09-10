# Análisis de Seguridad de APK No Oficial (Magis TV) — Enfoque SOC

Análisis estático y dinámico de una muestra Android de distribución no oficial,
documentado con enfoque de Threat Analysis / Blue Team: extracción de IOCs,
mapeo a MITRE ATT&CK y una regla de detección derivada de los hallazgos.

> ⚠️ Este análisis se realizó en un entorno aislado (sandbox) por motivos
> académicos. La muestra analizada es conocida por distribuir contenido
> protegido y está asociada a riesgos de malware. No se recomienda su
> instalación fuera de un entorno controlado.

## Objetivo

Simular el flujo de trabajo de un analista SOC Tier 1/2 frente a una muestra
sospechosa: triage inicial, análisis estático, análisis dinámico, correlación
con inteligencia de amenazas (VirusTotal, MobSF) y traducción de hallazgos en
una detección accionable.

## Entorno de análisis

- **Kali Linux (VM)** — herramientas de análisis estático y dinámico
- **Genymotion Android (VM)** — dispositivo de prueba
- Ambas VMs en red **Host-Only** (`VirtualBox Host-Only Ethernet Adapter #2`), sin salida a la red real, para
  evitar propagación de la muestra fuera del sandbox

## Estructura del repositorio

docs/ Informes: análisis estático, dinámico, IOCs, conclusión
evidence/ Capturas de pantalla organizadas por fase
detections/ Reglas de detección derivadas del análisis (YARA/Suricata)

## Descargo de responsabilidad

Proyecto con fines exclusivamente educativos, realizado en el marco de la
asignatura *Seguridad de la Información* — Universidad Jorge Tadeo Lozano.
No se distribuye la muestra analizada.
