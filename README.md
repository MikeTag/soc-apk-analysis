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
- Ambas VMs en red **Host-Only** (`VirtualBox Host-Only Ethernet Adapter #2`),
  sin salida a la red real, para evitar propagación de la muestra fuera del
  sandbox

## Estructura del repositorio

```
docs/         Informes: análisis estático, dinámico, IOCs, conclusión
evidence/     Capturas de pantalla organizadas por fase
detections/   Reglas de detección derivadas del análisis (YARA/Suricata)
```

## Índice de documentos

- [`docs/01-triage.md`](docs/01-triage.md) — Hash y verificación en VirusTotal
- [`docs/02-analisis-estatico.md`](docs/02-analisis-estatico.md) — Permisos, código, cadenas
- [`docs/03-analisis-dinamico.md`](docs/03-analisis-dinamico.md) — Tráfico de red, logcat
- [`docs/04-mobsf.md`](docs/04-mobsf.md) — Validación automatizada
- [`docs/05-iocs-mitre.md`](docs/05-iocs-mitre.md) — IOCs y mapeo MITRE ATT&CK
- [`docs/06-conclusion.md`](docs/06-conclusion.md) — Veredicto técnico final

## Detecciones

- [`detections/`](detections/) — Regla YARA basada en los indicadores encontrados

## Descargo de responsabilidad

Proyecto con fines exclusivamente educativos, realizado en el marco de la
asignatura *Seguridad de la Información* — Universidad Jorge Tadeo Lozano.
No se distribuye la muestra analizada.

## Nota sobre el uso de IA

Este proyecto se desarrolló con el apoyo de Claude (Anthropic) como asistente
técnico durante el proceso. Su uso se concentró en:
- Guía en la configuración del entorno (ARM Translation, MobSF)
- Ayuda en la interpretación de hallazgos técnicos (APKiD, permisos, MITRE ATT&CK)
- Estructuración de la documentación
- Elaboración de la regla YARA a partir de los IOCs identificados

La ejecución de las herramientas, la toma de decisiones sobre qué investigar
en cada fase, y la validación de los resultados (incluyendo la confirmación
cruzada con el sandbox Triage) fueron realizadas y verificadas por el autor.
