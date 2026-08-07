# Ransomware Writeups

Análisis y resolución de retos de identificación y respuesta ante ransomware, incluyendo triage de muestras, correlación de IOCs y análisis estático de binarios.

> ⚠️ **Disclaimer**: Todo el análisis se realiza en entornos aislados (máquinas virtuales) con fines exclusivamente educativos y de investigación. No se distribuyen binarios ni muestras de malware en este repositorio, únicamente hashes, IOCs y análisis propio.

## Índice

| Reto | Familia | Técnica principal | Estado |
|------|---------|-------------------|--------|
| [WannaCry](./wannacry) | WannaCry | Identificación de familia, análisis estático (IDA), OSINT sobre IOCs | ✅ Resuelto |

## Metodología general

Para cada muestra se sigue, cuando aplica, el siguiente flujo:

1. **Triage inicial** — hash (MD5/SHA256), consulta en VirusTotal.
2. **Identificación de familia** — herramientas como [ID Ransomware](https://id-ransomware.malwarehunterteam.com/) y [NoMoreRansom](https://www.nomoreransom.org/).
3. **Análisis estático** — desensamblado con IDA, extracción de strings, IOCs y dominios/C2 embebidos.
4. **Correlación con recursos públicos** — comprobación de disponibilidad de descifrador, mapeo a MITRE ATT&CK.

## Herramientas utilizadas

- IDA Free
- VirusTotal
- ID Ransomware
- NoMoreRansom
