# 📝 Ransomware Writeups

Análisis y resolución de retos de identificación y respuesta ante ransomware, incluyendo triage de muestras, correlación de IOCs y análisis estático de binarios.

> ⚠️ **Disclaimer**: Todo el análisis se realiza en entornos aislados (máquinas virtuales sin conexión a red de producción) con fines exclusivamente educativos y de investigación. No se distribuyen binarios ni muestras de malware en este repositorio, únicamente hashes, IOCs y análisis propio.

## Índice

| Reto | Familia | Técnica principal | Estado |
|------|---------|-------------------|--------|
| [WannaCry](./wannacry) | WannaCry | Identificación de familia, análisis estático (IDA), OSINT sobre IOCs | ✅ Resuelto |
| [BlueSky](./bluesky) | BlueSky (derivado de Conti) | Análisis de red y host, acceso inicial vía SQL Server, movimiento lateral, dump de credenciales | ✅ Resuelto |

## Metodología general

Para cada muestra se sigue, cuando aplica, el siguiente flujo:

1. **Triage inicial** — hash (MD5/SHA256), consulta en VirusTotal.
2. **Identificación de familia** — herramientas como [ID Ransomware](https://id-ransomware.malwarehunterteam.com/) y [NoMoreRansom](https://www.nomoreransom.org/).
3. **Análisis de red y host** — inspección de tráfico (Wireshark) y logs de eventos, correlación de IOCs y reconstrucción de la cadena de ataque.
4. **Análisis estático** — desensamblado con IDA (Free), extracción de strings, IOCs y dominios/C2 embebidos.
5. **Mapeo a MITRE ATT&CK** de las técnicas identificadas.

## Herramientas utilizadas

- Wireshark
- Visor de eventos de Windows
- IDA Free
- VirusTotal
- ID Ransomware
- NoMoreRansom
