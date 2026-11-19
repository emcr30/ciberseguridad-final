# NetWatch — prompts por fase

Uso: `CLAUDE.md` en la raíz del repo → `claude` en la terminal → pega una fase → copia la salida de las pruebas y pégamela en el chat → tú haces el commit → `/clear` → siguiente fase.

---

## Fase 0 — Base

```
Lee CLAUDE.md. Fase 0:
- Estructura: netwatch/ (capture/, analyzers/, db/, web/), tests/, samples/, data/ (en .gitignore).
- requirements.txt (scapy, flask, pytest) y .gitignore.
- netwatch/config.py: redes de laboratorio y gateway guardados en data/settings.json.
- netwatch/scope.py: validar CIDR e in_scope(ip) (RF14).
- netwatch/legal.py: texto de advertencia (RF15).
- CLI mínima: `python -m netwatch interfaces` (lista interfaces e indica si hay privilegios) y `python -m netwatch config --add-network 192.168.56.0/24`.
- Tests de scope.
Pruebas a mostrar: pytest -v, y la salida de ambos comandos.
```

## Fase 1 — Captura y protocolos (RF1, RF2, RF3)

```
Lee CLAUDE.md. Fase 1:
- scripts/gen_samples.py: crea con wrpcap (sin enviar nada) samples/normal.pcap, arp_spoof.pcap, port_scan.pcap, creds.pcap (FTP y HTTP con usuario/clave) y out_of_scope.pcap, en la red 192.168.56.0/24.
- Normalizar cada paquete a un dataclass simple y clasificar el protocolo.
- Fuente en vivo (AsyncSniffer) y de archivo (PcapReader) con el mismo flujo, aplicando el filtro de red.
- Comando: python -m netwatch analyze <archivo> → total, descartados y conteo por protocolo.
Pruebas a mostrar: pytest -v y analyze sobre normal.pcap y out_of_scope.pcap. Dime el comando para que yo pruebe la captura en vivo con sudo.
```

## Fase 2 — SQLite

```
Lee CLAUDE.md. Fase 2:
- Tablas: sessions, packets (con límite de filas), conversations, ip_mac, alerts, credentials.
- Repository con consultas con parámetros, incluido filtrar paquetes por ip/protocolo/puerto (RF11).
- analyze ahora guarda en data/netwatch.db.
Pruebas a mostrar: pytest -v y un analyze seguido de un conteo de filas por tabla.
```

## Fase 3 — Conversaciones e IP↔MAC (RF4, RF6)

```
Lee CLAUDE.md. Fase 3: analizador de conversaciones (paquetes y bytes por par de IPs) y tabla IP↔MAC (desde ARP e IP). Conectarlos al flujo.
Pruebas a mostrar: pytest -v, top 5 conversaciones y la tabla IP-MAC de normal.pcap.
Extra: config --add-network debe aceptar también redes IPv6 (por ejemplo fd00::/64), y el filtro de alcance debe funcionar igual para IPv4 e IPv6.
```

## Fase 4 — ARP spoofing y MITM (RF7, RF8, RF12)

```
Lee CLAUDE.md. Fase 4:
- Alerta ARP_SPOOFING si una IP aparece con 2+ MAC en 30 s.
- Alerta MITM (crítica) si el conflicto es sobre el gateway o una MAC reclama varias IPs.
- Las alertas se guardan con hora y detalle; no repetir la misma alerta en 60 s.
Pruebas a mostrar: pytest -v, alertas de arp_spoof.pcap y confirmar 0 alertas en normal.pcap.
```

## Fase 5 — Escaneo de puertos (RF9)

```
Lee CLAUDE.md. Fase 5: alerta PORT_SCAN si un origen manda SYN a 15+ puertos distintos de un destino en 10 s. Incluir en el detalle los puertos abiertos (respondieron SYN/ACK).
Pruebas a mostrar: pytest -v, alerta de port_scan.pcap y 0 alertas en normal.pcap.
```

## Fase 6 — Credenciales (RF5)

```
Lee CLAUDE.md. Fase 6: detectar credenciales en FTP (USER/PASS), HTTP Basic y formularios POST (y si es simple, POP3 y Telnet). Guardar usuario y contraseña enmascarada, y generar alerta.
Pruebas a mostrar: pytest -v, credenciales detectadas en creds.pcap y un test que confirme que la contraseña real no aparece en la base de datos.
```

## Fase 7 — API Flask (RF1, RF2, RF13)

```
Lee CLAUDE.md. Fase 7: python -m netwatch web (127.0.0.1:5000) con endpoints JSON:
status, interfaces, capture start/stop, upload de .pcap, settings (redes), stats, conversations, ip-mac, alerts, credentials, packets con filtros, y export (alertas CSV/JSON, paquetes CSV, .pcap de la sesión).
Capturar debe rechazarse si no hay redes declaradas o no se aceptó la advertencia.
Pruebas a mostrar: pytest -v con el test client de Flask y 3 ejemplos curl con su respuesta.
```

## Fase 8 — Panel web (RF10, RF11, RF15)

```
Lee CLAUDE.md. Fase 8: una página HTML simple y limpia con Chart.js (archivo local en static/):
banner fijo con la advertencia, controles de captura y subida de .pcap, configuración de redes, gráfico de paquetes/s y por protocolo (refresco cada 2 s), tablas de alertas, conversaciones, IP-MAC, credenciales y paquetes con filtros, y botones de exportar.
Usar textContent (no innerHTML) con datos de red.
Pruebas a mostrar: pytest -v y la lista de pasos para que yo lo revise en el navegador.
```

## Fase 9 — Cierre

```
Lee CLAUDE.md. Fase 9: README corto (instalación en Mac y Windows, uso, limitaciones) y docs/TRAZABILIDAD.md (tabla RF | archivo/función | test). Revisa que no haya send/sendp/sr en netwatch/.
Pruebas a mostrar: pytest -v completo y la tabla de trazabilidad.
```
