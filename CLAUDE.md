# NetWatch — contexto para Claude Code

Proyecto final de un curso de seguridad: "Analizador de Tráfico y Detector de ARP Spoofing".
Herramienta **defensiva**: solo escucha y lee archivos. Nunca usar `send`, `sendp`, `sr`, `srp` en el código.

## Requisitos (RF)
1. Captura en vivo desde una interfaz elegida por el usuario
2. Cargar y analizar archivos .pcap
3. Clasificar por protocolo (ARP, DNS, HTTP, HTTPS, etc.)
4. Conversaciones entre pares de IPs con volumen de paquetes
5. Detectar credenciales en texto plano
6. Tabla IP ↔ MAC
7. Detectar ARP spoofing (misma IP con varias MAC en poco tiempo)
8. Alerta de posible MITM en curso
9. Detectar escaneo de puertos
10. Estadísticas en tiempo real en un panel gráfico
11. Filtrar paquetes por IP, protocolo o puerto
12. Registrar alertas con hora y detalle
13. Exportar capturas y alertas
14. Analizar solo las redes de laboratorio declaradas por el usuario
15. Advertencia visible: capturar solo en redes propias y autorizadas

## Stack
Python 3.12 · Scapy · SQLite (`sqlite3`) · Flask · HTML + JS + Chart.js · pytest. No usar pyshark, Dash ni Docker.

## Reglas
- Debe funcionar en **macOS (M2) y Windows**: usar `pathlib`, sin comandos de shell en el código.
- Captura en vivo necesita privilegios (Mac: `sudo`; Windows: Npcap + terminal de administrador). Si no hay, la app no se cae: el análisis de .pcap sigue funcionando.
- Live y .pcap pasan por el **mismo** flujo: fuente → normalizar → filtro de red de laboratorio → analizadores → SQLite → Flask.
- Las detecciones usan el timestamp del paquete.
- Contraseñas siempre **enmascaradas** al guardarlas o mostrarlas.
- Código en inglés; textos de interfaz y docs en español.
- Mantener el código simple y corto. No agregar funciones que no pida la fase.

## Al terminar cada fase
1. Correr `pytest -v` y los comandos de prueba que pida la fase.
2. Mostrar la **salida completa** de esas pruebas.
3. Resumir en 5 líneas qué se hizo y qué archivos se tocaron.
4. **No hacer commit ni push** (lo hace el usuario). **No ejecutar sudo.** Detenerse y esperar.
