# cybersecurity-agentic

Es un asistente que planifica, actúa y verifica para proteger tus sistemas. Detecta puertos abiertos, revisa cabeceras y cifrado TLS, genera reportes claros y sugiere medidas concretas. Funciona con reglas locales y puede usar un modelo para tareas más complejas. Seguro por diseño con lista de destinos permitidos y registros de cada paso.

## Componentes principales

- **Allowlist de destinos:** `DestinationPolicy` permite definir los hosts autorizados y filtrar objetivos antes de cualquier acción.
- **Escaneo de puertos:** `scan_open_ports` realiza sondas TCP simples para identificar puertos accesibles en hosts permitidos.
- **Revisión de cabeceras:** `analyze_headers` valida la presencia de cabeceras de seguridad comunes y devuelve las faltantes.
- **Evaluación TLS:** `analyze_tls_profile` clasifica configuraciones TLS simuladas para detectar cifrados débiles o certificados inválidos.
- **Reportes estructurados:** `build_security_report` unifica hallazgos en un diccionario fácil de serializar o mostrar.

Ejecuta los tests con:

```bash
pytest -q
```
