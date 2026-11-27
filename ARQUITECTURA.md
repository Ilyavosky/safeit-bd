# SafeIT BD - Arquitectura

```mermaid
erDiagram
    users ||--o{ domains : "posee"
    users ||--o{ refresh_tokens : "sesiones"
    users ||--o{ password_reset_tokens : "recuperación"
    users ||--o{ public_analyses : "solicita"
    public_analyses ||--o{ public_analysis_hosts : "hosts"
    domains ||--o{ assets : "descubre"
    domains ||--o{ scans : "ejecuta"
    assets ||--o{ services : "puertos"
    assets ||--o{ endpoints : "URLs"
    scans ||--o{ test_runs : "pruebas"
    allowed_tools ||--o{ test_runs : "herramienta"
    endpoints ||--o{ test_runs : "objetivo"
    test_runs ||--o{ findings : "hallazgos"
    findings }o--o{ cve_catalog : "finding_cves"
    scans ||--o{ llm_decisions : "decisiones IA"
    scans ||--o| reports : "reporte"
    reports ||--o{ recommendations : "acciones"
    findings ||--o{ recommendations : "origen"
    users ||--o{ audit_log : "acciones"
```

La base está organizada en seis áreas: autenticación, alcance, pruebas y hallazgos, IA y reportes, catálogo de CVE, y auditoría con análisis público. Al borrar un dominio se eliminan en cascada sus activos, escaneos, pruebas, hallazgos y reportes; `audit_log` no tiene llave foránea a dominios para conservar el historial.

## Más información

- [About](ABOUT.md)
- [README](README.md)
