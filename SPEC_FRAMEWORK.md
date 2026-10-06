# FRAMEWORK DE DESARROLLO BASADO EN ESPECIFICACIONES (SDD)
## Estándar Operativo, Reglas de Especificación y Protocolo Multi-Agente

Este documento establece las directivas obligatorias para definir, planificar, trazar y ejecutar requerimientos técnicos bajo la metodología **Spec-Driven Development (SDD)** dentro del proyecto **Auth & Identity Service**.

Cualquier agente de Inteligencia Artificial (IA) o desarrollador humano que participe en este repositorio debe cumplir taxativamente las reglas, esquemas y ciclos de validación aquí expuestos.

---

## 1. Principios Fundamentales del SDD en este Proyecto

1. **Separación Estricta de Fases:**
   * **Spec (`spec.md`):** Define el *QUÉ*. Modela el comportamiento esperado, reglas de negocio, actores, precondiciones, observabilidad funcional y criterios de aceptación verificables. No asume detalles de bajo nivel ni bibliotecas concretas.
   * **Plan (`plan.md`):** Define el *CÓMO*. Modela la arquitectura de solución respetando la Arquitectura Hexagonal en Go (`internal/domain`, `internal/service`, `internal/adapter`), los contratos de interfaces, esquemas de bases de datos, instrumentación de telemetría y flujos asíncronos.
   * **Tasks (`tasks.md`):** Define el *ORDEN DE EJECUCIÓN*. Desglosa el trabajo en unidades mínimas de cambio atómicas, ordenadas por dependencia y con pruebas unitarias y de estrés asociadas.
   * **Contratos (`contracts.md`):** Define las *INTERFACES EXTERNAS*. Declaración explícita de contratos HTTP (OpenAPI/DTOs), payloads de Kafka y eventos de auditoría inmutables.
2. **Determinismo y Cero Ambigüedad:** Una IA o un desarrollador no debe interpretar ni rellenar vacíos lógicos. Toda validación, código de error, tiempo de vida (TTL) o algoritmo debe quedar plasmado con valores concretos.
3. **Consistencia Hexagonal Obligatoria:**
   * El dominio (`internal/domain`) nunca importa capas externas.
   * La lógica de aplicación vive en `internal/service`.
   * La infraestructura y transporte viven en `internal/adapter`.
4. **Gobierno por Roles Especializados:** Ningún agente realiza todo el ciclo en un único paso. El trabajo se distribuye entre los prompts definidos en el directorio `roles/`.
5. **Independencia de Sesión de IA:** El estado de un requerimiento debe ser serializable y comprensible en 30 segundos por una nueva IA leyendo el índice central (`spec/README.md`) y el tracker estructurado (`spec/project-tracker.json`).

---

## 2. Topología de Directorios del Sistema

```text
auth-identity-service/
├── roles/                         # Roles y System Prompts de los agentes de IA
│   ├── README.md                  # Orquestación del pipeline y Quality Gates
│   ├── asistente_de_preguntas.md  # Fase 1: Arquitectura, análisis y preguntas críticas
│   ├── dev_golang.md              # Fase 2: Implementación Go, SOLID y tests unitarios
│   ├── qa.md                      # Fase 3: Pruebas unitarias límite y estrés
│   └── seguridad.md               # Fase 4: Modelado STRIDE, AppSec y Security Gate
├── spec/
│   ├── README.md                  # Índice central y catálogo del estado de specs
│   ├── project-tracker.json       # Registro de estado serializable máquina-a-máquina
│   ├── CU-REG-01-registro-credenciales/
│   │   ├── spec.md                # Requerimiento formal y criterios de aceptación
│   │   ├── plan.md                # Diseño técnico bajo Clean Architecture en Go
│   │   ├── tasks.md               # Checklist atómico de implementación paso a paso
│   │   └── contracts.md           # DTOs, OpenAPI spec y schemas de eventos
│   └── ...
```

---

## 3. Protocolo Obligatorio para Crear o Modificar una Spec

Cuando se inicie el trabajo sobre cualquier caso de uso, **es obligatorio seguir este flujo secuencial**:

### Paso 1: Activación del Rol Asistente de Preguntas
* Cargar el rol `roles/asistente_de_preguntas.md`.
* Leer previamente `OVERVIEW.md`, `ARQUITECTURE.md`, `SPEC_FRAMEWORK.md` y el caso correspondiente en `Requerimientos version2.md`.
* **El agente debe formular un mínimo de 6 preguntas críticas** (cubriendo casos borde, fallos de infraestructura, mitigación de ataques de tiempo/fuerza bruta, semántica HTTP, diseño de puertos e instrumentación de observabilidad)[cite: 3].
* **Pausa obligatoria:** No se redacta ningún archivo en `spec/CU-XXX/` hasta que el usuario responda o valide las respuestas a estas 6 preguntas.

### Paso 2: Redacción Canónica de la Spec
Una vez acordadas las decisiones, el agente redacta los 4 archivos en `spec/CU-XXX/` aplicando estrictamente las plantillas de la **Sección 4**:
1. `spec.md` (incluyendo criterios de observabilidad funcional)md` (OpenAPI, DTOs y eventos de Kafka).
3(mapeo a paquetes de Go, migraciones SQL e instrumentación).
4. `tasks.md` (desglose secuencial de tareas de dominio, aplicación, infraestructura y tests).

### Paso 3: Actualización del Estado
* Actualizar la fila del caso de uso en `spec/README.md` a `🔵 READY_FOR_DEV`.
* Registrar el avance en `spec/project-tracker.json` bajo `"status": "READY_FOR_DEV"`.

### Prohibiciones Explícitas para la IA:
* Prohibido omitir códigos de error HTTP, payloads de respuesta o esquemas de eventos.
* Prohibido acoplar la capa de dominio a dependencias de SQL, Redis, Kafka o frameworks web.
* Prohibido marcar tareas como completadas (`[x]`) sin que el código y sus pruebas hayan sido verificados por los roles correspondientes (`dev_golang.md`, `qa.md` y `seguridad.md`).

---

## 4. Plantillas Canónicas para Cada Archivo

### 4.1. Plantilla: `spec.md`

```markdown
# Spec: [CÓDIGO-CU] - [Nombre Descriptivo del Requerimiento]

## 1. Contexto y Propósito
[Descripción clara y sintética del objetivo del requerimiento y valor para el sistema]

## 2. Actores y Precondiciones
* **Actores:** [ej. Usuario Anónimo, Microservicio, Worker]
* **Precondiciones:**
  * [Precondición 1]
  * [Precondición 2]

## 3. Flujo Principal (Happy Path)
1. El actor envía...
2. El sistema valida...
3. El sistema aplica...
4. Se persiste el estado...
5. Se emite el evento...

## 4. Flujos Alternativos y Excepciones
* **4.1. Validación fallida de entrada:**
  * Condición: Datos incompletos o fuera de formato.
  * Respuesta: Error `400 Bad Request` con payload estándar de error.
* **4.2. Conflicto o unicidad:**
  * Condición: El recurso ya existe.
  * Respuesta: Manejo defensivo (timing attack mitigado) o `409 Conflict`.
* **4.3. Falla de servicio externo o infraestructura:**
  * Condición: Fallo de conexión con almacenamiento o broker.
  * Respuesta: `500 Internal Server Error` sin fugar trazas internas.

## 5. Reglas de Negocio y Seguridad
* **RN-01:** [Regla de negocio formal]
* **SEC-01:** [Mitigación de enumeración, hashing, rate limiting, etc.]

## 6. Requerimientos de Observabilidad
* **Métrica funcional:** [ej. Contador de éxitos/fallos: `user_registration_total{status="success|failed"}`]
* **Trazabilidad:** [Nombre del Span raíz de negocio, ej. `UseCase.RegisterUser`]
* **Auditoría:** [Evento obligatorio que debe publicarse para el log inmutable]

## 7. Criterios de Aceptación (Given-When-Then)
* **Escenario 1: Ejecución exitosa**
  * **Dado** que el usuario ingresa un payload válido con datos no registrados.
  * **Cuando** se procesa la solicitud en el endpoint correspondiente.
  * **Entonces** la entidad se crea en el estado esperado y se despachan los eventos requeridos.
* **Escenario 2: Intento con datos duplicados**
  * **Dado** un identificador ya existente en el repositorio.
  * **Cuando** se solicita la operación.
  * **Entonces** el sistema responde en tiempo homogéneo sin alertar la existencia previa.
```

---

### 4.2. Plantilla: `plan.md`

```markdown
# Plan de Implementación Técnica: [CÓDIGO-CU]

## 1. Mapeo a Capas de Arquitectura Hexagonal

### Capa de Dominio (`internal/domain/`)
* **Subdominio:** `internal/domain/[user|auth|shared]/`
* **Entidades / Value Objects:**
  * `[NombreEntidad]`: Atributos e invariantes de negocio.
* **Puertos de Salida (Interfaces del Dominio):**
  * `[Nombre]Repository`: Métodos de persistencia necesarios.
  * `[Nombre]Hasher` o `TokenProvider`: Métodos de seguridad necesarios.
  * `EventPublisher`: Métodos para publicación en broker.

### Capa de Aplicación (`internal/service/`)
* **Servicio / Caso de Uso:** `internal/service/[nombre_caso_uso].go`
* **Estructura:** Inyección de dependencias mediante interfaces de dominio.
* **Flujo de Ejecución Orquestado:**
  1. Validación de reglas de dominio.
  2. Invocación de puertos criptográficos/seguridad.
  3. Llamada al repositorio.
  4. Publicación asíncrona de eventos de integración y auditoría.

### Capa de Adaptadores (`internal/adapter/`)
* **Entrada (HTTP):**
  * Handler: `internal/adapter/http/handlers/[nombre].go`
  * DTO: `internal/adapter/http/dto/[nombre]_dto.go`
  * Middleware: Aplicación de rate-limiting y auth context si aplica.
* **Salida (Persistencia):**
  * Postgres: `internal/adapter/persistencia/postgres/[nombre]_repository.go`
  * Redis: `internal/adapter/persistencia/redis/[nombre]_cache.go`
* **Salida (Mensajería):**
  * Kafka: `internal/adapter/colas/kafka/[nombre]_producer.go`

## 2. Plan de Observabilidad y Telemetría
* **Métricas (Prometheus):** Declaración de nombres y etiquetas seguras en el adaptador o servicio.
* **Tracing (OpenTelemetry):** Definición de Spans hijos (`db.query`, `crypto.hash`, `kafka.produce`).
* **Logs Estructurados:** Definición de claves obligatorias (`trace_id`, `use_case`, `action`). Prohibición estricta de PII.

## 3. Cambios en Base de Datos y Migraciones
* **Script:** `scripts/migrations/[TIMESTAMP]_[nombre_migracion].up.sql`
* **Definición de tablas, índices y restricciones:**
  ```sql
  -- DDL planificado
  ```

## 4. Estrategia de Pruebas
* **Pruebas Unitarias:** Dominio y Casos de Uso con mocks generados para interfaces.
* **Pruebas de Estrés / Carga:** Script de k6/Vegeta con percentiles p95 < 150ms.
```

---

### 4.3. Plantilla: `tasks.md`

```markdown
# Tareas de Implementación: [CÓDIGO-CU]

> **Regla de Ejecución:** Completar los ítems secuencialmente. No saltar fases. Marcar con `[x]` únicamente cuando la tarea cuente con código y pruebas correspondientes aprobadas.

## Fase 1: Dominio y Puertos
- [ ] T-01: Definir entidades y value objects en `internal/domain/[subdominio]/`.
- [ ] T-02: Definir interfaces de repositorios y servicios externos en `internal/domain/`.
- [ ] T-03: Implementar pruebas unitarias del dominio garantizando invariantes.

## Fase 2: Casos de Uso (Aplicación) y Telemetría
- [ ] T-04: Crear servicio en `internal/service/` implementando el flujo del caso de uso.
- [ ] T-05: Instrumentar métricas de Prometheus y Spans de tracing en el servicio.
- [ ] T-06: Implementar suite de pruebas unitarias (table-driven tests) para el servicio con mocks.

## Fase 3: Infraestructura y Adaptadores
- [ ] T-07: Crear migración SQL en `scripts/migrations/`.
- [ ] T-08: Implementar repositorio de persistencia en `internal/adapter/persistencia/`.
- [ ] T-09: Implementar productor de eventos en `internal/adapter/colas/`.
- [ ] T-10: Implementar DTOs y Handler HTTP en `internal/adapter/http/`.
- [ ] T-11: Registrar rutas y cableado de dependencias en `cmd/api/main.go`.

## Fase 4: Verificación, Carga y Seguridad
- [ ] T-12: Ejecutar pruebas de integración de punta a punta (E2E/HTTP).
- [ ] T-13: Ejecutar script de carga/estrés (k6) validando percentiles p95/p99.
- [ ] T-14: Ejecutar auditoría AppSec (Security Gate de STRIDE, PII y timing attacks).
- [ ] T-15: Actualizar `spec/project-tracker.json` reflejando el caso de uso como `COMPLETED`.
```

---

### 4.4. Plantilla: `contracts.md`

```markdown
# Contratos de Integración: [CÓDIGO-CU]

## 1. Contrato HTTP (API REST)

* **Ruta:** `POST /api/v1/...`
* **Autenticación requerida:** Ninguna / Bearer Token / API Key
* **Headers:**
  * `Content-Type: application/json`
  * `X-Request-ID: string (UUIDv4)`

### Request Payload
```json
{
  "campo": "valor"
}
```

### Respuestas

#### `201 Created` / `200 OK`
```json
{
  "success": true,
  "data": {
    "id": "uuid",
    "status": "string"
  }
}
```

#### `400 Bad Request`
```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_FAILED",
    "message": "Descripción comprensible",
    "details": []
  }
}
```

## 2. Eventos Asíncronos (Kafka)

* **Tópico:** `auth.[entidad].[evento].v1`
* **Key:** `user_id` (UUID)
* **Payload:**
```json
{
  "event_id": "uuid",
  "event_type": "user.registered",
  "occurred_at": "2026-10-05T12:00:00Z",
  "payload": {
    "user_id": "uuid",
    "email": "user@example.com"
  }
}
```
```

---

## 5. El Índice Maestro (`spec/README.md`)

Este archivo vive de forma permanente en `spec/README.md`. Proporciona un mapa inmediato para conocer el estado técnico de cada requerimiento.

```markdown
# Catálogo de Especificaciones de Casos de Uso (SDD)

Este catálogo centraliza todos los requerimientos funcionales del sistema Auth & Identity, vinculando su especificación formal con el estado actual de avance.

## Convención de Estados
* 🔴 **PENDING:** Requerimiento identificado, sin especificación técnica completa.
* 🟡 **IN_SPECIFICATION:** Sesión activa con `asistente_de_preguntas.md` resolviendo las 6 preguntas críticas.
* 🔵 **READY_FOR_DEV:** Especificación (`spec/plan/tasks/contracts`) aprobada y lista para programar en Go.
* 🟣 **IN_DEVELOPMENT:** Rol `dev_golang.md` ejecutando activamente tareas de `tasks.md`.
* 🧪 **IN_TESTING:** Roles `qa.md` y `seguridad.md` validando tests unitarios, estrés y Security Gate.
* 🟢 **COMPLETED:** Implementación terminada, auditada y verificada en el repositorio.

---

## Módulo 1: Flujo de Registro (Sign Up)
| ID | Caso de Uso | Estado | Carpeta Spec | Responsable / Agente |
| :--- | :--- | :---: | :--- | :--- |
| CU-REG-01 | Registro Clásico con Credenciales | 🔴 PENDING | [`CU-REG-01-registro-credenciales`](./CU-REG-01-registro-credenciales) | - |
| CU-REG-02 | Verificación de Identidad Obligatoria | 🔴 PENDING | [`CU-REG-02-verificacion-identidad`](./CU-REG-02-verificacion-identidad) | - |
| CU-REG-03 | Validación de Unicidad en Tiempo Real | 🔴 PENDING | [`CU-REG-03-validacion-unicidad`](./CU-REG-03-validacion-unicidad) | - |
| CU-REG-04 | Registro Federado (OAuth2 / OIDC) | 🔴 PENDING | [`CU-REG-04-registro-federado`](./CU-REG-04-registro-federado) | - |
| CU-REG-05 | Aceptación de Términos y Políticas | 🔴 PENDING | [`CU-REG-05-aceptacion-terminos`](./CU-REG-05-aceptacion-terminos) | - |
| CU-REG-06 | Vinculación y Desvinculación de Cuentas | 🔴 PENDING | [`CU-REG-06-vinculacion-cuentas`](./CU-REG-06-vinculacion-cuentas) | - |

## Módulo 2: Flujo de Inicio de Sesión (Sign In)
| ID | Caso de Uso | Estado | Carpeta Spec | Responsable / Agente |
| :--- | :--- | :---: | :--- | :--- |
| CU-AUTH-01 | Autenticación Estándar | 🔴 PENDING | [`CU-AUTH-01-autenticacion-estandar`](./CU-AUTH-01-autenticacion-estandar) | - |
| CU-AUTH-02 | Autenticación Multifactor (TOTP) | 🔴 PENDING | [`CU-AUTH-02-mfa-totp`](./CU-AUTH-02-mfa-totp) | - |
| CU-AUTH-03 | Códigos de Respaldo para MFA | 🔴 PENDING | [`CU-AUTH-03-backup-codes`](./CU-AUTH-03-backup-codes) | - |
| CU-AUTH-04 | Emisión y Gestión de Tokens Enterprise | 🔴 PENDING | [`CU-AUTH-04-emision-tokens`](./CU-AUTH-04-emision-tokens) | - |
| CU-AUTH-05 | Inicio de Sesión sin Contraseña | 🔴 PENDING | [`CU-AUTH-05-passwordless`](./CU-AUTH-05-passwordless) | - |
| CU-AUTH-06 | Autenticación Reforzada (Step-Up) | 🔴 PENDING | [`CU-AUTH-06-step-up-auth`](./CU-AUTH-06-step-up-auth) | - |

## Módulo 3: Recuperación y Gestión de Credenciales
| ID | Caso de Uso | Estado | Carpeta Spec | Responsable / Agente |
| :--- | :--- | :---: | :--- | :--- |
| CU-CRED-01 | Recuperación de Contraseña | 🔴 PENDING | [`CU-CRED-01-recuperacion-password`](./CU-CRED-01-recuperacion-password) | - |
| CU-CRED-02 | Cambio de Contraseña desde Sesión Activa | 🔴 PENDING | [`CU-CRED-02-cambio-password`](./CU-CRED-02-cambio-password) | - |
| CU-CRED-03 | Actualización de Correo Electrónico | 🔴 PENDING | [`CU-CRED-03-actualizacion-email`](./CU-CRED-03-actualizacion-email) | - |

## Módulo 4: Control y Gestión de Sesiones
| ID | Caso de Uso | Estado | Carpeta Spec | Responsable / Agente |
| :--- | :--- | :---: | :--- | :--- |
| CU-SES-01 | Cierre de Sesión Individual (Logout) | 🔴 PENDING | [`CU-SES-01-logout`](./CU-SES-01-logout) | - |
| CU-SES-02 | Cierre de Sesión Global (Revocación Masiva) | 🔴 PENDING | [`CU-SES-02-logout-global`](./CU-SES-02-logout-global) | - |
| CU-SES-03 | Listado y Terminación Selectiva | 🔴 PENDING | [`CU-SES-03-gestion-sesiones`](./CU-SES-03-gestion-sesiones) | - |
| CU-SES-04 | Renovación Controlada y Detección de Reúso | 🔴 PENDING | [`CU-SES-04-token-rotation`](./CU-SES-04-token-rotation) | - |

## Módulo 5: Seguridad Proactiva y Defensa Enterprise
| ID | Caso de Uso | Estado | Carpeta Spec | Responsable / Agente |
| :--- | :--- | :---: | :--- | :--- |
| CU-SEC-01 | Bloqueo por Intentos Fallidos (Brute Force) | 🔴 PENDING | [`CU-SEC-01-brute-force`](./CU-SEC-01-brute-force) | - |
| CU-SEC-02 | Rate Limiting y Throttling | 🔴 PENDING | [`CU-SEC-02-rate-limiting`](./CU-SEC-02-rate-limiting) | - |
| CU-SEC-03 | Detección de Viaje Imposible | 🔴 PENDING | [`CU-SEC-03-impossible-travel`](./CU-SEC-03-impossible-travel) | - |
| CU-SEC-04 | Trazabilidad y Logs de Auditoría | 🔴 PENDING | [`CU-SEC-04-audit-trail`](./CU-SEC-04-audit-trail) | - |
| CU-SEC-05 | Eliminación de Cuenta (Right to be Forgotten) | 🔴 PENDING | [`CU-SEC-05-derecho-olvido`](./CU-SEC-05-derecho-olvido) | - |
| CU-SEC-06 | Gestión de Roles y Alcances (RBAC) | 🔴 PENDING | [`CU-SEC-06-rbac-scopes`](./CU-SEC-06-rbac-scopes) | - |
| CU-SEC-07 | Detección de Dispositivo Desconocido | 🔴 PENDING | [`CU-SEC-07-device-fingerprint`](./CU-SEC-07-device-fingerprint) | - |

## Módulo 6: Identidades Máquina a Máquina (M2M)
| ID | Caso de Uso | Estado | Carpeta Spec | Responsable / Agente |
| :--- | :--- | :---: | :--- | :--- |
| CU-M2M-01 | Client Credentials Grant | 🔴 PENDING | [`CU-M2M-01-client-credentials`](./CU-M2M-01-client-credentials) | - |
| CU-M2M-02 | Gestión de API Keys | 🔴 PENDING | [`CU-M2M-02-api-keys`](./CU-M2M-02-api-keys) | - |

## Módulo 7: Criptografía y JWKS
| ID | Caso de Uso | Estado | Carpeta Spec | Responsable / Agente |
| :--- | :--- | :---: | :--- | :--- |
| CU-CRYP-01 | Publicación de JWKS Discovery | 🔴 PENDING | [`CU-CRYP-01-jwks-discovery`](./CU-CRYP-01-jwks-discovery) | - |
| CU-CRYP-02 | Rotación Programada de Claves Maestras | 🔴 PENDING | [`CU-CRYP-02-rotacion-claves`](./CU-CRYP-02-rotacion-claves) | - |
| CU-CRYP-03 | Mitigación de Desastres por Fuga | 🔴 PENDING | [`CU-CRYP-03-desastre-criptografico`](./CU-CRYP-03-desastre-criptografico) | - |

## Módulo 8: Privacidad Avanzada y Cumplimiento
| ID | Caso de Uso | Estado | Carpeta Spec | Responsable / Agente |
| :--- | :--- | :---: | :--- | :--- |
| CU-PRIV-01 | Portabilidad de Datos Personales | 🔴 PENDING | [`CU-PRIV-01-portabilidad-datos`](./CU-PRIV-01-portabilidad-datos) | - |
| CU-PRIV-02 | Gestión Granular de Consentimientos | 🔴 PENDING | [`CU-PRIV-02-gestion-consentimientos`](./CU-PRIV-02-gestion-consentimientos) | - |
```

---

## 6. Estructura del Tracker de Proyecto (`spec/project-tracker.json`)

Este archivo centraliza el estado máquina-a-máquina para evitar reprocesamientos:

```json
{
  "$schema": "[http://json-schema.org/draft-07/schema#](http://json-schema.org/draft-07/schema#)",
  "project": "auth-identity-service",
  "version": "1.0.0",
  "last_updated": "2026-10-05T12:00:00Z",
  "architecture": {
    "language": "Go",
    "pattern": "Hexagonal / Clean Architecture",
    "ports": "internal/domain",
    "use_cases": "internal/service",
    "adapters": "internal/adapter"
  },
  "metrics": {
    "total_use_cases": 32,
    "completed": 0,
    "in_progress": 0,
    "pending": 32
  },
  "active_work": {
    "current_use_case": null,
    "status": "IDLE",
    "current_task": null,
    "assigned_role": null,
    "blockers": []
  },
  "specs": [
    {
      "id": "CU-REG-01",
      "name": "Registro Clásico con Credenciales",
      "folder": "spec/CU-REG-01-registro-credenciales",
      "status": "PENDING",
      "priority": "HIGH",
      "dependencies": [],
      "tasks_summary": {
        "total": 15,
        "completed": 0
      }
    }
  ]
}
```

---

## 7. Protocolo de Inicio Rápido para Nuevas IAs (Context Handover Prompt)

Copia y pega este mensaje como primera instrucción cuando abras un nuevo chat con cualquier IA:

> *"Estamos desarrollando el microservicio `auth-identity-service` siguiendo la metodología Spec-Driven Development (SDD) bajo Clean Architecture en Go. Antes de realizar cualquier acción, consulta obligatoriamente:*
> 1. `OVERVIEW.md` *(visión de producto y directivas de seguridad)*
> 2. `ARQUITECTURE.md` *(capas, puertos y adaptadores en Go)*
> 3. `SPEC_FRAMEWORK.md` *(este framework de trabajo y plantillas)*
> 4. `roles/README.md` *(ecosistema de agentes y asignación de tareas)*
> 5. `spec/project-tracker.json` y `spec/README.md` *(estado actual de desarrollo)*
>
> *Dime qué rol tengo asignado según la tarea activa en `project-tracker.json` y espera mi confirmación antes de proceder."*