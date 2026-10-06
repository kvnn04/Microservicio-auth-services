# Catálogo de Roles y Agentes de IA (Multi-Agent System)

Este directorio centraliza las identidades, responsabilidades técnicas y directivas operativas de los agentes de Inteligencia Artificial que intervienen en el ciclo de vida del servicio `auth-identity-service`.

Cada archivo dentro de esta carpeta contiene el **System Prompt** exhaustivo que debe configurarse en la IA según la fase del flujo de trabajo en la que se encuentre el proyecto.

---

## 1. Topología del Directorio de Roles

```text
roles/
├── README.md                   # Catálogo maestro, matriz de responsabilidades y flujo de orquestación
├── asistente_de_preguntas.md   # Fase 1: Arquitectura, análisis crítico de requerimientos y generación de specs
├── dev_golang.md               # Fase 2: Implementación de código Go, SOLID y tests unitarios iniciales
├── qa.md                       # Fase 3: Pruebas unitarias de casos límite y tests de estrés/rendimiento
└── seguridad.md                # Fase 4: Modelado de amenazas (STRIDE), auditoría AppSec y Security Gate
```

---

## 2. Matriz de Responsabilidades y Asignación por Fase

| Rol / Archivo | Fase del Ciclo SDD | Propósito y Foco Principal | Archivos Clave que Consume |
| :--- | :---: | :--- | :--- |
| **`asistente_de_preguntas.md`**<br>*(Specification Architect)* | **1. Definición** | Desafía supuestos formulando un mínimo de 6 preguntas críticas antes de redactar `spec.md`, `plan.md`, `tasks.md` y `contracts.md`. Elimina ambigüedades funcionales y técnicas. | `OVERVIEW.md`<br>`ARQUITECTURE.md`<br>`Requerimientos version2.md`<br>`SPEC_FRAMEWORK.md` |
| **`dev_golang.md`**<br>*(Senior Golang Developer)* | **2. Implementación** | Escribe código limpio e idiomático en Go. Aplica principios SOLID, respeta la Arquitectura Hexagonal y ejecuta estrictamente las tareas atómicas de `tasks.md`. | `ARQUITECTURE.md`<br>`spec/CU-XXX/plan.md`<br>`spec/CU-XXX/tasks.md`<br>`spec/CU-XXX/contracts.md` |
| **`qa.md`**<br>*(Lead QA & Performance Engineer)* | **3. Verificación** | Diseña suites de pruebas unitarias (*table-driven tests*) para flujos límite y scripts de estrés/carga (k6) para validar latencias percentiles (p95/p99) y resiliencia. | `spec/CU-XXX/spec.md`<br>`spec/CU-XXX/contracts.md`<br>Código Go implementado |
| **`seguridad.md`**<br>*(Principal AppSec Auditor)* | **4. Certificación** | Modela amenazas bajo STRIDE, audita el uso de criptografía, mitiga ataques de temporización o enumeración, verifica sanitización de logs y otorga el *Security Gate*. | `OVERVIEW.md`<br>`ARQUITECTURE.md`<br>`spec/CU-XXX/spec.md`<br>Diff de código Go |

---

## 3. Pipeline de Trabajo entre Agentes

Para garantizar un desarrollo sin desvíos arquitectónicos ni brechas de seguridad, los roles deben invocarse de forma secuencial y desacoplada:

```text
[ Nueva Necesidad / Requerimiento ]
                 │
                 ▼
    ┌─────────────────────────┐
    │ asistente_de_preguntas  │ ──► Formula >= 6 preguntas críticas y redacta la Spec
    └─────────────────────────┘
                 │ (Spec aprobada en spec/CU-XXX/)
                 ▼
    ┌─────────────────────────┐
    │       dev_golang        │ ──► Implementa puertos, servicios y adaptadores en Go
    └─────────────────────────┘
                 │ (Código y tests iniciales listos)
                 ▼
    ┌─────────────────────────┐
    │           qa            │ ──► Somete el código a stress tests y casos extremos
    └─────────────────────────┘
                 │ (Pruebas aprobadas)
                 ▼
    ┌─────────────────────────┐
    │        seguridad        │ ──► Audita AppSec (STRIDE, PII, Timing Attacks, OWASP)
    └─────────────────────────┘
                 │ (Security Gate: PASSED)
                 ▼
[ Tarea marcada como COMPLETED en project-tracker.json ]
```

---

## 4. Guía de Uso para Nuevas Sesiones

1. **Identificar la fase de trabajo:**
   * **Definición de caso de uso:** Cargar el System Prompt de `roles/asistente_de_preguntas.md`.
   * **Codificación en Go:** Cargar el System Prompt de `roles/dev_golang.md`.
   * **Creación de tests y benchmarks:** Cargar el System Prompt de `roles/qa.md`.
   * **Auditoría de vulnerabilidades y seguridad:** Cargar el System Prompt de `roles/seguridad.md`.
2. **Inyección de contexto:** Copiar el contenido íntegro del rol como primer mensaje o instrucción de sistema en el cliente de IA.
3. **Paso de artefactos:** Facilitar únicamente los archivos referenciados en la columna *"Archivos Clave que Consume"* de la tabla para mantener limpia la ventana de contexto.

---

## 5. Criterios de Aceptación (Quality Gates)

Una tarea o caso de uso solo se considera finalizado cuando:
* Las tareas de `spec/CU-XXX/tasks.md` están ejecutadas secuencialmente.
* Las pruebas unitarias pasan sin condiciones de carrera (`go test -race ./...`).
* Las pruebas de estrés no arrojan degradación en percentiles p95/p99 ni fugas de memoria.
* El rol de seguridad emite dictamen `🟢 APROBADO (PASSED)`.
* El archivo `spec/project-tracker.json` refleja el estado `COMPLETED`.