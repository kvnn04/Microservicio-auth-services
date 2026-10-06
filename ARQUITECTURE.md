# Arquitectura del Servicio: Auth & Identity

Este documento detalla la estructura de directorios, la responsabilidad técnica de cada capa, el flujo de dependencias y la guía práctica para operar e interactuar con el proyecto en Go.

---

## 1. Árbol de Directorios

```text
auth-identity-service/
├── .github/
│   └── workflows/
├── cmd/
│   ├── api/
│   └── worker/
├── internal/
│   ├── domain/
│   │   ├── user/
│   │   ├── auth/
│   │   └── shared/
│   ├── service/
│   └── adapter/
│       ├── security/
│       ├── persistencia/
│       │   ├── postgres/
│       │   └── redis/
│       ├── colas/
│       │   └── kafka/
│       ├── identity/
│       └── http/
│           ├── handlers/
│           ├── middleware/
│           ├── dto/
│           └── errors/
├── pkg/
│   └── logger/
├── scripts/
│   └── migrations/
├── .env.example
├── .gitignore
├── compose.yml
├── Dockerfile
├── go.mod
└── go.sum
```

---

## 2. Descripción y Propósito de Cada Carpeta

La estructura implementa los principios de **Clean Architecture / Ports & Adapters (Hexagonal)**, asegurando que las reglas de negocio no dependan de la infraestructura ni de frameworks externos.

### `.github/workflows/`
* **¿Qué es?:** Directorio de automatización para GitHub Actions.
* **¿Para qué se usa?:** Contiene las recetas en YAML para ejecutar CI/CD (pruebas automáticas, análisis estático con `golangci-lint`, compilación de binarios y escaneo de vulnerabilidades en cada `push` o `pull request`).

### `cmd/` (Command / Puntos de Entrada)
* **¿Qué es?:** La raíz de los ejecutables independientes del proyecto. Cada subdirectorio aquí representa un binario que se compilará con `go build`.
* **Subcarpetas:**
  * `cmd/api/`: Punto de entrada para el servidor HTTP principal. Se encarga de inicializar la configuración, instanciar los adaptadores (base de datos, redis, seguridad), inyectar las dependencias en los servicios y levantar el router web.
  * `cmd/worker/`: Punto de entrada para procesos asíncronos y en segundo plano. Escucha eventos de colas (ej. Kafka) para tareas que no deben bloquear peticiones web (envío de correos, sincronizaciones diferidas).

### `internal/` (Código Privado)
* **¿Qué es?:** Código exclusivo del servicio. Por convención del compilador de Go, ningún paquete fuera de este repositorio puede importar lo que esté dentro de `internal/`.
* **Capas internas:**

#### `internal/domain/` (Capa de Dominio / Núcleo)
* **¿Qué es?:** El corazón del negocio. Es **código puro**: no importa bases de datos, librerías web, librerías de encriptación externa ni clientes de red.
* **¿Para qué se usa?:**
  * Define las entidades de negocio y sus invariantes (validaciones de estado).
  * Declara los **Puertos** (interfaces) que el dominio necesita para funcionar (ej. interfaces para repositorios, tokens, hashing, mensajería).
  * Organizado por subdominios:
    * `user/`: Reglas sobre la identidad del usuario y contratos de su repositorio.
    * `auth/`: Modelos de credenciales, tokens y contratos para proveedores externos.
    * `shared/`: Interfaces transversales (ej. contratos de publicación de eventos y errores genéricos).

#### `internal/service/` (Capa de Aplicación / Casos de Uso)
* **¿Qué es?:** El orquestador de las operaciones de negocio.
* **¿Para qué se usa?:** Implementa los casos de uso (ej. "Registrar usuario", "Iniciar sesión", "Autenticar con Google"). 
  * Solo interactúa con el dominio y consume las interfaces definidas en él mediante inyección de dependencias.
  * No sabe si una petición vino por HTTP, gRPC o CLI; solo recibe datos, ejecuta la lógica de negocio y delega persistencia o eventos a las interfaces.

#### `internal/adapter/` (Capa de Infraestructura / Adaptadores)
* **¿Qué es?:** El mundo exterior. Implementa los puertos (interfaces) definidos en `domain`.
* **Subcarpetas:**
  * `adapter/security/`: Implementaciones criptográficas reales (ej. generación/validación de JWT o PASETO, algoritmos de hash como Argon2 o Bcrypt).
  * `adapter/persistencia/`: Implementaciones de almacenamiento (`postgres` para consultas SQL y repositorios de entidades, `redis` para cachés, sesiones y listas de revocación).
  * `adapter/colas/`: Adaptadores de mensajería asíncrona (`kafka` para productores y consumidores de eventos).
  * `adapter/identity/`: Clientes externos de comunicación HTTP (ej. cliente para validar tokens con Google OAuth2).
  * `adapter/http/`: Adaptador web completo:
    * `handlers/`: Controladores que reciben peticiones HTTP, parsean payloads y llaman a los casos de uso en `service/`.
    * `middleware/`: Filtros transversales (validación de tokens, control de concurrencia/rate limit, recuperación de pánicos).
    * `dto/`: Estructuras de datos (Data Transfer Objects) para formatear requests y responses JSON.
    * `errors/`: Mapeo de errores de dominio puros a códigos de estado HTTP (400, 401, 403, 404, 500).

### `pkg/` (Librerías Públicas/Utilitarias)
* **¿Qué es?:** Paquetes utilitarios genéricos y reutilizables que no contienen lógica de negocio.
* **¿Para qué se usa?:** `pkg/logger/` centraliza la configuración de logging estructurado (JSON, niveles INFO/WARN/ERROR) para ser reutilizado por `cmd`, `adapters` o cualquier componente sin acoplar lógica funcional.

### `scripts/`
* **¿Qué es?:** Scripts auxiliares de entorno y despliegue.
* **Subcarpetas:**
  * `scripts/migrations/`: Archivos `.sql` versionados (migraciones Up/Down) para crear y modificar el esquema de base de datos de manera determinista.

---

## 3. Reglas de Dependencia (Dirección del Flujo)

```text
[ adapter (HTTP / DB / Kafka / Security) ]
                  │
                  ▼  (usa / inyecta)
         [ service (Casos de Uso) ]
                  │
                  ▼  (define modelos y contratos)
             [ domain ]
```

* **Regla estricta:** `domain` no importa a nadie dentro de `internal`.
* `service` solo importa `domain`.
* `adapter` implementa las interfaces de `domain` y traduce datos entre librerías externas y entidades de negocio.
* `cmd` orquesta: inicializa `adapter`, los pasa como parámetros a `service`, y arranca el ciclo de vida.

---

## 4. Guía de Uso del Proyecto

### 1. Preparar el Entorno Local
Levantar la infraestructura de soporte (Postgres, Redis, Kafka) mediante Docker:
```bash
docker compose up -d
```

### 2. Configurar Variables de Entorno
Copiar la plantilla de configuración e ingresar los valores locales correspondientes:
```bash
cp .env.example .env
```

### 3. Aplicar Migraciones
Ejecutar los scripts de migración de base de datos antes de iniciar los servicios:
```bash
# Ejemplo usando migrate CLI o script propio
migrate -path scripts/migrations -database "postgres://user:pass@localhost:5432/auth_db?sslmode=disable" up
```

### 4. Ejecutar los Componentes

* **Ejecutar la API HTTP:**
  ```bash
  go run cmd/api/main.go
  ```

* **Ejecutar el Worker en segundo plano (en otra terminal o contenedor):**
  ```bash
  go run cmd/worker/main.go
  ```

### 5. Compilar Binarios Productivos
Para compilar los binarios optimizados para producción:
```bash
go build -ldflags="-s -w" -o bin/api cmd/api/main.go
go build -ldflags="-s -w" -o bin/worker cmd/worker/main.go
```