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
| CU-REG-01 | Registro Clásico con Credenciales | 🟢 COMPLETED (fix email inicial F-16..F-18) | [\CU-REG-01-registro-credenciales\](./CU-REG-01-registro-credenciales) | dev_golang/qa/seguridad |
| CU-REG-02 | Verificación de Identidad Obligatoria | 🟢 COMPLETED (re-verificación V-16..V-17) | [\CU-REG-02-verificacion-identidad\](./CU-REG-02-verificacion-identidad) | dev_golang/qa/seguridad |
| CU-REG-03 | Validación de Unicidad en Tiempo Real | 🟢 COMPLETED | [\CU-REG-03-validacion-unicidad\](./CU-REG-03-validacion-unicidad) | dev_golang/qa/seguridad |
| CU-REG-04 | Registro Federado (OAuth2 / OIDC) | 🟢 COMPLETED | [\CU-REG-04-registro-federado\](./CU-REG-04-registro-federado) | dev_golang/qa/seguridad |
| CU-REG-05 | Aceptación de Términos y Políticas | 🟢 COMPLETED | [\CU-REG-05-aceptacion-terminos\](./CU-REG-05-aceptacion-terminos) | dev_golang/qa/seguridad |
| CU-REG-06 | Vinculación y Desvinculación de Cuentas | 🟢 COMPLETED | [\CU-REG-06-vinculacion-cuentas\](./CU-REG-06-vinculacion-cuentas) | dev_golang/qa/seguridad |

## Módulo 2: Flujo de Inicio de Sesión (Sign In)
| ID | Caso de Uso | Estado | Carpeta Spec | Responsable / Agente |
| :--- | :--- | :---: | :--- | :--- |
| CU-AUTH-01 | Autenticación Estándar | 🟢 COMPLETED | [\CU-AUTH-01-autenticacion-estandar\](./CU-AUTH-01-autenticacion-estandar) | dev_golang/qa/seguridad |
| CU-AUTH-02 | Autenticación Multifactor (TOTP) | 🟢 COMPLETED | [\CU-AUTH-02-mfa-totp\](./CU-AUTH-02-mfa-totp) | dev_golang/qa/seguridad |
| CU-AUTH-03 | Códigos de Respaldo para MFA | 🟢 COMPLETED | [\CU-AUTH-03-backup-codes\](./CU-AUTH-03-backup-codes) | dev_golang/qa/seguridad |
| CU-AUTH-04 | Emisión y Gestión de Tokens Enterprise | 🟢 COMPLETED | [`CU-AUTH-04-emision-tokens`](./CU-AUTH-04-emision-tokens) | dev_golang/qa/seguridad |
| CU-AUTH-05 | Inicio de Sesión sin Contraseña | 🟢 COMPLETED | [`CU-AUTH-05-passwordless`](./CU-AUTH-05-passwordless) | dev_golang/qa/seguridad |
| CU-AUTH-06 | Autenticación Reforzada (Step-Up) | 🟢 COMPLETED | [`CU-AUTH-06-step-up-auth`](./CU-AUTH-06-step-up-auth) | dev_golang/qa/seguridad |

## Módulo 3: Recuperación y Gestión de Credenciales
| ID | Caso de Uso | Estado | Carpeta Spec | Responsable / Agente |
| :--- | :--- | :---: | :--- | :--- |
| CU-CRED-01 | Recuperación de Contraseña | 🟢 COMPLETED | [`CU-CRED-01-recuperacion-password`](./CU-CRED-01-recuperacion-password) | dev_golang/qa/seguridad |
| CU-CRED-02 | Cambio de Contraseña desde Sesión Activa | 🟢 COMPLETED | [`CU-CRED-02-cambio-password`](./CU-CRED-02-cambio-password) | dev_golang/qa/seguridad |
| CU-CRED-03 | Actualización de Correo Electrónico | 🟢 COMPLETED | [`CU-CRED-03-actualizacion-email`](./CU-CRED-03-actualizacion-email) | dev_golang/qa/seguridad |

## Módulo 4: Control y Gestión de Sesiones
| ID | Caso de Uso | Estado | Carpeta Spec | Responsable / Agente |
| :--- | :--- | :---: | :--- | :--- |
| CU-SES-01 | Cierre de Sesión Individual (Logout) | 🟢 COMPLETED | [`CU-SES-01-logout`](./CU-SES-01-logout) | dev_golang/qa/seguridad |
| CU-SES-02 | Cierre de Sesión Global (Revocación Masiva) | 🟢 COMPLETED | [`CU-SES-02-logout-global`](./CU-SES-02-logout-global) | dev_golang/qa/seguridad |
| CU-SES-03 | Listado y Terminación Selectiva | 🟢 COMPLETED | [`CU-SES-03-gestion-sesiones`](./CU-SES-03-gestion-sesiones) | dev_golang/qa/seguridad |
| CU-SES-04 | Renovación Controlada y Detección de Reúso | 🟢 COMPLETED | [`CU-SES-04-token-rotation`](./CU-SES-04-token-rotation) | dev_golang/qa/seguridad |

## Módulo 5: Seguridad Proactiva y Defensa Enterprise
| ID | Caso de Uso | Estado | Carpeta Spec | Responsable / Agente |
| :--- | :--- | :---: | :--- | :--- |
| CU-SEC-01 | Bloqueo por Intentos Fallidos (Brute Force) | 🔵 READY_FOR_DEV | [`CU-SEC-01-brute-force`](./CU-SEC-01-brute-force) | asistente_de_preguntas |
| CU-SEC-02 | Rate Limiting y Throttling | 🔵 READY_FOR_DEV | [`CU-SEC-02-rate-limiting`](./CU-SEC-02-rate-limiting) | asistente_de_preguntas |
| CU-SEC-03 | Detección de Viaje Imposible | 🔵 READY_FOR_DEV | [`CU-SEC-03-impossible-travel`](./CU-SEC-03-impossible-travel) | asistente_de_preguntas |
| CU-SEC-04 | Trazabilidad y Logs de Auditoría | 🔵 READY_FOR_DEV | [`CU-SEC-04-audit-trail`](./CU-SEC-04-audit-trail) | asistente_de_preguntas |
| CU-SEC-05 | Eliminación de Cuenta (Right to be Forgotten) | 🔵 READY_FOR_DEV | [`CU-SEC-05-derecho-olvido`](./CU-SEC-05-derecho-olvido) | asistente_de_preguntas |
| CU-SEC-06 | Gestión de Roles y Alcances (RBAC) | 🔵 READY_FOR_DEV | [`CU-SEC-06-rbac-scopes`](./CU-SEC-06-rbac-scopes) | asistente_de_preguntas |
| CU-SEC-07 | Detección de Dispositivo Desconocido | 🔵 READY_FOR_DEV | [`CU-SEC-07-device-fingerprint`](./CU-SEC-07-device-fingerprint) | asistente_de_preguntas |

## Módulo 6: Identidades Máquina a Máquina (M2M)
| ID | Caso de Uso | Estado | Carpeta Spec | Responsable / Agente |
| :--- | :--- | :---: | :--- | :--- |
| CU-M2M-01 | Client Credentials Grant | 🔵 READY_FOR_DEV | [`CU-M2M-01-client-credentials`](./CU-M2M-01-client-credentials) | asistente_de_preguntas |
| CU-M2M-02 | Gestión de API Keys | 🔵 READY_FOR_DEV | [`CU-M2M-02-api-keys`](./CU-M2M-02-api-keys) | asistente_de_preguntas |

## Módulo 7: Criptografía y JWKS
| ID | Caso de Uso | Estado | Carpeta Spec | Responsable / Agente |
| :--- | :--- | :---: | :--- | :--- |
| CU-CRYP-01 | Publicación de JWKS Discovery | 🔵 READY_FOR_DEV | [`CU-CRYP-01-jwks-discovery`](./CU-CRYP-01-jwks-discovery) | asistente_de_preguntas |
| CU-CRYP-02 | Rotación Programada de Claves Maestras | 🔵 READY_FOR_DEV | [`CU-CRYP-02-rotacion-claves`](./CU-CRYP-02-rotacion-claves) | asistente_de_preguntas |
| CU-CRYP-03 | Mitigación de Desastres por Fuga | 🔵 READY_FOR_DEV | [`CU-CRYP-03-desastre-criptografico`](./CU-CRYP-03-desastre-criptografico) | asistente_de_preguntas |

## Módulo 8: Privacidad Avanzada y Cumplimiento
| ID | Caso de Uso | Estado | Carpeta Spec | Responsable / Agente |
| :--- | :--- | :---: | :--- | :--- |
| CU-PRIV-01 | Portabilidad de Datos Personales | 🔵 READY_FOR_DEV | [`CU-PRIV-01-portabilidad-datos`](./CU-PRIV-01-portabilidad-datos) | asistente_de_preguntas |
| CU-PRIV-02 | Gestión Granular de Consentimientos | 🔵 READY_FOR_DEV | [`CU-PRIV-02-gestion-consentimientos`](./CU-PRIV-02-gestion-consentimientos) | asistente_de_preguntas |
