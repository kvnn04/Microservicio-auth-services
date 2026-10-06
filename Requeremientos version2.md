# Especificación de Casos de Uso y Requerimientos Funcionales
## Microservicio de Autenticación, Registro y Gestión de Identidades (Nivel Enterprise)

---

## 1. Módulo: Flujo de Registro (Sign Up)

### CU-REG-01: Registro Clásico con Credenciales
* **Descripción:** Creación de cuenta mediante correo electrónico y contraseña con validaciones estrictas de formato, entropía y seguridad (sin uso de contraseñas vulnerables o expuestas en filtraciones).
* **Actores:** Usuario Anónimo, Microservicio de Autenticación.
* **Precondición:** El usuario no cuenta con una sesión iniciada.
* **Flujo Principal:**
  1. El usuario envía dirección de correo electrónico y contraseña.
  2. El sistema aplica normalización canónica al email y valida la fortaleza de la contraseña contra directivas de entropía y diccionarios de credenciales comprometidas.
  3. El sistema aplica un algoritmo de derivación de claves con factor de coste balanceado para almacenar la credencial de forma segura.
  4. La cuenta se persiste en estado `PENDIENTE_DE_VERIFICACION`.
  5. Se emite un evento asíncrono para despachar el código o enlace de verificación al correo provisto.
* **Validaciones de Seguridad:**
  * Validación sintáctica y canónica del email (normalización a minúsculas, eliminación de caracteres espurios).
  * Política de contraseñas de alta seguridad (longitud mínima, mezcla de caracteres, comprobación contra filtraciones conocidas).
  * Hashing seguro de contraseña con coste computacional antes de persistir.
  * La cuenta no permite emitir credenciales de sesión funcionales hasta completar la confirmación.

### CU-REG-02: Verificación de Identidad Obligatoria
* **Descripción:** Envío automático y validación de códigos de un solo uso (OTP) o enlaces mágicos por email antes de activar la cuenta.
* **Actores:** Usuario, Microservicio de Autenticación, Proveedor de Mensajería/Email.
* **Precondición:** Cuenta creada en estado pendiente; token de verificación generado.
* **Flujo Principal:**
  1. El usuario introduce el código OTP o pulsa sobre el enlace de verificación recibido.
  2. El sistema comprueba la existencia, estado y vigencia temporal del token.
  3. El sistema valida la coincidencia criptográfica del secreto presentado.
  4. Tras la validación exitosa, la cuenta pasa a estado `ACTIVA`.
  5. El token utilizado queda destruido de forma atómica e inmediata.
* **Validaciones de Seguridad:**
  * Token/OTP de un solo uso con ventana de vida corta (TTL configurable, ej. 15 minutos).
  * Límite estricto de reintentos de ingreso del código (ej. 3 fallos invalidan el código actual).
  * Invalidación inmediata del token una vez consumido para evitar ataques de repetición.

### CU-REG-03: Validación de Unicidad en Tiempo Real
* **Descripción:** Comprobación de existencia del correo electrónico mitigando ataques de enumeración de cuentas.
* **Actores:** Usuario Anónimo, Microservicio de Autenticación.
* **Flujo Principal:**
  1. El usuario solicita el registro o chequeo de disponibilidad de un correo.
  2. El microservicio evalúa la existencia del identificador en el repositorio de identidades.
  3. Si el correo no existe, el flujo de registro prosigue con normalidad.
  4. Si el correo ya existe, el sistema retorna una respuesta idéntica o genérica en tiempo equivalente para no revelar la existencia previa del usuario.
  5. De forma asíncrona, se despacha un correo de seguridad al dueño legítimo notificando el intento de registro y ofreciendo enlaces de acceso o cambio de clave.
* **Validaciones de Seguridad:**
  * **Protección contra enumeración de identidades:** El endpoint no revela información mediante variaciones en los tiempos de respuesta (timing attacks) ni mensajes asimétricos.
  * Mitigación de recopilación automatizada de usuarios mediante controles defensivos perimetrales y respuestas ambiguas deliberadas.

### CU-REG-04: Registro Federado (Social Auth / OAuth2 / OIDC)
* **Descripción:** Creación de cuenta utilizando proveedores de identidad externos de confianza (Google, Apple, Microsoft, GitHub).
* **Actores:** Usuario, Proveedor de Identidad Externo (IdP), Microservicio de Autenticación.
* **Flujo Principal:**
  1. El usuario inicia el flujo de autenticación federada y es redirigido al IdP con parámetros de seguridad criptográficos (`state`, `nonce`, `code_challenge`).
  2. El usuario autoriza en el IdP y el sistema recibe el código de autorización junto con el `state`.
  3. El microservicio intercambia el código por tokens del IdP y valida criptográficamente las firmas e integridad de las aserciones recibidas.
  4. Si el identificador federado no está registrado, se crea la cuenta asociándola al proveedor externo.
  5. Si el correo provisto por el IdP se encuentra certificado como verificado, la cuenta se inicializa directamente en estado `ACTIVA`.
* **Validaciones de Seguridad:**
  * Validación obligatoria de tokens ID (`id_token`), certificados y firmas criptográficas del proveedor.
  * Mapeo unívoco del identificador persistente del IdP (`sub`/`id`) con la cuenta local.
  * Mitigación de Cross-Site Request Forgery (CSRF) e inyección de tokens mediante validación de `state`, `nonce` y `PKCE`.

### CU-REG-05: Aceptación de Términos y Políticas (Compliance & Legal)
* **Descripción:** Registro obligatorio del consentimiento explícito del usuario a los términos de servicio, políticas de privacidad y procesamiento de datos.
* **Actores:** Usuario, Microservicio de Autenticación.
* **Flujo Principal:**
  1. El sistema presenta las versiones activas de los acuerdos legales durante el registro.
  2. El usuario confirma de forma afirmativa y explícita la aceptación de los términos.
  3. El sistema valida la integridad de la versión aceptada y vincula el registro de consentimiento a la cuenta creada.
* **Validaciones de Seguridad:**
  * Registro inmutable del identificador de la versión específica de términos aceptada, marca de tiempo UTC y dirección de red de origen.
  * Imposibilidad funcional de completar el registro sin un consentimiento afirmativo registrado.

### CU-REG-06: Vinculación y Desvinculación de Cuentas Federadas (Account Linking)
* **Descripción:** Asociación de múltiples proveedores de identidad a una misma cuenta corporativa preexistente.
* **Actores:** Usuario Autenticado, Microservicio de Autenticación, Proveedor Externo.
* **Precondición:** Sesión autenticada activa con verificación reforzada.
* **Flujo Principal:**
  1. El usuario autenticado solicita enlazar un nuevo proveedor de identidad.
  2. Se completa la autenticación ante el IdP externo.
  3. El microservicio valida que la nueva identidad externa no pertenezca a otra cuenta del sistema.
  4. Se crea el enlace formal entre el identificador del IdP y la cuenta del usuario.
  5. En caso de desvinculación, el sistema valida que el usuario mantenga al menos un método alternativo de acceso antes de disolver el enlace.
* **Validaciones de Seguridad:**
  * Prohibición absoluta de desvincular el único factor de autenticación configurado en la cuenta.
  * Requerimiento de autenticación reforzada previa para prevenir secuestro de cuenta por enlace no autorizado.

---

## 2. Módulo: Flujo de Inicio de Sesión (Sign In)

### CU-AUTH-01: Autenticación Estándar
* **Descripción:** Validación segura de credenciales contra el repositorio de identidades.
* **Actores:** Usuario, Microservicio de Autenticación.
* **Flujo Principal:**
  1. El usuario envía identificador y contraseña.
  2. El microservicio recupera el registro de la cuenta mediante operaciones de tiempo homogéneo.
  3. Se evalúa el hash de la contraseña contra el secreto almacenado.
  4. El sistema comprueba que la cuenta se encuentre en estado `ACTIVA` y no posea bloqueos preventivos vigentes.
  5. Si el usuario no tiene MFA configurado, se emite el par de tokens de sesión; de lo contrario, se genera un token temporal de desafío MFA.
* **Validaciones de Seguridad:**
  * Comparación resistente a ataques de temporización (timing attacks).
  * Mensajería de error genérica ("Credenciales incorrectas") para impedir la distinción entre usuario inexistente y clave errónea.
  * Verificación del estado de ciclo de vida de la cuenta antes de emitir cualquier derecho de sesión.

### CU-AUTH-02: Autenticación Multifactor (MFA / 2FA)
* **Descripción:** Segundo factor de verificación obligatorio o condicional mediante algoritmos de contraseñas de un solo uso basadas en tiempo (TOTP).
* **Actores:** Usuario, Microservicio de Autenticación.
* **Precondición:** Validación exitosa de credenciales primarias y posesión de token de pre-autenticación.
* **Flujo Principal:**
  1. El usuario suministra el código TOTP generado por su aplicación autenticadora junto con su token de pre-autenticación.
  2. El microservicio valida la autenticidad y vigencia del token de pre-autenticación.
  3. Se calcula el código esperado evaluando la ventana de tiempo actual y las adyacentes inmediatas sobre el secreto compartido del usuario.
  4. Si coincide y el código no ha sido utilizado en la misma ventana, se completa la autenticación emitiendo los tokens de sesión finales.
* **Validaciones de Seguridad:**
  * El token de pre-autenticación no permite acceder a recursos protegidos de negocio, únicamente al endpoint de resolución MFA.
  * Registro de códigos consumidos dentro de la ventana de tiempo para impedir ataques de repetición (replay attacks).

### CU-AUTH-03: Códigos de Respaldo para MFA (Backup Codes)
* **Descripción:** Generación, almacenamiento criptográfico y consumo de códigos de emergencia cuando el usuario carece de acceso a su generador TOTP.
* **Actores:** Usuario, Microservicio de Autenticación.
* **Flujo Principal:**
  1. Durante la activación de MFA, el microservicio genera un conjunto finito de códigos de rescate con alta entropía.
  2. El sistema almacena únicamente las representaciones hash de dichos códigos y los presenta al usuario para su resguardo.
  3. En un inicio de sesión sin TOTP, el usuario presenta uno de sus códigos de respaldo.
  4. El sistema valida el hash del código presentado, lo invalida de forma irreversible y otorga la sesión.
  5. Se emite una alerta de seguridad de alta prioridad al correo electrónico del usuario.
* **Validaciones de Seguridad:**
  * Los códigos de respaldo se persisten procesados mediante funciones hash seguras, impidiendo su recuperación en caso de filtración de datos.
  * Cada código es estrictamente de un solo uso y se destruye tras su consumo.

### CU-AUTH-04: Emisión y Gestión de Tokens Enterprise
* **Descripción:** Generación y entrega del par de tokens de sesión corporativos (Access Token y Refresh Token).
* **Actores:** Microservicio de Autenticación, Cliente.
* **Flujo Principal:**
  1. Tras una autenticación completa, el microservicio emite un Token de Acceso con ciclo de vida corto y claims mínimos necesarios.
  2. Se genera un Token de Renovación criptográficamente robusto, opaco o indexado, asociado a una familia de tokens.
  3. El sistema almacena la sesión en el repositorio de sesiones activas.
  4. Los tokens son transmitidos al cliente mediante mecanismos seguros de transporte.
* **Validaciones de Seguridad:**
  * Token de Acceso firmado con clave asimétrica, con ciclo de vida corto (ej. 5 a 15 minutos).
  * Token de Renovación entregado en entornos web exclusivamente a través de cookies con atributos de máxima protección (`HttpOnly`, `Secure`, `SameSite`).

### CU-AUTH-05: Inicio de Sesión sin Contraseña (Passwordless)
* **Descripción:** Acceso directo mediante enlace firmado temporal (Magic Link) o código unívoco enviado a canal seguro validado.
* **Actores:** Usuario, Microservicio de Autenticación, Servicio de Mensajería.
* **Flujo Principal:**
  1. El usuario solicita un acceso sin contraseña introduciendo su identificador de cuenta.
  2. El sistema genera un token de un solo uso criptográfico con ventana de expiración breve y lo despacha por canal seguro.
  3. El usuario consume el enlace o digita el código recibido.
  4. El sistema valida la integridad y vigencia del token de acceso temporal y emite los tokens de sesión definitivos.
* **Validaciones de Seguridad:**
  * Expiración ultra-corta del token de acceso (máximo 5 a 10 minutos).
  * Asociación defensiva con el contexto de emisión (huella del solicitante) para alertar si el consumo ocurre desde un entorno de red radicalmente diferente.
  * Inmediata invalidación atómica tras el primer intento de uso.

### CU-AUTH-06: Autenticación Reforzada (Step-Up Authentication)
* **Descripción:** Requerimiento dinámico de revalidación de identidad para autorizar operaciones de alto impacto dentro de una sesión ya iniciada.
* **Actores:** Usuario Autenticado, Microservicio de Autenticación.
* **Flujo Principal:**
  1. El usuario intenta ejecutar una mutación de seguridad crítica (ej. modificar credenciales, desactivar MFA o crear claves de acceso).
  2. El microservicio evalúa la marca de tiempo de la última autenticación completa registrada en el contexto del token.
  3. Si la antigüedad excede el umbral de seguridad (ej. 5 minutos), se suspende la operación y se exige la reintroducción de contraseña o factor MFA.
  4. Tras validar el desafío, se otorga una autorización temporal para proceder con la acción crítica.
* **Validaciones de Seguridad:**
  * Aislamiento de privilegios en el token: el token de elevación Step-Up solo posee vigencia momentánea y alcance acotado a la operación crítica en curso.

---

## 3. Módulo: Recuperación y Gestión de Credenciales

### CU-CRED-01: Recuperación de Contraseña ("Olvidé mi contraseña")
* **Descripción:** Flujo que genera un token temporal de un solo uso para reestablecer la clave de acceso.
* **Actores:** Usuario, Microservicio de Autenticación.
* **Flujo Principal:**
  1. El usuario introduce su correo solicitando restablecer su contraseña.
  2. El sistema emite una respuesta genérica estándar con independencia de si la cuenta existe o no.
  3. Si la cuenta existe, se genera un token temporal no predecible y se despacha por correo electrónico.
  4. El usuario accede al enlace y suministra una nueva contraseña que satisfaga las directivas de seguridad.
  5. El sistema actualiza la contraseña y revoca de forma masiva todas las sesiones abiertas del usuario.
* **Validaciones de Seguridad:**
  * Respuesta opaca que mitiga ataques de enumeración de cuentas.
  * Token no reutilizable con ventana de expiración breve (ej. 10 a 15 minutos).
  * Invalidación automática de todas las sesiones activas tras el cambio exitoso de clave.

### CU-CRED-02: Cambio de Contraseña desde la Sesión Activa
* **Descripción:** Actualización de contraseña por un usuario con sesión abierta, requiriendo confirmación obligatoria de la clave vigente.
* **Actores:** Usuario Autenticado, Microservicio de Autenticación.
* **Flujo Principal:**
  1. El usuario envía la contraseña actual y la nueva contraseña propuesta.
  2. El sistema valida la contraseña actual en tiempo constante.
  3. Se evalúa que la nueva clave no haya sido utilizada previamente por el usuario dentro del historial configurado.
  4. Se persiste el nuevo hash de contraseña y se actualiza el marcador de revocación de sesiones previas.
* **Validaciones de Seguridad:**
  * Validación obligatoria de la clave actual para mitigar accesos desatendidos o sesiones secuestradas.
  * Verificación de historial para impedir el reciclaje de las últimas $N$ contraseñas.
  * Cierre preventivo de todas las demás sesiones activas en otros dispositivos.

### CU-CRED-03: Actualización de Correo Electrónico
* **Descripción:** Modificación de la dirección de correo principal asegurando la posesión real de la nueva cuenta antes de hacer el cambio efectivo.
* **Actores:** Usuario Autenticado, Microservicio de Autenticación.
* **Flujo Principal:**
  1. El usuario solicita el cambio aportando el nuevo correo y resolviendo un desafío de re-autenticación.
  2. El sistema remite un token de confirmación a la nueva dirección propuesta.
  3. En paralelo, se emite una alerta de seguridad al correo electrónico actual.
  4. El usuario convalida el token desde el nuevo correo.
  5. El sistema efectúa la mutación de la dirección de correo y finaliza las sesiones preexistentes.
* **Validaciones de Seguridad:**
  * Requerimiento mandatorio de autenticación reforzada (Step-Up).
  * El cambio solo se consolida tras comprobar el control sobre la nueva casilla de destino.

---

## 4. Módulo: Control y Gestión de Sesiones

### CU-SES-01: Cierre de Sesión Individual (Logout)
* **Descripción:** Terminación intencional de la sesión en uso por parte del usuario.
* **Actores:** Usuario Autenticado, Microservicio de Autenticación.
* **Flujo Principal:**
  1. El cliente envía la solicitud de cierre de sesión.
  2. El microservicio revoca de forma inmediata el Token de Renovación en el repositorio de sesiones.
  3. El identificador del Token de Acceso (JTI) se incorpora a una lista de revocación inmediata en memoria hasta que expire su ciclo de vida natural.
  4. Se envían instrucciones al cliente para depurar las cookies de sesión.
* **Validaciones de Seguridad:**
  * Invalidación integral del par de tokens (acceso y renovación) impidiendo su reutilización posterior.

### CU-SES-02: Cierre de Sesión Global (Revocación Masiva)
* **Descripción:** Terminación inmediata de todas las sesiones activas en todos los clientes y plataformas vinculadas a la cuenta.
* **Actores:** Usuario Autenticado, Microservicio de Autenticación.
* **Flujo Principal:**
  1. El usuario solicita la finalización de todas sus sesiones activas.
  2. El sistema revoca en una sola operación atómica todos los Tokens de Renovación asociados a la cuenta.
  3. Se actualiza la marca temporal de corte (`tokens_valid_after`) en el registro del usuario.
  4. Cualquier Token de Acceso presentado con fecha de emisión previa a dicha marca temporal es rechazado inmediatamente por los componentes de verificación.
* **Validaciones de Seguridad:**
  * Corte instantáneo de sesiones concurrentes ante sospecha de robo de credenciales o pérdida de dispositivos.

### CU-SES-03: Listado y Terminación Selectiva de Sesiones Activas
* **Descripción:** Consulta estructurada de las sesiones abiertas asociadas a la identidad y revocación individual de accesos remotos.
* **Actores:** Usuario Autenticado, Microservicio de Autenticación.
* **Flujo Principal:**
  1. El usuario solicita la auditoría de sus sesiones activas.
  2. El sistema devuelve la lista de sesiones vigentes exponiendo metadatos operativos (dispositivo, sistema operativo, cliente, origen de red y última actividad registrada).
  3. El usuario selecciona una sesión remota específica y solicita su desconexión.
  4. El sistema revoca los tokens correspondientes a dicha sesión puntual sin degradar la sesión actual en uso.
* **Validaciones de Seguridad:**
  * Exposición exclusiva de metadatos no sensibles; nunca se transmiten ni reflejan los valores de los tokens de sesión.

### CU-SES-04: Renovación Controlada de Sesión y Detección de Reúso (Token Rotation)
* **Descripción:** Emisión de un nuevo par de credenciales de sesión mediante un Token de Renovación, con detección activa de robo.
* **Actores:** Cliente, Microservicio de Autenticación.
* **Flujo Principal:**
  1. El cliente presenta un Token de Renovación vigente para extender su sesión.
  2. El microservicio valida la pertenencia del token a una familia de sesiones activa y comprueba que no haya sido utilizado con anterioridad.
  3. El sistema invalida de forma inmediata el Token de Renovación recibido y emite un nuevo par de tokens (Access y Refresh).
  4. Si el token recibido ya figuraba como consumido previamente (detección de reúso), el sistema concluye que las credenciales fueron sustraídas e invalida inmediatamente a toda la familia de tokens asociada, revocando todas las sesiones del usuario de forma inmediata.
* **Validaciones de Seguridad:**
  * **Rotación obligatoria:** Cada Token de Renovación es de uso único y se reemplaza en cada ciclo.
  * **Detección y contención de robo:** La reutilización de un token revocado desencadena el bloqueo total de la sesión afectada y la notificación de incidente al titular.

---

## 5. Módulo: Seguridad Proactiva, Resiliencia y Defensa Enterprise

### CU-SEC-01: Bloqueo de Cuenta por Intentos Fallidos (Brute Force Defense)
* **Descripción:** Suspensión preventiva progresiva del acceso ante reiterados fallos de autenticación.
* **Actores:** Atacante/Usuario, Microservicio de Autenticación.
* **Flujo Principal:**
  1. El sistema contabiliza los intentos fallidos de acceso agrupando métricas por cuenta y por origen de red.
  2. Si los fallos consecutivos superan el umbral establecido dentro de una ventana temporal, la cuenta pasa a estado bloqueado temporalmente.
  3. Se rechazan solicitudes posteriores durante el tiempo de penalización.
  4. Se despacha una alerta informativa de seguridad al titular legítimo de la cuenta.
* **Validaciones de Seguridad:**
  * Incremento exponencial del tiempo de bloqueo ante reincidencias continuadas.
  * Contadores y bloqueos mantenidos en almacenamiento de alta velocidad con expiración automática.

### CU-SEC-02: Control de Tasa de Peticiones (Rate Limiting y Throttling)
* **Descripción:** Regulación del volumen máximo de solicitudes para mitigar ataques de denegación de servicio o barrido de contraseñas.
* **Actores:** Cliente de Red, Microservicio de Autenticación.
* **Flujo Principal:**
  1. Cada petición entrante es evaluada contra las políticas de cuota asociadas a su dirección de red y ruta de destino.
  2. Si la tasa sobrepasa el límite establecido para la ventana móvil, la petición es denegada de forma inmediata retornando un estado de sobrecarga (`429 Too Many Requests`) e indicando el tiempo de reintento.
* **Validaciones de Seguridad:**
  * Políticas diferenciadas: cuotas estrictas sobre endpoints sensibles (`/login`, `/register`, `/forgot-password`) y moderadas sobre consultas estándar.

### CU-SEC-03: Detección de Comportamiento Anómalo e Imposibilidad Física (Impossible Travel)
* **Descripción:** Evaluación contextual de la solicitud determinando inconsistencias físicas de traslado y acceso.
* **Actores:** Microservicio de Autenticación, Sistemas de Inteligencia Geográfica.
* **Flujo Principal:**
  1. Al recibir un intento de acceso, se analizan los metadatos de geolocalización respecto de la última sesión registrada.
  2. El sistema calcula la velocidad requerida para trasladarse entre ambas coordenadas geográficas.
  3. Si la velocidad excede los parámetros físicamente plausibles (viaje imposible), se bloquea la emisión de la sesión directa y se demanda una validación obligatoria por factor secundario (MFA).
* **Validaciones de Seguridad:**
  * Bloqueo adaptativo de autenticaciones anómalas sin degradar la experiencia de usuarios que se desplazan de forma legítima.

### CU-SEC-04: Trazabilidad y Logs de Auditoría Inmutables (Audit Trail)
* **Descripción:** Registro estructurado, desacoplado y protegido de la totalidad de eventos de identidad.
* **Actores:** Microservicio de Autenticación, Subsistema de Auditoría.
* **Flujo Principal:**
  1. Cada mutación, intento de autenticación y cambio administrativo genera un evento de auditoría unificado.
  2. El evento es transmitido de forma asíncrona hacia el broker de eventos.
  3. Los eventos son registrados con marcas de tiempo verificables y datos de correlación técnica.
* **Validaciones de Seguridad:**
  * Sanitización mandatoria: exclusión total de secretos, contraseñas y datos no enmascarados de los eventos.
  * Inmutabilidad e integridad de los registros frente a manipulaciones posteriores.

### CU-SEC-05: Eliminación de Cuenta y Derecho al Olvido (Data Privacy)
* **Descripción:** Proceso regulatorio para la supresión definitiva o anonimización de la cuenta y sus datos personales asociados.
* **Actores:** Usuario Autenticado, Microservicio de Autenticación.
* **Precondición:** Identidad verificada con autenticación reforzada.
* **Flujo Principal:**
  1. El usuario solicita la supresión definitiva de su identidad.
  2. Se ejecuta una confirmación reforzada (Step-Up).
  3. El sistema marca la cuenta en período de gracia ("soft delete") e invalida todas las sesiones vigentes.
  4. Vencido el período legal de gracia sin revocación de la solicitud, se destruyen o anonimizan los datos de identidad.
  5. Se emite un evento al ecosistema corporativo para que los servicios downstream depuren o disocien los datos del usuario.
* **Validaciones de Seguridad:**
  * Cancelación instantánea del acceso y de la capacidad de autenticación desde el momento de la solicitud.
  * Preservación disociada y aislada de aquellos datos que por mandato fiscal o legal requieran retención obligatoria durante un plazo estipulado.

### CU-SEC-06: Gestión de Roles y Alcances (RBAC / Scopes)
* **Descripción:** Inclusión y verificación de roles y permisos asociados a la identidad para consumo distribuido.
* **Actores:** Microservicio de Autenticación, Servicios Satélites.
* **Flujo Principal:**
  1. Durante la emisión del Token de Acceso, se resuelven los roles y alcances concedidos al usuario.
  2. Los permisos normalizados se encapsulan en las declaraciones firmadas (`claims`) del token.
  3. Ante una alteración administrativa en los privilegios de un usuario, se fuerza la revocación de sus sesiones para exigir la reemisión de tokens actualizados.
* **Validaciones de Seguridad:**
  * Concesión bajo el principio de menor privilegio.
  * Capacidad de invalidar de forma forzada tokens activos cuando se detectan degradaciones críticas de roles.

---

## 6. Módulo: Gestión de Identidades Máquina a Máquina (M2M & API Access)

### CU-M2M-01: Autenticación de Servicios Desatendidos (Client Credentials Grant)
* **Descripción:** Emisión de credenciales de acceso para aplicaciones internas, microservicios satélites o sistemas de terceros sin intervención humana directa.
* **Actores:** Servicio Cliente / Daemon, Microservicio de Autenticación.
* **Precondición:** El cliente cuenta con un identificador de cliente (`client_id`) y un secreto de cliente (`client_secret`) previamente aprovisionados.
* **Flujo Principal:**
  1. El servicio cliente realiza una solicitud de token autenticada transmitiendo sus credenciales corporativas y la lista de recursos/alcances (`scopes`) requeridos.
  2. El microservicio valida la existencia, el estado activo y la vigencia del par de credenciales mediante comparación en tiempo constante.
  3. El sistema evalúa si los alcances solicitados están formalmente concedidos al perfil del cliente (principio de menor privilegio).
  4. El sistema emite un token de acceso firmado con un tiempo de vida estrictamente acotado y sin capacidad de renovación por token de larga duración (sin Refresh Token).
  5. El sistema emite un evento de auditoría asíncrono registrando la autenticación exitosa del servicio.
* **Validaciones de Seguridad:**
  * **Almacenamiento Criptográfico de Secretos:** Los secretos de cliente jamás se persisten en texto plano en el repositorio de datos; deben almacenarse aplicando funciones hash criptográficas unidireccionales de alta entropía.
  * **Ausencia de Refresh Tokens:** Los clientes M2M no reciben tokens de renovación; deben autenticarse nuevamente al expirar el token de acceso para forzar la revalidación constante de sus permisos.
  * **Enlace Opcional de Red:** Capacidad de restringir la validez de las credenciales a listas de direcciones de red u orígenes autorizados (CIDR allowlisting).

### CU-M2M-02: Creación, Rotación y Revocación de Claves de API (API Keys)
* **Descripción:** Gestión del ciclo de vida de claves de acceso delegadas para desarrolladores o integraciones de terceros.
* **Actores:** Usuario Administrador, Microservicio de Autenticación.
* **Precondición:** Identidad autenticada con permisos suficientes de administración.
* **Flujo Principal:**
  1. El administrador solicita la generación de una nueva clave de API asignando nombre, fecha límite de expiración y un conjunto restrictivo de permisos.
  2. El microservicio genera una clave criptográfica de alta entropía dividida conceptualmente en dos partes: un prefijo identificador público y un secreto de alta entropía.
  3. El sistema persiste el prefijo junto con el hash unidireccional del secreto, asociándolo a las directivas de acceso.
  4. El sistema retorna la clave completa al solicitante advirtiendo que solo será visible una única vez en la interfaz.
  5. Ante una rotación, se genera una nueva clave permitiendo un período de solapamiento controlado (ej. 24 horas) para evitar caídas operativas antes de la revocación automática de la clave anterior.
* **Validaciones de Seguridad:**
  * **Visualización Única:** El secreto de la clave de API nunca es recuperable ni legible por administradores ni operadores una vez generado.
  * **Prefijos Estructurados:** Utilización de prefijos identificables para auditoría y escaneo proactivo de código (secret scanning).
  * **Revocación Inmediata:** La invalidación de una clave propaga su inhabilitación en estructuras en memoria de acceso ultra-rápido de forma atómica.

---

## 7. Módulo: Gestión Criptográfica, Federación y Recuperación de Desastres

### CU-CRYP-01: Publicación de Metadatos y Claves Públicas (JWKS Discovery)
* **Descripción:** Exposición estandarizada de las firmas públicas del sistema para permitir que los servicios y pasarelas de la arquitectura validen tokens de forma autónoma y desacoplada.
* **Actores:** Servicios Consumidores / API Gateway, Microservicio de Autenticación.
* **Precondición:** Par de claves asimétricas maestras cargadas y activas en el servicio.
* **Flujo Principal:**
  1. Un servicio consumidor envía una solicitud de lectura al endpoint público de descubrimiento criptográfico (ej. `/.well-known/jwks.json`).
  2. El microservicio responde con la colección de claves públicas activas, estructuradas con sus respectivos identificadores de clave (`kid`), algoritmo de firma y tipo de uso criptográfico.
  3. El cliente almacena temporalmente las claves públicas respetando las cabeceras de control de caché emitidas por el servicio.
* **Validaciones de Seguridad:**
  * **Aislamiento Criptográfico Estricto:** Bajo ninguna circunstancia los componentes de clave privada son expuestos o cargados fuera del enclave seguro o almacén protegido del microservicio.
  * **Identificación Unívoca de Clave:** Cada token emitido por el sistema debe contener en su encabezado el identificador unívoco de la clave (`kid`) que lo firmó, permitiendo validaciones multiclave concurrentes.

### CU-CRYP-02: Rotación Programada de Claves Asimétricas Maestras
* **Descripción:** Reemplazo periódico y sin degradación de servicio de las claves criptográficas utilizadas para firmar tokens en todo el sistema.
* **Actores:** Proceso Programado del Sistema / Administrador de Ciberseguridad.
* **Precondición:** Clave primaria actual en uso y en proximidad a su fecha límite de renovación planificada.
* **Flujo Principal:**
  1. El sistema genera un nuevo par de claves asimétricas de alta seguridad identificadas con un nuevo identificador (`kid_nuevo`).
  2. La nueva clave pública se incorpora inmediatamente a la lista pública de claves (JWKS), coexistiendo con la clave pública previa (`kid_anterior`).
  3. Se inicia un período de transición donde las emisiones de nuevos tokens se realizan exclusivamente con la nueva clave (`kid_nuevo`), mientras que los servicios consumidores aún pueden validar tokens emitidos previamente usando la clave previa (`kid_anterior`).
  4. Una vez transcurrido el tiempo de vida máximo (TTL) del token de acceso más largo emitido con la clave previa, la clave anterior es retirada definitivamente de la lista de validación activa y archivada para propósitos de auditoría legal de datos históricos.
* **Validaciones de Seguridad:**
  * **Continuidad de Servicio:** La rotación no debe invalidar prematuramente tokens legítimos emitidos inmediatamente antes del procedimiento.
  * **Caché Defensiva:** Las cabeceras de respuesta del conjunto de claves públicas deben manejar tiempos de caducidad bajos durante las ventanas de rotación para mitigar lecturas obsoletas por parte de los servicios satélites.

### CU-CRYP-03: Mitigación de Desastres por Fuga o Compromiso de Secretos Criptográficos
* **Descripción:** Procedimiento de emergencia automatizado ante la sospecha o confirmación del compromiso de la clave privada de firma del sistema.
* **Actores:** Administrador de Ciberseguridad, Microservicio de Autenticación.
* **Precondición:** Alerta crítica de seguridad o activación manual del protocolo de desastre.
* **Flujo Principal:**
  1. El administrador invoca la orden de rotación de emergencia acompañada de la invalidación forzada de la clave comprometida.
  2. El microservicio retira de forma inmediata e irrevocable la clave comprometida de la lista pública de claves (JWKS).
  3. Se genera un nuevo par de claves asimétricas para la continuidad del servicio.
  4. El sistema actualiza de manera atómica el registro de corte global (`tokens_valid_after`) para la totalidad de las identidades registradas, invalidando de golpe la validez contextual de cualquier token previo.
  5. Se emite una alerta crítica a través del canal de eventos asíncronos para que todos los servicios y pasarelas depuren sus cachés locales de verificación.
  6. Se fuerzan cierres de sesión globales en el repositorio de sesiones, exigiendo la re-autenticación obligatoria de todos los usuarios del ecosistema.
* **Validaciones de Seguridad:**
  * **Rechazo Instantáneo:** Los servicios downstream que consulten el endpoint JWKS fallarán inmediatamente la validación de tokens firmados con la clave revocada, mitigando el uso de credenciales forjadas por atacantes.

---

## 8. Módulo: Privacidad Avanzada y Gobierno de Datos (GDPR & Compliance)

### CU-PRIV-01: Descarga y Portabilidad de Datos Personales (Right of Access / Portability)
* **Descripción:** Suministro al usuario de un paquete estructurado e interoperable que contenga la totalidad de los datos de identidad, perfiles, sesiones históricas y registros asociados a su cuenta.
* **Actores:** Usuario Autenticado, Microservicio de Autenticación.
* **Precondición:** Identidad con sesión activa y validación de autenticación reforzada completada.
* **Flujo Principal:**
  1. El usuario solicita la exportación de sus datos personales y registros de identidad.
  2. El microservicio exige una validación de Step-Up Authentication inmediata para autorizar la operación.
  3. El sistema encola un evento asíncrono de recolección de datos.
  4. El subsistema procesador consolida la información del usuario en un formato estandarizado y portable (ej. JSON/CSV).
  5. Se genera un enlace de descarga temporal y firmado, cifrado con una clave secreta efímera compartida únicamente mediante canal seguro con el usuario.
  6. Se notifica al correo electrónico registrado que la descarga está lista para ser ejecutada durante una ventana máxima de tiempo (ej. 24 horas).
* **Validaciones de Seguridad:**
  * **Cifrado en Tránsito y Reposo:** El archivo generado se almacena temporalmente cifrado antes de su descarga y se autodestruye tras expirar el enlace.
  * **Protección contra Extracción Masiva:** Límite estricto de frecuencia para peticiones de descarga (ej. 1 solicitud cada 7 o 30 días).

### CU-PRIV-02: Gestión Granular de Consentimientos y Revocación de Finalidades
* **Descripción:** Registro, auditoría y actualización pormenorizada de los consentimientos individuales otorgados por el usuario (ej. comunicaciones operativas vs. analítica vs. perfiles de seguridad).
* **Actores:** Usuario Autenticado, Microservicio de Autenticación.
* **Precondición:** Cuenta activa con consentimientos previamente registrados.
* **Flujo Principal:**
  1. El usuario consulta el panel de gestión de privacidad donde se desglosan las finalidades de tratamiento vigentes.
  2. El usuario modifica el estado de un consentimiento específico (habilitar o revocar).
  3. El microservicio persiste el cambio registrando de forma inmutable la versión del texto legal, la fecha y hora UTC, la dirección IP y el nuevo estado del consentimiento.
  4. El sistema emite un evento al broker de eventos para notificar a los microservicios satélites que deben suspender de inmediato el procesamiento de datos vinculado a dicha finalidad.
* **Validaciones de Seguridad:**
  * **Inmutabilidad del Registro de Auditoría:** Las trazas de consentimiento jamás deben sobrescribirse; cada mutación debe generar un nuevo registro histórico inalterable.
  * **Separación de Obligatoriedad:** El retiro de consentimientos no esenciales no debe condicionar el funcionamiento del inicio de sesión ni la prestación de las funcionalidades básicas de la cuenta.

---

## 9. Módulo: Verificación Adaptativa y Detección de Dispositivos

### CU-SEC-07: Notificación y Desafío ante Nuevo Dispositivo o Agente Desconocido
* **Descripción:** Identificación de inicios de sesión ejecutados desde combinaciones no reconocidas de clientes, navegadores o sistemas operativos, detonando contramedidas defensivas automáticas.
* **Actores:** Usuario, Microservicio de Autenticación, Servicio de Mensajería.
* **Precondición:** Credenciales primarias validadas exitosamente.
* **Flujo Principal:**
  1. Durante el inicio de sesión, el microservicio calcula y evalúa la huella criptográfica del dispositivo basada en los metadatos contextuales recibidos.
  2. El sistema contrasta dicha huella contra la lista de dispositivos previamente reconocidos y autorizados por el usuario.
  3. Si el dispositivo no coincide con ningún registro previo:
     * El sistema clasifica el inicio de sesión como "riesgo medio/alto".
     * Se emite un desafío de verificación adicional (envío de código OTP o enlace de confirmación fuera de banda) antes de entregar los tokens definitivos de sesión.
  4. Si la validación es satisfactoria, el dispositivo se incorpora a la lista de dispositivos de confianza del usuario.
  5. Se despacha de forma inmediata una alerta de seguridad por correo electrónico informando detalles del nuevo dispositivo (plataforma, navegador, origen de red y ubicación estimada) junto con un mecanismo de revocación de emergencia.
* **Validaciones de Seguridad:**
  * **Persistencia Criptográfica de la Huella:** La información de reconocimiento de hardware y cliente se almacena estructurada y firmada para evitar falsificaciones o manipulaciones de atributos.
  * **Enlace de Terminación Rápida:** El correo de alerta debe contener un mecanismo de invalidación instantánea que permita al usuario cerrar esa sesión específica con un solo clic si no reconoce la actividad.

---

## 10. Matriz de Requerimientos No Funcionales Enterprise

| Dimensión | Requisito del Sistema | Criterio de Verificación de Casos de Uso |
| :--- | :--- | :--- |
| **Seguridad Criptográfica** | Zero-Knowledge Secrets & Desacoplamiento JWKS | Las contraseñas jamás se almacenan ni viajan sin procesar. Los servicios validadores de tokens no acceden a claves privadas; verifican firmas vía el conjunto público de claves asimétricas (JWKS). |
| **Seguridad Operativa** | Rotación Cero Inactividad (Zero-Downtime Key Rollover) | La renovación de firmas maestras opera con coexistencia temporal de claves para no invalidar sesiones activas legítimas. |
| **Gobernanza / Privacidad** | Trazabilidad del Consentimiento e Inmutabilidad | Cada consentimiento otorgado o revocado genera un registro histórico inalterable con marca de tiempo UTC y huella verificable para cumplimiento normativo (GDPR/CCPA). |
| **Aislamiento** | Segregación de Flujos Máquina a Máquina (M2M) | La autenticación de servicios opera bajo Client Credentials, con emisión de tokens de corta vida sin capacidad de refresco y permisos estrictamente acotados. |
| **Velocidad** | Latencia de Validación de Acceso | La resolución de tokens y la verificación de sesiones en curso se resuelve en tiempos sub-milisegundos mediante almacenamiento en memoria de acceso ultra-rápido. |
| **Escalabilidad** | Verificación Descentralizada Stateless | Los servicios consumidores comprueban los tokens de acceso de manera autónoma validando la firma criptográfica sin generar llamadas bloqueantes a la base de datos central. |
| **Resiliencia** | Tolerancia a Fallos y Consistencia Eventual | Notificaciones, auditoría y análisis de patrones se ejecutan de manera desacoplada y asíncrona mediante eventos, aislando el login del usuario de la disponibilidad de sistemas externos. |
| **Optimización** | Gestión de Caché y Listas Negras Efímeras | Las listas de revocación y los contadores defensivos utilizan estructuras de alta velocidad sujetas a tiempos de vida automáticos (TTL). |