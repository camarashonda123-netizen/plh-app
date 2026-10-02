# Playa Honda · Control de ingresos

App web con autenticación por roles. Node.js + Express + PostgreSQL (Neon). El servidor entrega también el frontend (`public/`).

## Puesta en marcha
1. En Neon crea un proyecto y copia la cadena de conexión *pooled*.
2. Crea `.env` con `DATABASE_URL` y `JWT_SECRET` (`openssl rand -hex 32`).
3. `npm install`
4. `npm run db:migrate` (crea tablas y datos de ejemplo; ejecútalo una sola vez).
5. Crea el primer administrador:
   `PW='ClaveSegura123' npm run user:create -- admin@club.pe "Administración" admin`
6. `npm run dev` y abre http://localhost:3000

Otros usuarios (mismo comando, cambia el rol):
- `... -- porton@club.pe "Portero Turno 1" porteria`
- `... -- cctv@club.pe "Operador CCTV" cctv`
- `... -- prado@correo.pe "Fam. Prado Ríos" propietario 14` (el último dato es el código de su unidad)

## Roles
| Rol | Puede |
|---|---|
| admin | Todo: portería, registrar cualquier visita, unidades (estado, excepción, motivo), informe |
| porteria | Ver visitas de hoy, verificar y registrar entrada/salida. Nunca ve el motivo de "no apto" |
| propietario | Registrar invitados, cotizaciones y materiales de su propiedad; ver sus visitas |
| cctv | Informe de las 10:00: ver, editar observaciones, imprimir |

## Seguridad incluida
Contraseñas con bcrypt (12 rondas); sesión en cookie httpOnly + SameSite estricta (JWT de 8 h); permisos validados en el servidor en cada petición; límite de 10 intentos de login por 15 min; cabeceras de seguridad (Helmet); consultas parametrizadas; bitácora en `audit_log`.

## Publicar en Vercel
1. Importa el repositorio en Vercel y deja la carpeta raíz como directorio del proyecto. `vercel.json` publica `public/`; `api/[...path].js` atiende la API Express.
2. En **Settings > Environment Variables**, configura `DATABASE_URL` con la cadena pooled de Neon y `JWT_SECRET` con un valor generado por `openssl rand -hex 32`. Añade `CUTOFF` solo si quieres cambiar `10:00`. No subas `.env` a Git.
3. Ejecuta `npm run db:migrate` una sola vez contra Neon y crea el primer usuario desde un entorno seguro con esas variables: `PW='...' npm run user:create -- admin@club.pe "Administración" admin`.
4. Despliega desde Vercel o ejecuta `npx vercel --prod`. La app y `/api` comparten dominio; deja `public/config.js` con `PLH_API_BASE` vacío. Vercel sirve por HTTPS y configura la cookie segura en producción.

Para desarrollo local, instala las dependencias, crea `.env` con las mismas variables y ejecuta `npm run dev`.

## Otros proveedores
Render, Railway o Fly.io: comando de inicio `npm start`, variables de entorno igual que `.env`, `NODE_ENV=production` (activa cookie `secure`; requiere HTTPS).
