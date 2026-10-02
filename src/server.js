import express from 'express';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { q, audit } from './db.js';

const { JWT_SECRET, PORT = 3000, CUTOFF = '10:00', NODE_ENV } = process.env;
if (!JWT_SECRET || JWT_SECRET.length < 32) throw new Error('JWT_SECRET debe tener al menos 32 caracteres.');
if (!process.env.DATABASE_URL) throw new Error('Falta DATABASE_URL (cadena de conexión de Neon).');

const TYPES = ['Invitado', 'Obra', 'Mantenimiento', 'Materiales', 'Cotización'];
const OWNER_TYPES = ['Invitado', 'Cotización', 'Materiales'];
const DUMMY = bcrypt.hashSync('no-user', 12);
const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: { directives: {
  defaultSrc: ["'self'"], scriptSrc: ["'self'", "'unsafe-inline'"], scriptSrcAttr: ["'unsafe-inline'"],
  styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'], fontSrc: ['https://fonts.gstatic.com'],
  imgSrc: ["'self'", 'data:'], connectSrc: ["'self'"] } } }));
app.use(express.json({ limit: '50kb' }));
app.use(cookieParser());

const wrap = f => (req, res, next) => f(req, res).catch(next);
const bad = (res, msg, code = 400) => res.status(code).json({ error: msg });

// Autenticación + autorización por rol (revalida al usuario en cada request)
const auth = (...roles) => async (req, res, next) => {
  try {
    const t = jwt.verify(req.cookies.plh, JWT_SECRET);
    const [u] = await q('select id, full_name, role, unit_id from users where id=$1 and active', [t.sub]);
    if (!u) throw new Error('inactivo');
    if (roles.length && !roles.includes(u.role)) return bad(res, 'No tienes permiso para esta acción.', 403);
    req.user = u; next();
  } catch { bad(res, 'Tu sesión venció. Ingresa de nuevo.', 401); }
};
const pub = u => ({ id: u.id, name: u.full_name, role: u.role });

// ---------- Auth ----------
app.post('/api/auth/login', rateLimit({ windowMs: 15 * 60e3, limit: 10, standardHeaders: true }), wrap(async (req, res) => {
  const email = String(req.body.email || '').trim(), pw = String(req.body.password || '');
  const [u] = await q('select * from users where lower(email)=lower($1) and active', [email]);
  const ok = await bcrypt.compare(pw, u?.password_hash || DUMMY);
  if (!u || !ok) { audit(null, 'login_fail', { email }); return bad(res, 'Correo o contraseña incorrectos.', 401); }
  res.cookie('plh', jwt.sign({ sub: u.id }, JWT_SECRET, { expiresIn: '8h' }),
    { httpOnly: true, sameSite: 'strict', secure: NODE_ENV === 'production', maxAge: 8 * 36e5 });
  audit(u.id, 'login'); res.json({ user: pub(u) });
}));
app.post('/api/auth/logout', (req, res) => { res.clearCookie('plh'); res.json({ ok: true }); });
app.get('/api/auth/me', auth(), (req, res) => res.json({ user: pub(req.user) }));

// ---------- Unidades ----------
app.get('/api/units', auth('admin', 'propietario'), wrap(async (req, res) => {
  const { role, unit_id } = req.user;
  const units = role === 'admin'
    ? await q(`select id, code, owner_name owner, lot, partida, is_club, apto, reason,
        to_char(exception_until,'YYYY-MM-DD') exc from units order by is_club desc, code`)
    : await q('select id, lot, owner_name owner from units where id=$1', [unit_id]);
  res.json({ units });
}));
app.patch('/api/units/:id', auth('admin'), wrap(async (req, res) => {
  const f = [], v = [], b = req.body;
  if ('apto' in b) { v.push(!!b.apto); f.push(`apto=$${v.length}`); }
  if ('exc' in b) { v.push(b.exc || null); f.push(`exception_until=$${v.length}`); }
  if ('reason' in b) { v.push(String(b.reason).slice(0, 300)); f.push(`reason=$${v.length}`); }
  if (!f.length) return bad(res, 'Nada que actualizar.');
  v.push(req.params.id);
  await q(`update units set ${f.join(',')} where id=$${v.length}`, v);
  audit(req.user.id, 'unit_update', { id: req.params.id, ...b }); res.json({ ok: true });
}));

// ---------- Pases ----------
app.get('/api/passes', auth('admin', 'porteria', 'propietario'), wrap(async (req, res) => {
  const own = req.user.role === 'propietario' ? req.user.unit_id : null;
  const passes = await q(`select p.id, p.type, p.name, p.doc, p.work, u.lot, u.code,
      coalesce((select sum(case when l.kind='in' then l.people else -l.people end)
                from access_logs l where l.pass_id=p.id),0)::int inside
    from passes p join units u on u.id=p.unit_id
    where p.visit_date=lima_today() and ($1::uuid is null or p.unit_id=$1) order by p.created_at`, [own]);
  res.json({ passes });
}));
app.post('/api/passes', auth('admin', 'propietario'), wrap(async (req, res) => {
  let { type, unit_id, name, doc = '', work = '' } = req.body;
  name = String(name || '').trim();
  if (!TYPES.includes(type) || !name) return bad(res, 'Completa el tipo y el nombre.');
  if (req.user.role === 'propietario') {
    if (!OWNER_TYPES.includes(type)) return bad(res, 'Solo administración registra este tipo de visita.', 403);
    unit_id = req.user.unit_id;
  }
  const [p] = await q(`insert into passes (type, unit_id, name, doc, work, created_by) values ($1,$2,$3,$4,$5,$6) returning id`,
    [type, unit_id, name.slice(0, 120), String(doc).slice(0, 60), String(work).slice(0, 160).toUpperCase(), req.user.id]);
  audit(req.user.id, 'pass_create', { id: p.id, type }); res.status(201).json({ id: p.id });
}));

// Regla única de acceso (el motivo de "no apto" nunca sale del servidor)
async function evaluate(id) {
  const [p] = await q(`select p.visit_date=lima_today() vigente,
      (u.apto or (u.exception_until is not null and u.exception_until>=lima_today())) habilitada
    from passes p join units u on u.id=p.unit_id where p.id=$1`, [id]);
  if (!p) return { ok: false, msg: 'Pase no encontrado.' };
  if (!p.vigente) return { ok: false, msg: 'El pase no está vigente para hoy.' };
  if (!p.habilitada) return { ok: false, msg: 'No autorizado. Comuníquese con administración.' };
  return { ok: true, msg: 'Autorizado' };
}
app.post('/api/passes/:id/verify', auth('admin', 'porteria'), wrap(async (req, res) => res.json(await evaluate(req.params.id))));
app.post('/api/passes/:id/log', auth('admin', 'porteria'), wrap(async (req, res) => {
  const { kind } = req.body, id = req.params.id;
  if (!['in', 'out'].includes(kind)) return bad(res, 'Tipo de registro inválido.');
  const [{ inside }] = await q(`select coalesce(sum(case when kind='in' then people else -people end),0)::int inside
    from access_logs where pass_id=$1`, [id]);
  let people;
  if (kind === 'in') {
    const e = await evaluate(id);
    if (!e.ok) return bad(res, e.msg, 403);
    people = Math.min(500, Math.max(1, parseInt(req.body.people) || 1));
  } else {
    people = inside;
    if (people <= 0) return bad(res, 'No hay personas dentro para registrar salida.');
  }
  await q('insert into access_logs (pass_id, kind, people, logged_by) values ($1,$2,$3,$4)', [id, kind, people, req.user.id]);
  res.json({ people });
}));

// ---------- Informe de las 10:00 ----------
app.get('/api/report', auth('admin', 'cctv'), wrap(async (req, res) => {
  const rows = await q(`select p.type, u.id uid, u.code, u.owner_name owner, u.lot, u.partida, p.name, p.work, sum(l.people)::int people
    from passes p join units u on u.id=p.unit_id
    join access_logs l on l.pass_id=p.id and l.kind='in' and (l.logged_at at time zone 'America/Lima')::time <= $1::time
    where p.visit_date=lima_today() and p.type in ('Obra','Mantenimiento')
    group by p.id, u.id order by u.code nulls last, p.name`, [CUTOFF]);
  const [r] = await q('select notes, signer from daily_reports where report_date=lima_today()');
  const props = [...new Map(rows.map(x => [x.uid, x])).values()];
  res.json({ obra: rows.filter(x => x.type === 'Obra'), mant: rows.filter(x => x.type === 'Mantenimiento'),
    props, notes: r?.notes || '', signer: r?.signer || 'Operador de CCTV', cutoff: CUTOFF });
}));
app.put('/api/report/notes', auth('admin', 'cctv'), wrap(async (req, res) => {
  await q(`insert into daily_reports (report_date, notes, signer, updated_by) values (lima_today(),$1,$2,$3)
    on conflict (report_date) do update set notes=$1, signer=$2, updated_by=$3, updated_at=now()`,
    [String(req.body.notes || '').slice(0, 4000), String(req.body.signer || '').slice(0, 80), req.user.id]);
  res.json({ ok: true });
}));

app.get('/api/health', (req, res) => res.json({ ok: true }));
app.use(express.static(path.join(path.dirname(fileURLToPath(import.meta.url)), '../public')));
app.use('/api', (req, res) => bad(res, 'Ruta no encontrada.', 404));
app.use((e, req, res, next) => { console.error(e); bad(res, e.code === '22P02' ? 'Dato inválido.' : 'Error interno del servidor.', e.code === '22P02' ? 400 : 500); });
if (!process.env.VERCEL) app.listen(PORT, () => console.log(`Playa Honda · Control de ingresos en http://localhost:${PORT}`));

export default app;
