// Uso: PW='ClaveSegura123' npm run user:create -- correo@x.com "Nombre Apellido" admin|porteria|propietario|cctv [codigoUnidad]
import bcrypt from 'bcryptjs';
import { q, pool } from '../src/db.js';
const [email, name, role, unitCode] = process.argv.slice(2), pw = process.env.PW || '';
if (!email || !name || !['admin', 'porteria', 'propietario', 'cctv'].includes(role)) { console.error('Uso: PW=... npm run user:create -- correo "Nombre" rol [codigoUnidad]'); process.exit(1); }
if (pw.length < 10) { console.error('Define PW con al menos 10 caracteres.'); process.exit(1); }
let unit = null;
if (role === 'propietario') { [unit] = await q('select id from units where code=$1', [unitCode]); if (!unit) { console.error('Unidad no encontrada.'); process.exit(1); } }
await q('insert into users (email, full_name, role, unit_id, password_hash) values ($1,$2,$3,$4,$5)', [email, name, role, unit?.id ?? null, await bcrypt.hash(pw, 12)]);
console.log(`Usuario ${email} creado con rol ${role}.`);
await pool.end();
