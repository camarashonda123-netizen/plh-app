import pg from 'pg';
export const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL, max: 5, idleTimeoutMillis: 30000 });
export const q = (text, params) => pool.query(text, params).then(r => r.rows);
export const audit = (userId, action, detail = null) =>
  q('insert into audit_log (user_id, action, detail) values ($1,$2,$3)', [userId, action, detail]).catch(() => {});
