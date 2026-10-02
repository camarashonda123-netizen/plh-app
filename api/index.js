import app from '../src/server.js';

export default function handler(req, res) {
  const target = req.query?.path;
  const route = Array.isArray(target) ? target.join('/') : String(target || '');
  if (route) {
    const url = new URL(req.url || '/', 'http://localhost');
    url.pathname = `/api/${route}`;
    url.searchParams.delete('path');
    req.url = `${url.pathname}${url.search}`;
  }
  return app(req, res);
}