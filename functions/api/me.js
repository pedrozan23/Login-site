import { getCookie } from '../_shared/cookies.js';
import { sha256Hex } from '../_shared/crypto.js';

export async function onRequestGet(context) {
  const { request, env } = context;
  const sessionId = getCookie(request, '__Host-session');
  if (!sessionId) {
    return Response.json({ error: 'not_authenticated' }, { status: 401, headers: { 'Cache-Control': 'no-store' } });
  }

  const idHash = await sha256Hex(sessionId);
  const row = await env.DB.prepare('SELECT * FROM sessions WHERE id_hash = ?').bind(idHash).first();
  const now = Math.floor(Date.now() / 1000);

  if (!row || row.expires_at < now) {
    return Response.json({ error: 'not_authenticated' }, { status: 401, headers: { 'Cache-Control': 'no-store' } });
  }

  return Response.json(
    { email: row.email, displayName: row.display_name },
    { headers: { 'Cache-Control': 'no-store' } }
  );
}
