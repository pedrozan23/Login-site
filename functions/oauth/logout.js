import { getCookie, clearCookie } from '../_shared/cookies.js';
import { sha256Hex } from '../_shared/crypto.js';

export async function onRequestPost(context) {
  const { request, env } = context;

  const origin = request.headers.get('Origin');
  if (origin !== env.PUBLIC_BASE_URL) {
    return new Response('Origem inválida.', { status: 403, headers: { 'Cache-Control': 'no-store' } });
  }

  const sessionId = getCookie(request, '__Host-session');
  if (sessionId) {
    const idHash = await sha256Hex(sessionId);
    await env.DB.prepare('DELETE FROM sessions WHERE id_hash = ?').bind(idHash).run();
  }

  const headers = new Headers();
  headers.set('Location', env.PUBLIC_BASE_URL);
  headers.append('Set-Cookie', clearCookie('__Host-session'));
  headers.set('Cache-Control', 'no-store');
  return new Response(null, { status: 303, headers });
}