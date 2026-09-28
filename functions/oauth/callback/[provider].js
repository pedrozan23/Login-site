import { PROVIDERS, getClientId, getClientSecret } from '../../_shared/providers.js';
import { randomToken, sha256Hex } from '../../_shared/crypto.js';
import { buildSessionCookie, clearCookie, getCookie } from '../../_shared/cookies.js';
import { verifyGoogleIdToken, confirmGitHubIdentity } from '../../_shared/oidc.js';

export async function onRequestGet(context) {
  const { request, env, params } = context;
  const provider = params.provider;
  if (provider !== 'google' && provider !== 'github') {
    return new Response('Not found', { status: 404 });
  }

  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const returnedState = url.searchParams.get('state');
  const error = url.searchParams.get('error');

  if (error || !code || !returnedState) {
    return new Response('Requisição de retorno inválida.', { status: 400, headers: { 'Cache-Control': 'no-store' } });
  }

  const transactionId = getCookie(request, '__Host-oauth-tx');
  if (!transactionId) {
    return new Response('Cookie de transação ausente.', { status: 400, headers: { 'Cache-Control': 'no-store' } });
  }

  const idHash = await sha256Hex(transactionId);
  const row = await env.DB.prepare('SELECT * FROM oauth_transactions WHERE id_hash = ?').bind(idHash).first();
  if (!row) {
    return new Response('Transação não encontrada, expirada ou já usada.', { status: 400, headers: { 'Cache-Control': 'no-store' } });
  }
  await env.DB.prepare('DELETE FROM oauth_transactions WHERE id_hash = ?').bind(idHash).run();

  const now = Math.floor(Date.now() / 1000);
  if (row.expires_at < now) {
    return new Response('Transação expirada.', { status: 400, headers: { 'Cache-Control': 'no-store' } });
  }
  if (row.provider !== provider) {
    return new Response('Provedor não corresponde à transação.', { status: 400, headers: { 'Cache-Control': 'no-store' } });
  }

  const stateHash = await sha256Hex(returnedState);
  if (stateHash !== row.state_hash) {
    return new Response('State inválido.', { status: 400, headers: { 'Cache-Control': 'no-store' } });
  }

  const config = PROVIDERS[provider];
  const clientId = getClientId(env, provider);
  const clientSecret = getClientSecret(env, provider);
  const redirectUri = `${env.PUBLIC_BASE_URL}/oauth/callback/${provider}`;

  const tokenResponse = await fetch(config.tokenEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      client_id: clientId,
      client_secret: clientSecret,
      code_verifier: row.code_verifier,
    }),
  });

  if (!tokenResponse.ok) {
    return new Response('Falha ao trocar o código pelo token.', { status: 400, headers: { 'Cache-Control': 'no-store' } });
  }
  const tokens = await tokenResponse.json();

  let identity;
  if (provider === 'google') {
    identity = await verifyGoogleIdToken(tokens.id_token, clientId, row.nonce);
  } else {
    if (!tokens.access_token || !/^bearer$/i.test(tokens.token_type || '')) {
      return new Response('Resposta de token inválida do GitHub.', { status: 400, headers: { 'Cache-Control': 'no-store' } });
    }
    identity = await confirmGitHubIdentity(tokens.access_token, clientId, clientSecret);
  }

  const sessionId = randomToken();
  const sessionHash = await sha256Hex(sessionId);
  await env.DB.prepare(
    `INSERT INTO sessions (id_hash, issuer, subject, email, display_name, expires_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).bind(sessionHash, identity.issuer, identity.subject, identity.email, identity.displayName, now + 28800, now).run();

  const headers = new Headers();
  headers.set('Location', env.PUBLIC_BASE_URL);
  headers.append('Set-Cookie', clearCookie('__Host-oauth-tx'));
  headers.append('Set-Cookie', buildSessionCookie(sessionId));
  headers.set('Cache-Control', 'no-store');
  return new Response(null, { status: 302, headers });
}