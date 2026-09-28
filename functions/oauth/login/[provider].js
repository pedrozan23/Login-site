import { PROVIDERS, getClientId } from '../../_shared/providers.js';
import { randomToken, sha256Hex, sha256Base64Url } from '../../_shared/crypto.js';
import { buildTransactionCookie } from '../../_shared/cookies.js';

export async function onRequestGet(context) {
  const { env, params } = context;
  const provider = params.provider;

  if (provider !== 'google' && provider !== 'github') {
    return new Response('Not found', { status: 404 });
  }

  const config = PROVIDERS[provider];
  const clientId = getClientId(env, provider);

  const transactionId = randomToken();
  const state = randomToken();
  const nonce = config.usesNonce ? randomToken() : null;
  const codeVerifier = randomToken();
  const codeChallenge = await sha256Base64Url(codeVerifier);

  const idHash = await sha256Hex(transactionId);
  const stateHash = await sha256Hex(state);
  const expiresAt = Math.floor(Date.now() / 1000) + 600;

  await env.DB.prepare(
    `INSERT INTO oauth_transactions (id_hash, provider, state_hash, nonce, code_verifier, expires_at)
     VALUES (?, ?, ?, ?, ?, ?)`
  ).bind(idHash, provider, stateHash, nonce, codeVerifier, expiresAt).run();

  const redirectUri = `${env.PUBLIC_BASE_URL}/oauth/callback/${provider}`;
  const authUrl = new URL(config.authorizationEndpoint);
  authUrl.searchParams.set('client_id', clientId);
  authUrl.searchParams.set('redirect_uri', redirectUri);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('code_challenge', codeChallenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');
  if (config.scope) authUrl.searchParams.set('scope', config.scope);
  if (nonce) authUrl.searchParams.set('nonce', nonce);

  const headers = new Headers();
  headers.set('Location', authUrl.toString());
  headers.append('Set-Cookie', buildTransactionCookie(transactionId));
  headers.set('Cache-Control', 'no-store');
  return new Response(null, { status: 302, headers });
}
