// Confirmação de identidade: valida o id_token do Google (JWT RS256)
// e consulta + revoga o access_token do GitHub.

import { base64UrlDecode, base64UrlToArrayBuffer } from './crypto.js';
import { PROVIDERS } from './providers.js';

export async function verifyGoogleIdToken(idToken, expectedAudience, expectedNonce) {
  const parts = idToken.split('.');
  if (parts.length !== 3) throw new Error('ID token malformado.');
  const [headerB64, payloadB64, signatureB64] = parts;

  const header = JSON.parse(base64UrlDecode(headerB64));
  if (header.alg !== 'RS256') throw new Error('Algoritmo inesperado no ID token.');

  const payload = JSON.parse(base64UrlDecode(payloadB64));
  const now = Math.floor(Date.now() / 1000);

  if (payload.iss !== PROVIDERS.google.issuer && payload.iss !== 'accounts.google.com') {
    throw new Error('Emissor (iss) inesperado.');
  }
  if (payload.aud !== expectedAudience) throw new Error('Audiência (aud) inesperada.');
  if (!payload.exp || payload.exp < now) throw new Error('ID token expirado.');
  if (!payload.iat || payload.iat > now + 60) throw new Error('iat inválido.');
  if (payload.nonce !== expectedNonce) throw new Error('Nonce inválido.');

  const jwks = await (await fetch(PROVIDERS.google.jwksEndpoint)).json();
  const jwk = jwks.keys.find((k) => k.kid === header.kid);
  if (!jwk) throw new Error('Chave pública não encontrada.');

  const key = await crypto.subtle.importKey(
    'jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']
  );
  const signedData = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const signature = base64UrlToArrayBuffer(signatureB64);
  const valid = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, signature, signedData);
  if (!valid) throw new Error('Assinatura do ID token inválida.');

  return { issuer: payload.iss, subject: payload.sub, email: payload.email, displayName: payload.name };
}

export async function confirmGitHubIdentity(accessToken, clientId, clientSecret) {
  const userResponse = await fetch(PROVIDERS.github.userEndpoint, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2026-03-10',
      'User-Agent': 'oauth-pages-lab',
    },
  });
  if (userResponse.status !== 200) throw new Error('Falha ao consultar /user no GitHub.');
  const user = await userResponse.json();
  if (typeof user.id !== 'number') throw new Error('Resposta do GitHub sem id numérico.');

  const basicAuth = btoa(`${clientId}:${clientSecret}`);
  const revokeResponse = await fetch(PROVIDERS.github.revokeEndpoint(clientId), {
    method: 'DELETE',
    headers: {
      Authorization: `Basic ${basicAuth}`,
      Accept: 'application/vnd.github+json',
      'Content-Type': 'application/json',
      'User-Agent': 'oauth-pages-lab',
    },
    body: JSON.stringify({ access_token: accessToken }),
  });
  if (revokeResponse.status !== 204) throw new Error('Falha ao revogar a autorização no GitHub.');

  return {
    issuer: 'https://github.com',
    subject: String(user.id),
    email: user.email || null,
    displayName: user.name || user.login,
  };
}
