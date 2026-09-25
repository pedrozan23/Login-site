// Configuração de cada provedor suportado.

export const PROVIDERS = {
  google: {
    authorizationEndpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenEndpoint: 'https://oauth2.googleapis.com/token',
    issuer: 'https://accounts.google.com',
    jwksEndpoint: 'https://www.googleapis.com/oauth2/v3/certs',
    scope: 'openid email profile',
    usesNonce: true,
  },
  github: {
    authorizationEndpoint: 'https://github.com/login/oauth/authorize',
    tokenEndpoint: 'https://github.com/login/oauth/access_token',
    userEndpoint: 'https://api.github.com/user',
    revokeEndpoint: (clientId) => `https://api.github.com/applications/${clientId}/grant`,
    scope: null,
    usesNonce: false,
  },
};

export function getClientId(env, provider) {
  return provider === 'google' ? env.GOOGLE_CLIENT_ID : env.GITHUB_CLIENT_ID;
}

export function getClientSecret(env, provider) {
  return provider === 'google' ? env.GOOGLE_CLIENT_SECRET : env.GITHUB_CLIENT_SECRET;
}
