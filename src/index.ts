import type { NightplayRoom } from './nightplay-room.js';
import type { RoomEnv } from './nightplay-room.js';

export { NightplayRoom } from './nightplay-room.js';

interface Env extends RoomEnv {
  ASSETS: Fetcher;
  NIGHTPLAY_ROOM: DurableObjectNamespace<NightplayRoom>;
  TURNSTILE_SECRET?: string;
}

const ACCESS_COOKIE = 'gplay_access';
const ACCESS_TTL_SECONDS = 12 * 60 * 60;
const PRODUCTION_HOSTS = new Set(['gplay.ntpl2.workers.dev']);
const json = (data: unknown, status = 200, headers?: HeadersInit) => new Response(JSON.stringify(data), {
  status,
  headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...Object.fromEntries(new Headers(headers).entries()) },
});

function allowedHost(hostname: string): boolean {
  return PRODUCTION_HOSTS.has(hostname) || hostname === 'localhost' || hostname === '127.0.0.1';
}

async function signAccess(secret: string, payload: string): Promise<string> {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode('gplay-access-v1|' + payload));
  return Array.from(new Uint8Array(signature), byte => byte.toString(16).padStart(2, '0')).join('');
}

async function hasAccess(request: Request, secret: string): Promise<boolean> {
  const cookie = request.headers.get('Cookie') ?? '';
  const value = cookie.split(';').map(part => part.trim()).find(part => part.startsWith(ACCESS_COOKIE + '='))?.slice(ACCESS_COOKIE.length + 1);
  if (!value) return false;
  const parts = value.split('.');
  if (parts.length !== 3) return false;
  const [expiryText, nonce, supplied] = parts;
  const expiry = Number(expiryText);
  if (!/^\d{10}$/.test(expiryText) || !/^[0-9a-f-]{36}$/i.test(nonce) || !/^[0-9a-f]{64}$/.test(supplied) || expiry <= Math.floor(Date.now() / 1000)) return false;
  const expected = await signAccess(secret, expiryText + '.' + nonce);
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ supplied.charCodeAt(i);
  return diff === 0;
}

async function verifyTurnstile(request: Request, env: Env): Promise<Response> {
  if (!env.TURNSTILE_SECRET) return json({ error: 'verification_unavailable' }, 503);
  const url = new URL(request.url);
  if (!allowedHost(url.hostname)) return json({ error: 'hostname_not_allowed' }, 403);
  let body: any;
  try { body = await request.json(); } catch { return json({ error: 'bad_json' }, 400); }
  const token = typeof body?.token === 'string' ? body.token : '';
  if (!body?.adultConfirmed || !token || token.length > 2048) return json({ error: 'challenge_required' }, 400);

  let result: any;
  try {
    const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        secret: env.TURNSTILE_SECRET,
        response: token,
        remoteip: request.headers.get('CF-Connecting-IP') ?? '',
      }),
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) return json({ error: 'verification_unavailable' }, 503);
    result = await response.json();
  } catch {
    return json({ error: 'verification_unavailable' }, 503);
  }

  if (result?.success !== true || result?.action !== 'gplay_access' || result?.hostname !== url.hostname) {
    return json({ error: 'challenge_failed' }, 403);
  }

  const expiry = String(Math.floor(Date.now() / 1000) + ACCESS_TTL_SECONDS);
  const payload = expiry + '.' + crypto.randomUUID();
  const signature = await signAccess(env.TURNSTILE_SECRET, payload);
  const secure = url.protocol === 'https:' ? '; Secure' : '';
  return json({ ok: true, expiresAt: Number(expiry) }, 200, {
    'set-cookie': ACCESS_COOKIE + '=' + payload + '.' + signature + '; HttpOnly; SameSite=Lax; Path=/; Max-Age=' + ACCESS_TTL_SECONDS + secure,
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === '/api/access/verify' && request.method === 'POST') return verifyTurnstile(request, env);
    if (url.pathname === '/api/access/status' && request.method === 'GET') {
      if (!env.TURNSTILE_SECRET) return json({ verified: false, unavailable: true }, 503);
      return json({ verified: await hasAccess(request, env.TURNSTILE_SECRET) });
    }
    if (url.pathname.startsWith('/api/') && url.pathname !== '/api/health') {
      if (!env.TURNSTILE_SECRET || !await hasAccess(request, env.TURNSTILE_SECRET)) return json({ error: 'access_required' }, 401);
    }
    if (url.pathname === '/ws' && request.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
      if (!env.TURNSTILE_SECRET || !await hasAccess(request, env.TURNSTILE_SECRET)) return json({ error: 'access_required' }, 401);
      const id = env.NIGHTPLAY_ROOM.idFromName('nightplay-global-room-hub-v1');
      return env.NIGHTPLAY_ROOM.get(id).fetch(request);
    }
    if (url.pathname.startsWith('/api/')) {
      const id = env.NIGHTPLAY_ROOM.idFromName('nightplay-global-room-hub-v1');
      return env.NIGHTPLAY_ROOM.get(id).fetch(request);
    }
    return env.ASSETS.fetch(request);
  },
};
