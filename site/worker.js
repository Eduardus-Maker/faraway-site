/* ============================================================
   Cloudflare Worker — Arizona Faraway — 26
   Расширенная версия: GitHub CMS + роли + заявки модераторов
   ============================================================ */

const SESSION_TTL_SEC = 12 * 60 * 60;
const TEMP_TTL_SEC = 10 * 60;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const cors = corsHeaders(request);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }

    try {
      // --- Auth ---
      if (path === '/api/auth/tg-verify' && request.method === 'POST') return await tgVerify(request, env, cors);
      if (path === '/api/auth/tg-confirm' && request.method === 'POST') return await tgConfirm(request, env, cors);
      if (path === '/api/auth/logout' && request.method === 'POST') return await logout(request, env, cors);

      // --- Admin ---
      if (path === '/api/admin/me' && request.method === 'GET') return await adminMe(request, env, cors);
      if (path === '/api/admin/updates' && request.method === 'GET') return await getUpdates(request, env, cors);
      if (path === '/api/admin/site' && request.method === 'GET') return await getSite(request, env, cors);
      if (path === '/api/admin/site' && request.method === 'POST') return await setSite(request, env, cors);
      if (path === '/api/admin/posts' && request.method === 'GET') return await adminPostsList(request, env, cors);
      if (path.startsWith('/api/admin/posts/') && request.method === 'DELETE') {
        const id = path.split('/').pop();
        return await adminPostDelete(request, env, cors, id);
      }

      // --- GitHub CMS ---
      if (path === '/api/admin/github/list' && request.method === 'GET') return await githubList(request, env, cors);
      if (path === '/api/admin/github/file' && request.method === 'GET') return await githubRead(request, env, cors);
      if (path === '/api/admin/github/file' && request.method === 'POST') return await githubWrite(request, env, cors);

      // --- Site Config (вкл/выкл разделы) ---
      if (path === '/api/admin/config' && request.method === 'GET') return await getConfig(request, env, cors);
      if (path === '/api/admin/config' && request.method === 'POST') return await setConfig(request, env, cors);

      // --- Moderator Applications ---
      if (path === '/api/moderator/apply' && request.method === 'POST') return await createModApp(request, env, cors);
      if (path === '/api/admin/moderator/applications' && request.method === 'GET') return await listModApps(request, env, cors);
      if (path.startsWith('/api/admin/moderator/applications/') && request.method === 'DELETE') {
        const id = path.split('/').pop();
        return await deleteModApp(request, env, cors, id);
      }

      // --- Roles (Founder only) ---
      if (path === '/api/admin/roles' && request.method === 'GET') return await listRoles(request, env, cors);
      if (path === '/api/admin/roles' && request.method === 'POST') return await setRole(request, env, cors);

      // --- Public ---
      if (path === '/api/posts' && request.method === 'GET') return await postsList(env, cors);
      if (path === '/api/posts' && request.method === 'POST') return await postCreate(request, env, cors);
      if (path === '/api/site' && request.method === 'GET') return await getSitePublic(env, cors);
      if (path === '/api/site/config' && request.method === 'GET') return await getPublicConfig(env, cors);

      // --- Telegram Webhook ---
      if (path === '/api/tg/webhook' && request.method === 'POST') return await tgWebhook(request, env, cors);

      return json({ error: 'Not found: ' + path }, 404, cors);
    } catch (e) {
      return json({ error: e.message || 'Server error' }, 500, cors);
    }
  }
};

/* ============================================================
   CORS
   ============================================================ */
function corsHeaders(req){
  const origin = req.headers.get('Origin') || '*';
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Credentials': 'true',
    'Vary': 'Origin'
  };
}
function json(obj, status, cors){
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: Object.assign({ 'Content-Type': 'application/json' }, cors || {})
  });
}

/* ============================================================
   TELEGRAM HASH VERIFY
   ============================================================ */
async function verifyTelegramHash(data, botToken){
  const { hash, ...rest } = data;
  if(!hash) return false;
  const dataCheckString = Object.keys(rest).sort().map(k => k + '=' + rest[k]).join('\n');
  const enc = new TextEncoder();
  const secretKey = await crypto.subtle.importKey(
    'raw', enc.encode('WebAppData'),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const secret = await crypto.subtle.sign('HMAC', secretKey, enc.encode(botToken));
  const hmacKey = await crypto.subtle.importKey(
    'raw', secret, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', hmacKey, enc.encode(dataCheckString));
  const hex = [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
  return hex === hash;
}

/* ============================================================
   TG AUTH
   ============================================================ */
async function tgVerify(request, env, cors){
  const body = await request.json();
  let tgUser = null;

  if(body.initData){
    const params = new URLSearchParams(body.initData);
    const obj = {};
    for(const [k, v] of params) obj[k] = v;
    if(!await verifyTelegramHash(obj, env.BOT_TOKEN)) return json({ error: 'TG hash invalid' }, 401, cors);
    tgUser = JSON.parse(obj.user || '{}');
  } else if(body.user){
    if(!body.user.hash) return json({ error: 'No hash' }, 400, cors);
    if(!await verifyTelegramHash(body.user, env.BOT_TOKEN)) return json({ error: 'TG hash invalid' }, 401, cors);
    tgUser = body.user;
  } else {
    return json({ error: 'No TG data' }, 400, cors);
  }

  const role = await getRole(env, tgUser.id);
  if(!role) {
    return json({ error: 'У твоего Telegram-аккаунта нет доступа к админке. Обратись к основателю.' }, 403, cors);
  }

  if (body.password) {
    if (!env.ADMIN_PASSWORD || body.password !== env.ADMIN_PASSWORD) {
      return json({ error: 'Неверный пароль' }, 401, cors);
    }
  } else if (env.ADMIN_PASSWORD) {
    return json({ error: 'Требуется админ-пароль' }, 401, cors);
  }

  const code = String(Math.floor(100000 + Math.random() * 900000));
  const tempToken = crypto.randomUUID();
  await env.AZFW_KV.put('temp:' + tempToken, JSON.stringify({
    tg: tgUser,
    code,
    role,
    created_at: Date.now()
  }), { expirationTtl: TEMP_TTL_SEC });

  const ip = request.headers.get('CF-Connecting-IP') || '0.0.0.0';
  await sendTelegramMessage(env, tgUser.id,
    `🔐 <b>Arizona Faraway — 26</b>\n\nКод для входа:\n\n<code>${code}</code>\n\nРоль: <b>${role}</b>\nIP: <code>${ip}</code>\nКод действует 10 минут.`);

  return json({ status: 'code_sent', temp_token: tempToken }, 200, cors);
}

async function tgConfirm(request, env, cors){
  const { temp_token, code } = await request.json();
  if(!temp_token || !code) return json({ error: 'No data' }, 400, cors);

  const raw = await env.AZFW_KV.get('temp:' + temp_token);
  if(!raw) return json({ error: 'Код истёк, запроси новый' }, 400, cors);
  const session = JSON.parse(raw);
  if(session.code !== String(code)) return json({ error: 'Неверный код' }, 401, cors);

  await env.AZFW_KV.delete('temp:' + temp_token);

  const ip = request.headers.get('CF-Connecting-IP') || '0.0.0.0';
  const token = await signJwt({
    sub: session.tg.id,
    username: session.tg.username || ('id' + session.tg.id),
    name: session.tg.first_name || '',
    role: session.role,
    ip,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SEC
  }, env.JWT_SECRET);

  return json({ status: 'ok', token, username: session.tg.username || ('id' + session.tg.id), role: session.role }, 200, cors);
}

async function logout(request, env, cors){
  return json({ ok: true }, 200, cors);
}

/* ============================================================
   ADMIN AUTH MIDDLEWARE
   ============================================================ */
async function requireAdmin(request, env, cors){
  const auth = request.headers.get('Authorization') || '';
  const token = auth.replace(/^Bearer\s+/i, '');
  if(!token) throw { status: 401, message: 'No token' };
  const payload = await verifyJwt(token, env.JWT_SECRET);
  if(!payload) throw { status: 401, message: 'Token invalid/expired' };
  if(payload.role !== 'admin' && payload.role !== 'founder') {
    throw { status: 403, message: 'Недостаточно прав' };
  }

  const ip = request.headers.get('CF-Connecting-IP') || '0.0.0.0';
  if(payload.ip && payload.ip !== ip){
    await sendTelegramMessage(env, payload.sub,
      `⚠️ IP изменился!\nБыло: ${payload.ip}\nСтало: ${ip}\n\nВойди заново.`);
    throw { status: 401, message: 'IP changed — re-login required' };
  }
  return payload;
}

async function requireFounder(request, env, cors){
  const payload = await requireAdmin(request, env, cors);
  if(payload.role !== 'founder') {
    throw { status: 403, message: 'Только основатель может выполнять это действие' };
  }
  return payload;
}

async function adminMe(request, env, cors){
  try {
    const payload = await requireAdmin(request, env, cors);
    return json({ username: payload.username, id: payload.sub, role: payload.role }, 200, cors);
  } catch(e){
    return json({ error: e.message }, e.status || 401, cors);
  }
}

/* ============================================================
   UPDATES
   ============================================================ */
async function getUpdates(request, env, cors){
  try {
    await requireAdmin(request, env, cors);
    const raw = await env.AZFW_KV.get('updates:latest');
    return json(raw ? JSON.parse(raw) : { items: [] }, 200, cors);
  } catch(e){
    return json({ error: e.message }, e.status || 500, cors);
  }
}

/* ============================================================
   SITE (maintenance + config)
   ============================================================ */
async function getSite(request, env, cors){
  try {
    await requireAdmin(request, env, cors);
    const raw = await env.AZFW_KV.get('site:status');
    return json(raw ? JSON.parse(raw) : { maintenance: false }, 200, cors);
  } catch(e){ return json({ error: e.message }, e.status || 401, cors); }
}
async function getSitePublic(env, cors){
  const raw = await env.AZFW_KV.get('site:status');
  return json(raw ? JSON.parse(raw) : { maintenance: false }, 200, cors);
}
async function setSite(request, env, cors){
  try {
    await requireAdmin(request, env, cors);
    const body = await request.json();
    await env.AZFW_KV.put('site:status', JSON.stringify(body));
    return json({ ok: true }, 200, cors);
  } catch(e){
    return json({ error: e.message }, e.status || 500, cors);
  }
}

/* ============================================================
   SITE CONFIG (sections visibility)
   ============================================================ */
async function getConfig(request, env, cors){
  try {
    await requireAdmin(request, env, cors);
    const raw = await env.AZFW_KV.get('site:config');
    const def = { sections: { updates: true, news: true, community: true, moderatorForm: false } };
    return json(raw ? JSON.parse(raw) : def, 200, cors);
  } catch(e){ return json({ error: e.message }, e.status || 401, cors); }
}
async function setConfig(request, env, cors){
  try {
    await requireAdmin(request, env, cors);
    const body = await request.json();
    await env.AZFW_KV.put('site:config', JSON.stringify(body));
    return json({ ok: true }, 200, cors);
  } catch(e){
    return json({ error: e.message }, e.status || 500, cors);
  }
}
async function getPublicConfig(env, cors){
  const raw = await env.AZFW_KV.get('site:config');
  const def = { sections: { updates: true, news: true, community: true, moderatorForm: false } };
  return json(raw ? JSON.parse(raw) : def, 200, cors);
}

/* ============================================================
   POSTS (community)
   ============================================================ */
async function postsList(env, cors){
  const raw = await env.AZFW_KV.get('posts:all');
  const posts = raw ? JSON.parse(raw) : [];
  return json({ posts: posts.slice(-100).reverse() }, 200, cors);
}

async function postCreate(request, env, cors){
  const body = await request.json();
  const text = String(body.text || '').trim();
  const user = body.user || {};
  if(text.length < 2) return json({ error: 'Too short' }, 400, cors);
  if(text.length > 2000) return json({ error: 'Too long' }, 400, cors);
  if(!user.id) return json({ error: 'No user' }, 400, cors);

  const raw = await env.AZFW_KV.get('posts:all');
  const posts = raw ? JSON.parse(raw) : [];
  const post = {
    id: Date.now(),
    user_id: user.id,
    username: user.username || ('id' + user.id),
    name: (user.first_name || '') + (user.last_name ? ' ' + user.last_name : ''),
    photo_url: user.photo_url || '',
    text,
    created_at: Date.now(),
    likes: 0, comments: 0
  };
  posts.push(post);
  const trimmed = posts.slice(-500);
  await env.AZFW_KV.put('posts:all', JSON.stringify(trimmed));
  return json({ ok: true, post }, 200, cors);
}

async function adminPostsList(request, env, cors){
  try {
    await requireAdmin(request, env, cors);
    const raw = await env.AZFW_KV.get('posts:all');
    const posts = raw ? JSON.parse(raw) : [];
    return json({ posts: posts.slice(-100).reverse() }, 200, cors);
  } catch(e){
    return json({ error: e.message }, e.status || 500, cors);
  }
}
async function adminPostDelete(request, env, cors, id){
  try {
    await requireAdmin(request, env, cors);
    const raw = await env.AZFW_KV.get('posts:all');
    let posts = raw ? JSON.parse(raw) : [];
    posts = posts.filter(p => String(p.id) !== String(id));
    await env.AZFW_KV.put('posts:all', JSON.stringify(posts));
    return json({ ok: true }, 200, cors);
  } catch(e){
    return json({ error: e.message }, e.status || 500, cors);
  }
}

/* ============================================================
   GITHUB CMS
   ============================================================ */
async function githubList(request, env, cors){
  try {
    await requireAdmin(request, env, cors);
    const path = new URL(request.url).searchParams.get('path') || 'data/updates';
    const repo = env.GITHUB_REPO;
    const branch = env.GITHUB_BRANCH || 'main';
    if(!repo) throw new Error('GITHUB_REPO not set');

    const r = await fetch(`https://api.github.com/repos/${repo}/contents/${path}?ref=${branch}`, {
      headers: {
        'Authorization': `Bearer ${env.GITHUB_TOKEN}`,
        'User-Agent': 'azfw26-bot',
        'Accept': 'application/vnd.github.v3+json'
      }
    });
    if(!r.ok) throw new Error('GitHub: ' + r.status);
    const data = await r.json();
    const files = Array.isArray(data) ? data.map(f => ({
      name: f.name,
      path: f.path,
      type: f.type,
      size: f.size,
      sha: f.sha
    })) : [];
    return json({ files }, 200, cors);
  } catch(e){
    return json({ error: e.message }, 500, cors);
  }
}

async function githubRead(request, env, cors){
  try {
    await requireAdmin(request, env, cors);
    const path = new URL(request.url).searchParams.get('path');
    if(!path) throw new Error('path is required');
    const repo = env.GITHUB_REPO;
    const branch = env.GITHUB_BRANCH || 'main';

    const r = await fetch(`https://api.github.com/repos/${repo}/contents/${path}?ref=${branch}`, {
      headers: {
        'Authorization': `Bearer ${env.GITHUB_TOKEN}`,
        'User-Agent': 'azfw26-bot',
        'Accept': 'application/vnd.github.v3+json'
      }
    });
    if(!r.ok) throw new Error('GitHub: ' + r.status);
    const data = await r.json();
    const content = atob(data.content.replace(/\n/g, ''));
    return json({ content, sha: data.sha, path: data.path }, 200, cors);
  } catch(e){
    return json({ error: e.message }, 500, cors);
  }
}

async function githubWrite(request, env, cors){
  try {
    await requireAdmin(request, env, cors);
    const body = await request.json();
    const { path, content, message, sha } = body;
    if(!path || content === undefined) throw new Error('path and content required');

    const repo = env.GITHUB_REPO;
    const branch = env.GITHUB_BRANCH || 'main';
    const encoded = btoa(unescape(encodeURIComponent(content)));

    const payload = {
      message: message || `Update ${path} via admin`,
      content: encoded,
      branch
    };
    if(sha) payload.sha = sha;

    const r = await fetch(`https://api.github.com/repos/${repo}/contents/${path}`, {
      method: 'PUT',
      headers: {
        'Authorization': `Bearer ${env.GITHUB_TOKEN}`,
        'User-Agent': 'azfw26-bot',
        'Content-Type': 'application/json',
        'Accept': 'application/vnd.github.v3+json'
      },
      body: JSON.stringify(payload)
    });
    if(!r.ok) {
      const err = await r.text();
      throw new Error('GitHub: ' + r.status + ' ' + err);
    }
    const data = await r.json();
    return json({ ok: true, sha: data.content.sha, commit: data.commit.sha }, 200, cors);
  } catch(e){
    return json({ error: e.message }, 500, cors);
  }
}

/* ============================================================
   MODERATOR APPLICATIONS
   ============================================================ */
async function createModApp(request, env, cors){
  const body = await request.json();
  const { nickname, tg, age, experience, reason } = body;
  if(!nickname || !tg || !reason) return json({ error: 'Заполните обязательные поля' }, 400, cors);

  const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
  const app = { id, nickname, tg, age: age || '', experience: experience || '', reason, created_at: Date.now() };

  const raw = await env.AZFW_KV.get('mod_apps:all');
  const apps = raw ? JSON.parse(raw) : [];
  apps.push(app);
  await env.AZFW_KV.put('mod_apps:all', JSON.stringify(apps.slice(-200)));

  // Уведомление в Telegram админам
  const admins = await getAdminsList(env);
  for (const a of admins) {
    if (a.role === 'founder' || a.role === 'admin') {
      await sendTelegramMessage(env, a.tg_id,
        `📝 <b>Новая заявка модератора</b>\n\nНик: ${nickname}\nTG: ${tg}\nВозраст: ${age || '—'}\nОпыт: ${experience || '—'}\n\nПричина:\n${reason}`);
    }
  }

  return json({ ok: true, id }, 200, cors);
}

async function listModApps(request, env, cors){
  try {
    await requireAdmin(request, env, cors);
    const raw = await env.AZFW_KV.get('mod_apps:all');
    return json({ apps: raw ? JSON.parse(raw) : [] }, 200, cors);
  } catch(e){ return json({ error: e.message }, e.status || 500, cors); }
}

async function deleteModApp(request, env, cors, id){
  try {
    await requireAdmin(request, env, cors);
    const raw = await env.AZFW_KV.get('mod_apps:all');
    let apps = raw ? JSON.parse(raw) : [];
    apps = apps.filter(a => a.id !== id);
    await env.AZFW_KV.put('mod_apps:all', JSON.stringify(apps));
    return json({ ok: true }, 200, cors);
  } catch(e){ return json({ error: e.message }, e.status || 500, cors); }
}

/* ============================================================
   ROLES (Founder only)
   ============================================================ */
async function getAdminsList(env){
  const raw = await env.AZFW_KV.get('roles:admins');
  return raw ? JSON.parse(raw) : [];
}

async function getRole(env, tgId){
  const list = await getAdminsList(env);
  const found = list.find(a => Number(a.tg_id) === Number(tgId));
  return found ? found.role : null;
}

async function listRoles(request, env, cors){
  try {
    await requireFounder(request, env, cors);
    const list = await getAdminsList(env);
    return json({ roles: list }, 200, cors);
  } catch(e){ return json({ error: e.message }, e.status || 401, cors); }
}

async function setRole(request, env, cors){
  try {
    await requireFounder(request, env, cors);
    const { tg_id, role } = await request.json();
    if(!tg_id || !['admin', 'founder'].includes(role)) throw new Error('Invalid data');

    const list = await getAdminsList(env);
    const idx = list.findIndex(a => Number(a.tg_id) === Number(tg_id));
    if(idx >= 0) list[idx].role = role;
    else list.push({ tg_id: Number(tg_id), role });

    await env.AZFW_KV.put('roles:admins', JSON.stringify(list));
    return json({ ok: true }, 200, cors);
  } catch(e){ return json({ error: e.message }, e.status || 500, cors); }
}

/* ============================================================
   JWT
   ============================================================ */
async function signJwt(payload, secret){
  const header = { alg: 'HS256', typ: 'JWT' };
  const b64 = obj => btoa(JSON.stringify(obj)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const data = b64(header) + '.' + b64(payload);
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(data));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  return data + '.' + sigB64;
}

async function verifyJwt(token, secret){
  try {
    const [h, p, s] = token.split('.');
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const sigBin = Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    const ok = await crypto.subtle.verify('HMAC', key, sigBin, enc.encode(h + '.' + p));
    if(!ok) return null;
    const payload = JSON.parse(atob(p.replace(/-/g, '+').replace(/_/g, '/')));
    if(payload.exp * 1000 < Date.now()) return null;
    return payload;
  } catch(e){ return null; }
}

/* ============================================================
   TELEGRAM SEND
   ============================================================ */
async function sendTelegramMessage(env, chatId, text){
  // Используем прокси, если задан, иначе напрямую
  const base = env.TG_API_BASE || 'https://api.telegram.org';
  const url = `${base}/bot${env.BOT_TOKEN}/sendMessage`;
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id: chatId, text, parse_mode: 'HTML', disable_web_page_preview: true })
  });
  if(!r.ok){
    const err = await r.text();
    console.error('TG send failed:', err);
  }
}

/* ============================================================
   TG WEBHOOK
   ============================================================ */
async function tgWebhook(request, env, cors) {
  const update = await request.json().catch(() => null);
  if (!update || !update.message) return json({ ok: true }, 200, cors);

  const msg = update.message;
  const text = (msg.text || '').trim();
  const chatId = msg.chat.id;
  const from = msg.from || {};

  if (text === '/start') {
    await sendTelegramMessage(env, chatId,
      'Привет! Я — бот сайта <b>Arizona Faraway — 26</b>.\n\n' +
      'Если ты хочешь получить доступ к админке, обратись к основателю.');
  }
  return json({ ok: true }, 200, cors);
}