/* ============================================================
   Cloudflare Worker — Arizona Faraway — 26 (FINAL CLEAN VERSION)
   ============================================================ */

/* ============================================================
   Cloudflare Worker — Arizona Faraway — 26 (V4 - SECURE)
   ============================================================ */

/* ============================================================
   Cloudflare Worker — Arizona Faraway — 26 (V4 - SECURE)
   ============================================================ */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const cors = corsHeaders(request);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }

    try {
      // --- 1. АВТОРИЗАЦИЯ ---
      if (path === '/api/auth/admin-login' && request.method === 'POST') return await adminLogin(request, env, cors);
      if (path === '/api/auth/logout' && request.method === 'POST') return json({ ok: true }, 200, cors);
      if (path === '/api/admin/me' && request.method === 'GET') return await adminMe(request, env, cors);
      if (path === '/api/admin/change-pass' && request.method === 'POST') return await adminChangePass(request, env, cors);

      // --- 2. API ДЛЯ PYTHON-БОТА ---
      if (path.startsWith('/api/bot/user/') && request.method === 'GET') return await botGetUser(request, env, cors);
      if (path === '/api/bot/user' && request.method === 'POST') return await botSaveUser(request, env, cors);
      if (path === '/api/bot/admins' && request.method === 'GET') return await botGetAdmins(request, env, cors);
      if (path === '/api/bot/sync-github' && request.method === 'POST') return await botSyncGithub(request, env, cors);

      // --- 3. АДМИНКА ---
      if (path === '/api/admin/stats' && request.method === 'GET') return await getStats(request, env, cors);
      if (path === '/api/admin/site' && request.method === 'GET') return await getSite(request, env, cors);
      if (path === '/api/admin/site' && request.method === 'POST') return await setSite(request, env, cors);
      if (path === '/api/admin/config' && request.method === 'GET') return await getConfig(request, env, cors);
      if (path === '/api/admin/config' && request.method === 'POST') return await setConfig(request, env, cors);
      
      if (path === '/api/admin/roles' && request.method === 'GET') return await listRoles(request, env, cors);
      if (path === '/api/admin/roles' && request.method === 'POST') return await setRole(request, env, cors);

      if (path === '/api/admin/moderator/applications' && request.method === 'GET') return await listModApps(request, env, cors);
      if (path.startsWith('/api/admin/moderator/applications/') && request.method === 'DELETE') {
        return await deleteModApp(request, env, cors, path.split('/').pop());
      }
      if (path === '/api/moderator/apply' && request.method === 'POST') return await createModApp(request, env, cors);

      if (path === '/api/admin/posts' && request.method === 'GET') return await adminPostsList(request, env, cors);
      if (path.startsWith('/api/admin/posts/') && request.method === 'DELETE') {
        return await adminPostDelete(request, env, cors, path.split('/').pop());
      }

      // --- 4. GITHUB CMS ---
      if (path === '/api/admin/github/list' && request.method === 'GET') return await githubList(request, env, cors);
      if (path === '/api/admin/github/file' && request.method === 'GET') return await githubRead(request, env, cors);
      if (path === '/api/admin/github/file' && request.method === 'POST') return await githubWrite(request, env, cors);
      if (path === '/api/admin/updates' && request.method === 'GET') return await getUpdatesList(request, env, cors);

      // --- 5. ПУБЛИЧНЫЕ ---
      if (path === '/api/posts' && request.method === 'GET') return await postsList(env, cors);
      if (path === '/api/posts' && request.method === 'POST') return await postCreate(request, env, cors);
      if (path === '/api/site' && request.method === 'GET') return await getSitePublic(env, cors);
      if (path === '/api/site/config' && request.method === 'GET') return await getPublicConfig(env, cors);

      return json({ error: 'Not found: ' + path }, 404, cors);
    } catch (e) {
      return json({ error: e.message || 'Server error' }, e.status || 500, cors);
    }
  }
};

/* ============================================================ HELPERS ============================================================ */
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

/* ============================================================ АВТОРИЗАЦИЯ ============================================================ */
async function adminLogin(request, env, cors) {
  const { login_code, password, admin_code } = await request.json();
  if (!login_code || !password || !admin_code) return json({ error: 'Заполните все поля' }, 400, cors);

  const raw = await env.AZFW_KV.get('bot_user:' + login_code);
  if (!raw) return json({ error: 'Неверный логин или пароль' }, 401, cors);
  
  const user = JSON.parse(raw);
  if (user.password !== password || user.admin_code !== admin_code) {
    return json({ error: 'Неверный логин или пароль' }, 401, cors);
  }

  const roleNum = Number(user.role);
  const roleString = roleNum === 3 ? 'founder' : (roleNum === 2 ? 'admin' : 'helper');

  const ip = request.headers.get('CF-Connecting-IP') || '0.0.0.0';
  const token = await signJwt({
    sub: user.tg_id,
    username: user.login_code,
    role: roleString,
    ip,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + (2 * 60 * 60) // Живёт 2 часа
  }, env.JWT_SECRET);

  return json({ status: 'ok', token, username: user.login_code, role: roleString }, 200, cors);
}

async function requireAdmin(request, env, cors){
  const auth = request.headers.get('Authorization') || '';
  const token = auth.replace(/^Bearer\s+/i, '');
  if(!token) throw { status: 401, message: 'Нет токена' };
  
  const payload = await verifyJwt(token, env.JWT_SECRET);
  if(!payload) throw { status: 401, message: 'Сессия истекла. Войдите заново.' };
  
  // Проверяем, существует ли пользователь в базе (если бот его удалил, доступ пропадет)
  const userRaw = await env.AZFW_KV.get('bot_user:' + payload.username);
  if(!userRaw) throw { status: 401, message: 'Доступ отозван. Войдите заново.' };
  
  const user = JSON.parse(userRaw);
  if(!user.role || user.role === 0) throw { status: 403, message: 'Братан, у тебя нет прав!' };

  return payload;
}

async function requireFounder(request, env, cors){
  const payload = await requireAdmin(request, env, cors);
  if(payload.role !== 'founder') throw { status: 403, message: 'Братан, у тебя нет прав (только основатель)!' };
  return payload;
}

async function adminMe(request, env, cors){
  try {
    const payload = await requireAdmin(request, env, cors);
    return json({ username: payload.username, id: payload.sub, role: payload.role }, 200, cors);
  } catch(e){ return json({ error: e.message }, e.status || 401, cors); }
}

async function getStats(request, env, cors) {
  try {
    await requireAdmin(request, env, cors);
    const postsRaw = await env.AZFW_KV.get('posts:all');
    const appsRaw = await env.AZFW_KV.get('mod_apps:all');
    const adminsRaw = await env.AZFW_KV.list({ prefix: 'bot_user:' });
    
    const posts = postsRaw ? JSON.parse(postsRaw) : [];
    const apps = appsRaw ? JSON.parse(appsRaw) : [];
    
    return json({ posts: posts.length, apps: apps.length, admins: adminsRaw.keys.length }, 200, cors);
  } catch(e) { return json({ error: e.message }, 500, cors); }
}

/* ============================================================ API БОТА ============================================================ */
async function checkBotSecret(request, env) {
  const auth = request.headers.get('Authorization') || '';
  if (auth !== `Bearer ${env.BOT_SECRET}`) throw new Error('Unauthorized bot');
}

async function botGetUser(request, env, cors) {
  try {
    await checkBotSecret(request, env);
    const tg_id = request.url.split('/').pop();
    const login_code = await env.AZFW_KV.get('bot_id_index:' + tg_id);
    if (!login_code) return json({ error: 'Not found' }, 404, cors);
    const raw = await env.AZFW_KV.get('bot_user:' + login_code);
    return json(JSON.parse(raw), 200, cors);
  } catch (e) { return json({ error: e.message }, 401, cors); }
}

async function botSaveUser(request, env, cors) {
  try {
    await checkBotSecret(request, env);
    let data = await request.json();
    const tg_id = String(data.tg_id);

    let old_login_code = await env.AZFW_KV.get('bot_id_index:' + tg_id);
    let final_login_code = data.login_code || old_login_code;

    if (!final_login_code) final_login_code = 'azfw_' + Math.random().toString(36).slice(2, 8);

    let existing = {};
    if (old_login_code) {
      const raw = await env.AZFW_KV.get('bot_user:' + old_login_code);
      if (raw) existing = JSON.parse(raw);
    }

    data = Object.assign(existing, data);
    data.login_code = final_login_code;

    // УДАЛЯЕМ СТАРЫЙ ЛОГИН (Очистка мусора)
    if (old_login_code && old_login_code !== final_login_code) {
      await env.AZFW_KV.delete('bot_user:' + old_login_code);
    }

    if (data.role === 0) {
      await env.AZFW_KV.delete('bot_user:' + final_login_code);
      await env.AZFW_KV.delete('bot_id_index:' + tg_id);
    } else {
      await env.AZFW_KV.put('bot_id_index:' + tg_id, final_login_code);
      await env.AZFW_KV.put('bot_user:' + final_login_code, JSON.stringify(data));
    }

    return json({ ok: true, user: data }, 200, cors);
  } catch (e) { return json({ error: e.message }, 401, cors); }
}

async function botGetAdmins(request, env, cors) {
  try {
    await checkBotSecret(request, env);
    const list = await env.AZFW_KV.list({ prefix: 'bot_user:' });
    const admins = [];
    for (const key of list.keys) {
      const raw = await env.AZFW_KV.get(key.name);
      const u = JSON.parse(raw);
      if (u.role >= 3) admins.push(u);
    }
    return json(admins, 200, cors);
  } catch (e) { return json({ error: e.message }, 401, cors); }
}

async function botSyncGithub(request, env, cors) {
  try {
    await checkBotSecret(request, env);
    const repo = env.GITHUB_REPO;
    const branch = env.GITHUB_BRANCH || 'main';
    
    const r = await fetch(`https://api.github.com/repos/${repo}/contents/data/updates?ref=${branch}`, {
      headers: { 'Authorization': `Bearer ${env.GITHUB_TOKEN}`, 'User-Agent': 'azfw26-bot' }
    });
    if(!r.ok) throw new Error('Не удалось получить файлы с GitHub');
    
    const files = await r.json();
    const index = { updates: [] };
    
    for (const file of files) {
      if(!file.name.endsWith('.json')) continue;
      const fileRes = await fetch(file.download_url);
      if(!fileRes.ok) continue;
      try {
        const upd = await fileRes.json();
        const items = Array.isArray(upd.items) ? upd.items : [];
        index.updates.push({
          id: upd.id, date: upd.date, title: upd.title, summary: upd.summary,
          kind: upd.kind || 'game', platforms: upd.platforms || [],
          file: file.name, commit_hash: upd.commit_hash || null,
          stats: upd.stats || { files: items.length, additions: items.length, deletions: 0, commits: 1 }
        });
      } catch(e) { console.error(`Ошибка чтения ${file.name}`, e); }
    }
    
    index.updates.sort((a, b) => String(b.date).localeCompare(String(a.date)));
    
    let idxSha = null;
    const idxRes = await fetch(`https://api.github.com/repos/${repo}/contents/data/index.json?ref=${branch}`, {
      headers: { 'Authorization': `Bearer ${env.GITHUB_TOKEN}`, 'User-Agent': 'azfw26-bot' }
    });
    if(idxRes.ok) { const idxData = await idxRes.json(); idxSha = idxData.sha; }
    
    const encoded = btoa(unescape(encodeURIComponent(JSON.stringify(index, null, 2))));
    const payload = { message: `Manual bot sync`, content: encoded, branch };
    if (idxSha) payload.sha = idxSha;
    
    await fetch(`https://api.github.com/repos/${repo}/contents/data/index.json`, {
      method: 'PUT',
      headers: { 'Authorization': `Bearer ${env.GITHUB_TOKEN}`, 'User-Agent': 'azfw26-bot', 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    return json({ ok: true, count: index.updates.length }, 200, cors);
  } catch(e) { return json({ error: e.message }, 500, cors); }
}

/* ============================================================
   3. GITHUB CMS
   ============================================================ */
async function githubList(request, env, cors){
  try {
    await requireAdmin(request, env, cors);
    const path = new URL(request.url).searchParams.get('path') || 'data/updates';
    const repo = env.GITHUB_REPO;
    const branch = env.GITHUB_BRANCH || 'main';
    
    const r = await fetch(`https://api.github.com/repos/${repo}/contents/${path}?ref=${branch}`, {
      headers: { 'Authorization': `Bearer ${env.GITHUB_TOKEN}`, 'User-Agent': 'azfw26-bot', 'Accept': 'application/vnd.github.v3+json' }
    });
    if(!r.ok) throw new Error('GitHub: ' + r.status);
    const data = await r.json();
    const files = Array.isArray(data) ? data.map(f => ({ name: f.name, path: f.path, size: f.size })) : [];
    return json({ files }, 200, cors);
  } catch(e) { return json({ error: e.message }, 500, cors); }
}

async function githubRead(request, env, cors){
  try {
    await requireAdmin(request, env, cors);
    const path = new URL(request.url).searchParams.get('path');
    const repo = env.GITHUB_REPO;
    const branch = env.GITHUB_BRANCH || 'main';

    const r = await fetch(`https://api.github.com/repos/${repo}/contents/${path}?ref=${branch}`, {
      headers: { 'Authorization': `Bearer ${env.GITHUB_TOKEN}`, 'User-Agent': 'azfw26-bot', 'Accept': 'application/vnd.github.v3+json' }
    });
    if(!r.ok) throw new Error('GitHub: ' + r.status);
    const data = await r.json();
    const content = decodeURIComponent(escape(atob(data.content.replace(/\n/g, ''))));
    return json({ content, sha: data.sha, path: data.path }, 200, cors);
  } catch(e) { return json({ error: e.message }, 500, cors); }
}

async function githubWrite(request, env, cors){
  try {
    await requireAdmin(request, env, cors);
    const { path, content, message, sha } = await request.json();
    const repo = env.GITHUB_REPO;
    const branch = env.GITHUB_BRANCH || 'main';
    const encoded = btoa(unescape(encodeURIComponent(content)));

    const payload = { message: message || `Update ${path}`, content: encoded, branch };
    if(sha) payload.sha = sha;

    const r = await fetch(`https://api.github.com/repos/${repo}/contents/${path}`, {
      method: 'PUT',
      headers: { 'Authorization': `Bearer ${env.GITHUB_TOKEN}`, 'User-Agent': 'azfw26-bot', 'Content-Type': 'application/json', 'Accept': 'application/vnd.github.v3+json' },
      body: JSON.stringify(payload)
    });
    if(!r.ok) throw new Error('GitHub PUT Error: ' + r.status);
    const data = await r.json();
    
    // Авто-синхронизация index.json
    if (path.startsWith('data/updates/')) {
      await syncIndex(env, path, content);
    }

    return json({ ok: true, sha: data.content.sha, commit: data.commit.sha }, 200, cors);
  } catch(e) { return json({ error: e.message }, 500, cors); }
}

async function syncIndex(env, path, content) {
  try {
    const repo = env.GITHUB_REPO;
    const branch = env.GITHUB_BRANCH || 'main';
    
    // Читаем текущий index.json
    let index = { updates: [] };
    let idxSha = null;
    const r = await fetch(`https://api.github.com/repos/${repo}/contents/data/index.json?ref=${branch}`, {
      headers: { 'Authorization': `Bearer ${env.GITHUB_TOKEN}`, 'User-Agent': 'azfw26-bot' }
    });
    if (r.ok) {
      const data = await r.json();
      idxSha = data.sha;
      try { index = JSON.parse(decodeURIComponent(escape(atob(data.content.replace(/\n/g, ''))))); } catch(e) {}
    }
    if (!Array.isArray(index.updates)) index.updates = [];

    // Парсим новое обновление
    const upd = JSON.parse(content);
    const items = Array.isArray(upd.items) ? upd.items : [];
    const entry = {
      id: upd.id, date: upd.date, title: upd.title, summary: upd.summary,
      kind: upd.kind || 'game', platforms: upd.platforms || [],
      file: path.split('/').pop(), commit_hash: upd.commit_hash || null,
      stats: upd.stats || { files: items.length, additions: items.length, deletions: 0, commits: 1 }
    };

    // Обновляем массив
    const existing = index.updates.findIndex(u => u.id === entry.id);
    if (existing >= 0) index.updates[existing] = entry;
    else index.updates.push(entry);
    
    // Сортируем по дате (новые сверху)
    index.updates.sort((a, b) => String(b.date).localeCompare(String(a.date)));

    // Записываем обратно
    const encoded = btoa(unescape(encodeURIComponent(JSON.stringify(index, null, 2))));
    const payload = { message: `Auto-index for ${entry.id}`, content: encoded, branch };
    if (idxSha) payload.sha = idxSha;
    
    await fetch(`https://api.github.com/repos/${repo}/contents/data/index.json`, {
      method: 'PUT',
      headers: { 'Authorization': `Bearer ${env.GITHUB_TOKEN}`, 'User-Agent': 'azfw26-bot', 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
  } catch(e) {
    console.error('Sync index error:', e);
  }
}

/* ============================================================
   4. ОСТАЛЬНЫЕ ФУНКЦИИ
   ============================================================ */
async function getSitePublic(env, cors){
  const raw = await env.AZFW_KV.get('site:status');
  return json(raw ? JSON.parse(raw) : { maintenance: false }, 200, cors);
}
async function getPublicConfig(env, cors){
  const raw = await env.AZFW_KV.get('site:config');
  return json(raw ? JSON.parse(raw) : { sections: { updates: true, news: true, community: true, moderatorForm: false } }, 200, cors);
}
async function getSite(request, env, cors){
  try {
    await requireAdmin(request, env, cors);
    const raw = await env.AZFW_KV.get('site:status');
    return json(raw ? JSON.parse(raw) : { maintenance: false }, 200, cors);
  } catch(e){ return json({ error: e.message }, e.status || 401, cors); }
}
async function setSite(request, env, cors){
  try {
    await requireAdmin(request, env, cors);
    await env.AZFW_KV.put('site:status', JSON.stringify(await request.json()));
    return json({ ok: true }, 200, cors);
  } catch(e){ return json({ error: e.message }, e.status || 500, cors); }
}
async function getConfig(request, env, cors){
  try {
    await requireAdmin(request, env, cors);
    const raw = await env.AZFW_KV.get('site:config');
    return json(raw ? JSON.parse(raw) : { sections: { updates: true, news: true, community: true, moderatorForm: false } }, 200, cors);
  } catch(e){ return json({ error: e.message }, e.status || 401, cors); }
}
async function setConfig(request, env, cors){
  try {
    await requireAdmin(request, env, cors);
    await env.AZFW_KV.put('site:config', JSON.stringify(await request.json()));
    return json({ ok: true }, 200, cors);
  } catch(e){ return json({ error: e.message }, e.status || 500, cors); }
}
async function listRoles(request, env, cors) {
  try {
    await requireFounder(request, env, cors);
    const list = await env.AZFW_KV.list({ prefix: 'bot_user:' });
    const roles = [];
    for (const k of list.keys) {
      const u = JSON.parse(await env.AZFW_KV.get(k.name));
      roles.push({ tg_id: u.tg_id, role: u.role === 3 ? 'founder' : 'admin' });
    }
    return json({ roles }, 200, cors);
  } catch(e) { return json({ error: e.message }, e.status || 500, cors); }
}
async function setRole(request, env, cors) {
  try {
    await requireFounder(request, env, cors);
    const { tg_id, role } = await request.json();
    const login_code = await env.AZFW_KV.get('bot_id_index:' + tg_id);
    if (login_code) {
      const raw = await env.AZFW_KV.get('bot_user:' + login_code);
      const u = JSON.parse(raw);
      u.role = role === 'founder' ? 3 : 2;
      await env.AZFW_KV.put('bot_user:' + login_code, JSON.stringify(u));
    }
    return json({ ok: true }, 200, cors);
  } catch(e) { return json({ error: e.message }, e.status || 500, cors); }
}

async function postsList(env, cors){
  const raw = await env.AZFW_KV.get('posts:all');
  return json({ posts: (raw ? JSON.parse(raw) : []).slice(-100).reverse() }, 200, cors);
}
async function postCreate(request, env, cors){
  const body = await request.json();
  const text = String(body.text || '').trim();
  const user = body.user || {};
  if(text.length < 2 || !user.id) return json({ error: 'Invalid data' }, 400, cors);
  
  const raw = await env.AZFW_KV.get('posts:all');
  const posts = raw ? JSON.parse(raw) : [];
  posts.push({ id: Date.now(), user_id: user.id, username: user.username || 'id'+user.id, name: user.first_name || '', text, created_at: Date.now() });
  await env.AZFW_KV.put('posts:all', JSON.stringify(posts.slice(-500)));
  return json({ ok: true }, 200, cors);
}
async function adminPostsList(request, env, cors){
  try {
    await requireAdmin(request, env, cors);
    const raw = await env.AZFW_KV.get('posts:all');
    return json({ posts: (raw ? JSON.parse(raw) : []).slice(-100).reverse() }, 200, cors);
  } catch(e){ return json({ error: e.message }, 500, cors); }
}
async function adminPostDelete(request, env, cors, id){
  try {
    await requireAdmin(request, env, cors);
    const raw = await env.AZFW_KV.get('posts:all');
    let posts = raw ? JSON.parse(raw) : [];
    posts = posts.filter(p => String(p.id) !== String(id));
    await env.AZFW_KV.put('posts:all', JSON.stringify(posts));
    return json({ ok: true }, 200, cors);
  } catch(e){ return json({ error: e.message }, 500, cors); }
}

async function createModApp(request, env, cors){
  const body = await request.json();
  const id = Date.now().toString(36);
  const raw = await env.AZFW_KV.get('mod_apps:all');
  const apps = raw ? JSON.parse(raw) : [];
  apps.push({ ...body, id, created_at: Date.now() });
  await env.AZFW_KV.put('mod_apps:all', JSON.stringify(apps.slice(-200)));
  return json({ ok: true, id }, 200, cors);
}
async function listModApps(request, env, cors){
  try {
    await requireAdmin(request, env, cors);
    const raw = await env.AZFW_KV.get('mod_apps:all');
    return json({ apps: raw ? JSON.parse(raw) : [] }, 200, cors);
  } catch(e){ return json({ error: e.message }, 500, cors); }
}
async function deleteModApp(request, env, cors, id){
  try {
    await requireAdmin(request, env, cors);
    const raw = await env.AZFW_KV.get('mod_apps:all');
    let apps = raw ? JSON.parse(raw) : [];
    apps = apps.filter(a => a.id !== id);
    await env.AZFW_KV.put('mod_apps:all', JSON.stringify(apps));
    return json({ ok: true }, 200, cors);
  } catch(e){ return json({ error: e.message }, 500, cors); }
}

async function adminChangePass(request, env, cors) {
  try {
    const payload = await requireAdmin(request, env, cors);
    const { password } = await request.json();
    if (!password || password.length < 4) return json({ error: 'Пароль слишком короткий' }, 400, cors);

    const login_code = await env.AZFW_KV.get('bot_id_index:' + payload.sub);
    if (!login_code) return json({ error: 'Пользователь не найден' }, 404, cors);

    const raw = await env.AZFW_KV.get('bot_user:' + login_code);
    if (!raw) return json({ error: 'Данные не найдены' }, 404, cors);

    const user = JSON.parse(raw);
    user.password = password;
    await env.AZFW_KV.put('bot_user:' + login_code, JSON.stringify(user));

    return json({ ok: true }, 200, cors);
  } catch(e) { return json({ error: e.message }, 500, cors); }
}

async function getSitePublic(env, cors){ const raw = await env.AZFW_KV.get('site:status'); return json(raw ? JSON.parse(raw) : { maintenance: false }, 200, cors); }
async function getPublicConfig(env, cors){ const raw = await env.AZFW_KV.get('site:config'); return json(raw ? JSON.parse(raw) : { sections: { updates: true, news: true, community: true, moderatorForm: false } }, 200, cors); }
async function getSite(request, env, cors){ try { await requireAdmin(request, env, cors); const raw = await env.AZFW_KV.get('site:status'); return json(raw ? JSON.parse(raw) : { maintenance: false }, 200, cors); } catch(e){ return json({ error: e.message }, e.status || 401, cors); } }
async function setSite(request, env, cors){ try { await requireAdmin(request, env, cors); await env.AZFW_KV.put('site:status', JSON.stringify(await request.json())); return json({ ok: true }, 200, cors); } catch(e){ return json({ error: e.message }, e.status || 500, cors); } }
async function getConfig(request, env, cors){ try { await requireAdmin(request, env, cors); const raw = await env.AZFW_KV.get('site:config'); return json(raw ? JSON.parse(raw) : { sections: { updates: true, news: true, community: true, moderatorForm: false } }, 200, cors); } catch(e){ return json({ error: e.message }, e.status || 401, cors); } }
async function setConfig(request, env, cors){ try { await requireAdmin(request, env, cors); await env.AZFW_KV.put('site:config', JSON.stringify(await request.json())); return json({ ok: true }, 200, cors); } catch(e){ return json({ error: e.message }, e.status || 500, cors); } }
async function listRoles(request, env, cors) { try { await requireFounder(request, env, cors); const list = await env.AZFW_KV.list({ prefix: 'bot_user:' }); const roles = []; for (const k of list.keys) { const u = JSON.parse(await env.AZFW_KV.get(k.name)); roles.push({ tg_id: u.tg_id, role: u.role === 3 ? 'founder' : 'admin' }); } return json({ roles }, 200, cors); } catch(e) { return json({ error: e.message }, e.status || 500, cors); } }
async function setRole(request, env, cors) { try { await requireFounder(request, env, cors); const { tg_id, role } = await request.json(); const login_code = await env.AZFW_KV.get('bot_id_index:' + tg_id); if (login_code) { const raw = await env.AZFW_KV.get('bot_user:' + login_code); const u = JSON.parse(raw); u.role = role === 'founder' ? 3 : 2; await env.AZFW_KV.put('bot_user:' + login_code, JSON.stringify(u)); } return json({ ok: true }, 200, cors); } catch(e) { return json({ error: e.message }, e.status || 500, cors); } }
async function postsList(env, cors){ const raw = await env.AZFW_KV.get('posts:all'); return json({ posts: (raw ? JSON.parse(raw) : []).slice(-100).reverse() }, 200, cors); }
async function postCreate(request, env, cors){ const body = await request.json(); const text = String(body.text || '').trim(); const user = body.user || {}; if(text.length < 2 || !user.id) return json({ error: 'Invalid data' }, 400, cors); const raw = await env.AZFW_KV.get('posts:all'); const posts = raw ? JSON.parse(raw) : []; posts.push({ id: Date.now(), user_id: user.id, username: user.username || 'id'+user.id, name: user.first_name || '', text, created_at: Date.now() }); await env.AZFW_KV.put('posts:all', JSON.stringify(posts.slice(-500))); return json({ ok: true }, 200, cors); }
async function adminPostsList(request, env, cors){ try { await requireAdmin(request, env, cors); const raw = await env.AZFW_KV.get('posts:all'); return json({ posts: (raw ? JSON.parse(raw) : []).slice(-100).reverse() }, 200, cors); } catch(e){ return json({ error: e.message }, 500, cors); } }
async function adminPostDelete(request, env, cors, id){ try { await requireAdmin(request, env, cors); const raw = await env.AZFW_KV.get('posts:all'); let posts = raw ? JSON.parse(raw) : []; posts = posts.filter(p => String(p.id) !== String(id)); await env.AZFW_KV.put('posts:all', JSON.stringify(posts)); return json({ ok: true }, 200, cors); } catch(e){ return json({ error: e.message }, 500, cors); } }
async function createModApp(request, env, cors){ const body = await request.json(); const id = Date.now().toString(36); const raw = await env.AZFW_KV.get('mod_apps:all'); const apps = raw ? JSON.parse(raw) : []; apps.push({ ...body, id, created_at: Date.now() }); await env.AZFW_KV.put('mod_apps:all', JSON.stringify(apps.slice(-200))); return json({ ok: true, id }, 200, cors); }
async function listModApps(request, env, cors){ try { await requireAdmin(request, env, cors); const raw = await env.AZFW_KV.get('mod_apps:all'); return json({ apps: raw ? JSON.parse(raw) : [] }, 200, cors); } catch(e){ return json({ error: e.message }, 500, cors); } }
async function deleteModApp(request, env, cors, id){ try { await requireAdmin(request, env, cors); const raw = await env.AZFW_KV.get('mod_apps:all'); let apps = raw ? JSON.parse(raw) : []; apps = apps.filter(a => a.id !== id); await env.AZFW_KV.put('mod_apps:all', JSON.stringify(apps)); return json({ ok: true }, 200, cors); } catch(e){ return json({ error: e.message }, 500, cors); } }

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