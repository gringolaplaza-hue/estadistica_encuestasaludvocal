const { getStore } = require('@netlify/blobs');
const crypto = require('crypto');
function verify(v,x){if(!x?.hash||!x?.salt)return false;try{return crypto.timingSafeEqual(crypto.scryptSync(String(v),x.salt,64),Buffer.from(x.hash,'hex'));}catch{return false;}}

// Borra todas las evaluaciones guardadas, solo si la contraseña de administrador es correcta.
exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: JSON.stringify({ error: 'Método no permitido' }) };
  }

  let body;
  try {
    body = JSON.parse(event.body || '{}');
  } catch (err) {
    return { statusCode: 400, body: JSON.stringify({ error: 'JSON inválido' }) };
  }

  const authStore = getStore('vox-auth');
  const config = await authStore.get('config', { type: 'json' });
  const adminPassword = process.env.ADMIN_PASSWORD || '';
  const valid = (config?.password && verify(body.password, config.password)) || (adminPassword && body.password === adminPassword);
  if (!valid) return { statusCode: 401, body: JSON.stringify({ error: 'Contraseña incorrecta.' }) };

  try {
    const store = getStore('vox-submissions');
    const { blobs } = await store.list();
    await Promise.all(blobs.map((b) => store.delete(b.key)));

    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ok: true })
    };
  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ error: 'No se pudieron borrar los datos' }) };
  }
};
