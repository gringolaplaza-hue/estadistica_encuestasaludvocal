const { getStore } = require('@netlify/blobs');
const crypto = require('crypto');

function json(statusCode, body) {
  return {
    statusCode,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  };
}

function hash(value) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derivedKey = crypto.scryptSync(String(value), salt, 64);
  return { hash: derivedKey.toString('hex'), salt };
}

function verify(v, x) {
  if (!x?.hash || !x?.salt) return false;
  try {
    const a = crypto.scryptSync(String(v), x.salt, 64);
    return crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(x.hash, 'hex'));
  } catch (e) {
    return false;
  }
}

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return json(405, { error: 'Método no permitido' });

  let body;
  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return json(400, { error: 'JSON inválido' });
  }

  try {
    const auth = getStore({
      name: 'vox-auth',
      siteID: process.env.NETLIFY_SITE_ID,
      token: process.env.NETLIFY_BLOBS_TOKEN
    });

    // Guardar o actualizar la contraseña y pregunta secreta
    if (body.action === 'setup' || body.password) {
      if (!body.password) return json(400, { error: 'Falta la contraseña' });

      const configData = {
        password: hash(body.password),
        question: body.question || '',
        answer: body.answer ? hash(body.answer) : null
      };

      await auth.set('config', JSON.stringify(configData));
      return json(200, { ok: true, message: 'Acceso guardado correctamente' });
    }

    // Obtener la pregunta secreta guardada
    if (body.action === 'get-question') {
      const config = (await auth.get('config', { type: 'json' })) || {};
      return json(200, { ok: true, question: config.question || '' });
    }

    return json(400, { error: 'Acción no válida' });
  } catch (err) {
    console.error(err);
    return json(500, { error: 'No se pudo administrar el acceso.' });
  }
};
