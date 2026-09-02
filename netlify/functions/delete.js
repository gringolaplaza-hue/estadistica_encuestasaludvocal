const { getStore } = require('@netlify/blobs');
const crypto = require('crypto');
function json(statusCode, body) { return { statusCode, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }; }
function hash(v,s){return crypto.scryptSync(String(v),s,64).toString('hex');}
function verify(v,x){if(!x?.hash||!x?.salt)return false;try{return crypto.timingSafeEqual(Buffer.from(hash(v,x.salt),'hex'),Buffer.from(x.hash,'hex'));}catch{return false;}}
exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return json(405,{error:'Método no permitido'});
  let body; try{body=JSON.parse(event.body||'{}')}catch{return json(400,{error:'JSON inválido'})}
  if(!body.id) return json(400,{error:'Falta el identificador de la encuesta.'});
  const store = getStore({ name: 'vox-auth', siteID: process.env.NETLIFY_SITE_ID, token: process.env.NETLIFY_AUTH_TOKEN });
  if(!((config?.password&&verify(body.password,config.password)) || (env&&body.password===env))) return json(401,{error:'Contraseña incorrecta.'});
  const store = getStore({ name: 'vox-auth', siteID: process.env.NETLIFY_SITE_ID, token: process.env.NETLIFY_AUTH_TOKEN });
  catch(e){return json(500,{error:'No se pudo eliminar la encuesta.'});}
};
