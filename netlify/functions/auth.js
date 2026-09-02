const { getStore } = require('@netlify/blobs');
const crypto = require('crypto');
const STORE = 'vox-auth';
const KEY = 'config';
function json(statusCode, body){ return {statusCode, headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)}; }
function norm(v){ return String(v ?? '').trim().toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g,''); }
function hash(value, salt=crypto.randomBytes(16).toString('hex')){ return {salt, hash:crypto.scryptSync(String(value),salt,64).toString('hex')}; }
function verify(value, stored){
  if(!stored?.hash || !stored?.salt) return false;
  try { const a=crypto.scryptSync(String(value),stored.salt,64); const b=Buffer.from(stored.hash,'hex'); return a.length===b.length && crypto.timingSafeEqual(a,b); } catch { return false; }
}
async function readConfig(store){
  try { return await store.get(KEY,{type:'json'}); }
  catch(err){ if(err?.status===404 || err?.code==='BLOB_NOT_FOUND') return null; throw err; }
}
exports.handler=async(event)=>{
  if(event.httpMethod!=='POST') return json(405,{error:'Método no permitido'});
  let body; try{body=JSON.parse(event.body||'{}')}catch{return json(400,{error:'JSON inválido'})}
  try{const store = getStore({
  name: STORE,
  siteID: process.env.NETLIFY_SITE_ID,
  token: process.env.NETLIFY_AUTH_TOKEN
});
    let config=await readConfig(store);
    const envPassword=String(process.env.ADMIN_PASSWORD||'');
    if(body.action==='status') return json(200,{configured:!!(config?.password||envPassword),hasSecretQuestion:!!config?.question});
    if(body.action==='question'){
      if(!config?.question) return json(404,{error:'Todavía no hay una pregunta secreta configurada.'});
      return json(200,{ok:true,question:config.question});
    }
    if(body.action==='setup'){
      if(config?.password || envPassword) return json(409,{error:'El acceso ya está configurado. Ingresá como administrador para modificarlo.'});
      const pw=String(body.password||'');
      if(pw.length<8) return json(400,{error:'La contraseña debe tener al menos 8 caracteres.'});
      if(pw!==String(body.password2||'')) return json(400,{error:'Las contraseñas no coinciden.'});
      const q=String(body.question||'').trim(), a=norm(body.answer);
      if(q.length<5) return json(400,{error:'Ingresá una pregunta secreta válida.'});
      if(a.length<2) return json(400,{error:'Ingresá una respuesta secreta válida.'});
      config={version:1,password:hash(pw),question:q.slice(0,300),answer:hash(a),updatedAt:new Date().toISOString()};
      await store.setJSON(KEY,config);
      return json(200,{ok:true,password:pw});
    }
    if(body.action==='change'){
      if(!config?.password) return json(400,{error:'No hay una configuración de administrador guardada.'});
      if(!verify(body.currentPassword,config.password) && !(envPassword && String(body.currentPassword)===envPassword)) return json(401,{error:'La contraseña actual es incorrecta.'});
      const pw=String(body.password||'');
      if(pw.length<8) return json(400,{error:'La nueva contraseña debe tener al menos 8 caracteres.'});
      if(pw!==String(body.password2||'')) return json(400,{error:'Las nuevas contraseñas no coinciden.'});
      const q=String(body.question||'').trim(), a=norm(body.answer);
      if(q.length<5 || a.length<2) return json(400,{error:'La pregunta y la respuesta secreta son obligatorias.'});
      config.password=hash(pw); config.question=q.slice(0,300); config.answer=hash(a); config.updatedAt=new Date().toISOString();
      await store.setJSON(KEY,config); return json(200,{ok:true,password:pw});
    }
    if(body.action==='recover'){
      if(!config?.question || !config?.answer) return json(400,{error:'No hay recuperación configurada.'});
      if(!verify(norm(body.answer),config.answer)) return json(401,{error:'La respuesta secreta no es correcta.'});
      const pw=String(body.newPassword||'');
      if(pw.length<8) return json(400,{error:'La nueva contraseña debe tener al menos 8 caracteres.'});
      if(pw!==String(body.newPassword2||'')) return json(400,{error:'Las contraseñas no coinciden.'});
      config.password=hash(pw); config.updatedAt=new Date().toISOString(); await store.setJSON(KEY,config);
      return json(200,{ok:true,password:pw});
    }
    return json(400,{error:'Acción no válida.'});
  }catch(err){ console.error(err); return json(500,{error:'No se pudo administrar el acceso. Verificá que el sitio esté publicado en Netlify con sus Functions habilitadas.'}); }
};
