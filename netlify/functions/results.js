const { getStore } = require('@netlify/blobs');
const crypto = require('crypto');
function json(statusCode, body){return {statusCode,headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}}
function verify(v,x){if(!x?.hash||!x?.salt)return false;try{const a=crypto.scryptSync(String(v),x.salt,64),b=Buffer.from(x.hash,'hex');return crypto.timingSafeEqual(a,b)}catch{return false}}
exports.handler = async (event) => {
  if(event.httpMethod!=='POST')return json(405,{error:'Método no permitido'});
  let body;try{body=JSON.parse(event.body||'{}')}catch{return json(400,{error:'JSON inválido'})}
  try{
    const auth=getStore('vox-auth'); const config=await auth.get('config',{type:'json'}); const env=process.env.ADMIN_PASSWORD||'';
    if(!((config?.password&&verify(body.password,config.password))||(env&&body.password===env)))return json(401,{error:'Contraseña incorrecta.'});
    const store=getStore('vox-submissions'); const {blobs}=await store.list();
    const records=(await Promise.all(blobs.map(b=>store.get(b.key,{type:'json'})))).filter(Boolean);
    records.sort((a,b)=>new Date(a.date)-new Date(b.date));
    return json(200,{ok:true,records});
  }catch(err){console.error(err);return json(500,{error:'No se pudieron leer los resultados'})}
};
