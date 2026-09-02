const { getStore } = require('@netlify/blobs');
exports.handler=async(event)=>{
  if(event.httpMethod!=='POST') return {statusCode:405,body:JSON.stringify({error:'Método no permitido'})};
  let data; try{data=JSON.parse(event.body||'{}')}catch{return {statusCode:400,body:JSON.stringify({error:'JSON inválido'})}};
  if(!data.sessionId || !data.role || typeof data.avg!=='number') return {statusCode:400,body:JSON.stringify({error:'Faltan datos obligatorios de la encuesta (rol, sesión o puntuación).'})};
  try{
    const store=getStore('vox-submissions'); const id=String(data.sessionId).slice(0,120);
    const record={id,date:new Date().toISOString(),status:data.status==='completed'?'completed':'partial',progress:Number(data.progress)||0,name:String(data.name||'Sin Nombre').slice(0,200),role:String(data.role).slice(0,100),sector:String(data.sector||'Sin Sector').slice(0,200),avg:Number(data.avg),critical:Number(data.critical)||0,answers:Array.isArray(data.answers)?data.answers.slice(0,100):[],interview:Array.isArray(data.interview)?data.interview.slice(0,50):[]};
    await store.setJSON(id,record); return {statusCode:200,headers:{'Content-Type':'application/json'},body:JSON.stringify({ok:true,id})};
  }catch(err){console.error(err);return {statusCode:500,headers:{'Content-Type':'application/json'},body:JSON.stringify({error:'No se pudo guardar la evaluación en Netlify Blobs. Publicá la carpeta completa del proyecto en Netlify.'})};}
};
