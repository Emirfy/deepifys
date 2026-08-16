import {json,text,currentUser,saveImage} from "../_common.js";
async function decoratePosts(env,rows){
 const out=[];
 for(const p of rows){
  const likes=await env.DB.prepare("SELECT username FROM likes WHERE post_id=?1 ORDER BY created_at").bind(p.id).all();
  const comments=await env.DB.prepare("SELECT id,username,display_name AS displayName,avatar,text,created_at AS createdAt FROM comments WHERE post_id=?1 ORDER BY created_at").bind(p.id).all();
  out.push({...p,createdAt:Number(p.createdAt),likes:likes.results.map(x=>x.username),comments:comments.results.map(x=>({...x,createdAt:Number(x.createdAt)}))});
 }
 return out;
}
export async function onRequestGet({request,env}){
 try{const url=new URL(request.url), username=(url.searchParams.get("user")||"").toLowerCase();let q="SELECT id,username,display_name AS displayName,avatar,image,text,created_at AS createdAt FROM posts";const binds=[];if(username){q+=" WHERE username=?1";binds.push(username)}q+=" ORDER BY created_at DESC LIMIT 80";const rows=await env.DB.prepare(q).bind(...binds).all();return json({posts:await decoratePosts(env,rows.results)});}catch(e){return json({error:"Sunucu hatası."},500)}}
export async function onRequestPost({request,env}){
 try{const u=await currentUser(env,request);if(!u)return json({error:"Bu işlem için giriş yapmalısın."},401);const b=await request.json(),action=b.action;
  if(action==="create"){
   const body=text(b.text);if(body.length<2&&!b.image)return json({error:"Bir şeyler yaz veya görsel ekle."},400);
   const image=await saveImage(env,b.image,"posts",1800*1024);const id=crypto.randomUUID(),now=Date.now();
   await env.DB.prepare("INSERT INTO posts(id,username,text,image,created_at) VALUES(?,?,?,?,?)").bind(id,u.username,body,image,now).run();return json({post:{id,username:u.username,displayName:u.displayName,avatar:u.avatar||"",text:body,image,createdAt:now,likes:[],comments:[]}},201);
  }
  const id=String(b.id||"");if(!id)return json({error:"Gönderi bulunamadı."},400);const p=await env.DB.prepare("SELECT id,username,text,image,created_at AS createdAt FROM posts WHERE id=?1").bind(id).first();if(!p)return json({error:"Gönderi bulunamadı."},404);
  if(action==="like"){const old=await env.DB.prepare("SELECT 1 FROM likes WHERE post_id=?1 AND username=?2").bind(id,u.username).first();if(old)await env.DB.prepare("DELETE FROM likes WHERE post_id=?1 AND username=?2").bind(id,u.username).run();else await env.DB.prepare("INSERT INTO likes(post_id,username,created_at) VALUES(?,?,?)").bind(id,u.username,Date.now()).run();const row=await env.DB.prepare("SELECT id,username,text,image,created_at AS createdAt FROM posts WHERE id=?1").bind(id).first();return json({post:(await decoratePosts(env,[row]))[0]});}
  if(action==="comment"){const body=text(b.text);if(body.length<2)return json({error:"Yorum çok kısa."},400);const cid=crypto.randomUUID();await env.DB.prepare("INSERT INTO comments(id,post_id,username,display_name,avatar,text,created_at) VALUES(?,?,?,?,?,?,?)").bind(cid,id,u.username,u.displayName,u.avatar||"",body,Date.now()).run();const row=await env.DB.prepare("SELECT id,username,text,image,created_at AS createdAt FROM posts WHERE id=?1").bind(id).first();return json({post:(await decoratePosts(env,[row]))[0]});}
  return json({error:"Geçersiz işlem."},400);
 }catch(e){console.error(e);return json({error:e.message||"Sunucu hatası."},500)}
}
