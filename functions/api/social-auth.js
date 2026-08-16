import {json,name,clean,hashPassword,verifyPassword,token,currentUser,getCookie,setCookieHeader} from "../_common.js";
export async function onRequestPost({request,env}){
 try{
  const b=await request.json();
  if(b.action==="me"){
    const u=await currentUser(env,request); if(!u)return json({user:null});
    const [fc,fg]=await Promise.all([
      env.DB.prepare("SELECT COUNT(*) c FROM follows WHERE following=?1").bind(u.username).first(),
      env.DB.prepare("SELECT COUNT(*) c FROM follows WHERE follower=?1").bind(u.username).first()
    ]);
    return json({user:{username:u.username,displayName:u.displayName,avatar:u.avatar||"",followers:Number(fc.c),following:Number(fg.c)}});
  }
  if(b.action==="logout"){
    const t=getCookie(request); if(t)await env.DB.prepare("DELETE FROM sessions WHERE token=?1").bind(t).run();
    return json({ok:true},200,setCookieHeader("",0));
  }
  const username=clean(b.username).toLowerCase(), password=String(b.password??"");
  if(b.action==="register"){
    const displayName=name(b.displayName);
    if(!/^[a-z0-9_.-]{3,24}$/.test(username))return json({error:"Kullanıcı adı 3-24 karakter olmalı."},400);
    if(displayName.length<2)return json({error:"Görünen adını gir."},400);
    if(password.length<6)return json({error:"Şifre en az 6 karakter olmalı."},400);
    if(await env.DB.prepare("SELECT username FROM users WHERE username=?1").bind(username).first())return json({error:"Bu kullanıcı adı alınmış."},409);
    const passwordHash=await hashPassword(password), now=Date.now();
    await env.DB.prepare("INSERT INTO users(username,display_name,password_hash,created_at,avatar,bio) VALUES(?,?,?,?,?,?)").bind(username,displayName,passwordHash,now,"","").run();
    const t=token(); await env.DB.prepare("INSERT INTO sessions(token,username,expires_at) VALUES(?,?,?)").bind(t,username,now+2592000000).run();
    return json({ok:true,user:{username,displayName,avatar:"",followers:0,following:0}},200,setCookieHeader(t));
  }
  if(b.action==="login"){
    const u=await env.DB.prepare("SELECT username,display_name AS displayName,password_hash AS passwordHash,avatar FROM users WHERE username=?1").bind(username).first();
    if(!u||!(await verifyPassword(password,u.passwordHash)))return json({error:"Kullanıcı adı veya şifre hatalı."},401);
    const t=token();await env.DB.prepare("INSERT INTO sessions(token,username,expires_at) VALUES(?,?,?)").bind(t,u.username,Date.now()+2592000000).run();
    const [fc,fg]=await Promise.all([env.DB.prepare("SELECT COUNT(*) c FROM follows WHERE following=?1").bind(u.username).first(),env.DB.prepare("SELECT COUNT(*) c FROM follows WHERE follower=?1").bind(u.username).first()]);
    return json({ok:true,user:{username:u.username,displayName:u.displayName,avatar:u.avatar||"",followers:Number(fc.c),following:Number(fg.c)}},200,setCookieHeader(t));
  }
  return json({error:"Geçersiz işlem."},400);
 }catch(e){console.error(e);return json({error:"Sunucu hatası."},500)}
}
export const onRequest=onRequestPost;
