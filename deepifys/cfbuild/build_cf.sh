#!/usr/bin/env bash
set -e
cd /mnt/data/cfbuild
rm -rf netlify netlify.toml
mkdir -p functions/api functions/media

# Replace Netlify function URLs with Cloudflare Pages Function routes.
for f in *.html; do
  sed -i 's#/.netlify/functions/social-auth#/api/social-auth#g; s#/.netlify/functions/social-profile#/api/social-profile#g; s#/.netlify/functions/social-posts#/api/social-posts#g; s#/.netlify/functions/admin#/api/admin#g; s#/.netlify/functions/presence#/api/presence#g; s#/.netlify/functions/reviews#/api/reviews#g' "$f"
done

cat > functions/_common.js <<'EOF'
const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function json(data, status=200, extra={}) {
  return Response.json(data, {status, headers:{"cache-control":"no-store", ...extra}});
}
export const clean = v => String(v ?? "").trim();
export const name = v => clean(v).replace(/\s+/g," ").slice(0,32);
export const text = v => clean(v).slice(0,500);
export const keyUser = u => encodeURIComponent(String(u).toLowerCase());

function b64(bytes){ let s=""; for(let i=0;i<bytes.length;i++) s+=String.fromCharCode(bytes[i]); return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,""); }
function unb64(s){ s=s.replace(/-/g,"+").replace(/_/g,"/"); while(s.length%4)s+="="; const raw=atob(s); return Uint8Array.from(raw,c=>c.charCodeAt(0)); }

export async function hashPassword(password){
  const salt=crypto.getRandomValues(new Uint8Array(16));
  const key=await crypto.subtle.importKey("raw",encoder.encode(password),"PBKDF2",false,["deriveBits"]);
  const bits=await crypto.subtle.deriveBits({name:"PBKDF2",salt,iterations:150000,hash:"SHA-256"},key,256);
  return `pbkdf2$150000$${b64(salt)}$${b64(new Uint8Array(bits))}`;
}
export async function verifyPassword(password,stored){
  const [scheme,it,salt64,hash64]=String(stored||"").split("$");
  if(scheme!=="pbkdf2"||!it||!salt64||!hash64)return false;
  const key=await crypto.subtle.importKey("raw",encoder.encode(password),"PBKDF2",false,["deriveBits"]);
  const bits=await crypto.subtle.deriveBits({name:"PBKDF2",salt:unb64(salt64),iterations:Number(it),hash:"SHA-256"},key,256);
  const a=new Uint8Array(bits), b=unb64(hash64); if(a.length!==b.length)return false;
  let x=0; for(let i=0;i<a.length;i++)x|=a[i]^b[i]; return x===0;
}
export function token(){ const b=crypto.getRandomValues(new Uint8Array(32)); return b64(b); }
export function cookie(value,maxAge=2592000){ return `deepifys_session=${value}; Max-Age=${maxAge}; Path=/; HttpOnly; SameSite=Lax; Secure`; }
export function getCookie(req){ const m=(req.headers.get("cookie")||"").match(/(?:^|;\s*)deepifys_session=([^;]+)/); return m?.[1]||null; }
export async function currentUser(env,req){
  const t=getCookie(req); if(!t)return null;
  const s=await env.DB.prepare("SELECT username, expires_at FROM sessions WHERE token=?1").bind(t).first();
  if(!s || Date.now()>Number(s.expires_at)){ if(s) await env.DB.prepare("DELETE FROM sessions WHERE token=?1").bind(t).run(); return null; }
  return await env.DB.prepare("SELECT username, display_name AS displayName, avatar, bio, created_at AS createdAt FROM users WHERE username=?1").bind(s.username).first();
}
export function setCookieHeader(value,maxAge=2592000){return {"set-cookie":cookie(value,maxAge)};}

export async function parseImage(data,maxBytes){
  const s=String(data??""); if(!s)return null;
  const m=s.match(/^data:(image\/(?:jpeg|jpg|png|webp));base64,([A-Za-z0-9+/=]+)$/i);
  if(!m)throw new Error("Sadece JPG, PNG veya WebP görsel yükleyebilirsin.");
  const raw=atob(m[2]); if(raw.length>maxBytes)throw new Error("Görsel çok büyük.");
  const bytes=Uint8Array.from(raw,c=>c.charCodeAt(0));
  const ext=m[1].toLowerCase().includes("png")?"png":m[1].toLowerCase().includes("webp")?"webp":"jpg";
  return {bytes,type:m[1],ext};
}
export async function saveImage(env,data,prefix,maxBytes){
  if(!data)return "";
  const img=await parseImage(data,maxBytes);
  const key=`${prefix}/${crypto.randomUUID()}.${img.ext}`;
  await env.MEDIA.put(key,img.bytes,{httpMetadata:{contentType:img.type,cacheControl:"public, max-age=31536000, immutable"}});
  return `/media/${key}`;
}
EOF

cat > functions/api/social-auth.js <<'EOF'
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
EOF

cat > functions/api/social-posts.js <<'EOF'
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
EOF

cat > functions/api/social-profile.js <<'EOF'
import {json,text,name,currentUser,saveImage} from "../_common.js";
async function profile(env,username){const u=await env.DB.prepare("SELECT username,display_name AS displayName,bio,avatar,created_at AS createdAt FROM users WHERE username=?1").bind(username).first();if(!u)return null;const [followers,following]=await Promise.all([env.DB.prepare("SELECT follower FROM follows WHERE following=?1 ORDER BY created_at").bind(username).all(),env.DB.prepare("SELECT following FROM follows WHERE follower=?1 ORDER BY created_at").bind(username).all()]);return {...u,createdAt:Number(u.createdAt),followers:followers.results.map(x=>x.follower),following:following.results.map(x=>x.following)};}
async function directory(env,mode){
 const users=(await env.DB.prepare("SELECT username,display_name AS displayName,bio,avatar,created_at AS createdAt FROM users").all()).results;
 const out=[];
 for(const u of users){const f=await env.DB.prepare("SELECT COUNT(*) c FROM follows WHERE following=?1").bind(u.username).first();const fg=await env.DB.prepare("SELECT COUNT(*) c FROM follows WHERE follower=?1").bind(u.username).first();const p=await env.DB.prepare("SELECT COUNT(*) c FROM posts WHERE username=?1").bind(u.username).first();const l=await env.DB.prepare("SELECT COUNT(*) c FROM likes l JOIN posts p ON p.id=l.post_id WHERE p.username=?1").bind(u.username).first();const c=await env.DB.prepare("SELECT COUNT(*) c FROM comments c JOIN posts p ON p.id=c.post_id WHERE p.username=?1").bind(u.username).first();out.push({...u,createdAt:Number(u.createdAt),followers:[],following:[],followersCount:Number(f.c),followingCount:Number(fg.c),posts:Number(p.c),likes:Number(l.c),comments:Number(c.c)});}
 if(mode==="popular")out.sort((a,b)=>(b.followersCount*5+b.likes*2+b.comments*3+b.posts)-(a.followersCount*5+a.likes*2+a.comments*3+a.posts));else out.sort((a,b)=>b.createdAt-a.createdAt);return out.slice(0,40);
}
async function userPosts(env,username){const rows=(await env.DB.prepare("SELECT id,username,text,image,created_at AS createdAt FROM posts WHERE username=?1 ORDER BY created_at DESC LIMIT 50").bind(username).all()).results;for(const p of rows){const l=await env.DB.prepare("SELECT username FROM likes WHERE post_id=?1").bind(p.id).all();const c=await env.DB.prepare("SELECT id,username,display_name AS displayName,avatar,text,created_at AS createdAt FROM comments WHERE post_id=?1 ORDER BY created_at").bind(p.id).all();p.likes=l.results.map(x=>x.username);p.comments=c.results.map(x=>({...x,createdAt:Number(x.createdAt)}));p.createdAt=Number(p.createdAt)}return rows;}
export async function onRequestGet({request,env}){try{const url=new URL(request.url),mode=(url.searchParams.get("mode")||"").toLowerCase();if(mode==="popular"||mode==="explore")return json({users:await directory(env,mode)});if(mode==="stats"){const x=await env.DB.prepare("SELECT COUNT(*) c FROM users").first();return json({userCount:Number(x.c)})}const q=(url.searchParams.get("username")||"").trim().toLowerCase();if(!q)return json({error:"Kullanıcı adı gerekli."},400);const p=await profile(env,q);if(!p)return json({error:"Kullanıcı bulunamadı."},404);const me=await currentUser(env,request);return json({profile:p,posts:await userPosts(env,p.username),me:me?.username||null});}catch(e){return json({error:"Sunucu hatası."},500)}}
export async function onRequestPost({request,env}){try{const me=await currentUser(env,request);if(!me)return json({error:"Bu işlem için giriş yapmalısın."},401);const b=await request.json(),action=b.action;
 if(action==="update"){const displayName=name(b.displayName),bio=text(b.bio).slice(0,160);if(displayName.length<2)return json({error:"Görünen adın en az 2 karakter olsun."},400);let avatar=me.avatar||"";if(b.avatar!==undefined&&b.avatar!==avatar){avatar=await saveImage(env,b.avatar,"avatars",900*1024)}await env.DB.prepare("UPDATE users SET display_name=?1,bio=?2,avatar=?3 WHERE username=?4").bind(displayName,bio,avatar,me.username).run();return json({ok:true,profile:await profile(env,me.username)});}
 if(action==="follow"){const target=String(b.username||"").toLowerCase();if(!target||target===me.username)return json({error:"Kendini takip edemezsin."},400);if(!await env.DB.prepare("SELECT username FROM users WHERE username=?1").bind(target).first())return json({error:"Kullanıcı bulunamadı."},404);const old=await env.DB.prepare("SELECT 1 FROM follows WHERE follower=?1 AND following=?2").bind(me.username,target).first();if(old)await env.DB.prepare("DELETE FROM follows WHERE follower=?1 AND following=?2").bind(me.username,target).run();else await env.DB.prepare("INSERT INTO follows(follower,following,created_at) VALUES(?,?,?)").bind(me.username,target,Date.now()).run();return json({ok:true,following:!old,profile:await profile(env,target)});}
 if(action==="search"){const q=text(b.query).toLowerCase().slice(0,30);const r=await env.DB.prepare("SELECT u.username,u.display_name AS displayName,u.avatar,(SELECT COUNT(*) FROM follows f WHERE f.following=u.username) followers FROM users u WHERE lower(u.username) LIKE ?1 OR lower(u.display_name) LIKE ?1 ORDER BY followers DESC LIMIT 20").bind(`%${q}%`).all();return json({users:r.results});}
 return json({error:"Geçersiz işlem."},400);}catch(e){console.error(e);return json({error:e.message||"Sunucu hatası."},500)}}
EOF

cat > functions/api/presence.js <<'EOF'
import {json} from "../_common.js";
export async function onRequestGet({request,env}){try{const id=new URL(request.url).searchParams.get("id");if(!id||!/^[A-Za-z0-9_-]{8,100}$/.test(id))return json({active:0},400);const now=Date.now();await env.DB.prepare("INSERT INTO presence(visitor_id,last_seen) VALUES(?,?) ON CONFLICT(visitor_id) DO UPDATE SET last_seen=excluded.last_seen").bind(id,now).run();await env.DB.prepare("DELETE FROM presence WHERE last_seen<?").bind(now-45000).run();const r=await env.DB.prepare("SELECT COUNT(*) c FROM presence WHERE last_seen>=?").bind(now-45000).first();return json({active:Number(r.c)});}catch(e){return json({active:0},503)}}
EOF

cat > functions/api/reviews.js <<'EOF'
import {json,text,currentUser} from "../_common.js";
export async function onRequestGet({env}){const r=await env.DB.prepare("SELECT id,text,display_name AS displayName,username,created_at AS createdAt FROM reviews ORDER BY created_at DESC LIMIT 50").all();return json({reviews:r.results});}
export async function onRequestPost({request,env}){const u=await currentUser(env,request);if(!u)return json({error:"Yorum yazmak için giriş yapmalısın."},401);const b=await request.json(),t=text(b.text);if(t.length<3)return json({error:"Yorumun en az 3 karakter olsun."},400);const id=crypto.randomUUID(),now=Date.now();const item={id,text:t,displayName:u.displayName,username:u.username,createdAt:now};await env.DB.prepare("INSERT INTO reviews(id,text,username,display_name,created_at) VALUES(?,?,?,?,?)").bind(id,t,u.username,u.displayName,now).run();return json({ok:true,review:item},201);}
EOF

cat > functions/api/admin.js <<'EOF'
import {json} from "../_common.js";
function ok(req,env){return !!env.ADMIN_KEY && req.headers.get("x-admin-key")===env.ADMIN_KEY;}
export async function onRequestPost({request,env}){try{if(!ok(request,env))return json({error:"Yetkisiz."},401);const b=await request.json();if(b.action==="overview"){const users=(await env.DB.prepare("SELECT username,display_name AS displayName,created_at AS createdAt FROM users ORDER BY created_at DESC").all()).results;const posts=(await env.DB.prepare("SELECT p.id,p.username,u.display_name AS displayName,p.text,p.image,p.created_at AS createdAt FROM posts p LEFT JOIN users u ON u.username=p.username ORDER BY p.created_at DESC LIMIT 100").all()).results;const reviews=(await env.DB.prepare("SELECT id,text,username,display_name AS displayName,created_at AS createdAt FROM reviews ORDER BY created_at DESC LIMIT 100").all()).results;return json({users,posts,reviews});}if(b.action==="deleteUser"){await env.DB.batch([env.DB.prepare("DELETE FROM sessions WHERE username=?1").bind(String(b.username).toLowerCase()),env.DB.prepare("DELETE FROM follows WHERE follower=?1 OR following=?1").bind(String(b.username).toLowerCase()),env.DB.prepare("DELETE FROM users WHERE username=?1").bind(String(b.username).toLowerCase())]);return json({ok:true});}if(b.action==="deletePost"){await env.DB.batch([env.DB.prepare("DELETE FROM likes WHERE post_id=?1").bind(String(b.id)),env.DB.prepare("DELETE FROM comments WHERE post_id=?1").bind(String(b.id)),env.DB.prepare("DELETE FROM posts WHERE id=?1").bind(String(b.id))]);return json({ok:true});}if(b.action==="deleteReview"){await env.DB.prepare("DELETE FROM reviews WHERE id=?1").bind(String(b.id)).run();return json({ok:true});}return json({error:"Geçersiz işlem."},400);}catch(e){return json({error:"Sunucu hatası."},500)}}
EOF

cat > functions/media/[[path]].js <<'EOF'
export async function onRequest({params,env}){
 const key=Array.isArray(params.path)?params.path.join("/"):String(params.path||"");
 const obj=await env.MEDIA.get(key); if(!obj)return new Response("Not found",{status:404});
 const h=new Headers(); obj.writeHttpMetadata(h); h.set("etag",obj.httpEtag); h.set("cache-control","public, max-age=31536000, immutable"); return new Response(obj.body,{headers:h});
}
EOF

cat > schema.sql <<'EOF'
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
 username TEXT PRIMARY KEY,
 display_name TEXT NOT NULL,
 password_hash TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 avatar TEXT DEFAULT '',
 bio TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS sessions (
 token TEXT PRIMARY KEY,
 username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
 expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS follows (
 follower TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
 following TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
 created_at INTEGER NOT NULL,
 PRIMARY KEY(follower,following)
);
CREATE TABLE IF NOT EXISTS posts (
 id TEXT PRIMARY KEY,
 username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
 text TEXT DEFAULT '',
 image TEXT DEFAULT '',
 created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS likes (
 post_id TEXT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
 username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
 created_at INTEGER NOT NULL,
 PRIMARY KEY(post_id,username)
);
CREATE TABLE IF NOT EXISTS comments (
 id TEXT PRIMARY KEY,
 post_id TEXT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
 username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
 display_name TEXT NOT NULL,
 avatar TEXT DEFAULT '',
 text TEXT NOT NULL,
 created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS reviews (
 id TEXT PRIMARY KEY,
 text TEXT NOT NULL,
 username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
 display_name TEXT NOT NULL,
 created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS presence (
 visitor_id TEXT PRIMARY KEY,
 last_seen INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_posts_created ON posts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_follows_following ON follows(following);
CREATE INDEX IF NOT EXISTS idx_follows_follower ON follows(follower);
CREATE INDEX IF NOT EXISTS idx_comments_post ON comments(post_id);
CREATE INDEX IF NOT EXISTS idx_likes_post ON likes(post_id);
EOF

cat > package.json <<'EOF'
{
  "name":"deepifys-veloraify-cloudflare",
  "private":true,
  "version":"2.0.0",
  "type":"module",
  "scripts":{"build":"echo Cloudflare Pages build ready"}
}
EOF

cat > README_CLOUDFLARE.md <<'EOF'
# DEEPIFYS / VELORAIFY — Cloudflare sürümü

Bu sürüm Netlify Blobs/Functions kullanmaz. Cloudflare Pages Functions + D1 + R2 kullanır.

## Cloudflare kurulumu

1. Pages projesini Git üzerinden bağla. Pages Functions içeren projeler dashboard Direct Upload ile deploy edilemez.
2. Cloudflare D1'de bir veritabanı oluştur.
3. `schema.sql` dosyasını D1'e uygula.
4. Pages projesi > Settings > Functions > Bindings bölümünden D1 binding ekle:
   - Variable name: `DB`
   - Database: oluşturduğun D1
5. R2'de bir bucket oluştur.
6. Aynı Bindings bölümünden R2 binding ekle:
   - Variable name: `MEDIA`
   - Bucket: oluşturduğun R2
7. Environment Variables/Secrets bölümünde `ADMIN_KEY` oluştur.
8. Yeniden deploy et.

## API

- `/api/social-auth`
- `/api/social-profile`
- `/api/social-posts`
- `/api/admin`
- `/api/presence`
- `/api/reviews`
- `/media/...`

## Özellikler

Kayıt/giriş, profil, profil fotoğrafı, takip, görselli gönderi, beğeni, yorum, arama, keşfet, popüler, admin ve aktif kullanıcı sayacı Cloudflare altyapısına taşındı.

### Önemli veri notu

Eski Netlify Blobs verileri otomatik olarak D1/R2'ye taşınmaz. Eski kullanıcıların ve gönderilerin korunması isteniyorsa ayrıca bir migration yapılmalıdır.
EOF

# Fix Veloraify counter endpoint if present.
sed -i "s#/.netlify/functions/social?action=stats#/api/social-profile?mode=stats#g" community.html

# Remove stale netlify references in robots/sitemap are fine; only redirects file is Netlify-specific.
rm -f _redirects

cd /mnt/data && rm -f DEEPIFYS_CLOUDFLARE_VELORAIFY.zip && zip -qr DEEPIFYS_CLOUDFLARE_VELORAIFY.zip cfbuild
