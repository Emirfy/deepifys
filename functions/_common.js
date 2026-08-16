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
