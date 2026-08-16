export async function onRequest({params,env}){
 const key=Array.isArray(params.path)?params.path.join("/"):String(params.path||"");
 const obj=await env.MEDIA.get(key); if(!obj)return new Response("Not found",{status:404});
 const h=new Headers(); obj.writeHttpMetadata(h); h.set("etag",obj.httpEtag); h.set("cache-control","public, max-age=31536000, immutable"); return new Response(obj.body,{headers:h});
}
