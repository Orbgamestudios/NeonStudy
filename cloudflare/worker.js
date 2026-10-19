const corsHeaders = {
  "Access-Control-Allow-Origin": "https://orbgamestudios.github.io",
  "Access-Control-Allow-Methods": "GET, POST, PUT, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Max-Age": "86400",
  "Vary": "Origin"
};
const json = (body, status = 200) => new Response(JSON.stringify(body), {status, headers: {...corsHeaders, "Content-Type":"application/json; charset=utf-8", "Cache-Control":"no-store"}});
const encoder = new TextEncoder();
const b64url = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
async function digest(value) { return b64url(await crypto.subtle.digest("SHA-256", encoder.encode(value))); }
function randomToken(bytes = 32) { const b = crypto.getRandomValues(new Uint8Array(bytes)); return b64url(b); }
function normalizedName(value) { return String(value||"").trim().normalize("NFKC"); }
function validName(name) { return [...name].length >= 2 && [...name].length <= 24 && /^[\p{L}\p{N}_ -]+$/u.test(name); }
async function pinHash(pin, salt, pepper) {
  const material = await crypto.subtle.importKey("raw", encoder.encode(pin + ":" + pepper), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({name:"PBKDF2", hash:"SHA-256", salt:Uint8Array.from(atob(salt.replace(/-/g,"+").replace(/_/g,"/")+"===".slice((salt.length+3)%4)), c=>c.charCodeAt(0)), iterations:100000}, material, 256);
  return b64url(bits);
}
function constantEqual(a,b) { if (a.length !== b.length) return false; let out=0; for(let i=0;i<a.length;i++) out |= a.charCodeAt(i)^b.charCodeAt(i); return out===0; }
async function readJson(request) { const len=Number(request.headers.get("Content-Length")||0); if(len>32768) throw new Error("Request is too large."); const raw=await request.text(); if(raw.length>32768) throw new Error("Request is too large."); try{return JSON.parse(raw)}catch{return null} }
function cleanProgress(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const allowed = ["c","m","ca","pathProgress","quizTotals","calcPosition"];
  const out={};
  for (const key of allowed) {
    const v=value[key];
    if (key==="calcPosition" && Number.isFinite(Number(v))) out[key]=Math.max(0,Math.min(100000,Number(v)));
    else if (v && typeof v==="object" && !Array.isArray(v)) out[key]=v;
  }
  if (Array.isArray(value.exams)) out.exams=[...new Set(value.exams.filter(x=>typeof x==="string" && /^[a-z0-9-]{1,40}$/.test(x)))].slice(0,20);
  if (["path","cyan","pink","violet","amber"].includes(value.theme)) out.theme=value.theme;
  if (JSON.stringify(out).length>24000) return null;
  return out;
}
async function authenticated(request, env) {
  const token=(request.headers.get("Authorization")||"").replace(/^Bearer\s+/i,"");
  if (!/^[A-Za-z0-9_-]{40,60}$/.test(token)) return null;
  const hash=await digest(token);
  const row=await env.DB.prepare("SELECT account_id FROM sessions WHERE token_hash=? AND expires_at>?").bind(hash,Date.now()).first();
  return row ? {accountId:row.account_id, tokenHash:hash} : null;
}
async function failedAllowed(env, key) {
  const now=Date.now(), since=now-15*60*1000;
  const result=await env.DB.prepare("SELECT COUNT(*) AS n FROM login_attempts WHERE attempt_key=? AND created_at>?").bind(key,since).first();
  return Number(result?.n||0)<5;
}
async function recordFailure(env,key) {
  const now=Date.now();
  await env.DB.prepare("INSERT INTO login_attempts(attempt_key,created_at) VALUES(?,?)").bind(key,now).run();
  await env.DB.prepare("DELETE FROM login_attempts WHERE created_at<?").bind(now-20*60*1000).run();
}
async function issueSession(env, accountId) {
  const token=randomToken(), hash=await digest(token), expiry=Date.now()+30*24*60*60*1000;
  await env.DB.prepare("INSERT INTO sessions(token_hash,account_id,expires_at,created_at) VALUES(?,?,?,?)").bind(hash,accountId,expiry,Date.now()).run();
  return token;
}
export default {
  async fetch(request, env) {
    const url=new URL(request.url);
    if (request.headers.get("Origin") && request.headers.get("Origin")!=="https://orbgamestudios.github.io") return new Response("Origin not allowed", {status:403});
    if (request.method==="OPTIONS") return new Response(null,{status:204,headers:corsHeaders});
    if (url.pathname==="/health" && request.method==="GET") return json({ok:true,service:"NeonStudy sync"});
    try {
      if (url.pathname==="/api/register" && request.method==="POST") {
        const body=await readJson(request), name=normalizedName(body?.name), pin=String(body?.pin||"");
        if(!validName(name) || !/^\d{4}$/.test(pin)) return json({error:"Use a 2–24 character name and a 4-digit PIN."},400);
        const norm=name.toLocaleLowerCase("en-US");
        const key=await digest(norm+":"+String(request.headers.get("CF-Connecting-IP")||""));
        if(!await failedAllowed(env,key)) return json({error:"Too many attempts. Wait 15 minutes and try again."},429);
        const salt=randomToken(16), verifier=await pinHash(pin,salt,env.PIN_PEPPER);
        const id=randomToken(18), now=Date.now();
        try { await env.DB.prepare("INSERT INTO accounts(id,username,display_name,pin_salt,pin_verifier,progress_json,created_at,updated_at) VALUES(?,?,?,?,?,'{}',?,?)").bind(id,norm,name,salt,verifier,now,now).run(); }
        catch(e) { return json({error:"That account name is already taken."},409); }
        const token=await issueSession(env,id);
        return json({token,name,progress:{},updatedAt:now});
      }
      if (url.pathname==="/api/login" && request.method==="POST") {
        const body=await readJson(request), name=normalizedName(body?.name), pin=String(body?.pin||"");
        if(!validName(name) || !/^\d{4}$/.test(pin)) return json({error:"Enter your account name and 4-digit PIN."},400);
        const norm=name.toLocaleLowerCase("en-US"), key=await digest(norm+":"+String(request.headers.get("CF-Connecting-IP")||""));
        if(!await failedAllowed(env,key)) return json({error:"Too many attempts. Wait 15 minutes and try again."},429);
        const account=await env.DB.prepare("SELECT id,display_name,pin_salt,pin_verifier,progress_json,updated_at FROM accounts WHERE username=?").bind(norm).first();
        const candidate=account ? await pinHash(pin,account.pin_salt,env.PIN_PEPPER) : await pinHash(pin,randomToken(16),env.PIN_PEPPER);
        if(!account || !constantEqual(candidate,account.pin_verifier)) { await recordFailure(env,key); return json({error:"Name or PIN did not match."},401); }
        await env.DB.prepare("DELETE FROM login_attempts WHERE attempt_key=?").bind(key).run();
        const token=await issueSession(env,account.id);
        let progress={}; try{progress=JSON.parse(account.progress_json)||{}}catch{}
        return json({token,name:account.display_name,progress,updatedAt:account.updated_at});
      }
      if (url.pathname==="/api/sync" && request.method==="GET") {
        const auth=await authenticated(request,env); if(!auth)return json({error:"Please sign in again."},401);
        const row=await env.DB.prepare("SELECT display_name,progress_json,updated_at FROM accounts WHERE id=?").bind(auth.accountId).first();
        if(!row)return json({error:"Account not found."},404);
        let progress={};try{progress=JSON.parse(row.progress_json)||{}}catch{}
        return json({name:row.display_name,progress,updatedAt:row.updated_at});
      }
      if (url.pathname==="/api/sync" && request.method==="PUT") {
        const auth=await authenticated(request,env); if(!auth)return json({error:"Please sign in again."},401);
        const body=await readJson(request), progress=cleanProgress(body?.progress);
        if(!progress)return json({error:"Progress data is invalid or too large."},400);
        const now=Date.now();
        await env.DB.prepare("UPDATE accounts SET progress_json=?,updated_at=? WHERE id=?").bind(JSON.stringify(progress),now,auth.accountId).run();
        return json({ok:true,updatedAt:now});
      }
      if (url.pathname==="/api/logout" && request.method==="POST") {
        const auth=await authenticated(request,env); if(auth)await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(auth.tokenHash).run();
        return json({ok:true});
      }
      return json({error:"Not found."},404);
    } catch(error) {
      return json({error:"Sync service error. Check Worker and database setup."},500);
    }
  }
};