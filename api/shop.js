const crypto=require('crypto'),{Redis}=require('@upstash/redis');
const db=new Redis({url:process.env.KV_REST_API_URL||process.env.UPSTASH_REDIS_REST_URL,token:process.env.KV_REST_API_TOKEN||process.env.UPSTASH_REDIS_REST_TOKEN});
const SECRET=process.env.ADMIN_PASSWORD||'';
const sign=e=>crypto.createHmac('sha256',SECRET).update(e).digest('hex');
const same=(a,b)=>{a=Buffer.from(String(a));b=Buffer.from(String(b));return a.length===b.length&&crypto.timingSafeEqual(a,b)};
const hash=(p,s)=>crypto.scryptSync(p,s,32).toString('hex');
module.exports=async(req,res)=>{
const b=req.body||{},a=b.action,t=s=>String(s||'').trim().slice(0,300),out=(c,o)=>res.status(c).json(o);
if(req.method!=='POST'||!SECRET)return out(400,{error:'Server is not set up yet.'});
try{
if(a==='auth'){
const e=t(b.email).toLowerCase(),n=t(b.name),p=String(b.password||'');
if(!/\S+@\S+\.\S+/.test(e)||p.length<6)return out(400,{error:'Enter a valid email and a password of 6 or more characters.'});
let u=await db.hget('users',e);
if(!u){const s=crypto.randomBytes(8).toString('hex');u={name:n||e,email:e,salt:s,hash:hash(p,s),at:new Date().toISOString()};await db.hset('users',{[e]:u})}
else if(!same(hash(p,u.salt),u.hash))return out(401,{error:'Wrong password for this email.'});
return out(200,{name:u.name,token:e+'|'+sign(e)})}
if(a==='order'){
const [e,g]=String(b.token||'').split('|');
if(!e||!same(sign(e),g||''))return out(401,{error:'Please log in again.'});
const items=(Array.isArray(b.items)?b.items:[]).slice(0,50).map(i=>({name:t(i.name),price:Number(i.price)||0}));
if(!items.length)return out(400,{error:'Your cart is empty.'});
const id='HS'+Date.now().toString().slice(-6)+crypto.randomInt(10,99);
await db.lpush('orders',{id,email:e,name:t(b.name),mobile:t(b.mobile),address:t(b.address),method:t(b.method),items,total:items.reduce((s,i)=>s+i.price,0),status:'Payment pending',at:new Date().toISOString()});
return out(200,{id})}
if(a==='admin'){
if(!same(b.password||'',SECRET))return out(401,{error:'Wrong admin password.'});
const users=Object.values(await db.hgetall('users')||{}).map(({name,email,at})=>({name,email,at}));
return out(200,{users,orders:await db.lrange('orders',0,199)})}
out(400,{error:'Unknown request.'})
}catch(x){out(500,{error:'Server error. Check the database is connected.'})}
};
