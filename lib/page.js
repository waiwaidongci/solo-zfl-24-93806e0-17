export const PAGE = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>赛鸽登记站 · 电子环防伪</title>
<style>
:root{--bg:#eef2f5;--panel:#fff;--ink:#1f2833;--muted:#697786;--line:#d3dce4;--accent:#315f83;--green:#2e7d4f;--red:#9b3f35;--amber:#a06d1c;}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:Arial,"PingFang SC",sans-serif}
header{padding:18px 26px;background:#fff;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:center;gap:14px;flex-wrap:wrap}
h1{margin:0;font-size:22px}.meta{color:var(--muted);font-size:13px}
nav{display:flex;gap:8px;padding:14px 26px 0}.tab{border:1px solid var(--line);background:#fff;border-radius:8px 8px 0 0;padding:9px 18px;cursor:pointer;font-weight:700;color:var(--muted)}
.tab.active{color:var(--accent);border-bottom-color:#fff;position:relative;top:1px}
main{padding:0 26px 26px}.view{display:none}.view.active{display:block}
.panel,form.card,.stat{background:#fff;border:1px solid var(--line);border-radius:8px;padding:16px}
.grid2{display:grid;grid-template-columns:400px 1fr;gap:16px;margin-top:-1px}
h2{margin:0 0 12px;font-size:17px}h3{margin:14px 0 8px;font-size:15px}
label{display:block;margin:9px 0 4px;color:var(--muted);font-size:13px}
input,select,textarea{width:100%;border:1px solid var(--line);border-radius:6px;padding:8px;font:inherit}
button{border:0;border-radius:6px;background:var(--accent);color:#fff;padding:8px 12px;font-weight:700;cursor:pointer;margin:4px 4px 0 0}
button.warn{background:var(--amber)}button.danger{background:var(--red)}button.ghost{background:#e7edf2;color:var(--ink)}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
table{width:100%;border-collapse:collapse;font-size:13px;background:#fff}th,td{border:1px solid var(--line);padding:7px 9px;text-align:left;vertical-align:top}
th{background:#f5f8fa}
.pill{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:2px 9px;font-size:12px}
.pill.active{background:#e6f4ec;color:var(--green);border-color:#b9dcc8}
.pill.issued{background:#eef3f8;color:var(--accent)}
.pill.lost,.pill.damaged,.pill.revoked{background:#f9e9e7;color:var(--red);border-color:#e3bdb8}
.once{background:#fff8e8;border:1px dashed var(--amber);border-radius:8px;padding:10px;font-family:Menlo,Consolas,monospace;font-size:12.5px;word-break:break-all;white-space:pre-wrap}
.ok{color:var(--green);font-weight:700}.bad{color:var(--red);font-weight:700}
.log{font-family:Menlo,Consolas,monospace;font-size:12.5px;white-space:pre-wrap;max-height:260px;overflow:auto}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:12px}
.devcard{background:#fff;border:1px solid var(--line);border-radius:8px;padding:12px;display:grid;gap:6px;font-size:13px}
@media(max-width:960px){.grid2{grid-template-columns:1fr}}
</style>
</head>
<body>
<header>
  <div><h1>赛鸽登记站</h1><div class="meta">档案管理 + 电子环防伪：发放 · 激活 · 校验 · 轮换 · 撤销</div></div>
  <div class="row">
    <select id="role" style="width:auto">
      <option value="admin">管理员</option>
      <option value="keeper">棚管员</option>
    </select>
    <input id="token" placeholder="访问令牌" style="width:210px">
    <span id="who" class="pill"></span>
  </div>
</header>
<nav><div class="tab active" data-tab="rings">电子环防伪</div><div class="tab" data-tab="pigeons">鸽只档案</div></nav>
<main>
<!-- ================= 电子环 ================= -->
<section class="view active" id="view-rings">
  <div class="grid2">
    <div style="display:grid;gap:16px;align-content:start">
      <form class="card" id="issueBox" style="display:none">
        <h2>① 发放电子环（管理员）</h2>
        <label>电子环编号 ringCode</label><input id="i-ring" placeholder="如 E2026-0001">
        <label>绑定鸽只（同一鸽只能绑定一次）</label><select id="i-pigeon"></select>
        <button>发环并生成一次性凭证</button>
        <div id="issueResult" style="margin-top:10px"></div>
      </form>

      <form class="card" id="activateBox" style="display:none">
        <h2>② 激活本棚设备（棚管员）</h2>
        <div class="meta">本棚：<b id="a-loft"></b>，只能激活发放给本棚的环；凭证一次性，激活后立即作废。</div>
        <label>一次性激活凭证</label><textarea id="a-voucher" rows="3" placeholder="粘贴管理员发放的凭证"></textarea>
        <button>激活并领取设备密钥</button>
        <div id="activateResult" style="margin-top:10px"></div>
      </form>

      <div class="card">
        <h2>③ 防伪校验（HMAC 签名）</h2>
        <div class="meta">签名原文 deviceId|loft|timestamp|nonce|pigeonRingNo；窗口 ±5 分钟；nonce 用一次即废。</div>
        <label>设备</label><select id="v-device"></select>
        <label>设备当前密钥（激活/轮换时领取，仅存本浏览器）</label><input id="v-key" placeholder="deviceKey">
        <label>校验棚号 loft</label><input id="v-loft" placeholder="棚管员自动带入本棚">
        <div class="row" style="margin-top:8px">
          <button type="button" id="btn-verify">正常校验</button>
          <button type="button" class="ghost" id="btn-cross">跨棚请求（应拦截）</button>
          <button type="button" class="ghost" id="btn-replay">重放上次请求</button>
          <button type="button" class="ghost" id="btn-tamper">篡改签名</button>
          <button type="button" class="ghost" id="btn-expired">过期时间戳</button>
        </div>
        <div id="verifyResult" class="log" style="margin-top:10px"></div>
      </div>
    </div>

    <div style="display:grid;gap:16px;align-content:start">
      <div class="panel">
        <div class="row" style="justify-content:space-between">
          <h2 style="margin:0">设备列表 <span id="devScope" class="meta"></span></h2>
          <button class="ghost" type="button" id="btn-refresh">刷新</button>
        </div>
        <div class="cards" id="devices" style="margin-top:10px"></div>
      </div>
      <div class="panel">
        <h2>校验记录（重启后仍可查）</h2>
        <table><thead><tr><th>时间</th><th>设备</th><th>棚</th><th>结果</th><th>原因码</th><th>nonce</th></tr></thead>
        <tbody id="verifies"></tbody></table>
      </div>
    </div>
  </div>
</section>

<!-- ================= 鸽只档案（原有功能保留） ================= -->
<section class="view" id="view-pigeons">
  <div class="grid2">
    <form class="card" id="pform">
      <h2>创建鸽只档案</h2>
      <label>足环号</label><input name="ringNo" required>
      <label>鸽主</label><input name="owner" required>
      <label>父鸽足环号</label><input name="fatherRing">
      <label>母鸽足环号</label><input name="motherRing">
      <label>羽色</label><input name="color" required>
      <label>出生棚号</label><input name="loft" placeholder="如 北岸A棚 / 种鸽棚" required>
      <button>保存档案</button>
    </form>
    <section>
      <div class="panel"><h2>档案列表</h2><div id="pigeons"></div></div>
    </section>
  </div>
</section>
</main>

<script>
const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];
const LS = {
  get(k){ try{return JSON.parse(localStorage.getItem(k))}catch{return null} },
  set(k,v){ localStorage.setItem(k, JSON.stringify(v)) }
};
const state = { role:'admin', identity:null, pigeons:[], devices:[], verifies:[], lastPayload:null, keyStore: LS.get('ringKeys')||{} };

function authHeaders(){
  const h = { 'Content-Type':'application/json', 'X-Role': state.role };
  if(state.role==='admin') h['X-Admin-Token'] = $('#token').value.trim();
  else h['X-Keeper-Token'] = $('#token').value.trim();
  return h;
}
async function api(path, opt={}){
  const res = await fetch(path, { ...opt, headers: { ...authHeaders(), ...(opt.headers||{}) } });
  const data = await res.json().catch(()=>({}));
  return { ok:res.ok, status:res.status, data };
}
function esc(s){ return String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function fmt(ts){ return ts ? new Date(ts).toLocaleString('zh-CN',{hour12:false}) : '—'; }

async function login(){
  const r = await api('/api/whoami');
  if(!r.ok){ state.identity=null; $('#who').textContent='未通过鉴权'; $('#who').className='pill lost'; return null; }
  state.identity = r.data;
  $('#who').textContent = r.data.role==='admin' ? '管理员' : '棚管员 · '+r.data.loft;
  $('#who').className = 'pill active';
  $('#issueBox').style.display = r.data.role==='admin' ? '' : 'none';
  $('#activateBox').style.display = r.data.role==='keeper' ? '' : 'none';
  $('#a-loft').textContent = r.data.loft || '';
  if(r.data.role==='keeper') $('#v-loft').value = r.data.loft;
  return r.data;
}

async function loadPigeons(){
  const r = await api('/api/pigeons');
  if(!r.ok) return;
  state.pigeons = r.data;
  $('#i-pigeon').innerHTML = r.data.map(p=>'<option value="'+esc(p.ringNo)+'">'+esc(p.ringNo)+'（'+esc(p.loft)+'）</option>').join('');
  $('#pigeons').innerHTML = '<table><thead><tr><th>足环号</th><th>鸽主</th><th>棚</th><th>羽色</th></tr></thead><tbody>'
    + r.data.map(p=>'<tr><td>'+esc(p.ringNo)+'</td><td>'+esc(p.owner)+'</td><td>'+esc(p.loft)+'</td><td>'+esc(p.color)+'</td></tr>').join('')
    + '</tbody></table>';
}

async function loadDevices(){
  const r = await api('/api/rings/devices');
  if(!r.ok){ $('#devices').innerHTML='<div class="bad">'+esc(r.data.error)+'</div>'; return; }
  state.devices = r.data;
  $('#devScope').textContent = state.identity?.role==='keeper' ? '（仅本棚）' : '（全部）';
  $('#v-device').innerHTML = r.data.map(d=>'<option value="'+esc(d.deviceId)+'">'+esc(d.deviceId)+' · '+esc(d.ringCode)+' · '+esc(d.status)+'</option>').join('');
  fillKeyFromStore();
  $('#devices').innerHTML = r.data.map(d=>{
    const canManage = state.identity.role==='admin' || d.loft===state.identity.loft;
    const keyHint = state.keyStore[d.deviceId] ? '（密钥已在本机保存）' : '';
    return '<div class="devcard"><div><b>'+esc(d.deviceId)+'</b> <span class="pill '+d.status+'">'+
      ({issued:'待激活',active:'生效中',lost:'已报失',damaged:'已报损',revoked:'已撤销'}[d.status]||d.status)+'</span></div>'
      +'<div>电子环：'+esc(d.ringCode)+' ｜ 鸽：'+esc(d.pigeonRingNo)+'</div>'
      +'<div>绑定棚：'+esc(d.loft||d.loftAtIssue)+' ｜ 密钥版本 v'+d.keyVersion+' '+esc(keyHint)+'</div>'
      +'<div class="meta">发放 '+fmt(d.issuedAt)+' ｜ 激活 '+fmt(d.activatedAt)+(d.revokedAt?' ｜ 撤销 '+fmt(d.revokedAt):'')+'</div>'
      +(canManage && d.status==='active' ? '<div class="row"><button data-act="rotate" data-id="'+esc(d.deviceId)+'">轮换密钥</button>'
        +(state.identity.role==='keeper'?'':'')
        +'<button class="warn" data-act="lost" data-id="'+esc(d.deviceId)+'">报失</button>'
        +'<button class="warn" data-act="damaged" data-id="'+esc(d.deviceId)+'">报损</button>'
        +(state.identity.role==='admin'?'<button class="danger" data-act="revoke" data-id="'+esc(d.deviceId)+'">管理员撤销</button>':'')
        +'</div>':'')
      +(state.identity.role==='admin' && d.status!=='revoked' && d.status!=='active' ? '<div class="row"><button class="danger" data-act="revoke" data-id="'+esc(d.deviceId)+'">管理员撤销</button></div>':'')
      +'</div>';
  }).join('');
  $$('#devices [data-act]').forEach(b=>b.onclick=()=>deviceAction(b.dataset.act,b.dataset.id));
}

async function deviceAction(act, id){
  const paths = { rotate:'/rotate', lost:'/report', damaged:'/report', revoke:'/revoke' };
  let body = '{}';
  if(act==='lost'||act==='damaged') body = JSON.stringify({reason:act});
  if(act==='rotate'){ const d=state.devices.find(x=>x.deviceId===id); body = JSON.stringify({keyVersion:d.keyVersion}); }
  const r = await api('/api/rings/devices/'+encodeURIComponent(id)+paths[act], { method:'POST', body });
  if(act==='rotate' && r.ok && r.data.deviceKey){
    state.keyStore[id] = r.data.deviceKey; LS.set('ringKeys', state.keyStore);
  }
  alert(r.ok ? '操作成功'+(r.data.deviceKey?'\\n新密钥已保存到本机：\\n'+r.data.deviceKey:'') : '失败：'+r.data.error);
  await refreshAll();
}

async function loadVerifies(){
  const r = await api('/api/rings/verifications');
  if(!r.ok) return;
  state.verifies = r.data;
  $('#verifies').innerHTML = r.data.slice(0,50).map(v=>'<tr><td>'+fmt(v.at)+'</td><td>'+esc(v.deviceId)+'</td><td>'+esc(v.loft)+'</td>'
    +'<td class="'+(v.ok?'ok':'bad')+'">'+(v.ok?'通过':'拒绝')+'</td><td>'+esc(v.code)+'</td><td class="meta">'+esc((v.nonce||'').slice(0,16))+'</td></tr>').join('')
    || '<tr><td colspan="6" class="meta">暂无记录</td></tr>';
}

async function refreshAll(){ await login(); await Promise.all([loadPigeons(),loadDevices(),loadVerifies()]); }

// ---- HMAC-SHA256（浏览器 WebCrypto，与 Node crypto 完全一致）----
async function hmacHex(key, message){
  const enc = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey('raw', enc.encode(key), {name:'HMAC',hash:'SHA-256'}, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, enc.encode(message));
  return [...new Uint8Array(sig)].map(b=>b.toString(16).padStart(2,'0')).join('');
}
function selectedDevice(){ return state.devices.find(d=>d.deviceId===$('#v-device').value); }
function fillKeyFromStore(){ const d=selectedDevice(); if(d && state.keyStore[d.deviceId]) $('#v-key').value=state.keyStore[d.deviceId]; }
$('#v-device').onchange = fillKeyFromStore;

async function buildPayload({cross=false, tamper=false, expired=false}){
  const d = selectedDevice(); if(!d){ alert('暂无设备'); return null; }
  const ts = expired ? Date.now()-10*60*1000 : Date.now();
  const nonce = crypto.randomUUID();
  const loft = cross ? ((d.loft||'北岸A棚')==='北岸A棚' ? '种鸽棚' : '北岸A棚') : ($('#v-loft').value.trim() || d.loft);
  const fields = { deviceId:d.deviceId, loft, timestamp:ts, nonce, pigeonRingNo:d.pigeonRingNo };
  let signature = await hmacHex($('#v-key').value.trim(), fields.deviceId+'|'+fields.loft+'|'+fields.timestamp+'|'+fields.nonce+'|'+fields.pigeonRingNo);
  if(tamper) signature = signature.slice(0,-2)+(signature.slice(-2)==='00'?'01':'00');
  return { ...fields, signature };
}

async function doVerify(payload, label){
  if(!payload) return;
  state.lastPayload = payload;
  const r = await api('/api/rings/verify', { method:'POST', body:JSON.stringify(payload) });
  $('#verifyResult').textContent = '【'+label+'】HTTP '+r.status+'\\n'+JSON.stringify(r.data,null,2)+'\\n\\n'
    + '请求：'+JSON.stringify(payload,null,2) + '\\n\\n' + ($('#verifyResult').textContent||'');
  await loadVerifies();
}

$('#btn-verify').onclick = async()=>doVerify(await buildPayload({}),'正常校验');
$('#btn-cross').onclick  = async()=>doVerify(await buildPayload({cross:true}),'跨棚请求（预期 403 cross_loft_denied）');
$('#btn-tamper').onclick = async()=>doVerify(await buildPayload({tamper:true}),'篡改签名（预期 401 bad_signature）');
$('#btn-expired').onclick= async()=>doVerify(await buildPayload({expired:true}),'过期时间戳（预期 401 timestamp_expired）');
$('#btn-replay').onclick = async()=>{
  if(!state.lastPayload){ alert('请先发起一次校验'); return; }
  await doVerify({ ...state.lastPayload }, '重放（预期 409 replay_detected）');
};

$('#issueBox').onsubmit = async e=>{
  e.preventDefault();
  const r = await api('/api/rings/devices', { method:'POST', body:JSON.stringify({
    ringCode:$('#i-ring').value.trim(), pigeonRingNo:$('#i-pigeon').value
  })});
  if(r.ok){
    $('#issueResult').innerHTML = '<div class="once">电子环已发放：'+esc(r.data.device.deviceId)
      +'\\n鸽只：'+esc(r.data.device.pigeonRingNo)+'　棚：'+esc(r.data.device.loftAtIssue)
      +'\\n一次性激活凭证（仅显示这一次，有效期24h）：\\n'+esc(r.data.voucher)+'</div>';
    $('#i-ring').value='';
  } else $('#issueResult').innerHTML='<div class="bad">'+esc(r.data.error)+'</div>';
  await loadDevices();
};
$('#activateBox').onsubmit = async e=>{
  e.preventDefault();
  const r = await api('/api/rings/activate', { method:'POST', body:JSON.stringify({ voucher:$('#a-voucher').value.trim() })});
  if(r.ok){
    state.keyStore[r.data.device.deviceId]=r.data.deviceKey; LS.set('ringKeys',state.keyStore);
    $('#v-key').value = r.data.deviceKey;
    $('#activateResult').innerHTML='<div class="once">激活成功：'+esc(r.data.device.deviceId)
      +'\\n设备密钥（仅显示这一次，轮换后旧密钥立即失效）：\\n'+esc(r.data.deviceKey)+'</div>';
    $('#a-voucher').value='';
  } else $('#activateResult').innerHTML='<div class="bad">'+esc(r.data.error)+'</div>';
  await refreshAll();
};
$('#pform').onsubmit = async e=>{
  e.preventDefault();
  const r = await api('/api/pigeons',{method:'POST',body:JSON.stringify(Object.fromEntries(new FormData($('#pform')).entries()))});
  alert(r.ok?'档案已保存':'失败：'+r.data.error);
  $('#pform').reset(); loadPigeons();
};
$$('.tab').forEach(t=>t.onclick=()=>{
  $$('.tab').forEach(x=>x.classList.toggle('active',x===t));
  $$('.view').forEach(v=>v.classList.toggle('active',v.id==='view-'+t.dataset.tab));
});
$('#role').onchange = async e=>{ state.role=e.target.value; localStorage.setItem('role',state.role); $('#token').value=state.role==='admin'?'admin-secret':'keeper-beian'; await refreshAll(); };
$('#token').onchange = refreshAll;
$('#btn-refresh').onclick = refreshAll;

state.role = localStorage.getItem('role') || 'admin';
$('#role').value = state.role;
$('#token').value = state.role==='admin' ? 'admin-secret' : 'keeper-beian';
refreshAll();
</script>
</body>
</html>`;
