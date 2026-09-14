const API='/api/admin';
let serverKey=null, clientKeys=null, usersCache=[], logsCache=[], suspiciousCache=[];

const b64=a=>btoa(String.fromCharCode(...new Uint8Array(a))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const unb64=s=>{s=String(s||'').replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';return Uint8Array.from(atob(s),c=>c.charCodeAt(0));};
const $=id=>document.getElementById(id);
const esc=v=>String(v??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
const fmt=t=>t?new Date(Number(t)).toLocaleString('id-ID',{dateStyle:'short',timeStyle:'medium'}):'-';

function toast(text,ok=true){
  const el=$('toast');el.textContent=text;el.className='toast '+(ok?'ok':'err');
  clearTimeout(window.__toast);window.__toast=setTimeout(()=>el.classList.add('hidden'),3200);
}
function setLoginMsg(t){$('loginMsg').textContent=t||'';}

async function initCrypto(){
  const r=await fetch(API+'?action=key',{cache:'no-store',credentials:'include'});
  if(!r.ok) throw new Error('Public key server gagal diambil');
  const j=await r.json();
  serverKey=await crypto.subtle.importKey('jwk',j.publicKey,{name:'RSA-OAEP',hash:'SHA-256'},false,['encrypt']);
  clientKeys=await crypto.subtle.generateKey({name:'RSA-OAEP',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['encrypt','decrypt']);
}
function fingerprint(){
  const s=[navigator.userAgent,navigator.language,screen.width+'x'+screen.height,screen.colorDepth,Intl.DateTimeFormat().resolvedOptions().timeZone].join('|');
  let h=2166136261;for(let i=0;i<s.length;i++){h^=s.charCodeAt(i);h=Math.imul(h,16777619)}return (h>>>0).toString(16);
}
async function request(action,payload={}){
  if(!clientKeys) await initCrypto();
  const aes=await crypto.subtle.generateKey({name:'AES-GCM',length:256},true,['encrypt','decrypt']);
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const plain=new TextEncoder().encode(JSON.stringify(payload));
  const encrypted=await crypto.subtle.encrypt({name:'AES-GCM',iv},aes,plain);
  const rawKey=await crypto.subtle.exportKey('raw',aes);
  const wrapped=await crypto.subtle.encrypt({name:'RSA-OAEP'},serverKey,rawKey);
  const jwk=await crypto.subtle.exportKey('jwk',clientKeys.publicKey);
  const bytes=new Uint8Array(encrypted),tag=bytes.slice(-16),data=bytes.slice(0,-16);
  const envelope={v:1,alg:'RSA-OAEP-256/AES-256-GCM',key:b64(wrapped),iv:b64(iv),tag:b64(tag),data:b64(data)};
  const r=await fetch(API+'?action='+encodeURIComponent(action),{
    method:'POST',credentials:'include',
    headers:{'Content-Type':'application/json','X-Fingerprint':fingerprint()},
    body:JSON.stringify({envelope,clientPublicKey:jwk})
  });
  let raw;try{raw=await r.json()}catch{throw new Error('Response server tidak valid')}
  if(!raw.encrypted){if(!r.ok)throw new Error(raw.message||raw.error||'Request gagal');return raw}
  try{
    const aesRaw=await crypto.subtle.decrypt({name:'RSA-OAEP'},clientKeys.privateKey,unb64(raw.data.key));
    const aesKey=await crypto.subtle.importKey('raw',aesRaw,{name:'AES-GCM'},false,['decrypt']);
    const all=new Uint8Array([...unb64(raw.data.data),...unb64(raw.data.tag)]);
    const dec=await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(raw.data.iv)},aesKey,all);
    const out=JSON.parse(new TextDecoder().decode(dec));
    if(!r.ok)throw new Error(out.message||'Request gagal');
    return out;
  }catch(e){if(e.message&&/gagal|valid|sesi|admin/i.test(e.message))throw e;throw new Error('Gagal membuka response server')}
}

async function login(){
  const btn=$('loginBtn');btn.disabled=true;setLoginMsg('Memproses...');
  try{
    const r=await request('login',{username:$('loginUser').value.trim(),password:$('loginPass').value});
    if(!r.success)throw new Error(r.message||'Login gagal');
    $('loginPass').value='';$('loginPage').classList.add('hidden');$('app').classList.remove('hidden');
    $('who').textContent=`${r.username} • ${r.role}`;
    await loadAll();
  }catch(e){setLoginMsg(e.message);toast(e.message,false)}
  finally{btn.disabled=false}
}
async function logout(){try{await request('logout');location.reload()}catch(e){toast(e.message,false)}}
async function loadAll(){
  await Promise.allSettled([loadStats(),loadUsers(),loadLogs(),loadSuspicious(),loadMaintenance()]);
  renderDerived(); 
}
async function loadStats(){
  const r=await request('stats');$('total').textContent=r.stats.total;$('banned').textContent=r.stats.banned;$('accessBanned').textContent=r.stats.accessBanned;$('forced').textContent=r.stats.forced;$('maintenanceStat').textContent=r.stats.maintenance?'ON':'OFF';
  $('adminStat').textContent=$('who').textContent.split('•')[0].trim()||'-';
}
async function loadUsers(){const r=await request('users');usersCache=r.users||[];renderUsers();renderDerived()}
function actionBtn(action,u,cls='gray'){return `<button class="btn small ${cls}" data-act="${esc(action)}" data-user="${esc(u.username)}">${esc(action)}</button>`}
function userTable(list){
 if(!list.length)return '<div class="empty">Tidak ada data.</div>';
 return `<table><thead><tr><th>User</th><th>Role</th><th>Status</th><th>Reset</th><th>Aksi</th></tr></thead><tbody>${list.map(u=>{
  const badges=[];
  if(u.banned)badges.push('<span class="badge danger">BANNED</span>');
  if(u.accessBanned)badges.push('<span class="badge warn">BAN AKSES</span>');
  if(u.forceLogout)badges.push('<span class="badge danger">FORCE</span>');
  if(!badges.length)badges.push('<span class="badge ok">AKTIF</span>');
  return `<tr><td><b>${esc(u.username)}</b><br><span class="muted">${esc(u.email)}</span></td><td>${esc(u.role)}</td><td>${badges.join(' ')}</td><td>${esc(u.resetCount)}</td><td><div class="actions">${actionBtn(u.banned?'unbanned':'banned',u,u.banned?'ok':'danger')}${actionBtn(u.accessBanned?'unban-akses':'ban-akses',u,u.accessBanned?'ok':'warn')}${actionBtn(u.forceLogout?'unforce':'force',u,u.forceLogout?'ok':'gray')}<button class="btn small gray" data-act="edit" data-user="${esc(u.username)}">Edit</button><button class="btn small danger" data-act="delete-user" data-user="${esc(u.username)}">Hapus</button></div></td></tr>`;
 }).join('')}</tbody></table>`;
}
function renderUsers(){
 const q=($('search').value||'').toLowerCase();
 const rows=usersCache.filter(u=>(`${u.username} ${u.email} ${u.role}`).toLowerCase().includes(q));
 $('userCount').textContent=`${rows.length} dari ${usersCache.length} user`;$('usersTable').innerHTML=userTable(rows);
}
function renderFiltered(id,list){$(id).innerHTML=userTable(list)}
function renderDerived(){
 const pending=usersCache.filter(u=>u.needsActivation||u.activationStatus==='pending'||u.status==='pending');
 renderActivation(pending);
 renderFiltered('bannedTable',usersCache.filter(u=>u.banned));
 renderFiltered('accessTable',usersCache.filter(u=>u.accessBanned));
 renderFiltered('forceTable',usersCache.filter(u=>u.forceLogout));
 renderFiltered('problemTable',usersCache.filter(u=>u.banned||u.accessBanned||u.forceLogout||Number(u.resetCount)>3));
}
function renderActivation(list){
 if(!list.length){$('activationTable').innerHTML='<div class=\"empty\">Tidak ada user yang menunggu aktivasi.</div>';return}
 $('activationTable').innerHTML=`<table><thead><tr><th>User</th><th>Status</th><th>Aksi</th></tr></thead><tbody>${list.map(u=>`<tr><td><b>${esc(u.username)}</b><br><span class=\"muted\">${esc(u.email)}</span></td><td><span class=\"badge warn\">${esc(u.activationStatus||u.status||'pending')}</span></td><td><button class=\"btn small ok\" data-act=\"activate\" data-user=\"${esc(u.username)}\">Aktifkan</button></td></tr>`).join('')}</tbody></table>`;
}
function logsTable(list){
 if(!list.length)return '<div class="empty">Belum ada log.</div>';
 return `<table><thead><tr><th>Waktu</th><th>User</th><th>Action</th><th>IP</th><th>Fingerprint</th><th>Detail</th></tr></thead><tbody>${list.map(x=>`<tr><td>${esc(fmt(x.timestamp))}</td><td>${esc(x.username||'-')}</td><td><span class="badge">${esc(x.action||'-')}</span></td><td>${esc(x.ip||'-')}</td><td>${esc(x.fingerprint||'-')}</td><td>${esc(x.details||x.message||'-')}</td></tr>`).join('')}</tbody></table>`;
}
async function loadLogs(){
 try{const r=await request('logs',{limit:300});logsCache=r.logs||[];$('logsTable').innerHTML=logsTable(logsCache);$('dashboardLogs').innerHTML=logsTable(logsCache.slice(0,10));$('logCount').textContent=logsCache.length;renderDerived()}catch(e){console.error(e)}
}
async function loadSuspicious(){
 try{const r=await request('suspicious-logs',{limit:500});suspiciousCache=r.logs||[];$('suspiciousTable').innerHTML=logsTable(suspiciousCache);$('suspiciousCount').textContent=suspiciousCache.length}catch(e){console.error(e)}
}
async function loadMaintenance(){
 try{const r=await request('maintenance-status');const m=r.maintenance||{};$('maintEnabled').value=m.maintenance?'true':'false';$('maintTitle').value=m.title||'SEDANG PERBAIKAN SISTEM';$('maintMessage').value=m.message||'';$('maintUntil').value=m.until||'';$('maintState').textContent=m.maintenance?'ON':'OFF';$('maintState').className='badge '+(m.maintenance?'warn':'ok');$('maintenanceStat').textContent=m.maintenance?'ON':'OFF'}catch(e){console.error(e)}
}
async function doUser(action,username){
 if(action==='delete-user'&&!confirm(`Hapus user ${username}?`))return;
 try{const r=await request(action,{username});toast(r.message||'Berhasil');await Promise.all([loadStats(),loadUsers(),loadLogs(),loadSuspicious()])}catch(e){toast(e.message,false)}
}
async function activateUser(username){
 try{const r=await request('edit-user',{username,needsActivation:false,activationStatus:'active',status:'active',isActive:true});toast(r.message||'User diaktifkan');await Promise.all([loadUsers(),loadStats(),loadLogs()])}catch(e){toast(e.message,false)}
}
async function editUser(username){
 const u=usersCache.find(x=>x.username===username);if(!u)return;
 const email=prompt('Email user:',u.email||'');if(email===null)return;
 const role=prompt('Role (User/Admin):',u.role||'User');if(role===null)return;
 const password=prompt('Password baru (kosongkan jika tidak diganti):','');if(password===null)return;
 try{const r=await request('edit-user',{username,email,role,password});toast(r.message||'Data diubah');await Promise.all([loadUsers(),loadLogs()])}catch(e){toast(e.message,false)}
}
async function addUser(){
 try{
  const p={username:$('newUser').value.trim(),email:$('newEmail').value.trim(),password:$('newPass').value,role:$('newRole').value};
  const r=await request('add-user',p);if(!r.success)throw new Error(r.message);toast(r.message||'User ditambahkan');$('newUser').value=$('newEmail').value=$('newPass').value='';$('addBox').classList.add('hidden');await Promise.all([loadStats(),loadUsers(),loadLogs()])
 }catch(e){toast(e.message,false)}
}
async function setMaintenance(){
 try{const r=await request('maintenance',{enabled:$('maintEnabled').value==='true',title:$('maintTitle').value,message:$('maintMessage').value,until:$('maintUntil').value});toast(r.message||'Maintenance disimpan');await Promise.all([loadStats(),loadMaintenance(),loadLogs()])}catch(e){toast(e.message,false)}
}
async function migrate(action){
 const label=action==='migrate-passwords'?'Migrasi password':'Migrasi format data';
 if(!confirm(`Jalankan ${label}?`))return;
 try{const r=await request(action);const x=r.result||{};$('migrationResult').textContent=`${r.message} Scan: ${x.scanned||0}, diubah: ${x.changed||0}, dilewati: ${x.skipped||0}.`;toast(r.message||'Migrasi selesai');await Promise.all([loadUsers(),loadLogs()])}catch(e){toast(e.message,false)}
}
async function saveEmail(){
 const email=$('adminEmail').value.trim();if(!email)return toast('Email wajib diisi',false);
 try{const r=await request('change-email',{email});toast(r.message||'Email berhasil diubah');$('adminEmail').value=email;await loadLogs()}catch(e){toast(e.message,false)}
}
async function savePassword(){
 const p=$('adminPassword').value,p2=$('adminPassword2').value;
 if(p.length<8)return toast('Password minimal 8 karakter',false);if(p!==p2)return toast('Konfirmasi password tidak sama',false);
 try{const r=await request('change-password',{password:p});toast(r.message||'Password berhasil diubah');setTimeout(()=>location.reload(),900)}catch(e){toast(e.message,false)}
}
function setup(){
 $('loginBtn').onclick=login;$('logoutBtn').onclick=logout;$('refreshBtn').onclick=loadAll;
 $('search').oninput=renderUsers;$('showAddBtn').onclick=()=>$('addBox').classList.toggle('hidden');$('addUserBtn').onclick=addUser;
 $('saveMaintBtn').onclick=setMaintenance;$('loadLogsBtn').onclick=loadLogs;$('loadSuspiciousBtn').onclick=loadSuspicious;
 $('migratePassBtn').onclick=()=>migrate('migrate-passwords');$('migrateFormatBtn').onclick=()=>migrate('migrate_users_format');
 $('saveEmailBtn').onclick=saveEmail;$('savePasswordBtn').onclick=savePassword;$('menuBtn').onclick=()=>$('sidebar').classList.toggle('open');
 $('loginPass').addEventListener('keydown',e=>{if(e.key==='Enter')login()});
 document.addEventListener('click',e=>{
  const nav=e.target.closest('[data-target]');if(nav){document.querySelectorAll('.nav button').forEach(x=>x.classList.remove('active'));if(nav.classList.contains('nav'))nav.classList.add('active');const target=$(nav.dataset.target);if(target)target.scrollIntoView({behavior:'smooth'});$('sidebar').classList.remove('open');}
  const act=e.target.closest('[data-act]');if(act){const a=act.dataset.act,u=act.dataset.user;if(a==='edit')editUser(u);else if(a==='activate')activateUser(u);else doUser(a,u)}
 });
}
(async()=>{setup();try{await initCrypto();const r=await request('me');if(r.success){$('loginPage').classList.add('hidden');$('app').classList.remove('hidden');$('who').textContent=`${r.admin.username} • ${r.admin.role}`;$('adminEmail').value=r.admin.email||'';await loadAll()}}catch{}})();
setInterval(async()=>{if($('app').classList.contains('hidden'))return;try{const r=await request('me');if(!r.success)location.reload()}catch{}},60000);
