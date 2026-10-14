/* APK 静态分析器：ZIP 解析 + AXML Manifest 解析 + 报告生成 */
(function(){
'use strict';

/* 权限中文说明 */
var PERM_DESC={
 'android.permission.INTERNET':'联网',
 'android.permission.ACCESS_NETWORK_STATE':'查看网络状态',
 'android.permission.ACCESS_WIFI_STATE':'查看 WiFi 状态',
 'android.permission.CHANGE_WIFI_STATE':'更改 WiFi 状态',
 'android.permission.WRITE_EXTERNAL_STORAGE':'写外部存储',
 'android.permission.READ_EXTERNAL_STORAGE':'读外部存储',
 'android.permission.READ_MEDIA_IMAGES':'读图片',
 'android.permission.READ_MEDIA_VIDEO':'读视频',
 'android.permission.READ_MEDIA_AUDIO':'读音频',
 'android.permission.CAMERA':'相机',
 'android.permission.RECORD_AUDIO':'麦克风录音',
 'android.permission.ACCESS_FINE_LOCATION':'精确定位',
 'android.permission.ACCESS_COARSE_LOCATION':'粗略定位',
 'android.permission.ACCESS_BACKGROUND_LOCATION':'后台定位',
 'android.permission.READ_SMS':'读短信',
 'android.permission.SEND_SMS':'发短信',
 'android.permission.RECEIVE_SMS':'收短信',
 'android.permission.READ_CALL_LOG':'读通话记录',
 'android.permission.WRITE_CALL_LOG':'写通话记录',
 'android.permission.READ_PHONE_STATE':'读手机状态',
 'android.permission.CALL_PHONE':'拨打电话',
 'android.permission.READ_CONTACTS':'读联系人',
 'android.permission.WRITE_CONTACTS':'写联系人',
 'android.permission.GET_ACCOUNTS':'获取账户',
 'android.permission.BIND_DEVICE_ADMIN':'设备管理器',
 'android.permission.SYSTEM_ALERT_WINDOW':'悬浮窗',
 'android.permission.REQUEST_INSTALL_PACKAGES':'安装未知应用',
 'android.permission.VIBRATE':'震动',
 'android.permission.WAKE_LOCK':'防止休眠',
 'android.permission.RECEIVE_BOOT_COMPLETED':'开机自启',
 'android.permission.FOREGROUND_SERVICE':'前台服务',
 'android.permission.POST_NOTIFICATIONS':'发送通知',
 'android.permission.BLUETOOTH':'蓝牙',
 'android.permission.BLUETOOTH_CONNECT':'连接蓝牙设备',
 'android.permission.NFC':'NFC',
 'android.permission.USE_BIOMETRIC':'生物识别',
 'android.permission.USE_FINGERPRINT':'指纹'
};
/* 高危权限（标红） */
var PERM_DANGER=[
 'android.permission.READ_SMS','android.permission.SEND_SMS','android.permission.RECEIVE_SMS',
 'android.permission.READ_CALL_LOG','android.permission.WRITE_CALL_LOG',
 'android.permission.CALL_PHONE','android.permission.READ_PHONE_STATE',
 'android.permission.ACCESS_FINE_LOCATION','android.permission.ACCESS_BACKGROUND_LOCATION',
 'android.permission.READ_CONTACTS','android.permission.WRITE_CONTACTS',
 'android.permission.RECORD_AUDIO','android.permission.BIND_DEVICE_ADMIN',
 'android.permission.REQUEST_INSTALL_PACKAGES','android.permission.SYSTEM_ALERT_WINDOW'
];

function permDesc(p){
  if(PERM_DESC[p])return PERM_DESC[p];
  // 自定义权限：取最后一段
  var parts=p.split('.');
  return parts[parts.length-1];
}
function isDanger(p){return PERM_DANGER.indexOf(p)>=0;}

function fmtSize(n){
  if(n<1024)return n+' B';
  if(n<1048576)return (n/1024).toFixed(1)+' KB';
  return (n/1048576).toFixed(1)+' MB';
}

/* assets 文本配置文件：类型 + 大小上限 */
var ASSET_TEXT_RE=/\.(json|xml|txt|properties|cfg|ini|conf)$/i;
var ASSET_MAX_SIZE=500*1024;

var state={file:null,report:null,analyzing:false,
  cmpA:null,cmpB:null,cmpReport:null,comparing:false};

function $(id){return document.getElementById(id);}

function setStatus(msg,cls){
  var el=$('ana-status');
  el.textContent=msg;
  el.className='hint '+(cls||'');
}

/* 解析单个 APK 文件：entries + manifest info + 证书。file: File 或 Node Buffer */
async function analyzeApkFile(file){
  var isBuf=typeof Buffer!=='undefined'&&Buffer.isBuffer(file);
  var fileName=isBuf?(file._name||'buffer.apk'):(file.name||'');
  var fileSize=isBuf?file.length:file.size;
  var zr=new ZipParser.ZipReader(file);
  var entries=await zr.parse();
  var mf=zr.find('AndroidManifest.xml');
  if(!mf)throw new Error('APK 内找不到 AndroidManifest.xml');
  var raw=await zr.extract(mf);
  var parser=new AxmlParser.AxmlParser(raw);
  parser.parse();
  var info=parser.getInfo();
  /* 证书：找 META-INF/*.RSA */
  var cert=null, certErr=null, certName=null;
  for(var i=0;i<entries.length;i++){
    if(/^META-INF\/[^\/]+\.RSA$/i.test(entries[i].name)){ certName=entries[i].name; break; }
  }
  if(certName){
    try{
      var rsaRaw=await zr.extract(zr.find(certName));
      var certs=CertParser.parse(rsaRaw);
      cert=certs[0];
      cert.fileName=certName;
    }catch(e){ certErr=e.message||String(e); }
  }
  return {fileName:fileName,fileSize:fileSize,entries:entries,info:info,
          cert:cert,certErr:certErr,zr:zr};
}

/* 提取 dex 分类字符串：返回 {str: cats} 映射 */
async function extractClassifiedStrings(analyzed, onProgress){
  var map={};
  var dexEntries=analyzed.entries.filter(function(e){return /\.dex$/.test(e.name);});
  for(var d=0; d<dexEntries.length; d++){
    var e=dexEntries[d];
    if(onProgress)onProgress('正在解压 '+e.name+'…', d, dexEntries.length);
    var raw=await analyzed.zr.extract(e);
    var strs=await DexParser.extractStrings(raw, function(done,tot){
      if(onProgress)onProgress('正在提取 '+e.name+' '+Math.round(done/tot*100)+'%…', d, dexEntries.length);
    });
    var r=await DexParser.analyzeStrings(strs);
    for(var i=0;i<r.items.length;i++){
      var it=r.items[i];
      if(!map[it.s])map[it.s]=it.cats;
    }
  }
  return map;
}

function analyze(){
  var fi=$('apk-file');
  if(!fi.files||!fi.files.length){toast('请先选择 APK 文件');return;}
  if(state.analyzing)return;
  var file=fi.files[0];
  if(file.size>200*1048576){toast('文件过大（>200MB），拒绝分析');return;}
  state.analyzing=true;
  setStatus('正在解析…（'+fmtSize(file.size)+'）','');
  $('ana-result').innerHTML='';
  $('btn-send-ai').style.display='none';

  // 分块读：只读中央目录 + Manifest，不一次性加载整个文件
  analyzeApkFile(file).then(function(r){
    state.zr=r.zr; // dex 字符串提取复用
    state.report=r;
    renderReport(r);
    setStatus('解析完成','ok');
    $('btn-send-ai').style.display='';
  }).catch(function(e){
    setStatus('解析失败：'+(e.message||e),'err');
  }).finally(function(){
    state.analyzing=false;
  });
}

function renderReport(r){
  var info=r.info, entries=r.entries;
  var h='';
  // 基本信息
  h+='<section class="card"><h3>基本信息</h3><div class="kv">';
  h+=kv('文件名',esc(r.fileName));
  h+=kv('大小',fmtSize(r.fileSize));
  h+=kv('包名','<code class="inline">'+esc(info.package)+'</code>');
  h+=kv('版本',esc(info.versionName)+' ('+info.versionCode+')');
  if(info.label&&!/^\d+$/.test(String(info.label)))h+=kv('应用名',esc(String(info.label)));
  h+='</div></section>';
  // 证书
  h+=renderCertCard(r);
  // 风险评分（权限已知即渲染，dex/so 提取后更新）
  h+='<div id="risk-card"></div>';
  // 权限
  h+='<section class="card"><h3>权限（'+info.permissions.length+'）</h3>';
  if(!info.permissions.length)h+='<p class="hint">无</p>';
  info.permissions.forEach(function(p){
    var danger=isDanger(p);
    h+='<div class="perm'+(danger?' danger':'')+'">'
      +'<code class="inline">'+esc(p)+'</code>'
      +'<span class="pdesc">'+esc(permDesc(p))+'</span>'
      +(danger?'<span class="ptag">敏感</span>':'')
      +'</div>';
  });
  h+='</section>';
  // 组件
  h+='<section class="card"><h3>组件</h3><div class="kv">';
  h+=kv('Activity',info.activities.length);
  h+=kv('Service',info.services.length);
  h+=kv('Receiver',info.receivers.length);
  h+=kv('Provider',info.providers.length);
  h+='</div>';
  function compList(title,arr){
    if(!arr.length)return '';
    var s='<details class="compl"><summary>'+title+'（'+arr.length+'）</summary>';
    arr.slice(0,30).forEach(function(c){s+='<code class="inline">'+esc(shortName(c,info.package))+'</code>';});
    if(arr.length>30)s+='<p class="hint">…还有 '+(arr.length-30)+' 个</p>';
    return s+'</details>';
  }
  h+=compList('Activity',info.activities);
  h+=compList('Service',info.services);
  h+=compList('Receiver',info.receivers);
  h+=compList('Provider',info.providers);
  h+='</section>';
  // 文件清单
  var dex=entries.filter(e=>/\.dex$/.test(e.name));
  var so=entries.filter(e=>/\.so$/.test(e.name));
  var archs={};
  so.forEach(function(e){
    var m=e.name.match(/lib\/([^\/]+)\//);
    if(m)archs[m[1]]=(archs[m[1]]||0)+1;
  });
  h+='<section class="card"><h3>文件结构</h3><div class="kv">';
  h+=kv('总文件',entries.length);
  h+=kv('dex',dex.length+' 个');
  h+=kv('so',so.length+' 个'+(Object.keys(archs).length?'（'+Object.keys(archs).join(', ')+'）':''));
  h+='</div>';
  var sorted=entries.slice().sort((a,b)=>b.usize-a.usize).slice(0,20);
  h+='<div class="filelist">';
  sorted.forEach(function(e){
    var tag='';
    if(/\.dex$/.test(e.name))tag='<span class="ftag dex">dex</span>';
    else if(/\.so$/.test(e.name))tag='<span class="ftag so">so</span>';
    else if(/^assets\//.test(e.name))tag='<span class="ftag assets">assets</span>';
    else if(/^res\//.test(e.name))tag='<span class="ftag res">res</span>';
    h+='<div class="filerow">'+tag+'<span class="fname">'+esc(e.name)+'</span><span class="fsize">'+fmtSize(e.usize)+'</span></div>';
  });
  h+='</div><p class="hint">仅显示最大的 20 个文件</p></section>';
  // 网络行为画像（dex/so 提取后填充）
  h+='<div id="net-card"></div>';
  // dex 字符串分析
  if(dex.length){
    h+='<section class="card"><h3>dex 字符串分析</h3>'
      +'<p class="hint">提取 dex 内硬编码字符串，按 URL / IP / API 路径 / 可疑 / 包名分类。</p>'
      +'<div class="row" style="margin:10px 0"><button id="btn-dex" class="primary">提取字符串</button></div>'
      +'<p id="dex-status" class="hint"></p>'
      +'<div id="dex-result"></div>'
      +'</section>';
  }
  // so 字符串分析
  if(so.length){
    h+='<section class="card"><h3>so 字符串分析</h3>'
      +'<p class="hint">扫描原生库中的硬编码字符串，按 URL / IP / API 路径 / JNI 方法 / 可疑 / 包名分类。</p>'
      +'<div class="row" style="margin:10px 0"><button id="btn-so" class="primary">提取字符串</button></div>'
      +'<p id="so-status" class="hint"></p>'
      +'<div id="so-result"></div>'
      +'</section>';
  }
  // assets 配置文件
  var assetFiles=entries.filter(function(e){
    return /^assets\//.test(e.name)&&ASSET_TEXT_RE.test(e.name)&&e.usize<ASSET_MAX_SIZE;
  });
  if(assetFiles.length){
    state.assetFiles=assetFiles;
    h+='<section class="card"><h3>assets 配置文件（'+assetFiles.length+'）</h3>'
      +'<p class="hint">很多 App 把服务器地址、配置藏在 assets 里。点击查看内容。</p>'
      +'<div class="assetlist">';
    assetFiles.forEach(function(e,i){
      h+='<div class="filerow assetrow" data-idx="'+i+'"><span class="ftag assets">cfg</span><span class="fname">'+esc(e.name)+'</span><span class="fsize">'+fmtSize(e.usize)+'</span></div>';
    });
    h+='</div><div id="asset-viewer"></div></section>';
  }
  // 完整报告
  h+='<section class="card"><h3>完整报告</h3>'
    +'<p class="hint">把 Manifest、权限、证书、dex/so 字符串拼成一份 Markdown 报告，方便发给 AI 或存档。</p>'
    +'<div class="row" style="margin:10px 0"><button id="btn-report" class="primary">生成完整报告</button>'
    +'<button id="btn-report-copy" style="display:none">复制报告</button>'
    +'<button id="btn-report-ai" style="display:none">发给 AI 分析</button></div>'
    +'<div id="report-viewer"></div>'
    +'</section>';
  $('ana-result').innerHTML=h;
  bindFpCompare();
  if(dex.length){
    $('btn-dex').onclick=extractDexStrings;
  }
  if(so.length){
    $('btn-so').onclick=extractSoStrings;
  }
  // assets 行点击
  var rows=document.querySelectorAll('.assetrow');
  for(var ai=0;ai<rows.length;ai++){
    (function(el){
      el.onclick=function(){viewAsset(parseInt(el.getAttribute('data-idx'),10));};
    })(rows[ai]);
  }
  $('btn-report').onclick=generateFullReport;
  $('btn-report-copy').onclick=copyFullReport;
  $('btn-report-ai').onclick=sendReportToAi;
  updateAnalysisCards();
}

function kv(k,v){return '<div class="kvrow"><span class="k">'+k+'</span><span class="v">'+v+'</span></div>';}

/* ---------- 证书卡片 ---------- */

function renderCertCard(r){
  var h='<section class="card"><h3>签名证书</h3>';
  if(r.certErr){
    return h+'<p class="hint err">证书解析失败：'+esc(r.certErr)+'</p></section>';
  }
  var c=r.cert;
  if(!c) return h+'<p class="hint">未找到 META-INF/*.RSA 签名文件</p></section>';
  var stCls=c.status==='有效'?'cert-ok':(c.status==='已过期'?'cert-err':'cert-warn');
  h+='<div class="kv">';
  h+=kv('签名文件','<code class="inline">'+esc(c.fileName||'')+'</code>');
  h+=kv('签名者',esc(c.subjectCN||c.subjectStr)+(c.selfSigned?' <span class="ptag warn">自签名</span>':''));
  h+=kv('颁发者',esc(c.issuerStr));
  h+=kv('有效期',esc(c.notBeforeStr)+' ~ '+esc(c.notAfterStr)+' <span class="'+stCls+'">（'+esc(c.status)+'）</span>');
  h+=kv('序列号','<code class="inline">'+esc(c.serial.slice(0,32))+(c.serial.length>32?'…':'')+'</code>');
  h+='</div>';
  h+='<p class="hint">SHA-256 指纹</p><div class="fp">'+esc(c.fingerprint)+'</div>';
  h+='<div class="fp-compare"><input id="fp-known" type="text" placeholder="粘贴已知指纹（如已安装版本的）对比…">'
    +'<button id="btn-fp-cmp">对比</button></div>'
    +'<p id="fp-result" class="hint"></p>';
  h+='</section>';
  return h;
}

function bindFpCompare(){
  var btn=$('btn-fp-cmp');
  if(!btn||!state.report||!state.report.cert)return;
  btn.onclick=function(){
    var v=$('fp-known').value.replace(/[^0-9a-fA-F]/g,'').toUpperCase();
    var el=$('fp-result');
    if(v.length!==64){el.textContent='指纹应为 64 位十六进制';el.className='hint err';return;}
    if(v===state.report.cert.fingerprint){
      el.textContent='✓ 指纹一致：与已知版本同签名，可放心覆盖安装';
      el.className='hint ok';
    }else{
      el.textContent='✗ 指纹不一致：签名不同！覆盖安装会失败，可能是不同开发者/渠道包';
      el.className='hint err';
    }
  };
}
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function escAttr(s){return esc(s).replace(/"/g,'&quot;');}
function shortName(c,pkg){
  if(c.indexOf(pkg)===0)return c.slice(pkg.length+1);
  return c;
}

/* ================= 网络行为画像 + 风险评分 ================= */

function collectRiskInputs(){
  var dex=state.dexItems||[], so=state.soItems||[];
  var all=dex.concat(so);
  var sus=all.filter(function(it){return it.cats.indexOf('sus')>=0;});
  var net=NetProfile.buildNetProfile(dex,so);
  var fp=NetProfile.findFingerprint(all);
  var risk=NetProfile.scoreRisk({
    permissions: state.report?state.report.info.permissions:[],
    susItems: sus,
    net: net,
    fpItems: fp
  });
  return {net:net, risk:risk, susCount:sus.length, fpCount:fp.length, dexDone:!!state.dexItems, soDone:!!state.soItems};
}

function levelCls(level){return level==='高危'?'high':(level==='中危'?'mid':'low');}

function renderRiskCard(){
  var box=$('risk-card');
  if(!box||!state.report)return;
  var inputs=collectRiskInputs();
  var risk=inputs.risk, cls=levelCls(risk.level);
  var h='<section class="card"><h3>风险评分</h3>';
  h+='<div class="riskhead"><span class="risk-score '+cls+'">'+risk.score+'</span>'
    +'<span class="risk-badge '+cls+'">'+risk.level+'</span></div>';
  if(risk.deductions.length){
    risk.deductions.forEach(function(d){
      h+='<div class="deduct"><span class="dpts">+'+d.pts+'</span>'+esc(d.reason)+'</div>';
    });
  }else{
    h+='<p class="hint">无扣分项。</p>';
  }
  if(!inputs.dexDone||!inputs.soDone){
    h+='<p class="hint">注：dex/so 字符串尚未提取（下方点击"提取字符串"），当前评分仅基于权限。</p>';
  }
  h+='<p class="disclaimer">仅供参考，不构成安全结论。</p></section>';
  box.innerHTML=h;
}

function renderNetCard(){
  var box=$('net-card');
  if(!box||!state.report)return;
  var inputs=collectRiskInputs();
  var profile=inputs.net;
  if(!inputs.dexDone&&!inputs.soDone){
    box.innerHTML='<section class="card"><h3>网络行为画像</h3><p class="hint">提取 dex/so 字符串后自动生成。</p></section>';
    return;
  }
  var h='<section class="card"><h3>网络行为画像</h3>';
  h+='<p class="netsum">'+esc(NetProfile.netSummaryText(profile))+'</p>';
  if(profile.stats.total){
    profile.hosts.slice(0,15).forEach(function(x){
      var tags='';
      if(x.isIp)tags+='<span class="htag ip">IP直连</span>';
      if(x.isInternal)tags+='<span class="htag internal">内网</span>';
      if(x.isPlain)tags+='<span class="htag plain">明文HTTP</span>';
      tags+='<span class="htag src">'+(x.dex&&x.so?'dex+so':(x.dex?'dex':'so'))+' ×'+x.count+'</span>';
      h+='<div class="netrow"><span class="nhost">'+esc(x.host)+'</span>'+tags;
      x.pathList.slice(0,3).forEach(function(p){
        h+='<div class="netpath">'+esc(p)+'</div>';
      });
      h+='</div>';
    });
    if(profile.hosts.length>15)h+='<p class="hint">…还有 '+(profile.hosts.length-15)+' 个</p>';
  }
  h+='</section>';
  box.innerHTML=h;
}

/* 三处完成后都刷新两张卡片 */
function updateAnalysisCards(){
  renderRiskCard();
  renderNetCard();
}

/* ================= 分析历史 ================= */

var HIST_KEY='rea_history_v1', HIST_MAX=20;

function loadHistory(){
  try{
    var v=localStorage.getItem(HIST_KEY);
    return v?JSON.parse(v):[];
  }catch(e){return [];}
}
function saveHistoryList(list){
  try{localStorage.setItem(HIST_KEY,JSON.stringify(list));}catch(e){}
}
function pushHistory(entry){
  var list=loadHistory();
  list.unshift(entry);
  if(list.length>HIST_MAX)list=list.slice(0,HIST_MAX);
  saveHistoryList(list);
}
function renderHistory(){
  var box=$('history-list');
  if(!box)return;
  var list=loadHistory();
  if(!list.length){box.innerHTML='<p class="hint">暂无历史</p>';return;}
  var h='';
  list.forEach(function(e){
    h+='<div class="histrow" data-id="'+e.id+'">'
      +'<span class="scorepill '+levelCls(e.level)+'">'+e.score+' '+e.level+'</span>'
      +'<span class="hname">'+esc(e.fileName)+'<div class="hmeta">'+esc(e.pkg)+' · '+esc(e.ver)+' · '+esc(e.time)+'</div></span>'
      +'<button class="hdel" data-id="'+e.id+'" title="删除">✕</button>'
      +'</div>';
  });
  box.innerHTML=h;
  var rows=box.querySelectorAll('.histrow');
  for(var i=0;i<rows.length;i++){
    (function(el){
      el.onclick=function(ev){
        if(ev.target.className==='hdel')return;
        viewHistory(parseInt(el.getAttribute('data-id'),10));
      };
    })(rows[i]);
  }
  var dels=box.querySelectorAll('.hdel');
  for(var j=0;j<dels.length;j++){
    (function(btn){
      btn.onclick=function(ev){
        ev.stopPropagation();
        var id=parseInt(btn.getAttribute('data-id'),10);
        saveHistoryList(loadHistory().filter(function(e){return e.id!==id;}));
        renderHistory();
        $('history-viewer').innerHTML='';
      };
    })(dels[j]);
  }
}
function viewHistory(id){
  var list=loadHistory();
  var e=null;
  for(var i=0;i<list.length;i++)if(list[i].id===id){e=list[i];break;}
  var box=$('history-viewer');
  if(!e){box.innerHTML='';return;}
  box.innerHTML='<section class="card"><div class="assethead"><code class="inline">'+esc(e.fileName)+'（'+esc(e.time)+'）</code>'
    +'<span><button id="btn-hist-copy">复制</button> <button id="btn-hist-ai">发给 AI</button></span></div>'
    +'<pre class="assetpre">'+esc(e.markdown)+'</pre></section>';
  $('btn-hist-copy').onclick=function(){copyText(e.markdown);toast('已复制');};
  $('btn-hist-ai').onclick=function(){fillChatWith(e.markdown);};
}
function fillChatWith(text){
  switchTab('chat');
  var sel=$('assistant-select');
  for(var i=0;i<sel.options.length;i++){
    if(sel.options[i].value==='rea'){sel.value='rea';sel.dispatchEvent(new Event('change'));break;}
  }
  var input=$('input');
  input.value=text;
  input.focus();
  input.style.height='auto';
  input.style.height=Math.min(input.scrollHeight,120)+'px';
  toast('已填入输入框，点发送即可');
}

/* ---------- dex 字符串提取 ---------- */

function setDexStatus(msg,cls){
  var el=$('dex-status');
  if(el){el.textContent=msg;el.className='hint '+(cls||'');}
}

function catName(id){
  for(var i=0;i<DexParser.CATS.length;i++)
    if(DexParser.CATS[i].id===id)return DexParser.CATS[i].name;
  return id;
}

async function extractDexStrings(){
  var btn=$('btn-dex');
  if(!state.zr||!state.report){toast('请先完成 APK 解析');return;}
  btn.disabled=true;
  btn.textContent='提取中…';
  var entries=state.report.entries.filter(function(e){return /\.dex$/.test(e.name);});
  var seen={};
  var items=[];
  var total=0, counted=0;
  try{
    for(var d=0; d<entries.length; d++){
      var e=entries[d];
      setDexStatus('正在解压 '+e.name+'（'+fmtSize(e.usize)+'）…');
      var raw=await state.zr.extract(e);
      var strs=await DexParser.extractStrings(raw,function(done,tot){
        setDexStatus('正在提取 '+e.name+'… '+Math.round(done/tot*100)+'%');
      });
      total+=strs.length;
      setDexStatus('正在分类 '+e.name+'…');
      var r=await DexParser.analyzeStrings(strs);
      for(var i=0;i<r.items.length;i++){
        var it=r.items[i];
        if(seen[it.s])continue;
        seen[it.s]=1;
        items.push(it);
      }
      counted+=r.unique;
    }
    state.dexItems=items;
    state.dexTotal=total;
    setDexStatus('完成：'+total+' 个字符串，去重 '+counted+'，命中分类 '+items.length+' 个','ok');
    renderDexResults('all','');
    updateAnalysisCards();
  }catch(err){
    setDexStatus('提取失败：'+(err.message||err),'err');
  }finally{
    btn.disabled=false;
    btn.textContent='重新提取';
  }
}

var DEX_SHOW_MAX=300;

function renderDexResults(cat,query){
  var box=$('dex-result');
  if(!box)return;
  var items=state.dexItems||[];
  // 计数
  var counts={all:items.length};
  DexParser.CATS.forEach(function(c){counts[c.id]=0;});
  items.forEach(function(it){it.cats.forEach(function(c){counts[c]++;});});
  var q=(query||'').toLowerCase();
  var list=items.filter(function(it){
    if(cat!=='all'&&it.cats.indexOf(cat)<0)return false;
    if(q&&it.s.toLowerCase().indexOf(q)<0)return false;
    return it;
  });
  var h='<div class="dextabs">';
  h+=dexTab('all','全部',counts.all,cat);
  DexParser.CATS.forEach(function(c){h+=dexTab(c.id,c.name,counts[c.id],cat);});
  h+='</div>';
  h+='<input id="dex-search" class="dex-search" type="text" placeholder="搜索字符串…" value="'+escAttr(query||'')+'">';
  h+='<p class="hint">'+list.length+' 条'+(list.length>DEX_SHOW_MAX?'（仅显示前 '+DEX_SHOW_MAX+' 条）':'')+'</p>';
  h+='<div class="dexlist">';
  list.slice(0,DEX_SHOW_MAX).forEach(function(it){
    var tags=it.cats.map(function(c){return '<span class="dtag '+c+'">'+catName(c)+'</span>';}).join('');
    h+='<div class="dexrow"><code>'+esc(it.s.length>220?it.s.slice(0,220)+'…':it.s)+'</code><div class="dtags">'+tags+'</div></div>';
  });
  if(!list.length)h+='<p class="hint">无匹配</p>';
  h+='</div>';
  box.innerHTML=h;
  // 绑定
  var tabs=box.querySelectorAll('.dextab');
  for(var i=0;i<tabs.length;i++){
    (function(el){
      el.onclick=function(){renderDexResults(el.getAttribute('data-cat'),$('dex-search').value);};
    })(tabs[i]);
  }
  var si=$('dex-search');
  var timer=null;
  si.oninput=function(){
    if(timer)clearTimeout(timer);
    timer=setTimeout(function(){renderDexResults(cat,si.value);},250);
  };
  // 恢复焦点
  si.focus();
  si.setSelectionRange(si.value.length,si.value.length);
}

function dexTab(id,name,count,active){
  return '<button class="dextab'+(id===active?' active':'')+'" data-cat="'+id+'">'+name+'（'+count+'）</button>';
}

/* 生成发给 AI 的文本报告 */
function buildAiReport(){
  var r=state.report;
  if(!r)return '';
  var info=r.info, entries=r.entries;
  var L=[];
  L.push('请分析这个 APK：');
  L.push('');
  L.push('文件名：'+r.fileName+'（'+fmtSize(r.fileSize)+'）');
  L.push('包名：'+info.package);
  L.push('版本：'+info.versionName+'（versionCode '+info.versionCode+'）');
  if(info.label&&!/^\d+$/.test(String(info.label)))L.push('应用名：'+info.label);
  L.push('');
  L.push('权限（'+info.permissions.length+'）：');
  info.permissions.forEach(function(p){
    L.push('- '+p+'（'+permDesc(p)+(isDanger(p)?'，敏感':'')+'）');
  });
  L.push('');
  L.push('组件：Activity '+info.activities.length+'，Service '+info.services.length+'，Receiver '+info.receivers.length+'，Provider '+info.providers.length);
  ['Activity|activities','Service|services','Receiver|receivers','Provider|providers'].forEach(function(pair){
    var parts=pair.split('|'), title=parts[0], arr=info[parts[1]];
    if(arr.length){
      L.push(title+'：');
      arr.slice(0,20).forEach(function(c){L.push('  - '+shortName(c,info.package));});
    }
  });
  var dex=entries.filter(e=>/\.dex$/.test(e.name));
  var so=entries.filter(e=>/\.so$/.test(e.name));
  L.push('');
  L.push('dex 文件 '+dex.length+' 个，so 文件 '+so.length+' 个，总文件 '+entries.length+' 个');
  // dex 字符串分析结果
  if(state.dexItems&&state.dexItems.length){
    var items=state.dexItems;
    var counts={url:0,ip:0,api:0,sus:0,pkg:0};
    items.forEach(function(it){it.cats.forEach(function(c){counts[c]++;});});
    L.push('');
    L.push('dex 硬编码字符串（共 '+state.dexTotal+' 个，去重命中分类 '+items.length+' 个）：');
    L.push('- URL '+counts.url+' 个，IP '+counts.ip+' 个，API 路径 '+counts.api+' 个，可疑 '+counts.sus+' 个，包名 '+counts.pkg+' 个');
    function top(cat,title,n){
      var arr=items.filter(function(it){return it.cats.indexOf(cat)>=0;}).slice(0,n);
      if(!arr.length)return;
      L.push('');
      L.push(title+'：');
      arr.forEach(function(it){L.push('  - '+it.s.slice(0,160));});
    }
    top('sus','可疑字符串（前20）',20);
    top('url','URL（前20）',20);
    top('api','API 路径（前15）',15);
  }
  L.push('');
  L.push('请从逆向角度分析：这个 App 可能是做什么的？权限是否合理？有没有可疑之处？');
  return L.join('\n');
}

function sendToAi(){
  var text=buildAiReport();
  if(!text){toast('没有可发送的报告');return;}
  // 切到聊天页，选中 REA 助手，把报告填入输入框
  switchTab('chat');
  // 确保 REA 助手被选中
  var sel=$('assistant-select');
  var reaOpt=null;
  for(var i=0;i<sel.options.length;i++){
    if(sel.options[i].value==='rea'){reaOpt=sel.options[i];break;}
  }
  if(reaOpt&&sel.value!=='rea'){
    sel.value='rea';
    sel.dispatchEvent(new Event('change'));
  }
  var input=$('input');
  input.value=text;
  input.focus();
  // 自动调整高度
  input.style.height='auto';
  input.style.height=Math.min(input.scrollHeight,120)+'px';
  toast('报告已填入输入框，点发送即可');
}

/* ================= APK 对比 ================= */

function setCmpStatus(msg,cls){
  var el=$('cmp-status');
  el.textContent=msg;
  el.className='hint '+(cls||'');
}

function arrDiff(a,b){
  var setB={}, added=[], removed=[], same=[];
  for(var i=0;i<b.length;i++)setB[b[i]]=1;
  var setA={};
  for(i=0;i<a.length;i++)setA[a[i]]=1;
  for(i=0;i<b.length;i++){ if(setA[b[i]])same.push(b[i]); else added.push(b[i]); }
  for(i=0;i<a.length;i++){ if(!setB[a[i]])removed.push(a[i]); }
  return {added:added,removed:removed,same:same};
}

async function compare(){
  var fa=$('apk-file-a').files, fb=$('apk-file-b').files;
  if(!fa||!fa.length){toast('请先选择 A（旧版）APK');return;}
  if(!fb||!fb.length){toast('请先选择 B（新版）APK');return;}
  if(state.comparing)return;
  state.comparing=true;
  setCmpStatus('正在解析 A…','');
  $('cmp-result').innerHTML='';
  $('btn-compare-ai').style.display='none';
  try{
    var A=await analyzeApkFile(fa[0]);
    setCmpStatus('正在解析 B…','');
    var B=await analyzeApkFile(fb[0]);
    state.cmpA=A; state.cmpB=B;
    var d={A:A,B:B};
    /* 版本/包名/大小 */
    d.pkgSame=A.info.package===B.info.package;
    d.verChanged=(A.info.versionName!==B.info.versionName)||(A.info.versionCode!==B.info.versionCode);
    d.sizeDiff=B.fileSize-A.fileSize;
    /* 权限 */
    d.perms=arrDiff(A.info.permissions,B.info.permissions);
    /* 组件 */
    d.comp={};
    ['activities','services','receivers','providers'].forEach(function(k){
      d.comp[k]=arrDiff(A.info[k],B.info[k]);
    });
    /* 证书 */
    d.certA=A.cert?{fp:A.cert.fingerprint,cn:A.cert.subjectCN,status:A.cert.status}:null;
    d.certB=B.cert?{fp:B.cert.fingerprint,cn:B.cert.subjectCN,status:B.cert.status}:null;
    d.certSame=!!(d.certA&&d.certB&&d.certA.fp===d.certB.fp);
    /* dex 字符串 */
    d.dex=null;
    if($('cmp-dexstr').checked){
      setCmpStatus('正在提取 A 的 dex 字符串…','');
      var mapA=await extractClassifiedStrings(A,function(msg){setCmpStatus('[A] '+msg,'');});
      setCmpStatus('正在提取 B 的 dex 字符串…','');
      var mapB=await extractClassifiedStrings(B,function(msg){setCmpStatus('[B] '+msg,'');});
      var added={}, removed={};
      for(var s in mapB)if(!mapA[s])added[s]=mapB[s];
      for(var s2 in mapA)if(!mapB[s2])removed[s2]=mapA[s2];
      d.dex={added:added,removed:removed,countA:Object.keys(mapA).length,countB:Object.keys(mapB).length};
    }
    state.cmpReport=d;
    renderDiffReport(d);
    setCmpStatus('对比完成','ok');
    $('btn-compare-ai').style.display='';
  }catch(e){
    setCmpStatus('对比失败：'+(e.message||e),'err');
  }finally{
    state.comparing=false;
  }
}

var COMP_NAMES={activities:'Activity',services:'Service',receivers:'Receiver',providers:'Provider'};

function diffListHtml(title, diff, pkg){
  var h='<details class="compl"'+(diff.added.length||diff.removed.length?' open':'')+'>';
  h+='<summary>'+title+'（<span class="diff-add">+'+diff.added.length+'</span> / <span class="diff-del">-'+diff.removed.length+'</span>）</summary>';
  diff.added.slice(0,40).forEach(function(c){
    h+='<div class="diffrow add"><span class="dmark">+</span><code class="inline">'+esc(shortName(c,pkg))+'</code></div>';
  });
  diff.removed.slice(0,40).forEach(function(c){
    h+='<div class="diffrow del"><span class="dmark">−</span><code class="inline">'+esc(shortName(c,pkg))+'</code></div>';
  });
  if(diff.added.length>40||diff.removed.length>40)
    h+='<p class="hint">…还有 '+(diff.added.length+diff.removed.length-80)+' 项未显示</p>';
  if(!diff.added.length&&!diff.removed.length)h+='<p class="hint">无变化（'+diff.same.length+' 项相同）</p>';
  return h+'</details>';
}

function renderDiffReport(d){
  var A=d.A,B=d.B;
  var h='';
  /* 概览 */
  h+='<section class="card"><h3>版本概览</h3><div class="kv">';
  h+=kv('A（旧版）',esc(A.fileName)+'（'+fmtSize(A.fileSize)+'）');
  h+=kv('B（新版）',esc(B.fileName)+'（'+fmtSize(B.fileSize)+'）');
  var sizeTxt=fmtSize(B.fileSize)+'（'+(d.sizeDiff>=0?'+':'')+fmtSize(Math.abs(d.sizeDiff))+(d.sizeDiff>=0?' 增大':' 减小')+'）';
  if(d.sizeDiff===0)sizeTxt=fmtSize(B.fileSize)+'（无变化）';
  h+=kv('包名',(d.pkgSame?esc(A.info.package):('<span class="diff-del">'+esc(A.info.package)+'</span> → <span class="diff-add">'+esc(B.info.package)+'</span>')));
  h+=kv('版本',d.verChanged
    ?('<span class="diff-del">'+esc(A.info.versionName)+' ('+A.info.versionCode+')</span> → <span class="diff-add">'+esc(B.info.versionName)+' ('+B.info.versionCode+')</span>')
    :(esc(A.info.versionName)+' ('+A.info.versionCode+')（无变化）'));
  h+=kv('大小',sizeTxt);
  h+=kv('签名',d.certA&&d.certB
    ?(d.certSame?'<span class="cert-ok">✓ 同签名</span>':'<span class="cert-err">✗ 签名不同</span>')
    :'<span class="hint">证书缺失，无法对比</span>');
  h+='</div></section>';
  /* 权限 */
  var pd=d.perms;
  h+='<section class="card"><h3>权限变化（<span class="diff-add">+'+pd.added.length+'</span> / <span class="diff-del">-'+pd.removed.length+'</span>）</h3>';
  pd.added.forEach(function(p){
    h+='<div class="perm diff-add-bg"><code class="inline">'+esc(p)+'</code><span class="pdesc">'+esc(permDesc(p))+'</span><span class="ptag add">新增</span></div>';
  });
  pd.removed.forEach(function(p){
    h+='<div class="perm diff-del-bg"><code class="inline">'+esc(p)+'</code><span class="pdesc">'+esc(permDesc(p))+'</span><span class="ptag del">删除</span></div>';
  });
  if(!pd.added.length&&!pd.removed.length)h+='<p class="hint">无变化（'+pd.same.length+' 个相同）</p>';
  h+='</section>';
  /* 组件 */
  h+='<section class="card"><h3>组件变化</h3>';
  Object.keys(COMP_NAMES).forEach(function(k){
    h+=diffListHtml(COMP_NAMES[k],d.comp[k],B.info.package);
  });
  h+='</section>';
  /* dex 字符串 */
  if(d.dex){
    var da=d.dex.added, dr=d.dex.removed;
    var nA=Object.keys(da).length, nR=Object.keys(dr).length;
    h+='<section class="card"><h3>dex 字符串差异（<span class="diff-add">+'+nA+'</span> / <span class="diff-del">-'+nR+'</span>）</h3>';
    h+='<p class="hint">A 有 '+d.dex.countA+' 个分类字符串，B 有 '+d.dex.countB+' 个</p>';
    function catCount(map,cat){
      var n=0;
      for(var s in map)if(map[s].indexOf(cat)>=0)n++;
      return n;
    }
    h+='<div class="kv">';
    h+=kv('新增 URL',catCount(da,'url'));h+=kv('新增 API 路径',catCount(da,'api'));
    h+=kv('新增可疑',catCount(da,'sus'));h+=kv('新增 IP',catCount(da,'ip'));
    h+='</div>';
    function topList(map,cat,title,n){
      var arr=[];
      for(var s in map)if(map[s].indexOf(cat)>=0)arr.push(s);
      if(!arr.length)return '';
      var s='<details class="compl"><summary>'+title+'（'+arr.length+'）</summary>';
      arr.slice(0,n).forEach(function(x){
        s+='<div class="dexrow"><code>'+esc(x.length>160?x.slice(0,160)+'…':x)+'</code></div>';
      });
      return s+'</details>';
    }
    h+=topList(da,'sus','新增可疑字符串',20);
    h+=topList(da,'url','新增 URL',20);
    h+=topList(da,'api','新增 API 路径',15);
    if(!nA&&!nR)h+='<p class="hint">无差异</p>';
    h+='</section>';
  }
  $('cmp-result').innerHTML=h;
}

/* 对比报告 → AI 文本 */
function buildCompareAiReport(){
  var d=state.cmpReport;
  if(!d)return '';
  var A=d.A,B=d.B,L=[];
  L.push('请解读这个 APK 的版本变化（A=旧版，B=新版）：');
  L.push('');
  L.push('A：'+A.fileName+'，包名 '+A.info.package+'，版本 '+A.info.versionName+'（'+A.info.versionCode+'），'+fmtSize(A.fileSize));
  L.push('B：'+B.fileName+'，包名 '+B.info.package+'，版本 '+B.info.versionName+'（'+B.info.versionCode+'），'+fmtSize(B.fileSize)
    +(d.sizeDiff!==0?'（'+(d.sizeDiff>0?'增大':'减小')+fmtSize(Math.abs(d.sizeDiff))+'）':'（大小无变化）'));
  if(!d.pkgSame)L.push('注意：包名变了！');
  L.push('签名：'+(d.certA&&d.certB?(d.certSame?'同签名':'签名不同！'):'未知'));
  L.push('');
  var pd=d.perms;
  L.push('权限：新增 '+pd.added.length+' 个，删除 '+pd.removed.length+' 个');
  pd.added.forEach(function(p){L.push('  + '+p+'（'+permDesc(p)+'）');});
  pd.removed.forEach(function(p){L.push('  - '+p+'（'+permDesc(p)+'）');});
  L.push('');
  Object.keys(COMP_NAMES).forEach(function(k){
    var c=d.comp[k];
    if(c.added.length||c.removed.length){
      L.push(COMP_NAMES[k]+'：新增 '+c.added.length+'，删除 '+c.removed.length);
      c.added.slice(0,10).forEach(function(x){L.push('  + '+shortName(x,B.info.package));});
      c.removed.slice(0,10).forEach(function(x){L.push('  - '+shortName(x,A.info.package));});
    }
  });
  if(d.dex){
    var da=d.dex.added, n=0;
    L.push('');
    L.push('dex 新增字符串 '+Object.keys(da).length+' 个，删除 '+Object.keys(d.dex.removed).length+' 个');
    ['sus','url','api'].forEach(function(cat){
      var arr=[];
      for(var s in da)if(da[s].indexOf(cat)>=0)arr.push(s);
      if(arr.length){
        L.push(cat==='sus'?'新增可疑字符串：':(cat==='url'?'新增 URL：':'新增 API 路径：'));
        arr.slice(0,15).forEach(function(x){L.push('  - '+x.slice(0,140));});
      }
    });
  }
  L.push('');
  L.push('请从逆向角度解读：这个版本可能改了什么？新增的权限/组件/字符串是否合理？有没有可疑之处？');
  return L.join('\n');
}

function sendCompareToAi(){
  var text=buildCompareAiReport();
  if(!text){toast('没有可发送的报告');return;}
  switchTab('chat');
  var sel=$('assistant-select');
  for(var i=0;i<sel.options.length;i++){
    if(sel.options[i].value==='rea'){sel.value='rea';sel.dispatchEvent(new Event('change'));break;}
  }
  var input=$('input');
  input.value=text;
  input.focus();
  input.style.height='auto';
  input.style.height=Math.min(input.scrollHeight,120)+'px';
  toast('对比报告已填入输入框，点发送即可');
}

/* ================= so 字符串提取 ================= */

function setSoStatus(msg,cls){
  var el=$('so-status');
  if(el){el.textContent=msg;el.className='hint '+(cls||'');}
}

function soCatName(id){
  for(var i=0;i<SoParser.CATS.length;i++)
    if(SoParser.CATS[i].id===id)return SoParser.CATS[i].name;
  return id;
}

async function extractSoStrings(){
  var btn=$('btn-so');
  if(!state.zr||!state.report){toast('请先完成 APK 解析');return;}
  btn.disabled=true;
  btn.textContent='提取中…';
  var entries=state.report.entries.filter(function(e){return /\.so$/.test(e.name);});
  var seen={};
  var items=[];
  var total=0;
  try{
    for(var d=0; d<entries.length; d++){
      var e=entries[d];
      var m=e.name.match(/lib\/([^\/]+)\//);
      var arch=m?m[1]:'未知';
      setSoStatus('正在解压 '+e.name+'（'+fmtSize(e.usize)+'）…');
      var raw=await state.zr.extract(e);
      if(!SoParser.isElf(raw)){setSoStatus(e.name+' 不是有效 ELF，跳过','err');continue;}
      var strs=await SoParser.extractStrings(raw,function(done,tot){
        setSoStatus('正在扫描 '+e.name+'… '+Math.round(done/tot*100)+'%');
      });
      total+=strs.length;
      setSoStatus('正在分类 '+e.name+'…');
      var r=await SoParser.analyzeStrings(strs);
      for(var i=0;i<r.items.length;i++){
        var it=r.items[i];
        if(seen[it.s])continue;
        seen[it.s]=1;
        it.arch=arch;
        items.push(it);
      }
    }
    state.soItems=items;
    state.soTotal=total;
    setSoStatus('完成：扫描 '+total+' 个字符串，命中分类 '+items.length+' 个','ok');
    renderSoResults('all','all','');
    updateAnalysisCards();
  }catch(err){
    setSoStatus('提取失败：'+(err.message||err),'err');
  }finally{
    btn.disabled=false;
    btn.textContent='重新提取';
  }
}

var SO_SHOW_MAX=300;

function renderSoResults(cat,arch,query){
  var box=$('so-result');
  if(!box)return;
  var items=state.soItems||[];
  // 架构列表
  var archs={};
  items.forEach(function(it){archs[it.arch]=1;});
  var archList=Object.keys(archs);
  // 计数
  var counts={all:items.length};
  SoParser.CATS.forEach(function(c){counts[c.id]=0;});
  items.forEach(function(it){it.cats.forEach(function(c){counts[c]++;});});
  var q=(query||'').toLowerCase();
  var list=items.filter(function(it){
    if(cat!=='all'&&it.cats.indexOf(cat)<0)return false;
    if(arch!=='all'&&it.arch!==arch)return false;
    if(q&&it.s.toLowerCase().indexOf(q)<0)return false;
    return it;
  });
  var h='<div class="dextabs">';
  h+=soTab('all','全部',counts.all,cat,'cat');
  SoParser.CATS.forEach(function(c){h+=soTab(c.id,c.name,counts[c.id],cat,'cat');});
  h+='</div>';
  if(archList.length>1){
    h+='<div class="dextabs">';
    h+=soTab('all','全部架构',items.length,arch,'arch');
    archList.forEach(function(a){
      var n=items.filter(function(it){return it.arch===a;}).length;
      h+=soTab(a,a,n,arch,'arch');
    });
    h+='</div>';
  }
  h+='<input id="so-search" class="dex-search" type="text" placeholder="搜索字符串…" value="'+escAttr(query||'')+'">';
  h+='<p class="hint">'+list.length+' 条'+(list.length>SO_SHOW_MAX?'（仅显示前 '+SO_SHOW_MAX+' 条）':'')+'</p>';
  h+='<div class="dexlist">';
  list.slice(0,SO_SHOW_MAX).forEach(function(it){
    var tags=it.cats.map(function(c){return '<span class="dtag '+c+'">'+soCatName(c)+'</span>';}).join('');
    tags+='<span class="dtag arch">'+esc(it.arch)+'</span>';
    h+='<div class="dexrow"><code>'+esc(it.s.length>220?it.s.slice(0,220)+'…':it.s)+'</code><div class="dtags">'+tags+'</div></div>';
  });
  if(!list.length)h+='<p class="hint">无匹配</p>';
  h+='</div>';
  box.innerHTML=h;
  var tabs=box.querySelectorAll('.dextab');
  for(var i=0;i<tabs.length;i++){
    (function(el){
      el.onclick=function(){
        var kind=el.getAttribute('data-kind');
        if(kind==='cat')renderSoResults(el.getAttribute('data-cat'),arch,$('so-search').value);
        else renderSoResults(cat,el.getAttribute('data-cat'),$('so-search').value);
      };
    })(tabs[i]);
  }
  var si=$('so-search');
  var timer=null;
  si.oninput=function(){
    if(timer)clearTimeout(timer);
    timer=setTimeout(function(){renderSoResults(cat,arch,si.value);},250);
  };
}

function soTab(id,name,count,active,kind){
  return '<button class="dextab'+(id===active?' active':'')+'" data-cat="'+id+'" data-kind="'+kind+'">'+name+'（'+count+'）</button>';
}

/* ================= assets 配置文件查看 ================= */

async function viewAsset(idx){
  var files=state.assetFiles;
  if(!files||!files[idx])return;
  var e=files[idx];
  var box=$('asset-viewer');
  if(!box)return;
  box.innerHTML='<p class="hint">正在加载 '+esc(e.name)+'…</p>';
  try{
    var raw=await state.zr.extract(e);
    var text;
    try{text=new TextDecoder('utf-8',{fatal:true}).decode(raw);}
    catch(de){text=new TextDecoder('utf-8').decode(raw);}
    var display=text;
    if(/\.json$/i.test(e.name)){
      try{display=JSON.stringify(JSON.parse(text),null,2);}
      catch(je){/* 不是合法 JSON，原样显示 */}
    }
    if(display.length>200000)display=display.slice(0,200000)+'\n…（内容过长，已截断前 200KB）';
    state.assetText=display;
    box.innerHTML='<div class="assethead"><code class="inline">'+esc(e.name)+'</code>'
      +'<button id="btn-asset-copy">复制</button></div>'
      +'<pre class="assetpre">'+esc(display)+'</pre>';
    $('btn-asset-copy').onclick=function(){copyText(state.assetText);toast('已复制');};
  }catch(err){
    box.innerHTML='<p class="hint err">读取失败：'+esc(err.message||err)+'</p>';
  }
}

/* ================= 完整报告 ================= */

function appendStrSection(L,items,Parser){
  Parser.CATS.forEach(function(c){
    var arr=items.filter(function(it){return it.cats.indexOf(c.id)>=0;});
    if(!arr.length)return;
    L.push('### '+c.name+'（'+arr.length+'）');
    arr.slice(0,30).forEach(function(it){
      var s=it.s.length>160?it.s.slice(0,160)+'…':it.s;
      L.push('- '+s+(it.arch?' `['+it.arch+']`':''));
    });
  });
}

function buildFullReport(){
  var r=state.report;
  if(!r)return '';
  var info=r.info, entries=r.entries;
  var L=[];
  L.push('# APK 静态分析报告');
  L.push('');
  L.push('## 基本信息');
  L.push('- 文件名：'+r.fileName+'（'+fmtSize(r.fileSize)+'）');
  L.push('- 包名：'+info.package);
  L.push('- 版本：'+info.versionName+'（versionCode '+info.versionCode+'）');
  if(info.label&&!/^\d+$/.test(String(info.label)))L.push('- 应用名：'+info.label);
  L.push('');
  L.push('## 签名证书');
  if(r.certErr){L.push('证书解析失败：'+r.certErr);}
  else if(r.cert){
    var c=r.cert;
    L.push('- 签名文件：'+(c.fileName||''));
    L.push('- 签名者：'+(c.subjectCN||c.subjectStr)+(c.selfSigned?'（自签名）':''));
    L.push('- 颁发者：'+c.issuerStr);
    L.push('- 有效期：'+c.notBeforeStr+' ~ '+c.notAfterStr+'（'+c.status+'）');
    L.push('- SHA-256：'+c.fingerprint);
  }else{L.push('未找到签名证书');}
  L.push('');
  L.push('## 权限（'+info.permissions.length+'）');
  info.permissions.forEach(function(p){
    L.push('- '+p+'（'+permDesc(p)+(isDanger(p)?'，敏感':'')+'）');
  });
  L.push('');
  L.push('## 组件');
  L.push('- Activity '+info.activities.length+'，Service '+info.services.length+'，Receiver '+info.receivers.length+'，Provider '+info.providers.length);
  [['activities','Activity'],['services','Service'],['receivers','Receiver'],['providers','Provider']].forEach(function(pair){
    var arr=info[pair[0]];
    if(arr.length){
      L.push('### '+pair[1]+'（'+arr.length+'）');
      arr.slice(0,30).forEach(function(x){L.push('- '+shortName(x,info.package));});
      if(arr.length>30)L.push('（还有 '+(arr.length-30)+' 个未列出）');
    }
  });
  L.push('');
  var dex=entries.filter(function(e){return /\.dex$/.test(e.name);});
  var so=entries.filter(function(e){return /\.so$/.test(e.name);});
  L.push('## 文件结构');
  L.push('- 总文件 '+entries.length+' 个，dex '+dex.length+' 个，so '+so.length+' 个');
  L.push('');
  /* 网络画像 + 风险评分（本次分析的最新数据） */
  var inputs=collectRiskInputs();
  L.push(NetProfile.netMarkdown(inputs.net));
  L.push('');
  L.push(NetProfile.riskMarkdown(inputs.risk));
  L.push('');
  if(state.dexItems&&state.dexItems.length){
    L.push('## dex 硬编码字符串（'+state.dexItems.length+' 个分类命中，共扫描 '+(state.dexTotal||'?')+' 个）');
    appendStrSection(L,state.dexItems,DexParser);
    L.push('');
  }else if(dex.length){
    L.push('## dex 硬编码字符串');
    L.push('（未提取，点击"提取字符串"后再生成报告）');
    L.push('');
  }
  if(state.soItems&&state.soItems.length){
    L.push('## so 硬编码字符串（'+state.soItems.length+' 个分类命中，共扫描 '+(state.soTotal||'?')+' 个）');
    appendStrSection(L,state.soItems,SoParser);
    L.push('');
  }else if(so.length){
    L.push('## so 硬编码字符串');
    L.push('（未提取，点击"提取字符串"后再生成报告）');
    L.push('');
  }
  L.push('请从逆向角度分析：这个 App 可能是做什么的？权限是否合理？有没有可疑之处？');
  return L.join('\n');
}

function generateFullReport(){
  var text=buildFullReport();
  if(!text){toast('没有可生成的报告');return;}
  state.fullReport=text;
  var r=state.report;
  /* 存入分析历史 */
  var inputs=collectRiskInputs();
  pushHistory({
    id: Date.now(),
    fileName: r.fileName,
    pkg: r.info.package,
    ver: r.info.versionName+' ('+r.info.versionCode+')',
    time: new Date().toLocaleString('zh-CN',{hour12:false}),
    score: inputs.risk.score,
    level: inputs.risk.level,
    markdown: text
  });
  renderHistory();
  var box=$('report-viewer');
  var lines=text.split('\n').length;
  box.innerHTML='<p class="hint">报告已生成（'+lines+' 行，'+fmtSize(text.length)+'），可复制或发给 AI。</p>'
    +'<pre class="assetpre">'+esc(text.length>8000?text.slice(0,8000)+'\n…（预览截断，复制获取完整）':text)+'</pre>';
  $('btn-report-copy').style.display='';
  $('btn-report-ai').style.display='';
  toast('完整报告已生成');
}

function copyFullReport(){
  if(!state.fullReport){toast('请先生成报告');return;}
  copyText(state.fullReport);
  toast('报告已复制');
}

function sendReportToAi(){
  var text=state.fullReport||buildFullReport();
  if(!text){toast('没有可发送的报告');return;}
  switchTab('chat');
  var sel=$('assistant-select');
  for(var i=0;i<sel.options.length;i++){
    if(sel.options[i].value==='rea'){sel.value='rea';sel.dispatchEvent(new Event('change'));break;}
  }
  var input=$('input');
  input.value=text;
  input.focus();
  input.style.height='auto';
  input.style.height=Math.min(input.scrollHeight,120)+'px';
  toast('报告已填入输入框，点发送即可');
}

/* 复制文本：clipboard + execCommand 双 fallback */
function copyText(text){
  if(navigator.clipboard&&navigator.clipboard.writeText){
    navigator.clipboard.writeText(text).catch(function(){fallbackCopy(text);});
  }else{fallbackCopy(text);}
}
function fallbackCopy(text){
  var ta=document.createElement('textarea');
  ta.value=text;
  ta.style.cssText='position:fixed;top:0;left:0;opacity:0';
  document.body.appendChild(ta);
  ta.select();
  try{document.execCommand('copy');}catch(e){}
  ta.remove();
}

/* Tab 切换 */
function switchTab(which){
  var chatPage=$('page-chat'), anaPage=$('page-analyze'), kbPage=$('page-kb');
  var tabChat=$('tab-chat'), tabAna=$('tab-analyze'), tabKb=$('tab-kb');
  chatPage.classList.add('hidden'); anaPage.classList.add('hidden'); kbPage.classList.add('hidden');
  tabChat.classList.remove('active'); tabAna.classList.remove('active'); tabKb.classList.remove('active');
  if(which==='analyze'){ anaPage.classList.remove('hidden'); tabAna.classList.add('active'); }
  else if(which==='kb'){ kbPage.classList.remove('hidden'); tabKb.classList.add('active'); }
  else { chatPage.classList.remove('hidden'); tabChat.classList.add('active'); }
}

function toast(msg){
  var old=document.querySelector('.toast');
  if(old)old.remove();
  var d=document.createElement('div');
  d.className='toast';d.textContent=msg;
  d.style.cssText='position:fixed;bottom:90px;left:50%;transform:translateX(-50%);background:#333;color:#fff;padding:8px 16px;border-radius:8px;font-size:13px;z-index:99';
  document.body.appendChild(d);
  setTimeout(function(){d.remove();},1600);
}

function init(){
  $('tab-chat').onclick=function(){switchTab('chat');};
  $('tab-analyze').onclick=function(){switchTab('analyze');};
  $('tab-kb').onclick=function(){switchTab('kb');};
  renderHistory();
  $('btn-analyze').onclick=analyze;
  $('btn-send-ai').onclick=sendToAi;
  $('btn-compare').onclick=compare;
  $('btn-compare-ai').onclick=sendCompareToAi;
  $('mode-single').onclick=function(){setMode('single');};
  $('mode-compare').onclick=function(){setMode('compare');};
  $('apk-file').addEventListener('change',function(){
    if(this.files&&this.files.length){
      $('file-label').textContent=this.files[0].name+'（'+fmtSize(this.files[0].size)+'）';
    }
  });
  $('apk-file-a').addEventListener('change',function(){
    if(this.files&&this.files.length){
      $('file-label-a').textContent='A: '+this.files[0].name+'（'+fmtSize(this.files[0].size)+'）';
    }
  });
  $('apk-file-b').addEventListener('change',function(){
    if(this.files&&this.files.length){
      $('file-label-b').textContent='B: '+this.files[0].name+'（'+fmtSize(this.files[0].size)+'）';
    }
  });
}

function setMode(which){
  var single=which==='single';
  $('single-pane').classList.toggle('hidden',!single);
  $('compare-pane').classList.toggle('hidden',single);
  $('mode-single').classList.toggle('active',single);
  $('mode-compare').classList.toggle('active',!single);
}

if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init);
else init();

})();
