/* 网络行为画像 + 风险评分：WebView/Node 兼容（ES6） */
(function(root, factory){
  if(typeof module==='object'&&module.exports)module.exports=factory();
  else root.NetProfile=factory();
})(typeof window==='object'?window:this,()=>{

/* ---------- 常量 ---------- */

var RE_IP=/\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/;
var RE_INTERNAL_IP=/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)/;
var RE_URL_FULL=/^(https?):\/\/([^\/\s?#:]+)(:\d+)?(\/[^\s]*)?$/i;
/* 非网络噪音：XML 命名空间等 */
var NOISE_HOSTS={'schemas.android.com':1,'www.w3.org':1,'www.w3.org.':1};
/* 设备指纹信号：排除指纹识别（生物识别）API 本身 */
var RE_DEVICE_FP=/devicefingerprint|deviceinfo|getdeviceinfo|getdeviceid|getimei|geticcid|getmeid|getserial|oaid|android_id|device_id|build\.fingerprint|nativecollectsignals|collectdeviceinfo/i;
var RE_FP_EXCLUDE=/hardware\/fingerprint|FingerprintManager|USE_FINGERPRINT|hasEnrolledFingerprints|BiometricPrompt|fingerprint\.FingerprintManager/i;

/* 敏感权限 → 扣分（5~15） */
var PERM_RISK={
 'android.permission.BIND_DEVICE_ADMIN':{pts:15,desc:'设备管理器'},
 'android.permission.REQUEST_INSTALL_PACKAGES':{pts:15,desc:'安装未知应用'},
 'android.permission.READ_SMS':{pts:12,desc:'读短信'},
 'android.permission.SEND_SMS':{pts:12,desc:'发短信'},
 'android.permission.RECEIVE_SMS':{pts:10,desc:'收短信'},
 'android.permission.READ_CALL_LOG':{pts:10,desc:'读通话记录'},
 'android.permission.WRITE_CALL_LOG':{pts:10,desc:'写通话记录'},
 'android.permission.CALL_PHONE':{pts:10,desc:'拨打电话'},
 'android.permission.READ_PHONE_STATE':{pts:10,desc:'读手机状态'},
 'android.permission.ACCESS_BACKGROUND_LOCATION':{pts:12,desc:'后台定位'},
 'android.permission.ACCESS_FINE_LOCATION':{pts:10,desc:'精确定位'},
 'android.permission.ACCESS_COARSE_LOCATION':{pts:5,desc:'粗略定位'},
 'android.permission.READ_CONTACTS':{pts:10,desc:'读联系人'},
 'android.permission.WRITE_CONTACTS':{pts:10,desc:'写联系人'},
 'android.permission.RECORD_AUDIO':{pts:10,desc:'麦克风录音'},
 'android.permission.CAMERA':{pts:5,desc:'相机'},
 'android.permission.SYSTEM_ALERT_WINDOW':{pts:8,desc:'悬浮窗'}
};

var SUS_PTS=3, SUS_CAP=30;       // 可疑字符串：每个 +3，上限 30
var IP_DIRECT_PTS=10;             // IP 直连 +10
var PLAIN_HTTP_PTS=10;            // HTTP 明文 +10
var DEVICE_FP_PTS=15;             // 设备指纹 +15

/* ---------- 网络行为画像 ---------- */

/* items: [{s, cats, arch?}]（dexItems + soItems 合并传入）
   返回 {hosts:[{host,isIp,isInternal,isPlain,count,dex,so,paths[]}], stats:{...}} */
function buildNetProfile(dexItems, soItems){
  var map={};
  function add(item, from){
    var s=item.s, cats=item.cats;
    var hasUrl=cats.indexOf('url')>=0, hasIp=cats.indexOf('ip')>=0;
    if(!hasUrl&&!hasIp) return;
    var m=s.match(RE_URL_FULL);
    var host, path='', isPlain=false, isIp=false;
    if(m){
      isPlain=(m[1].toLowerCase()==='http');
      host=m[2].toLowerCase();
      if(NOISE_HOSTS[host]) return;
      path=(m[3]||'')+(m[4]||'');
      isIp=RE_IP.test(host);
    }else{
      // 纯 IP 字符串（如内网地址、服务端 IP）
      var ipm=s.match(RE_IP);
      if(!ipm) return;
      host=ipm[0];
      isIp=true;
    }
    var h=map[host];
    if(!h){
      h={host:host,isIp:isIp,isInternal:RE_INTERNAL_IP.test(host),isPlain:false,
         count:0,dex:0,so:0,paths:{},pathList:[]};
      map[host]=h;
    }
    h.count++;
    if(from==='dex')h.dex++; else h.so++;
    if(isPlain)h.isPlain=true;
    if(path&&path.length>1){
      var p=path.length>80?path.slice(0,80)+'…':path;
      if(!h.paths[p]&&h.pathList.length<5){h.paths[p]=1;h.pathList.push(p);}
    }
  }
  (dexItems||[]).forEach(function(it){add(it,'dex');});
  (soItems||[]).forEach(function(it){add(it,'so');});
  var hosts=Object.keys(map).map(function(k){return map[k];});
  hosts.sort(function(a,b){return b.count-a.count;});
  var stats={total:hosts.length,ipDirect:0,plainHttp:0,internal:0};
  hosts.forEach(function(h){
    if(h.isIp)stats.ipDirect++;
    if(h.isPlain)stats.plainHttp++;
    if(h.isInternal)stats.internal++;
  });
  return {hosts:hosts,stats:stats};
}

function netSummaryText(profile){
  var st=profile.stats;
  if(!st.total) return '未发现网络连接行为（dex/so 中无 URL/IP 字符串）。';
  var s='这个 App 会连接 '+st.total+' 个域名/IP';
  var parts=[];
  if(st.ipDirect)parts.push(st.ipDirect+' 个 IP 直连');
  if(st.plainHttp)parts.push(st.plainHttp+' 个明文 HTTP');
  if(st.internal)parts.push(st.internal+' 个内网地址');
  if(parts.length)s+='，其中 '+parts.join('、');
  return s+'。';
}

/* 设备指纹信号：返回命中的字符串数组 */
function findFingerprint(items){
  var out=[], seen={};
  (items||[]).forEach(function(it){
    var s=it.s;
    if(seen[s])return;
    if(RE_FP_EXCLUDE.test(s))return;
    if(RE_DEVICE_FP.test(s)){seen[s]=1;out.push(s);}
  });
  return out;
}

/* ---------- 风险评分 ---------- */

/* opts: {permissions:[], susItems:[{s}], net:profile, fpItems:[s]}
   返回 {score, level, deductions:[{pts,reason}]} */
function scoreRisk(opts){
  opts=opts||{};
  var deductions=[];
  var score=0;
  // 1. 敏感权限
  (opts.permissions||[]).forEach(function(p){
    var r=PERM_RISK[p];
    if(r){
      score+=r.pts;
      deductions.push({pts:r.pts, reason:'敏感权限 '+p+'（'+r.desc+'）'});
    }
  });
  // 2. 可疑字符串
  var sus=(opts.susItems||[]).length;
  if(sus>0){
    var pts=Math.min(sus*SUS_PTS, SUS_CAP);
    score+=pts;
    deductions.push({pts:pts, reason:'可疑字符串 '+sus+' 个（含 key/secret/token 等）'});
  }
  // 3. IP 直连
  var st=(opts.net&&opts.net.stats)||{ipDirect:0,plainHttp:0};
  if(st.ipDirect>0){
    score+=IP_DIRECT_PTS;
    deductions.push({pts:IP_DIRECT_PTS, reason:'IP 直连 '+st.ipDirect+' 个（不上域名，疑似躲避域名封锁/审查）'});
  }
  // 4. HTTP 明文
  if(st.plainHttp>0){
    score+=PLAIN_HTTP_PTS;
    deductions.push({pts:PLAIN_HTTP_PTS, reason:'明文 HTTP '+st.plainHttp+' 个（传输未加密）'});
  }
  // 5. 设备指纹
  var fp=(opts.fpItems||[]).length;
  if(fp>0){
    score+=DEVICE_FP_PTS;
    var sample=(opts.fpItems||[]).slice(0,2).map(function(s){return s.length>60?s.slice(0,60)+'…':s;}).join('；');
    deductions.push({pts:DEVICE_FP_PTS, reason:'设备指纹相关 '+fp+' 处（如 '+sample+'）'});
  }
  if(score>100)score=100;
  var level=score<=30?'低危':(score<=60?'中危':'高危');
  return {score:score, level:level, deductions:deductions};
}

/* 风险报告 Markdown（拼入完整报告 / 发给 AI） */
function riskMarkdown(risk){
  var L=[];
  L.push('## 风险评分：'+risk.score+' 分（'+risk.level+'）');
  if(risk.deductions.length){
    L.push('扣分项：');
    risk.deductions.forEach(function(d){L.push('- +'+d.pts+'：'+d.reason);});
  }else{
    L.push('无扣分项。');
  }
  L.push('');
  L.push('> 仅供参考，不构成安全结论。');
  return L.join('\n');
}

/* 网络画像 Markdown */
function netMarkdown(profile){
  var L=[];
  L.push('## 网络行为画像');
  L.push(netSummaryText(profile));
  if(profile.stats.total){
    L.push('');
    profile.hosts.slice(0,20).forEach(function(h){
      var tags=[];
      if(h.isIp)tags.push('IP直连');
      if(h.isInternal)tags.push('内网');
      if(h.isPlain)tags.push('明文HTTP');
      var src=h.dex&&h.so?'dex+so':(h.dex?'dex':'so');
      var line='- '+h.host+'（出现 '+h.count+' 次，'+src+(tags.length?'，'+tags.join('/'):'')+'）';
      L.push(line);
      h.pathList.slice(0,3).forEach(function(p){L.push('  - '+p);});
    });
    if(profile.hosts.length>20)L.push('（还有 '+(profile.hosts.length-20)+' 个未列出）');
  }
  return L.join('\n');
}

return {
  buildNetProfile:buildNetProfile,
  netSummaryText:netSummaryText,
  findFingerprint:findFingerprint,
  scoreRisk:scoreRisk,
  riskMarkdown:riskMarkdown,
  netMarkdown:netMarkdown,
  RE_DEVICE_FP:RE_DEVICE_FP,
  RE_IP:RE_IP
};
});
