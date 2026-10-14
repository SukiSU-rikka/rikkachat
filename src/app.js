/* REA Chat - AI 逆向聊天 App */
(function(){
'use strict';

var REA_SYSTEM = '你是 REA 逆向工程助手，按 REA（morluto/rea，「逆向一切」）的工作流帮用户调查 App 功能：\n'
  + '1. 先明确用户想弄清的是哪个 App 的哪个功能、哪部分行为\n'
  + '2. 指导调查：查 Manifest 声明、权限、dex 字符串与方法、so 的 JNI 方法、网络画像，追踪相关代码和调用链\n'
  + '3. 每个结论必须给证据（类名/方法名/字符串/权限/URL），不确定的明确说"不确定"，并说明限制\n'
  + '4. 解释完原理后，给出在用户自己项目中实现类似功能的具体思路和代码框架\n'
  + '5. 涉及绕过他人软件保护/授权/黑名单的要求，直接拒绝\n'
  + '6. 如实说明边界：REA 的 MCP 工具链（jadx/Hopper/Ghidra）是桌面端的，手机上跑不了；本 App 的本地解析器是手机端替代，深度反编译需要上桌面\n'
  + '7. 用简体中文，技术细节讲透，不说空话';

var BUILTIN = [
  {id:'rea', name:'REA 逆向', system:REA_SYSTEM, builtin:true},
  {id:'general', name:'通用聊天', system:'', builtin:true}
];

var LS_API='rea_api', LS_ASST='rea_assistants', LS_HIST='rea_histories', LS_ACTIVE='rea_active';

function load(k,d){try{var v=localStorage.getItem(k);return v?JSON.parse(v):d;}catch(e){return d;}}
function save(k,v){try{localStorage.setItem(k,JSON.stringify(v));}catch(e){}}

/* ---------- 配置 ---------- */
function getConfig(){return load(LS_API,{provider:'deepseek',base:'',model:'',protocol:'openai',key:''});}
function saveConfig(c){save(LS_API,c);}
function getKey(){return load(LS_API,{}).key||'';}

/* ---------- 助手 ---------- */
function getAssistants(){
  var custom=load(LS_ASST,[]);
  return BUILTIN.concat(custom);
}
function getAssistant(id){
  var all=getAssistants();
  for(var i=0;i<all.length;i++) if(all[i].id===id) return all[i];
  return all[0];
}
function activeId(){
  var id=load(LS_ACTIVE,'rea');
  return getAssistant(id).id;
}
function setActive(id){save(LS_ACTIVE,id);}

/* ---------- 历史 ---------- */
function getHist(id){return load(LS_HIST,{})[id]||[];}
function setHist(id,msgs){
  var all=load(LS_HIST,{});
  all[id]=msgs;
  // 只保留最近 60 条，防止爆 localStorage
  if(all[id].length>60) all[id]=all[id].slice(-60);
  save(LS_HIST,all);
}

/* ---------- Markdown 简易渲染 ---------- */
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function md(src){
  var codeBlocks=[], inlineCodes=[];
  var s=esc(src);
  // 代码块 ```lang\n...\n```
  s=s.replace(/```(\w*)\n?([\s\S]*?)```/g,function(m,lang,code){
    codeBlocks.push('<pre><code>'+code.replace(/^\n+|\n+$/g,'')+'</code></pre>');
    return '\u0000CB'+(codeBlocks.length-1)+'\u0000';
  });
  // 行内代码
  s=s.replace(/`([^`\n]+)`/g,function(m,code){
    inlineCodes.push('<code class="inline">'+code+'</code>');
    return '\u0000IC'+(inlineCodes.length-1)+'\u0000';
  });
  // 粗体
  s=s.replace(/\*\*([^*]+)\*\*/g,'<strong>$1</strong>');
  // 行处理：列表与段落
  var lines=s.split('\n'), out=[], inUl=false, inOl=false, buf=[];
  function flushP(){
    if(buf.length){out.push('<p>'+buf.join('<br>')+'</p>');buf=[];}
  }
  function closeLists(){
    if(inUl){out.push('</ul>');inUl=false;}
    if(inOl){out.push('</ol>');inOl=false;}
  }
  lines.forEach(function(ln){
    var t=ln.replace(/^\s+|\s+$/g,'');
    var ulm=t.match(/^[-*•]\s+(.*)/), olm=t.match(/^\d+[.)]\s+(.*)/);
    if(ulm){
      flushP();
      if(!inUl){closeLists();out.push('<ul>');inUl=true;}
      out.push('<li>'+ulm[1]+'</li>');
    }else if(olm){
      flushP();
      if(!inOl){closeLists();out.push('<ol>');inOl=true;}
      out.push('<li>'+olm[1]+'</li>');
    }else if(t===''||/^\u0000/.test(t)){
      flushP();closeLists();out.push(t);
    }else{
      buf.push(ln);
    }
  });
  flushP();closeLists();
  s=out.join('\n');
  // 还原占位
  s=s.replace(/\u0000CB(\d+)\u0000/g,function(m,i){return codeBlocks[+i];});
  s=s.replace(/\u0000IC(\d+)\u0000/g,function(m,i){return inlineCodes[+i];});
  return s;
}

/* ---------- DOM ---------- */
var $=function(id){return document.getElementById(id);};
var messagesEl, inputEl, sendBtn, asstSel;
var sending=false;

function scrollBottom(){var c=$('chat');c.scrollTop=c.scrollHeight;}

function renderAll(){
  var id=activeId(), hist=getHist(id);
  messagesEl.innerHTML='';
  hist.forEach(function(m,i){addMsgEl(m.role,m.content,i);});
  // 同步下拉
  asstSel.value=id;
  scrollBottom();
}

function addMsgEl(role,content,idx){
  var d=document.createElement('div');
  d.className='msg '+role;
  d.dataset.idx=idx;
  if(role==='user'){
    d.textContent=content;
  }else{
    var inner=document.createElement('div');
    inner.className='md';
    inner.innerHTML=md(content);
    d.appendChild(inner);
    var ops=document.createElement('div');
    ops.className='msg-ops';
    var b1=document.createElement('button');b1.textContent='复制';
    b1.onclick=function(){copyText(content);};
    var b2=document.createElement('button');b2.textContent='重新生成';
    b2.onclick=function(){regenerate(idx);};
    ops.appendChild(b1);ops.appendChild(b2);
    d.appendChild(ops);
  }
  messagesEl.appendChild(d);
  return d;
}

function copyText(t){
  function done(ok){toast(ok?'已复制':'复制失败');}
  if(navigator.clipboard&&navigator.clipboard.writeText){
    navigator.clipboard.writeText(t).then(function(){done(true);},function(){fallback();});
  }else fallback();
  function fallback(){
    try{
      var ta=document.createElement('textarea');
      ta.value=t;ta.style.position='fixed';ta.style.opacity='0';
      document.body.appendChild(ta);ta.select();
      var ok=document.execCommand('copy');
      document.body.removeChild(ta);done(ok);
    }catch(e){done(false);}
  }
}

var toastTimer=null;
function toast(msg){
  var old=document.querySelector('.toast');
  if(old)old.remove();
  var d=document.createElement('div');
  d.className='toast';d.textContent=msg;
  d.style.cssText='position:fixed;bottom:90px;left:50%;transform:translateX(-50%);background:#333;color:#fff;padding:8px 16px;border-radius:8px;font-size:13px;z-index:99';
  document.body.appendChild(d);
  clearTimeout(toastTimer);
  toastTimer=setTimeout(function(){d.remove();},1600);
}

/* ---------- 发送 ---------- */
function send(){
  var text=inputEl.value.replace(/^\s+|\s+$/g,'');
  if(!text||sending)return;
  var cfg=getConfig();
  if(!cfg.key){toast('请先在设置里填写 API Key');openSettings();return;}
  var id=activeId(), hist=getHist(id);
  hist.push({role:'user',content:text});
  setHist(id,hist);
  addMsgEl('user',text,hist.length-1);
  inputEl.value='';autoGrow();
  // loading
  sending=true;sendBtn.disabled=true;
  var ld=document.createElement('div');
  ld.className='msg ai loading';ld.id='loading-msg';
  ld.innerHTML='<span class="typing"><i></i><i></i><i></i></span>';
  messagesEl.appendChild(ld);scrollBottom();
  doChat(id,hist,function(err,reply){
    var l=$('loading-msg');if(l)l.remove();
    sending=false;sendBtn.disabled=false;
    var h=getHist(id);
    if(err){
      h.push({role:'assistant',content:'⚠️ '+err});
    }else{
      h.push({role:'assistant',content:reply});
    }
    setHist(id,h);
    renderAll();
    inputEl.focus();
  });
}

function regenerate(idx){
  if(sending)return;
  var id=activeId(), hist=getHist(id).slice();
  // 找到 idx 这条 AI 消息，删掉它（保留之前的上下文）
  hist=hist.filter(function(m,i){return i<idx;});
  if(!hist.length||hist[hist.length-1].role!=='user'){
    toast('没有可重新生成的内容');return;
  }
  setHist(id,hist);
  renderAll();
  sending=true;sendBtn.disabled=true;
  var ld=document.createElement('div');
  ld.className='msg ai loading';ld.id='loading-msg';
  ld.innerHTML='<span class="typing"><i></i><i></i><i></i></span>';
  messagesEl.appendChild(ld);scrollBottom();
  doChat(id,hist,function(err,reply){
    var l=$('loading-msg');if(l)l.remove();
    sending=false;sendBtn.disabled=false;
    var h=getHist(id);
    h.push({role:'assistant',content:err?('⚠️ '+err):reply});
    setHist(id,h);
    renderAll();
  });
}

function doChat(asstId,hist,cb){
  var cfg=getConfig(), asst=getAssistant(asstId);
  var messages=[];
  if(asst.system)messages.push({role:'system',content:asst.system});
  hist.forEach(function(m){
    if(m.role==='user'||m.role==='assistant')messages.push({role:m.role,content:m.content});
  });
  var spec;
  try{
    spec=RikkaProviders.request(
      {base:cfg.base,model:cfg.model,protocol:cfg.protocol||'openai'},
      messages,{maxTokens:4000}
    );
  }catch(e){cb(e.message||String(e));return;}
  var xhr=new XMLHttpRequest();
  var done=false;
  var timer=setTimeout(function(){
    if(!done){done=true;try{xhr.abort();}catch(e){}cb('请求超时，请重试');}
  },120000);
  xhr.onreadystatechange=function(){
    if(xhr.readyState!==4||done)return;
    done=true;clearTimeout(timer);
    var data;
    try{data=JSON.parse(xhr.responseText);}catch(e){cb('AI 服务返回了非 JSON（HTTP '+xhr.status+'）');return;}
    if(xhr.status<200||xhr.status>=300){
      var msg={401:'密钥无效或已过期',402:'余额不足',403:'拒绝访问，请检查权限',404:'接口或模型不存在',429:'请求太频繁，请稍后再试'}[xhr.status]||'请求失败';
      cb(msg+'（HTTP '+xhr.status+'）'+(data&&data.error&&data.error.message?'：'+String(data.error.message).slice(0,200):''));
      return;
    }
    try{
      var text=RikkaProviders.content(data,cfg.protocol||'openai');
      if(!text||!String(text).trim()){cb('AI 返回了空内容');return;}
      cb(null,String(text));
    }catch(e){cb(e.message||String(e));}
  };
  xhr.onerror=function(){if(!done){done=true;clearTimeout(timer);cb('网络错误，请检查地址和网络');}};
  try{
    xhr.open('POST',spec.url,true);
    xhr.setRequestHeader('Content-Type','application/json');
    for(var k in spec.headers)xhr.setRequestHeader(k,spec.headers[k]);
    if(cfg.protocol==='anthropic')xhr.setRequestHeader('x-api-key',cfg.key);
    else xhr.setRequestHeader('Authorization','Bearer '+cfg.key);
    xhr.send(JSON.stringify(spec.body));
  }catch(e){done=true;clearTimeout(timer);cb(e.message||String(e));}
}

/* ---------- 设置页 ---------- */
function fillProviderOptions(){
  var sel=$('set-provider'), P=RikkaProviders.presets;
  sel.innerHTML='';
  Object.keys(P).forEach(function(k){
    var o=document.createElement('option');
    o.value=k;o.textContent=P[k].name;
    sel.appendChild(o);
  });
}
function renderSettings(){
  var cfg=getConfig(), P=RikkaProviders.presets;
  fillProviderOptions();
  $('set-provider').value=cfg.provider||'deepseek';
  $('set-key').value=cfg.key||'';
  $('set-base').value=cfg.base||(P[cfg.provider]||P.deepseek).base;
  $('set-model').value=cfg.model||(P[cfg.provider]||P.deepseek).model;
  $('api-status').textContent='';
  $('api-status').className='hint';
  renderAsstList();
}
function onProviderChange(){
  var P=RikkaProviders.presets[$('set-provider').value]||RikkaProviders.presets.deepseek;
  $('set-base').value=P.base;
  $('set-model').value=P.model;
  $('set-key').value='';
}
function saveApi(){
  var provider=$('set-provider').value;
  var P=RikkaProviders.presets[provider];
  var cfg={
    provider:provider,
    base:$('set-base').value.replace(/^\s+|\s+$/g,''),
    model:$('set-model').value.replace(/^\s+|\s+$/g,''),
    protocol:P.protocol||'openai',
    key:$('set-key').value.replace(/^\s+|\s+$/g,'')
  };
  try{
    RikkaProviders.endpoint(cfg.base,cfg.protocol);
  }catch(e){setStatus(e.message||String(e),'err');return;}
  if(!cfg.model){setStatus('请填写模型名称','err');return;}
  saveConfig(cfg);
  setStatus('已保存','ok');
}
function setStatus(msg,cls){
  var el=$('api-status');
  el.textContent=msg;el.className='hint '+cls;
}
function testApi(){
  saveApi();
  var cfg=getConfig();
  if(!cfg.key){setStatus('请先填写 API Key','err');return;}
  setStatus('正在测试…','');
  doChat(activeId(),[{role:'user',content:'请只回复 OK'}],function(err,reply){
    // 测试不污染历史：doChat 不写历史，这里直接显示结果
    if(err)setStatus(err,'err');
    else setStatus('连接成功：'+String(reply).slice(0,60),'ok');
  });
}
function openSettings(){renderSettings();$('settings').classList.remove('hidden');}
function closeSettings(){$('settings').classList.add('hidden');}

/* ---------- 自定义助手 ---------- */
function renderAsstList(){
  var box=$('assistant-list');box.innerHTML='';
  getAssistants().forEach(function(a){
    var d=document.createElement('div');
    d.className='asst-item';
    var nm=document.createElement('span');nm.className='nm';nm.textContent=a.name;
    d.appendChild(nm);
    if(a.builtin){
      var tag=document.createElement('span');tag.className='tag';tag.textContent='内置';
      d.appendChild(tag);
    }else{
      var del=document.createElement('button');del.textContent='删除';
      del.onclick=function(){delAssistant(a.id);};
      d.appendChild(del);
    }
    box.appendChild(d);
  });
}
function addAssistant(){
  var name=$('new-asst-name').value.replace(/^\s+|\s+$/g,'').slice(0,30);
  var prompt=$('new-asst-prompt').value;
  if(!name){toast('请填写助手名字');return;}
  var custom=load(LS_ASST,[]);
  var id='c_'+Date.now().toString(36);
  custom.push({id:id,name:name,system:prompt});
  save(LS_ASST,custom);
  $('new-asst-name').value='';$('new-asst-prompt').value='';
  renderAsstList();refreshAsstSelect();
  toast('已添加助手');
}
function delAssistant(id){
  var custom=load(LS_ASST,[]).filter(function(a){return a.id!==id;});
  save(LS_ASST,custom);
  var all=load(LS_HIST,{});
  delete all[id];save(LS_HIST,all);
  if(activeId()===id)setActive('rea');
  renderAsstList();refreshAsstSelect();renderAll();
}
function refreshAsstSelect(){
  var sel=asstSel;sel.innerHTML='';
  getAssistants().forEach(function(a){
    var o=document.createElement('option');
    o.value=a.id;o.textContent=a.name;
    sel.appendChild(o);
  });
  sel.value=activeId();
}

/* ---------- 输入框自适应 ---------- */
function autoGrow(){
  inputEl.style.height='auto';
  inputEl.style.height=Math.min(inputEl.scrollHeight,120)+'px';
}

/* ---------- 初始化 ---------- */
function init(){
  messagesEl=$('messages');inputEl=$('input');sendBtn=$('btn-send');asstSel=$('assistant-select');
  refreshAsstSelect();
  renderAll();
  $('btn-send').onclick=send;
  inputEl.addEventListener('keydown',function(e){
    if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();send();}
  });
  inputEl.addEventListener('input',autoGrow);
  $('btn-new').onclick=function(){
    if(sending)return;
    setHist(activeId(),[]);
    renderAll();
    toast('已开始新会话');
  };
  asstSel.onchange=function(){
    if(sending){asstSel.value=activeId();return;}
    setActive(asstSel.value);
    renderAll();
  };
  $('btn-settings').onclick=openSettings;
  $('btn-back').onclick=closeSettings;
  $('set-provider').onchange=onProviderChange;
  $('btn-save-api').onclick=saveApi;
  $('btn-test-api').onclick=testApi;
  $('btn-add-asst').onclick=addAssistant;
  autoGrow();
}

if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init);
else init();
})();
