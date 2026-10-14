/* SO 字符串提取器：ELF 二进制可打印字符串扫描 + 分类，WebView/Node 兼容（ES6） */
(function(root, factory){
  if(typeof module==='object'&&module.exports)module.exports=factory();
  else root.SoParser=factory();
})(typeof window==='object'?window:this,()=>{

/* ---------- ELF 校验 ---------- */

function isElf(data){
  return data && data.length>4 &&
    data[0]===0x7F && data[1]===0x45 && data[2]===0x4C && data[3]===0x46; // \x7FELF
}

function elfInfo(data){
  if(!isElf(data)) throw new Error('不是有效的 ELF 文件');
  var cls=data[4]===1?'32-bit':(data[4]===2?'64-bit':'未知');
  var machine=data[18]|(data[19]<<8);
  var archName={0x03:'x86',0x28:'arm32',0xB7:'aarch64',0x3E:'x86-64'}[machine]||('machine='+machine);
  return {bits:cls, arch:archName};
}

/* ---------- 字符串扫描（类似 strings 命令） ---------- */

var MIN_LEN=4;
function isPrint(b){ return b>=0x20 && b<=0x7E; }

async function extractStrings(data, onProgress){
  if(!(data instanceof Uint8Array)) throw new Error('需要 Uint8Array');
  var out=[];
  var buf=[];
  var n=data.length;
  for(var i=0;i<n;i++){
    var b=data[i];
    if(isPrint(b)){
      buf.push(b);
    }else{
      if(buf.length>=MIN_LEN){
        out.push(String.fromCharCode.apply(null, buf));
      }
      buf.length=0;
    }
    if((i+1)%1048576===0){
      if(onProgress) onProgress(i+1, n);
      await new Promise(function(res){setTimeout(res,0);}); // 让出 UI 线程
    }
  }
  if(buf.length>=MIN_LEN) out.push(String.fromCharCode.apply(null, buf));
  if(onProgress) onProgress(n, n);
  return out;
}

/* ---------- 分类 ---------- */

var CATS=[
  {id:'url', name:'URL'},
  {id:'ip',  name:'IP 地址'},
  {id:'api', name:'API 路径'},
  {id:'jni', name:'JNI 方法'},
  {id:'sus', name:'可疑'},
  {id:'pkg', name:'包名'}
];

var RE_URL=/^https?:\/\/[^\/\s?#]{3,}/i;
var RE_IP=/\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/;
var RE_INTERNAL_IP=/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)/;
var RE_PKG=/^(com|cn)\.[a-zA-Z_]/;
var RE_API=/(^|\/)(api|v[1-9]\d*|rest|graphql)(\/|$)/i;
var RE_JNI=/^Java_[a-zA-Z0-9_]+(_[a-zA-Z0-9_]+)*$/;

/* so 特有的噪音：ELF 节名、版本符号、路径碎片 */
var NOISE=/^(\.|\/|__|\*\*|\(|GCC:|\.symtab|\.strtab|\.shstrtab|\.rodata|\.text|\.data|\.bss|\.dynsym|\.dynstr|\.rel\.|\.rela\.|\.init|\.fini|\.plt|\.got|\.note|\.comment|\.eh_frame|\.ARM\.|\.gnu)/;
/* libc/系统函数名不算可疑 */
var LIBC_FN=/^(pthread_|malloc|free|memcpy|memset|strlen|strcmp|strcpy|fopen|fclose|dlopen|dlsym|__cxa_|_Z|abort|exit|printf|sprintf|snprintf|socket|connect|send|recv|open|read|write|close|mmap|munmap|getenv|setenv|strstr|strchr|atoi|atol)/;

var SUS_EXACT=['key','pwd','auth'];
var SUS_SUB=['token','secret','password','passwd','apikey','accesskey','credential'];

function isSuspicious(s){
  var toks=s.replace(/([a-z0-9])([A-Z])/g,'$1 $2').toLowerCase().split(/[^a-z0-9]+/);
  for(var i=0;i<toks.length;i++){
    var t=toks[i].replace(/\d+$/,'');
    if(!t) continue;
    var j;
    for(j=0;j<SUS_EXACT.length;j++) if(t===SUS_EXACT[j]) return true;
    for(j=0;j<SUS_SUB.length;j++) if(t.indexOf(SUS_SUB[j])>=0) return true;
  }
  return false;
}

function classify(s){
  var cats=[];
  if(!s||!s.length) return cats;
  if(NOISE.test(s)) return cats; // 噪音直接跳过
  if(RE_URL.test(s)) cats.push('url');
  if(RE_IP.test(s)) cats.push('ip');
  if(RE_API.test(s)) cats.push('api');
  if(RE_JNI.test(s)) cats.push('jni');
  if(RE_PKG.test(s)) cats.push('pkg');
  if(!LIBC_FN.test(s)&&(isSuspicious(s)||RE_INTERNAL_IP.test(s))) cats.push('sus');
  return cats;
}

async function analyzeStrings(strings, onProgress){
  var seen={};
  var items=[];
  var total=strings.length;
  for(var i=0;i<total;i++){
    var s=strings[i];
    if(!s||seen[s]) continue;
    seen[s]=1;
    var cats=classify(s);
    if(cats.length) items.push({s:s, cats:cats});
    if((i+1)%8000===0){
      if(onProgress) onProgress(i+1, total);
      await new Promise(function(res){setTimeout(res,0);});
    }
  }
  if(onProgress) onProgress(total, total);
  return {total:total, unique:Object.keys(seen).length, items:items};
}

return {
  isElf:isElf,
  elfInfo:elfInfo,
  extractStrings:extractStrings,
  analyzeStrings:analyzeStrings,
  classify:classify,
  isSuspicious:isSuspicious,
  CATS:CATS
};
});
