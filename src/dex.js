/* DEX 字符串提取器：解析 string_ids + MUTF-8 解码 + 分类，WebView/Node 兼容（ES6） */
(function(root, factory){
  if(typeof module==='object'&&module.exports)module.exports=factory();
  else root.DexParser=factory();
})(typeof window==='object'?window:this,()=>{

/* ---------- 基础解码 ---------- */

function u32le(data,o){
  return ((data[o]|(data[o+1]<<8)|(data[o+2]<<16)|(data[o+3]<<24))>>>0);
}

/* uleb128：返回 {value, next} */
function readUleb128(data, off){
  var result=0, shift=0, i=off, b;
  do{
    if(i>=data.length) throw new Error('uleb128 越界');
    b=data[i++];
    result|=(b&0x7F)<<shift;
    shift+=7;
  }while(b&0x80);
  return {value:result>>>0, next:i};
}

/* MUTF-8 解码：从 off 开始读到 0x00，返回 {str, next}
   MUTF-8 = UTF-8 变体：U+0000 编为 C0 80；增补字符按代理对分别 3 字节编码 */
function decodeMut8(data, off){
  var units=[];
  var i=off;
  while(true){
    if(i>=data.length) throw new Error('字符串数据越界');
    var b=data[i++];
    if(b===0) break;
    if(b<0x80){
      units.push(b);
    }else if((b&0xE0)===0xC0){
      var b2=data[i++];
      units.push(((b&0x1F)<<6)|(b2&0x3F));
    }else if((b&0xF0)===0xE0){
      var c2=data[i++], c3=data[i++];
      units.push(((b&0x0F)<<12)|((c2&0x3F)<<6)|(c3&0x3F));
    }else{
      units.push(0xFFFD); // 非法字节，容错
    }
  }
  // 分块转字符串，避免大数组 apply 栈溢出
  var s='';
  for(var k=0;k<units.length;k+=8192){
    s+=String.fromCharCode.apply(null, units.slice(k,k+8192));
  }
  return {str:s, next:i};
}

/* ---------- DEX 头解析 ---------- */

function parseHeader(data){
  if(!(data instanceof Uint8Array)) throw new Error('需要 Uint8Array');
  if(data.length<112) throw new Error('文件太小，不是有效的 dex');
  var magic='';
  for(var i=0;i<8;i++) magic+=String.fromCharCode(data[i]);
  if(magic.slice(0,4)!=='dex\n'||data[7]!==0)
    throw new Error('magic 不匹配，不是 dex 文件');
  if(u32le(data,40)!==0x12345678)
    throw new Error('endian_tag 不匹配');
  var stringIdsSize=u32le(data,56), stringIdsOff=u32le(data,60);
  if(stringIdsSize>2000000) throw new Error('string_ids 数量异常：'+stringIdsSize);
  if(stringIdsOff+stringIdsSize*4>data.length)
    throw new Error('string_ids 越界');
  return {stringIdsSize:stringIdsSize, stringIdsOff:stringIdsOff, fileSize:u32le(data,32)};
}

/* ---------- 字符串提取（异步分块，大 dex 不卡 UI） ---------- */

var BATCH=2000;

async function extractStrings(data, onProgress){
  var h=parseHeader(data);
  var n=h.stringIdsSize, base=h.stringIdsOff;
  var out=new Array(n);
  for(var i=0;i<n;i++){
    var off=u32le(data, base+i*4);
    if(off>=data.length){ out[i]=''; continue; } // 容错：坏偏移跳过
    try{
      var r=readUleb128(data, off);       // utf16_size（校验用，不直接使用）
      var d=decodeMut8(data, r.next);     // 读到 0x00
      out[i]=d.str;
    }catch(e){ out[i]=''; }
    if((i+1)%BATCH===0){
      if(onProgress) onProgress(i+1, n);
      await new Promise(function(res){setTimeout(res,0);}); // 让出 UI 线程
    }
  }
  if(onProgress) onProgress(n, n);
  return out;
}

/* ---------- 分类 ---------- */

var CATS=[
  {id:'url', name:'URL'},
  {id:'ip',  name:'IP 地址'},
  {id:'api', name:'API 路径'},
  {id:'sus', name:'可疑'},
  {id:'pkg', name:'包名'}
];

var RE_URL=/^https?:\/\/[^\/\s?#]{3,}/i;   // host 至少 3 字符，过滤 "http://c" 碎片
var RE_IP=/\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/;
var RE_INTERNAL_IP=/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)/;
var RE_PKG=/^(com|cn)\.[a-zA-Z_]/;
var RE_API=/(^|\/)(api|v[1-9]\d*|rest|graphql)(\/|$)/i;  // /api/x、/v1/users 等接口路径
var RE_DEX_DESC=/^\(|^L[\w\/$]+;$/;  // dex 类型/方法描述符，不算可疑

/* 短词必须整个 token 相等（避免 keyboard 误报）；长词允许子串 */
var SUS_EXACT=['key','pwd','auth'];
var SUS_SUB=['token','secret','password','passwd','apikey','accesskey','credential'];

function isSuspicious(s){
  // 按驼峰/下划线/分隔符切 token
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

/* 返回匹配的分类 id 数组（一个字符串可属多个分类） */
function classify(s){
  var cats=[];
  if(!s||!s.length) return cats;
  if(RE_URL.test(s)) cats.push('url');
  if(RE_IP.test(s)) cats.push('ip');
  if(RE_API.test(s)) cats.push('api');
  if(RE_PKG.test(s)) cats.push('pkg');
  if(!RE_DEX_DESC.test(s)&&(isSuspicious(s)||RE_INTERNAL_IP.test(s))) cats.push('sus');
  return cats;
}

/* 批量分类去重：返回 {total, unique, items:[{s, cats}]}（items 只保留命中分类的） */
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
    if((i+1)%5000===0){
      if(onProgress) onProgress(i+1, total);
      await new Promise(function(res){setTimeout(res,0);});
    }
  }
  if(onProgress) onProgress(total, total);
  return {total:total, unique:Object.keys(seen).length, items:items};
}

return {
  parseHeader:parseHeader,
  extractStrings:extractStrings,
  analyzeStrings:analyzeStrings,
  classify:classify,
  isSuspicious:isSuspicious,
  CATS:CATS
};
});
