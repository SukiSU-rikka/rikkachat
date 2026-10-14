/* APK 证书解析器：解析 META-INF/CERT.RSA（PKCS7 SignedData DER），提取 X.509 证书信息
   纯 JS 实现，WebView/Node 兼容（ES5+，无外部依赖，自带 SHA-256） */
(function(root, factory){
  if(typeof module==='object'&&module.exports)module.exports=factory();
  else root.CertParser=factory();
})(typeof window==='object'?window:this,function(){
'use strict';

/* ================= ASN.1 DER 基础 ================= */

function parseNode(data, off){
  var b0=data[off];
  var cls=(b0>>6)&3, constructed=!!(b0&0x20), tag=b0&0x1f, pos=off+1, b;
  if(tag===0x1f){ tag=0; do{ b=data[pos++]; tag=(tag<<7)|(b&0x7f); }while(b&0x80); }
  var len=data[pos++];
  if(len===0x80) throw new Error('不支持不定长编码');
  if(len&0x80){
    var n=len&0x7f;
    if(n>4||n===0) throw new Error('DER 长度异常');
    len=0;
    for(var i=0;i<n;i++) len=(len<<8)|data[pos++];
  }
  var headerLen=pos-off;
  var node={cls:cls,constructed:constructed,tag:tag,offset:off,
            headerLen:headerLen,totalLen:headerLen+len};
  if(constructed){
    node.children=[];
    var end=pos+len, p=pos;
    while(p<end){ var c=parseNode(data,p); node.children.push(c); p+=c.totalLen; }
    if(p!==end) throw new Error('DER 构造类型长度不匹配');
  }else{
    node.value=data.subarray(pos,pos+len);
  }
  return node;
}

function bytesToHex(b){
  var s='';
  for(var i=0;i<b.length;i++){ var h=b[i].toString(16); s+=(h.length<2?'0'+h:h); }
  return s.toUpperCase();
}

function decodeOID(bytes){
  if(!bytes.length) return '';
  var out=[Math.floor(bytes[0]/40), bytes[0]%40], v=0;
  for(var i=1;i<bytes.length;i++){
    v=(v<<7)|(bytes[i]&0x7f);
    if(!(bytes[i]&0x80)){ out.push(v); v=0; }
  }
  return out.join('.');
}

var OID_NAME={
  '2.5.4.3':'CN','2.5.4.10':'O','2.5.4.11':'OU','2.5.4.7':'L',
  '2.5.4.8':'ST','2.5.4.6':'C','1.2.840.113549.1.9.1':'E',
  '2.5.4.4':'SN','2.5.4.42':'GN'
};

function decodeStr(node){
  var v=node.value, s='', i;
  if(node.tag===30){ /* BMPString: UTF-16BE */
    for(i=0;i+1<v.length;i+=2) s+=String.fromCharCode((v[i]<<8)|v[i+1]);
    return s;
  }
  if(node.tag===28){ /* UniversalString: UTF-32BE */
    for(i=0;i+3<v.length;i+=4) s+=String.fromCharCode((v[i]<<24)|(v[i+1]<<16)|(v[i+2]<<8)|v[i+3]);
    return s;
  }
  try{
    if(typeof TextDecoder!=='undefined') return new TextDecoder('utf-8').decode(v);
  }catch(e){}
  for(i=0;i<v.length;i++) s+=String.fromCharCode(v[i]);
  return s;
}

/* Name ::= SEQUENCE OF RDNSet */
function parseName(node){
  var parts=[];
  var rdns=node.children||[];
  for(var i=0;i<rdns.length;i++){
    var atvs=rdns[i].children||[];
    for(var j=0;j<atvs.length;j++){
      var atv=atvs[j];
      if(!atv.children||atv.children.length<2) continue;
      var oid=decodeOID(atv.children[0].value);
      var key=OID_NAME[oid]||oid;
      parts.push({k:key, v:decodeStr(atv.children[1])});
    }
  }
  return parts;
}
function nameStr(parts){
  var a=[];
  for(var i=0;i<parts.length;i++) a.push(parts[i].k+'='+parts[i].v);
  return a.join(', ');
}
function nameCN(parts){
  for(var i=0;i<parts.length;i++) if(parts[i].k==='CN') return parts[i].v;
  return parts.length?parts[0].v:'';
}

/* UTCTime(tag 23) / GeneralizedTime(tag 24)，只处理 Zulu 时间 */
function decodeTime(node){
  var v=node.value, s='';
  for(var i=0;i<v.length;i++) s+=String.fromCharCode(v[i]);
  var m=s.match(/^(\d{2}|\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/);
  if(!m) return {raw:s, date:null};
  var yy=m[1], year=yy.length===2?(+yy<50?2000+ +yy:1900+ +yy):+yy;
  var d=new Date(Date.UTC(year, +m[2]-1, +m[3], +m[4], +m[5], +(m[6]||0)));
  return {raw:s, date:d};
}
function fmtDate(d){
  if(!d) return '?';
  function p(n){ return (n<10?'0':'')+n; }
  return d.getUTCFullYear()+'-'+p(d.getUTCMonth()+1)+'-'+p(d.getUTCDate());
}

/* ================= SHA-256（纯 JS） ================= */

var SHA_K=[
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
];

function sha256Bytes(msg){
  var l=msg.length;
  var bitLenHi=Math.floor(l/0x20000000), bitLenLo=(l<<3)>>>0;
  var padLen=(((l+8)>>6)+1)<<6;
  var m=new Uint8Array(padLen);
  m.set(msg);
  m[l]=0x80;
  var dv=new DataView(m.buffer);
  dv.setUint32(padLen-8,bitLenHi);
  dv.setUint32(padLen-4,bitLenLo);
  var h=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
  var w=new Uint32Array(64);
  function rotr(x,n){ return (x>>>n)|(x<<(32-n)); }
  for(var off=0;off<padLen;off+=64){
    for(var i=0;i<16;i++) w[i]=dv.getUint32(off+i*4);
    for(i=16;i<64;i++){
      var s0=rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>>3);
      var s1=rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>>10);
      w[i]=(w[i-16]+s0+w[i-7]+s1)|0;
    }
    var a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for(i=0;i<64;i++){
      var S1=rotr(e,6)^rotr(e,11)^rotr(e,25);
      var ch=(e&f)^(~e&g);
      var t1=(hh+S1+ch+SHA_K[i]+w[i])|0;
      var S0=rotr(a,2)^rotr(a,13)^rotr(a,22);
      var maj=(a&b)^(a&c)^(b&c);
      var t2=(S0+maj)|0;
      hh=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0;
    }
    h[0]=(h[0]+a)|0;h[1]=(h[1]+b)|0;h[2]=(h[2]+c)|0;h[3]=(h[3]+d)|0;
    h[4]=(h[4]+e)|0;h[5]=(h[5]+f)|0;h[6]=(h[6]+g)|0;h[7]=(h[7]+hh)|0;
  }
  var out=new Uint8Array(32);
  var od=new DataView(out.buffer);
  for(i=0;i<8;i++) od.setUint32(i*4,h[i]>>>0);
  return out;
}

/* ================= X.509 证书解析 ================= */

function parseCertNode(node, fullData){
  if(node.tag!==16||!node.children||node.children.length<3)
    throw new Error('证书结构异常');
  var tbs=node.children[0].children, i=0;
  var version=1;
  if(tbs[i].cls===2&&tbs[i].tag===0){ /* [0] version EXPLICIT */
    version=tbs[i].children[0].value[0]+1; i++;
  }
  var serial=bytesToHex(tbs[i].value); i++;
  var sigAlg=decodeOID(tbs[i].children[0].value); i++;
  var issuer=parseName(tbs[i]); i++;
  var valKids=tbs[i].children; i++;
  var nb=decodeTime(valKids[0]), na=decodeTime(valKids[1]);
  var subject=parseName(tbs[i]); i++;
  var now=Date.now();
  var status='有效';
  if(nb.date&&now<nb.date.getTime()) status='未生效';
  else if(na.date&&now>na.date.getTime()) status='已过期';
  else if(na.date&&na.date.getTime()-now<90*864e5) status='即将过期（90天内）';
  var issuerS=nameStr(issuer), subjectS=nameStr(subject);
  var der=fullData.subarray(node.offset, node.offset+node.totalLen);
  return {
    version:version, serial:serial, sigAlgOid:sigAlg,
    issuer:issuer, issuerStr:issuerS,
    subject:subject, subjectStr:subjectS, subjectCN:nameCN(subject),
    notBefore:nb, notAfter:na,
    notBeforeStr:fmtDate(nb.date), notAfterStr:fmtDate(na.date),
    status:status, selfSigned:(issuerS===subjectS),
    fingerprint:bytesToHex(sha256Bytes(der))
  };
}

/* 严格路径：ContentInfo -> SignedData -> [0] certificates */
function findCertsStrict(data){
  var root=parseNode(data,0);
  if(root.tag!==16||!root.children||root.children.length<2)
    throw new Error('不是 PKCS7 结构');
  if(root.children[0].tag!==6) throw new Error('ContentInfo 缺少 OID');
  var ctype=decodeOID(root.children[0].value);
  if(ctype!=='1.2.840.113549.1.7.2')
    throw new Error('不是 SignedData（OID='+ctype+'）');
  var wrap=root.children[1];
  if(!(wrap.cls===2&&wrap.tag===0&&wrap.children&&wrap.children.length))
    throw new Error('SignedData 包装异常');
  var sd=wrap.children[0];
  var certs=[];
  for(var i=0;i<sd.children.length;i++){
    var ch=sd.children[i];
    if(ch.cls===2&&ch.tag===0){ /* [0] IMPLICIT certificates */
      for(var j=0;j<ch.children.length;j++)
        certs.push(parseCertNode(ch.children[j], data));
    }
  }
  return certs;
}

/* 兜底：全树扫描形如 [SEQUENCE(tbs), SEQUENCE(oid...), BITSTRING] 的证书 */
function findCertsHeuristic(data){
  var found=[];
  function looksLikeCert(n){
    if(n.tag!==16||!n.children||n.children.length!==3) return false;
    var tbs=n.children[0], alg=n.children[1], sig=n.children[2];
    if(tbs.tag!==16||alg.tag!==16||sig.tag!==3||sig.cls!==0) return false;
    if(!alg.children||!alg.children.length||alg.children[0].tag!==6) return false;
    /* tbs 里找 validity：含两个时间 tag 的 SEQUENCE */
    var tk=tbs.children||[];
    for(var i=0;i<tk.length;i++){
      var c=tk[i];
      if(c.tag===16&&c.children&&c.children.length===2){
        var t0=c.children[0].tag, t1=c.children[1].tag;
        if((t0===23||t0===24)&&(t1===23||t1===24)) return true;
      }
    }
    return false;
  }
  function walk(n){
    if(looksLikeCert(n)){
      try{ found.push(parseCertNode(n,data)); }catch(e){}
      return; /* 不再深入 */
    }
    var ks=n.children||[];
    for(var i=0;i<ks.length;i++) walk(ks[i]);
  }
  try{ walk(parseNode(data,0)); }catch(e){}
  return found;
}

function parse(data){
  if(!(data instanceof Uint8Array)) data=new Uint8Array(data);
  var certs=[];
  try{ certs=findCertsStrict(data); }catch(e){ certs=[]; }
  if(!certs.length) certs=findCertsHeuristic(data);
  if(!certs.length) throw new Error('未找到 X.509 证书');
  return certs;
}

return {
  parse:parse,
  parseNode:parseNode,
  sha256hex:function(b){ return bytesToHex(sha256Bytes(b instanceof Uint8Array?b:new Uint8Array(b))); }
};
});
