/* Android 二进制 XML (AXML) 解析器：专用于 AndroidManifest.xml
   纯 JS，WebView/Node 兼容 */
(function(root, factory){
  if(typeof module==='object'&&module.exports)module.exports=factory();
  else root.AxmlParser=factory();
})(typeof window==='object'?window:this,()=>{

const CHUNK_STRING_POOL=0x0001;
const CHUNK_RESOURCE_MAP=0x0180;
const CHUNK_NS_START=0x0100;
const CHUNK_NS_END=0x0101;
const CHUNK_EL_START=0x0102;
const CHUNK_EL_END=0x0103;

const TYPE_STRING=0x03;
const TYPE_INT_DEC=0x10;
const TYPE_INT_HEX=0x11;
const TYPE_INT_BOOL=0x12;

function utf16ToStr(u16arr){
  var s='';
  for(var i=0;i<u16arr.length;i++) s+=String.fromCharCode(u16arr[i]);
  return s;
}

class AxmlParser {
  constructor(buf){
    this.dv = buf instanceof DataView ? buf : new DataView(buf.buffer||buf, buf.byteOffset||0, buf.byteLength||buf.length);
    this.strings=[];
    this.manifest=null;
  }
  parse(){
    var dv=this.dv;
    if(dv.getUint16(0,true)!==0x0003||dv.getUint16(2,true)!==8)
      throw new Error('不是 AXML 文件');
    var fileSize=dv.getUint32(4,true);
    var pos=8;
    var stack=[]; // 元素栈
    var root=null;
    while(pos+8<=fileSize&&pos+8<=dv.byteLength){
      var type=dv.getUint16(pos,true);
      var headerSize=dv.getUint16(pos+2,true);
      var size=dv.getUint32(pos+4,true);
      if(size<8||pos+size>dv.byteLength) break;
      if(type===CHUNK_STRING_POOL){
        this.strings=this._parseStringPool(pos);
      }else if(type===CHUNK_EL_START){
        var el=this._parseElStart(pos);
        if(stack.length===0){root=el;}
        else{stack[stack.length-1].children.push(el);}
        stack.push(el);
      }else if(type===CHUNK_EL_END){
        stack.pop();
      }
      // NS_START/END、RESOURCE_MAP 解析时不需要
      pos+=size;
    }
    this.manifest=root;
    return root;
  }
  _str(idx){
    if(idx===0xFFFFFFFF||idx<0||idx>=this.strings.length) return '';
    return this.strings[idx];
  }
  _parseStringPool(pos){
    var dv=this.dv;
    var stringCount=dv.getUint32(pos+8,true);
    var styleCount=dv.getUint32(pos+12,true);
    var flags=dv.getUint32(pos+16,true);
    var stringsStart=dv.getUint32(pos+20,true);
    var isUtf8=(flags&0x100)!==0;
    var offBase=pos+28;
    var out=[];
    for(var i=0;i<stringCount;i++){
      var strOff=dv.getUint32(offBase+i*4,true);
      var p=pos+stringsStart+strOff;
      if(isUtf8){
        // UTF-8: [charLen][byteLen] bytes 0x00，长度可能是 1 或 2 字节
        var clen=dv.getUint8(p), blen;
        if(clen&0x80){clen=((clen&0x7F)<<8)|dv.getUint8(p+1);p+=2;}else{p+=1;}
        blen=dv.getUint8(p);
        if(blen&0x80){blen=((blen&0x7F)<<8)|dv.getUint8(p+1);p+=2;}else{p+=1;}
        var bytes=new Uint8Array(dv.buffer,dv.byteOffset+p,blen);
        try{out.push(new TextDecoder('utf-8').decode(bytes));}
        catch(e){
          var s='';for(var k=0;k<bytes.length;k++)s+=String.fromCharCode(bytes[k]);
          out.push(s);
        }
      }else{
        // UTF-16: u16 len, chars, 0x0000
        var len=dv.getUint16(p,true);p+=2;
        var chars=new Uint16Array(dv.buffer,dv.byteOffset+p,len);
        // 复制避免 endianness/对齐问题
        var cp=new Uint16Array(len);
        for(var k=0;k<len;k++)cp[k]=dv.getUint16(p+k*2,true);
        out.push(utf16ToStr(cp));
      }
    }
    return out;
  }
  _parseElStart(pos){
    var dv=this.dv;
    var nsIdx=dv.getUint32(pos+16,true);
    var nameIdx=dv.getUint32(pos+20,true);
    var attrStart=dv.getUint16(pos+24,true);
    var attrSize=dv.getUint16(pos+26,true);
    var attrCount=dv.getUint16(pos+28,true);
    var el={
      ns:this._str(nsIdx),
      name:this._str(nameIdx),
      attrs:{},
      children:[]
    };
    var ap=pos+16+attrStart; // attributeStart 相对 +16 偏移
    for(var i=0;i<attrCount;i++){
      var aNs=dv.getUint32(ap,true);
      var aName=dv.getUint32(ap+4,true);
      var aRaw=dv.getUint32(ap+8,true);
      var vType=dv.getUint8(ap+15); // typedValue: size(2B)+res0(1B)+type(1B)+data(4B)
      var vData=dv.getUint32(ap+16,true);
      var key=this._str(aName);
      var val;
      if(vType===TYPE_STRING){
        val=this._str(vData);
      }else if(vType===TYPE_INT_BOOL){
        val=vData!==0;
      }else if(vType===TYPE_INT_DEC){
        val=vData|0; // 转有符号
      }else if(vType===TYPE_INT_HEX){
        val='0x'+(vData>>>0).toString(16);
      }else{
        // 兜底：用 rawValue 字符串
        val=this._str(aRaw);
        if(val===''&&vData!==0)val=String(vData);
      }
      el.attrs[key]=val;
      ap+=attrSize;
    }
    return el;
  }
  /* 提取 Manifest 关键信息 */
  getInfo(){
    var root=this.manifest;
    if(!root) throw new Error('Manifest 解析失败');
    function findKids(el,name){
      return el.children.filter(c=>c.name===name);
    }
    function findAll(el,name,out){
      out=out||[];
      el.children.forEach(c=>{
        if(c.name===name)out.push(c);
        findAll(c,name,out);
      });
      return out;
    }
    var info={
      package:root.attrs['package']||'',
      versionName:String(root.attrs['versionName']||''),
      versionCode:root.attrs['versionCode']||0,
      label:'',
      permissions:[],
      activities:[],
      services:[],
      receivers:[],
      providers:[],
      metaData:[]
    };
    var apps=findKids(root,'application');
    if(apps.length){
      var app=apps[0];
      info.label=String(app.attrs['label']||'');
      findKids(app,'activity').forEach(a=>info.activities.push(a.attrs['name']||''));
      findKids(app,'activity-alias').forEach(a=>info.activities.push((a.attrs['name']||'')+' (alias)'));
      findKids(app,'service').forEach(s=>info.services.push(s.attrs['name']||''));
      findKids(app,'receiver').forEach(r=>info.receivers.push(r.attrs['name']||''));
      findKids(app,'provider').forEach(p=>info.providers.push(p.attrs['name']||''));
      findKids(app,'meta-data').forEach(m=>info.metaData.push({name:m.attrs['name'],value:m.attrs['value']}));
    }
    findAll(root,'uses-permission').forEach(p=>{
      var n=p.attrs['name']||'';
      if(n)info.permissions.push(n);
    });
    // 去重
    info.permissions=[...new Set(info.permissions)];
    return info;
  }
}

return {AxmlParser:AxmlParser};
});
