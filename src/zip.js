/* 最小 ZIP 解析器：APK 分析用，WebView/Node 兼容（ES6） */
(function(root, factory){
  if(typeof module==='object'&&module.exports)module.exports=factory();
  else root.ZipParser=factory();
})(typeof window==='object'?window:this,()=>{

/* 从 Blob/File 分块读取，返回 ArrayBuffer */
function readSlice(blob, start, length){
  return new Promise((resolve,reject)=>{
    var r=new FileReader();
    r.onload=()=>resolve(r.result);
    r.onerror=()=>reject(r.error||new Error('读取失败'));
    r.readAsArrayBuffer(blob.slice(start, start+length));
  });
}

/* Node 环境：buffer 切片，转成 ArrayBuffer 视图 */
function bufSlice(buf, start, length){
  var ab = buf.buffer.slice(buf.byteOffset+start, buf.byteOffset+start+length);
  return Promise.resolve(ab);
}

class ZipReader {
  constructor(source){
    // source: Blob(File) 或 Uint8Array/Buffer
    this.src=source;
    this.isBlob = typeof Blob!=='undefined' && source instanceof Blob;
    this.size = this.isBlob ? source.size : source.length;
    this.entries=null;
  }
  _read(start,length){
    if(length<=0) return Promise.resolve(new Uint8Array(0).buffer);
    if(this.isBlob) return readSlice(this.src,start,length);
    return bufSlice(this.src,start,length);
  }
  /* 解析中央目录，返回 entries: [{name, method, csize, usize, offset}] */
  async parse(){
    if(this.entries) return this.entries;
    // 1. 找 EOCD：从尾部读 64KB+22
    var tailLen=Math.min(this.size, 65558);
    var tailBuf=await this._read(this.size-tailLen, tailLen);
    var tail=new DataView(tailBuf);
    var eocdOff=-1;
    for(var i=tailLen-22;i>=0;i--){
      if(tail.getUint32(i,true)===0x06054b50){eocdOff=i;break;}
    }
    if(eocdOff<0) throw new Error('不是有效的 ZIP/APK 文件');
    var cdCount=tail.getUint16(eocdOff+10,true);
    var cdSize=tail.getUint32(eocdOff+12,true);
    var cdOff=tail.getUint32(eocdOff+16,true);
    // 2. 读中央目录
    var cdBuf=await this._read(cdOff,cdSize);
    var dv=new DataView(cdBuf);
    var entries=[], pos=0;
    // 中央目录条目数以实际解析为准（zip64 等情况）
    while(pos+46<=cdSize){
      if(dv.getUint32(pos,true)!==0x02014b50) break;
      var method=dv.getUint16(pos+10,true);
      var csize=dv.getUint32(pos+20,true);
      var usize=dv.getUint32(pos+24,true);
      var nameLen=dv.getUint16(pos+28,true);
      var extraLen=dv.getUint16(pos+30,true);
      var commentLen=dv.getUint16(pos+32,true);
      var lhOff=dv.getUint32(pos+42,true);
      var nameBytes=new Uint8Array(cdBuf,pos+46,nameLen);
      var name;
      try{name=new TextDecoder('utf-8').decode(nameBytes);}
      catch(e){name='';for(var k=0;k<nameBytes.length;k++)name+=String.fromCharCode(nameBytes[k]);}
      entries.push({name:name,method:method,csize:csize,usize:usize,offset:lhOff});
      pos+=46+nameLen+extraLen+commentLen;
      if(cdCount>0&&entries.length>=cdCount) break;
    }
    this.entries=entries;
    return entries;
  }
  /* 提取单个文件，返回 Uint8Array（自动处理 STORED/DEFLATE） */
  async extract(entry){
    // 读 local header 找数据偏移
    var lhBuf=await this._read(entry.offset, 30);
    var lh=new DataView(lhBuf);
    if(lh.getUint32(0,true)!==0x04034b50) throw new Error('local header 损坏: '+entry.name);
    var nameLen=lh.getUint16(26,true);
    var extraLen=lh.getUint16(28,true);
    var dataOff=entry.offset+30+nameLen+extraLen;
    var rawBuf=await this._read(dataOff, entry.csize);
    var raw=new Uint8Array(rawBuf);
    if(entry.method===0) return raw; // STORED
    if(entry.method===8){
      // DEFLATE：浏览器用 DecompressionStream，Node 用 zlib
      if(typeof DecompressionStream!=='undefined'){
        var ds=new DecompressionStream('deflate-raw');
        var stream=new Blob([raw]).stream().pipeThrough(ds);
        var ab=await new Response(stream).arrayBuffer();
        return new Uint8Array(ab);
      }else{
        // Node fallback
        var zlib=require('zlib');
        return new Uint8Array(zlib.inflateRawSync(Buffer.from(raw)));
      }
    }
    throw new Error('不支持的压缩方式: '+entry.method);
  }
  /* 按名查找 */
  find(name){
    if(!this.entries) return null;
    for(var i=0;i<this.entries.length;i++)
      if(this.entries[i].name===name) return this.entries[i];
    return null;
  }
}

return {ZipReader:ZipReader};
});
