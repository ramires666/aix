const test=require('node:test');
const assert=require('node:assert/strict');
const {createHash}=require('node:crypto');
const {prepare,createStore}=require('./attachments.js');
const hash=value=>createHash('sha256').update(value).digest('hex');
test('a legacy text read becomes an exact native-file payload and compact metadata',async()=>{
  const text='print("Привет 😀")\r\n'+('line\n'.repeat(20000));
  const result={isError:false,structuredContent:{path:'W:\\algo\\agents.py',content:text,sha256:hash(text),size:Buffer.byteLength(text),offset:1,next_offset:20002,truncated:false}};
  const prepared=await prepare({name:'read_file',result});
  assert.equal(prepared.attachments.length,1);const file=prepared.attachments[0];
  assert.equal(Buffer.from(file.data,'base64').toString('utf8'),text);assert.equal(file.name,'agents.py');
  assert.equal(file.sha256,hash(text));assert.ok(JSON.stringify(prepared.result).length<1500);
  assert.equal(prepared.result.structuredContent.content,undefined);
  assert.equal(result.structuredContent.content,text,'preparation never mutates the original operation result');
});
test('binary embedded MCP resources keep PDF bytes, filename and MIME type',async()=>{
  const bytes=Buffer.from('%PDF-1.7\n\x00\xffbinary','latin1'),sha256=hash(bytes),uri='urn:helper:sha256:'+sha256;
  const attachment={name:'report.pdf',mimeType:'application/pdf',size:bytes.length,sha256,uri};
  const result={isError:false,structuredContent:{path:'W:/report.pdf',attachment},content:[{type:'resource',resource:{uri,mimeType:'application/pdf',blob:bytes.toString('base64')}}]};
  const prepared=await prepare({name:'read_file',result});
  assert.deepEqual(Buffer.from(prepared.attachments[0].data,'base64'),bytes);
  assert.equal(prepared.attachments[0].mimeType,'application/pdf');
  assert.ok(!JSON.stringify(prepared.result).includes(bytes.toString('base64')));
  await assert.rejects(prepare({name:'read_file',result:{...result,structuredContent:{attachment:{...attachment,size:99},path:'W:/report.pdf'}}}),/checksum|size/);
});
test('read ranges are identified as fragments; disabled and failed reads remain untouched',async()=>{
  const result={structuredContent:{path:'W:/data.py',content:'second\n',offset:2,next_offset:3,truncated:true}};
  assert.equal((await prepare({name:'read_file',result})).attachments[0].name,'data.py.lines-2-2.txt');
  for(const value of [{name:'read_file',enabled:false,result},{name:'exec_command',result},{name:'read_file',result:{...result,isError:true}}])assert.deepEqual(await prepare(value),{result:value.result,attachments:[]});
});

test('artifact descriptors survive restart and preserve empty, binary and large Unicode bytes',async()=>{
  for(const bytes of [Buffer.alloc(0),Buffer.from([0,255,254,13,10]),Buffer.from('Привет 😀\r\n'.repeat(200000))]){
    const data=bytes.toString('base64'),sha256=hash(bytes),db={};
    const storage={set:async values=>Object.assign(db,structuredClone(values)),get:async key=>({[key]:db[key]})};
    const [descriptor]=await createStore(storage).persist([{id:sha256,name:'file.bin',mimeType:'application/octet-stream',size:bytes.length,sha256,data}]);
    assert.equal(descriptor.data,undefined);assert.ok(JSON.stringify(descriptor).length<600);
    const restored=createStore(storage);
    let received='',offset=0;
    do{
      const chunk=await restored.chunk(descriptor,offset);
      assert.ok(chunk.data.length<=65536);received+=chunk.data;offset=chunk.nextOffset;
      if(chunk.eof)break;
    }while(offset<data.length);
    assert.deepEqual(Buffer.from(received,'base64'),bytes);
    await assert.rejects(restored.chunk({...descriptor,size:bytes.length+1},0),/size/);
    await assert.rejects(restored.chunk(descriptor,3),/offset/);
    db[descriptor.artifactKey]='Y29ycnVwdA==';
    await assert.rejects(createStore(storage).chunk(descriptor,0),/checksum|size/);
    delete db[descriptor.artifactKey];
    await assert.rejects(createStore(storage).chunk(descriptor,0),/unavailable/);
  }
});

test('artifact persistence failure cannot publish a descriptor and full text verifies its agent hash',async()=>{
  const file={id:'legacy',name:'file.txt',mimeType:'text/plain',size:4,data:'ZmlsZQ=='};
  await assert.rejects(createStore({set:async()=>{throw Error('disk full');}}).persist([file]),/disk full/);
  assert.equal(file.data,'ZmlsZQ==');assert.equal(file.artifactKey,undefined);
  const result={structuredContent:{path:'W:/file.txt',content:'file',size:4,sha256:hash('other'),offset:1,truncated:false}};
  await assert.rejects(prepare({name:'read_file',result}),/checksum/);
  const partial={structuredContent:{...result.structuredContent,offset:2,truncated:true}};
  assert.equal((await prepare({name:'read_file',result:partial})).attachments[0].sha256,hash('file'));
});
