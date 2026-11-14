const fs=require('node:fs');
const path=require('node:path');
const assert=require('node:assert/strict');
const {version}=require('./package.json');
const check=process.argv.includes('--check');
assert.match(version,/^\d+\.\d+\.\d+$/);
assert.ok(process.argv.slice(2).every(argument=>argument==='--check'),'Unknown version sync argument');

function update(name,transform){
  const file=path.join(__dirname,name),before=fs.readFileSync(file,'utf8'),after=transform(before);
  if(check)assert.equal(before.replaceAll('\r\n','\n'),after.replaceAll('\r\n','\n'),name+' version is stale');
  else if(before!==after)fs.writeFileSync(file,after);
}
function stamp(name,pattern,replace){
  update(name,text=>{
    assert.equal([...text.matchAll(new RegExp(pattern.source,'g'))].length,1,name+' version stamp must be unique');
    return text.replace(pattern,replace);
  });
}
stamp('manifest.json',/"version":\s*"[^"]*"/,'"version": "'+version+'"');
update('package-lock.json',text=>{
  const lock=JSON.parse(text);lock.version=version;lock.packages[''].version=version;
  return JSON.stringify(lock,null,2)+'\n';
});
stamp('content.js',/const contentVersion='[^']*'/,"const contentVersion='"+version+"'");
stamp('local-client.js',/version = '[^']*'/,"version = '"+version+"'");
stamp('native-client.js',/version = '[^']*'/,"version = '"+version+"'");
stamp('mcp-client.js',/clientInfo: \{ name: 'WebCodex AI Studio Bridge', version: '[^']*' \}/,"clientInfo: { name: 'WebCodex AI Studio Bridge', version: '"+version+"' }");
stamp('panel.html',/AI Studio · alpha \d+\.\d+\.\d+/, 'AI Studio · alpha '+version);
