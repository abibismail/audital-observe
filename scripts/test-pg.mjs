#!/usr/bin/env node
// Runs apps/api/tests/pg/*.test.mjs against a REAL PostgreSQL server.
//  - If AUDITAL_PG_ADMIN_URL is set (e.g. CI service container), it is used directly.
//  - Otherwise a throwaway Docker container (AUDITAL_PG_IMAGE, default postgres:16-alpine) is started on a
//    random loopback port and removed afterwards. No AWS, no persistent volumes.
import {spawnSync,spawn} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import pg from 'pg';
const sh=(cmd,args)=>{const r=spawnSync(cmd,args,{encoding:'utf8'});if(r.status!==0)throw Error(`${cmd} ${args.join(' ')} failed: ${r.stderr||r.stdout}`);return r.stdout.trim();};
async function waitReady(url,ms=60000){const end=Date.now()+ms;let last;
 while(Date.now()<end){const c=new pg.Client({connectionString:url});try{await c.connect();await c.query('SELECT 1');await c.end();return;}catch(e){last=e;await c.end().catch(()=>{});await new Promise(r=>setTimeout(r,500));}}
 throw Error(`postgres not ready: ${last?.message}`);}
let container=null,url=process.env.AUDITAL_PG_ADMIN_URL;
try{
 if(!url){
  const image=process.env.AUDITAL_PG_IMAGE||'postgres:16-alpine',pw=randomBytes(18).toString('hex');
  container=`audital-observe-pg-${randomBytes(4).toString('hex')}`;
  sh('docker',['run','-d','--rm','--name',container,'-e',`POSTGRES_PASSWORD=${pw}`,'-p','127.0.0.1::5432',image]);
  const port=sh('docker',['port',container,'5432/tcp']).split('\n')[0].split(':').pop();
  url=`postgres://postgres:${pw}@127.0.0.1:${port}/postgres`;
  console.error(`[test:pg] started ${image} as ${container} on 127.0.0.1:${port}`);
 }
 await waitReady(url);
 const v=new pg.Client({connectionString:url});await v.connect();console.error(`[test:pg] ${(await v.query('SELECT version()')).rows[0].version}`);await v.end();
 const code=await new Promise(res=>spawn(process.execPath,['--test','--test-concurrency=1','apps/api/tests/pg/rls.test.mjs'],{stdio:'inherit',env:{...process.env,AUDITAL_PG_ADMIN_URL:url}}).on('exit',c=>res(c??1)));
 process.exitCode=code;
}catch(e){console.error(`[test:pg] ${e.message}`);process.exitCode=1;}
finally{if(container){spawnSync('docker',['rm','-f',container]);console.error(`[test:pg] removed ${container}`);}}
