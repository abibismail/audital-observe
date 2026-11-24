import {readFileSync,readdirSync} from 'node:fs';
import {createHash} from 'node:crypto';
import pg from 'pg';

// Forward-only, checksummed migrations. Each file runs in its own transaction under a global advisory
// lock; an edited already-applied migration aborts with MIGRATION_CHECKSUM_MISMATCH.
// Run with an ADMIN connection (role creation + schema ownership). The app must use a separate
// login that is a member of observe_app only.
export const SQL_DIR=new URL('../../sql/',import.meta.url);
const LOCK_KEY=7240310021n;
export function listMigrations(dir=SQL_DIR){
 return readdirSync(dir).filter(f=>/^\d{3}_[a-z0-9_]+\.sql$/.test(f)).sort().map(file=>{
  const sql=readFileSync(new URL(file,dir),'utf8');
  return {version:file.slice(0,3),file,sql,checksum:createHash('sha256').update(sql).digest('hex')};
 });
}
export async function migrate(target,{dir=SQL_DIR,log=()=>{}}={}){
 const own=typeof target==='string';const client=own?new pg.Client({connectionString:target}):target;
 if(own)await client.connect();
 const applied=[];
 try{
  await client.query('SELECT pg_advisory_lock($1)',[LOCK_KEY.toString()]);
  await client.query('CREATE SCHEMA IF NOT EXISTS observe_migrations');
  await client.query('REVOKE ALL ON SCHEMA observe_migrations FROM PUBLIC');
  await client.query(`CREATE TABLE IF NOT EXISTS observe_migrations.applied(version text PRIMARY KEY,file text NOT NULL,checksum text NOT NULL,applied_at timestamptz NOT NULL DEFAULT now())`);
  const done=new Map((await client.query('SELECT version,checksum FROM observe_migrations.applied')).rows.map(r=>[r.version,r.checksum]));
  for(const m of listMigrations(dir)){
   if(done.has(m.version)){if(done.get(m.version)!==m.checksum)throw Error(`MIGRATION_CHECKSUM_MISMATCH ${m.file}`);continue;}
   await client.query('BEGIN');
   try{
    await client.query(m.sql);
    await client.query('RESET ROLE');
    await client.query('INSERT INTO observe_migrations.applied(version,file,checksum) VALUES ($1,$2,$3)',[m.version,m.file,m.checksum]);
    await client.query('COMMIT');applied.push(m.file);log(`applied ${m.file}`);
   }catch(e){await client.query('ROLLBACK').catch(()=>{});throw Object.assign(Error(`MIGRATION_FAILED ${m.file}: ${e.message}`),{cause:e});}
  }
 }finally{
  await client.query('SELECT pg_advisory_unlock($1)',[LOCK_KEY.toString()]).catch(()=>{});
  if(own)await client.end();
 }
 return applied;
}
