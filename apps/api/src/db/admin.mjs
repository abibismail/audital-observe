import {createHash,randomUUID} from 'node:crypto';
import pg from 'pg';
import {migrate} from './migrate.mjs';
// Operator-only helpers. They run with the ADMIN connection, never from the request path.
const sha=t=>createHash('sha256').update(t).digest('hex');
const IDENT=/^[a-z_][a-z0-9_]{2,62}$/;
export async function createAppLogin(admin,{name,password}){
 if(!IDENT.test(name))throw Error('ROLE_NAME_INVALID');
 if(!password||password.length<24)throw Error('ROLE_PASSWORD_TOO_SHORT');
 const exists=(await admin.query('SELECT 1 FROM pg_roles WHERE rolname=$1',[name])).rowCount;
 const lit=(await admin.query('SELECT quote_literal($1) AS q',[password])).rows[0].q;
 await admin.query(`${exists?'ALTER':'CREATE'} ROLE ${name} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB INHERIT PASSWORD ${lit}`);
 await admin.query(`GRANT observe_app TO ${name}`); // policies are written TO observe_app; membership inherits them
 return name;
}
export async function provisionProject(admin,{tenantId=randomUUID(),tenantName='tenant',projectId=randomUUID(),projectName='project',apiKey}){
 if(!apiKey||String(apiKey).length<20)throw Error('API_KEY_TOO_SHORT');
 await admin.query('BEGIN');
 try{
  await admin.query('INSERT INTO observe.tenants(tenant_id,name) VALUES ($1,$2) ON CONFLICT (tenant_id) DO NOTHING',[tenantId,tenantName]);
  await admin.query('INSERT INTO observe.projects(tenant_id,project_id,name) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING',[tenantId,projectId,projectName]);
  await admin.query('INSERT INTO observe.api_keys(key_hash,tenant_id,project_id) VALUES ($1,$2,$3)',[sha(apiKey),tenantId,projectId]);
  await admin.query('COMMIT');
 }catch(e){await admin.query('ROLLBACK');throw e;}
 return {tenantId,projectId};
}
if(import.meta.url===`file://${process.argv[1]}`){
 const [cmd]=process.argv.slice(2);const url=process.env.AUDITAL_PG_ADMIN_URL;
 if(!url)throw Error('AUDITAL_PG_ADMIN_URL required');
 if(cmd==='migrate'){const applied=await migrate(url,{log:console.log});console.log(applied.length?`applied ${applied.length}`:'up to date');}
 else if(cmd==='provision'){const c=new pg.Client({connectionString:url});await c.connect();try{console.log(JSON.stringify(await provisionProject(c,{apiKey:process.env.AUDITAL_API_KEY,tenantName:process.env.AUDITAL_TENANT_NAME||'tenant',projectName:process.env.AUDITAL_PROJECT_NAME||'project'})));}finally{await c.end();}}
 else{console.error('usage: admin.mjs migrate|provision');process.exitCode=2;}
}
