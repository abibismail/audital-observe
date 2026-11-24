// Deterministic JSON for signing: recursively sorted object keys, no whitespace.
// Survives PostgreSQL jsonb round-trips (which reorder keys) so stored packs re-verify.
export function canonicalJSON(value){
 if(value===null||typeof value==='boolean')return JSON.stringify(value);
 if(typeof value==='number'){if(!Number.isFinite(value))throw Error('CANONICAL_NON_FINITE_NUMBER');return JSON.stringify(value);}
 if(typeof value==='string')return JSON.stringify(value);
 if(Array.isArray(value))return `[${value.map(v=>v===undefined?'null':canonicalJSON(v)).join(',')}]`;
 if(typeof value==='object'){
  const keys=Object.keys(value).filter(k=>value[k]!==undefined).sort();
  return `{${keys.map(k=>`${JSON.stringify(k)}:${canonicalJSON(value[k])}`).join(',')}}`;
 }
 throw Error('CANONICAL_UNSUPPORTED_TYPE');
}
