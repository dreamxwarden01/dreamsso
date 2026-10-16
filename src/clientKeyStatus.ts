import type {SigningKeyStatus} from './signingKeyRotation.js';
const kid=(value:unknown):value is string=>typeof value==='string'&&value.length>0&&value.length<=200&&!/[\x00-\x20\x7f]/.test(value);
const instant=(value:unknown):value is string=>typeof value==='string'&&Number.isFinite(Date.parse(value));
const need=(value:unknown)=>{if(!value)throw Error('portal_key_status_invalid');};
/** Only a small public status document may cross the admin relay boundary. */
export async function readClientKeyStatus(response:Response):Promise<SigningKeyStatus>{
  const reader=response.body?.getReader();let size=0;const chunks:Uint8Array[]=[];
  try{
    need(response.ok&&response.headers.get('content-type')?.split(';')[0].trim().toLowerCase()==='application/json'&&reader);
    while(true){const item=await reader!.read();if(item.done)break;size+=item.value.byteLength;need(size<=8192);chunks.push(item.value);}
    const value=JSON.parse(Buffer.concat(chunks).toString('utf8'));
    need(value&&kid(value.kid)&&(value.rotated_at===null||instant(value.rotated_at)));
    need(value.state==='active'||value.state==='pending');
    let rotation:SigningKeyStatus['rotation']=null;
    if(value.state==='active')need(value.rotation===null);
    else{
      const row=value.rotation;
      need(row&&typeof row.id==='string'&&/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/.test(row.id)&&kid(row.kid)&&row.kid!==value.kid);
      need((row.published_at===null&&row.activate_after===null)||(instant(row.published_at)&&instant(row.activate_after)&&Date.parse(row.activate_after)-Date.parse(row.published_at)>=300000));
      rotation={id:row.id,kid:row.kid,published_at:row.published_at,activate_after:row.activate_after};
    }
    return{kid:value.kid,rotated_at:value.rotated_at,state:value.state,rotation};
  }catch{await reader?.cancel().catch(()=>{});throw Error('portal_key_status_invalid');}
  finally{reader?.releaseLock();}
}
