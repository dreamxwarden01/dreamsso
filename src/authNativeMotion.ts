/** Optimize only the decorative native auth shell; authentication remains native navigation. */
export function renderAuthNativeMotionScript(nonce: string): string {
  const safeNonce = nonce.replace(/[&<>"']/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[character]!);
  return `<script nonce="${safeNonce}">${AUTH_NATIVE_MOTION_SCRIPT}</script>`;
}

const AUTH_NATIVE_MOTION_SCRIPT = String.raw`(function(){
  'use strict';
  if(!('onpagereveal' in window)||typeof matchMedia!=='function'||
     typeof document.getAnimations!=='function'||typeof getComputedStyle!=='function'||
     typeof ResizeObserver!=='function')return;
  var motion=matchMedia('(prefers-reduced-motion: reduce)'),generation=0,changed=null;
  if(typeof motion.addEventListener!=='function')return;
  function release(){
    var saved=changed;changed=null;
    if(saved)try{saved.observer.disconnect();}catch(_){}
    return saved;
  }
  function restore(){
    var saved=release();if(!saved)return false;
    try{saved.effect.setKeyframes(saved.frames);return true;}catch(_){return false;}
  }
  function mark(name){
    try{if(typeof performance!=='undefined'&&typeof performance.mark==='function')performance.mark(name);}catch(_){}
  }
  addEventListener('pagehide',function(){generation++;restore();});
  motion.addEventListener('change',function(event){if(event.matches){generation++;restore();}});
  function finite(value,min,max){return typeof value==='number'&&Number.isFinite(value)&&value>=min&&value<=max;}
  function pixels(value){
    if(typeof value!=='string'||!/^\d+(?:\.\d+)?px$/.test(value))return null;
    var number=Number(value.slice(0,-2));return finite(number,1,8192)?number:null;
  }
  function translation(value){
    if(typeof value!=='string'||!/^matrix\([^()]+\)$/.test(value))return null;
    var parts=value.slice(7,-1).split(',');
    if(parts.length!==6||parts.some(function(part){return !/^[-+]?(?:\d+\.?\d*|\.\d+)(?:e[-+]?\d+)?$/i.test(part.trim());}))return null;
    var values=parts.map(Number);
    if(!values.every(function(n){return finite(n,-16384,16384);})||
       values[0]!==1||values[1]!==0||values[2]!==0||values[3]!==1)return null;
    return {x:values[4],y:values[5]};
  }
  function geometry(frame){
    var width=pixels(frame.width),height=pixels(frame.height),position=translation(frame.transform);
    return width&&height&&position?{w:width,h:height,x:position.x,y:position.y}:null;
  }
  function finalGeometry(){
    // The UA's underlying group uses the final border box in viewport coordinates.
    // Resolve implicit endpoints only in the untransformed, unscrolled auth layout.
    var card=document.querySelector('.card'),visual=window.visualViewport;
    if(!card||!card.isConnected||scrollX!==0||scrollY!==0||
       (visual&&(visual.scale!==1||visual.offsetLeft!==0||visual.offsetTop!==0)))return null;
    for(var element=card;element;element=element.parentElement){
      var style=getComputedStyle(element);
      if(style.transform!=='none'||(style.translate&&style.translate!=='none')||
         (style.scale&&style.scale!=='none')||(style.rotate&&style.rotate!=='none'))return null;
    }
    var rect=card.getBoundingClientRect();
    return finite(rect.width,1,8192)&&finite(rect.height,1,8192)&&
      finite(rect.left,-16384,16384)&&finite(rect.top,-16384,16384)?
      {w:rect.width,h:rect.height,x:rect.left,y:rect.top,element:card}:null;
  }
  function close(a,b){return Math.abs(a-b)<0.1;}
  function optimize(){
    var shellStyle=getComputedStyle(document.documentElement,'::view-transition-group(authcard)');
    if(shellStyle.transformOrigin!=='0px 0px'&&shellStyle.transformOrigin!=='0px 0px 0px')return;
    var candidates=document.getAnimations().filter(function(animation){
      var effect=animation.effect;
      return effect&&effect.target===document.documentElement&&
        effect.pseudoElement==='::view-transition-group(authcard)';
    });
    if(candidates.length!==1)return;
    var animation=candidates[0],effect=animation.effect;
    if(typeof animation.animationName!=='string'||
       animation.animationName.indexOf('-ua-view-transition-group-anim-')!==0||
       animation.playState!=='running'||typeof effect.getKeyframes!=='function'||
       typeof effect.setKeyframes!=='function')return;
    var frames=effect.getKeyframes(),allowed=['offset','computedOffset','easing','composite','width','height','transform','backdropFilter'];
    if(!Array.isArray(frames)||frames.length<1||frames.length>2||frames.some(function(frame){
      return !frame||Object.keys(frame).some(function(key){return allowed.indexOf(key)<0;})||
        (frame.composite&&frame.composite!=='auto'&&frame.composite!=='replace')||
        (frame.backdropFilter&&frame.backdropFilter!=='none');
    })||frames[0].computedOffset!==0||(frames[1]&&frames[1].computedOffset!==1))return;
    var before=geometry(frames[0]),after=frames[1]&&geometry(frames[1]),final=finalGeometry();
    if(!before||!final)return;
    if(!after){
      var last=frames[1];
      if(last&&('width' in last||'height' in last||'transform' in last))return;
      after=final;
    }
    if(!close(after.w,final.w)||!close(after.h,final.h)||!close(after.x,final.x)||!close(after.y,final.y))return;
    if(close(before.w,after.w)&&close(before.h,after.h))return;
    var sx=before.w/after.w,sy=before.h/after.h;
    if(sx<0.75||sx>4/3||sy<0.75||sy>4/3)return;
    // Keep the end implicit so keyboard/font layout changes retain the UA's live translation.
    var replacement=[{offset:0,easing:frames[0].easing||'linear',composite:'replace',
      transform:'matrix('+sx+',0,0,'+sy+','+before.x+','+before.y+')'}];
    var token=generation,record=null,observer=new ResizeObserver(function(){
      if(!record||changed!==record||token!==generation)return;
      var rect=final.element.getBoundingClientRect();
      if(Math.abs(rect.width-final.w)>0.1||Math.abs(rect.height-final.h)>0.1){
        if(restore())mark('auth-vt-resize-fallback');
      }
    });
    try{
      observer.observe(final.element,{box:'border-box'});
      // setKeyframes validates before assigning; failure leaves the original effect intact.
      effect.setKeyframes(replacement);
    }catch(_){observer.disconnect();return;}
    record={effect:effect,frames:[frames[0]],observer:observer};changed=record;
    mark('auth-vt-transform');
  }
  addEventListener('pagereveal',function(event){
    var transition=event.viewTransition,token=++generation;
    restore();
    if(!transition||motion.matches)return;
    Promise.resolve(transition.ready).then(function(){
      if(token!==generation||motion.matches||document.visibilityState==='hidden')return;
      try{optimize();}catch(_){}
      var finished=transition.finished;
      if(finished&&typeof finished.then==='function')Promise.resolve(finished).then(function(){
        if(token===generation)release();
      },function(){if(token===generation)release();});
    },function(){});
  });
})();`;
