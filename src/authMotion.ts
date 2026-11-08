/** Visual-only enhancement for browsers without cross-document view transitions. */
export function renderAuthMotionScript(nonce: string): string {
  const safeNonce = nonce.replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[character]!);
  return `<script nonce="${safeNonce}">${AUTH_MOTION_SCRIPT}</script>`;
}

// Keep this as browser JavaScript: it is emitted unchanged in the nonce'd script.
const AUTH_MOTION_SCRIPT = String.raw`(function(){
  'use strict';
  var key='authcard.geometry.v1',raw=null,previous=null;
  // Consume even invalid/unsupported entries so they cannot animate a later load.
  try{raw=sessionStorage.getItem(key);sessionStorage.removeItem(key);}catch(_){raw=null;}
  if('onpagereveal' in window||'CSSViewTransitionRule' in window)return;
  var card=document.querySelector('.card'),body=card&&card.querySelector('.cb');
  if(!body||typeof card.animate!=='function'||typeof body.animate!=='function'||
     typeof matchMedia!=='function'||typeof performance.getEntriesByType!=='function')return;
  var motion=matchMedia('(prefers-reduced-motion: reduce)'),visual=window.visualViewport;
  if(typeof motion.addEventListener!=='function')return;
  function finite(n,min,max){return typeof n==='number'&&Number.isFinite(n)&&n>=min&&n<=max;}
  function viewport(){return {vw:innerWidth,vh:innerHeight,
    xw:visual?visual.width:innerWidth,xh:visual?visual.height:innerHeight,s:visual?visual.scale:1};}
  function valid(o){return !!o&&Object.keys(o).length===9&&
    finite(o.w,120,4096)&&finite(o.h,64,8192)&&finite(o.vw,240,8192)&&
    finite(o.vh,200,8192)&&finite(o.xw,120,8192)&&finite(o.xh,100,8192)&&
    finite(o.s,0.1,10)&&finite(o.t,1,Number.MAX_SAFE_INTEGER)&&o.v===1&&o.w<=o.vw+2;}
  function sameViewport(a,b){return Math.abs(a.vw-b.vw)<1&&Math.abs(a.vh-b.vh)<1&&
    Math.abs(a.xw-b.xw)<1&&Math.abs(a.xh-b.xh)<1&&Math.abs(a.s-b.s)<0.001;}
  function unzoomed(v){return Math.abs(v.s-1)<0.001;}
  function discard(){try{sessionStorage.removeItem(key);}catch(_){}}
  var initial=viewport(),animations=[],active=false,originalWidth=body.style.width;
  function settle(){
    if(!active&&animations.length===0)return;
    active=false;
    var running=animations;animations=[];
    running.forEach(function(a){a.onfinish=null;a.oncancel=null;try{a.cancel();}catch(_){}});
    card.classList.remove('morphing');body.style.width=originalWidth;
  }
  addEventListener('pagehide',function(event){
    // Read the currently painted geometry BEFORE cancelling a partially finished morph.
    var rect=card.getBoundingClientRect(),v=viewport();
    var next={v:1,w:rect.width,h:rect.height,vw:v.vw,vh:v.vh,xw:v.xw,xh:v.xh,s:v.s,t:Date.now()};
    // The outgoing page may enter BFCache even when the destination is a fresh navigation.
    // Incoming history entries are rejected below; restored documents settle on pageshow.
    if(!motion.matches&&unzoomed(v)&&valid(next)){
      try{sessionStorage.setItem(key,JSON.stringify(next));}catch(_){}
    }else discard();
    settle();
  });
  addEventListener('pageshow',function(event){if(event.persisted){discard();settle();}});
  motion.addEventListener('change',function(event){if(event.matches){discard();settle();}});
  function resize(){if(active&&!sameViewport(initial,viewport()))settle();}
  addEventListener('resize',resize,{passive:true});
  if(visual)visual.addEventListener('resize',resize,{passive:true});
  // Focus (including the existing OTP autofocus) is deliberately untouched.
  ['pointerdown','touchstart','keydown','wheel'].forEach(function(type){
    addEventListener(type,function(event){if(event.isTrusted&&active)settle();},{passive:true});
  });
  if(raw&&raw.length<=512){try{previous=JSON.parse(raw);}catch(_){}}
  var navigation=performance.getEntriesByType('navigation')[0];
  if(!valid(previous)||!navigation||navigation.type!=='navigate'||motion.matches||
     !unzoomed(initial)||!sameViewport(previous,initial))return;
  var age=Date.now()-previous.t;
  if(age<0||age>3000)return;
  var final=card.getBoundingClientRect(),width=final.width,height=final.height;
  if(!finite(width,120,4096)||!finite(height,64,8192)||
     Math.abs(width-previous.w)>256||Math.abs(height-previous.h)>2048||
     (Math.abs(width-previous.w)<1&&Math.abs(height-previous.h)<2))return;
  try{
    body.style.width=body.getBoundingClientRect().width+'px';
    card.classList.add('morphing');active=true;
    var shell=card.animate([{width:previous.w+'px',height:previous.h+'px'},
      {width:width+'px',height:height+'px'}],{duration:250,easing:'cubic-bezier(.2,0,0,1)'});
    animations.push(shell);
    shell.onfinish=settle;shell.oncancel=settle;
    Array.prototype.forEach.call(body.children,function(child){
      if(!child.classList.contains('brand')){
        var fade=child.animate([{opacity:0},{opacity:1}],
          {duration:180,delay:70,easing:'cubic-bezier(0,0,.2,1)',fill:'backwards'});
        animations.push(fade);fade.oncancel=settle;
      }
    });
  }catch(_){settle();}
})();`;
