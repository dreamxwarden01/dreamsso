import test from 'node:test';
import assert from 'node:assert/strict';
import { createAuthCardMotion } from '../account/client/src/components/authCardMotion.js';

type Box={left:number;top:number;width:number;height:number};
class Events {
  listeners=new Map<string,Set<Function>>();
  addEventListener(type:string,callback:Function){if(!this.listeners.has(type))this.listeners.set(type,new Set());this.listeners.get(type)!.add(callback);}
  removeEventListener(type:string,callback:Function){this.listeners.get(type)?.delete(callback);}
  emit(type:string){for(const callback of [...this.listeners.get(type)??[]])callback();}
  count(){return [...this.listeners.values()].reduce((sum,set)=>sum+set.size,0);}
}
function fixture(){
  let clock=0,resolveFonts!:()=>void;
  const windowEvents=new Events(),visualEvents=new Events(),mediaEvents=new Events(),documentEvents=new Events(),fontEvents=new Events();
  const allAnimations:any[]=[],observers:any[]=[];
  const identity=[1,0,0,1,0,0];
  class Node {
    style={width:'',height:''};box:Box={left:0,top:0,width:400,height:400};paint=identity.slice();opacity=1;
    rejectAnimation=false;
    constructor(readonly name:string){}
    getBoundingClientRect(){
      return {...this.box,left:this.box.left+this.paint[4]!,top:this.box.top+this.paint[5]!,
        width:this.box.width*this.paint[0]!,height:this.box.height*this.paint[3]!};
    }
    animate(frames:any[],timing:any){
      if(this.rejectAnimation)throw Error('Synthetic animation assignment failure');
      const node=this;
      const animation={node,frames,timing,onfinish:null as Function|null,oncancel:null as Function|null,cancelled:false,
        cancel(){this.cancelled=true;node.paint=identity.slice();node.opacity=1;this.oncancel?.();}};
      allAnimations.push(animation);return animation;
    }
  }
  const card=new Node('card'),surface=new Node('surface'),content=new Node('content'),main=new Node('main'),foot=new Node('foot'),cta=new Node('cta'),wrap=new Node('wrap');
  let hasCta=true;
  const elements=()=>({card,surface,content,main,foot,wrap,cta:hasCta?cta:null});
  const media=Object.assign(mediaEvents,{matches:false});
  const visual=Object.assign(visualEvents,{width:800,height:800,scale:1,offsetLeft:0,offsetTop:0});
  const fonts=Object.assign(fontEvents,{ready:new Promise<void>(resolve=>{resolveFonts=resolve;})});
  const document=Object.assign(documentEvents,{visibilityState:'visible',fonts});
  class Observer {
    disconnected=false;targets:any[]=[];
    constructor(readonly callback:()=>void){observers.push(this);}
    observe(target:any){assert.ok(target===content||target===wrap);this.targets.push(target);}
    disconnect(){this.disconnected=true;}
    deliver(){this.callback();} // A queued delivery may run after disconnect.
  }
  const win=Object.assign(windowEvents,{innerWidth:800,innerHeight:800,scrollX:0,scrollY:0,
    visualViewport:visual,document,matchMedia:(query:string)=>{assert.equal(query,'(prefers-reduced-motion: reduce)');return media;},
    ResizeObserver:Observer,performance:{now:()=>clock},
    getComputedStyle:(node:Node)=>({transform:node.paint.every((v,i)=>v===identity[i])?'none':`matrix(${node.paint.join(',')})`,opacity:String(node.opacity)}),
  });
  function layout(height:number,withCta=hasCta){
    hasCta=withCta;const total=height+(hasCta?80:0)+36,top=(win.innerHeight-total)/2;
    card.box={left:200,top,width:400,height};surface.box={...card.box};
    content.box={left:201,top:top+1,width:398,height:height-2};main.box={left:235,top:top+80,width:330,height:height-120};
    cta.box={left:200,top:top+height+16,width:400,height:64};
    foot.box={left:200,top:top+height+(hasCta?80:0)+18,width:400,height:18};
    wrap.box={left:200,top,width:400,height:total};
  }
  layout(400);
  const create=()=>createAuthCardMotion(elements,win);
  const controller=create();
  const latest=(node:Node)=>allAnimations.filter(a=>a.node===node&&!a.cancelled).at(-1);
  const active=()=>allAnimations.filter(a=>!a.cancelled);
  return {controller,create,win,media,visual,document,fonts,resolveFonts,observers,allAnimations,
    card,surface,content,main,foot,cta,wrap,layout,latest,active,
    clock:(value:number)=>{clock=value;},
    resize:()=>observers.filter(observer=>!observer.disconnected).forEach(observer=>observer.deliver()),
    listenerCount:()=>[windowEvents,visualEvents,mediaEvents,documentEvents,fontEvents].reduce((sum,events)=>sum+events.count(),0),
    clean:()=>{assert.equal(active().length,0);assert.deepEqual(surface.style,{width:'',height:''});},
  };
}
const near=(actual:number,expected:number)=>assert.ok(Math.abs(actual-expected)<1e-8,`${actual} != ${expected}`);
function transform(value:string){
  const match=/^translate\(([-\d.]+)px,([-\d.]+)px\)(?: scale\(([^,]+),([^\)]+)\))?$/.exec(value);
  assert.ok(match,`Unexpected keyframe transform ${value}`);
  return{x:Number(match[1]),y:Number(match[2]),sx:match[3]===undefined?1:Number(match[3]),sy:match[4]===undefined?1:Number(match[4])};
}

test('initial/unchanged measurements are quiet; idle intrinsic changes animate one bounded frame morph without fading the live form',()=>{
  const f=fixture();try{
    f.controller.update('form');f.controller.update('form');f.resize();assert.equal(f.allAnimations.length,0);f.clean();
    f.layout(410);f.resize();
    assert.equal(f.latest(f.surface).timing.duration,250);
    assert.equal(f.latest(f.main).frames[0].opacity,1);assert.equal(f.latest(f.main).frames[1].opacity,1);
    assert.equal(f.latest(f.main).timing.delay,undefined);
    // Intermediate grid/error/font sizes retarget the same250ms deadline.
    for(const [time,height]of [[40,425],[80,440],[140,420],[220,400]]){
      f.clock(time);f.layout(height);f.resize();
      assert.equal(time+f.latest(f.surface).timing.duration,250);
      assert.equal(f.latest(f.main).frames[0].opacity,1);
    }
    f.clock(245);f.layout(430);f.resize();f.clean();
    const count=f.allAnimations.length;f.resize();f.controller.update('form');assert.equal(f.allAnimations.length,count);
    // A later structural phase starts from the most recently settled natural size.
    const before=f.card.box;f.layout(500);f.controller.update('challenge');
    const first=transform(f.latest(f.surface).frames[0].transform);near(first.sy,before.height/500);
    assert.equal(f.latest(f.surface).timing.duration,250);
  }finally{f.controller.destroy();}
});

test('structural growth accounts for centered card position and a removed CTA without scaling live content',()=>{
  const f=fixture();try{
    f.controller.update('form');const oldCard={...f.card.box},oldContent={...f.content.box},oldFoot={...f.foot.box};
    f.layout(600,false);f.controller.update('sent');
    const frame=f.latest(f.surface),start=transform(frame.frames[0].transform);
    assert.equal(frame.timing.duration,250);assert.equal(frame.timing.easing,'cubic-bezier(.2,0,0,1)');
    near(f.card.box.top+start.y,oldCard.top);near(f.card.box.left+start.x,oldCard.left);
    near(f.card.box.height*start.sy,oldCard.height);near(f.card.box.width*start.sx,oldCard.width);
    const live=transform(f.latest(f.content).frames[0].transform);
    near(f.content.box.top+live.y,oldContent.top);assert.equal(live.sx,1);assert.equal(live.sy,1);
    assert.match(f.latest(f.content).frames[0].clipPath,/^inset\(/);
    near(f.foot.box.top+transform(f.latest(f.foot).frames[0].transform).y,oldFoot.top);
    assert.equal(f.allAnimations.some(a=>a.node===f.cta),false);
    assert.equal(f.surface.style.height,'600px');
    const fade=f.latest(f.main);assert.equal(fade.timing.duration,180);assert.equal(fade.timing.delay,70);
    frame.onfinish();f.clean();
    const tallTop=f.card.box.top;f.layout(300,false);f.controller.update('compact-result');
    const shrink=f.latest(f.surface),shrinkStart=transform(shrink.frames[0].transform);
    near(shrinkStart.sy,2);near(f.card.box.top+shrinkStart.y,tallTop);
    shrink.onfinish();f.clean();
  }finally{f.controller.destroy();}
});

test('rapid structural retarget starts at the currently painted intermediate frame and fences old completion',()=>{
  const f=fixture();try{
    f.controller.update('form');f.layout(600,false);f.controller.update('challenge');
    const stale=f.latest(f.surface).onfinish;
    // The natural target is600px, but the white surface currently paints480px.
    f.surface.paint=[1,0,0,.8,0,30];f.content.paint=[1,0,0,1,0,30];f.foot.paint=[1,0,0,1,0,-30];
    const painted={top:f.card.box.top+30,height:480,contentTop:f.content.box.top+30};
    f.clock(90);f.layout(500,false);f.controller.update('invalid');
    const frame=f.latest(f.surface),start=transform(frame.frames[0].transform);
    near(f.card.box.top+start.y,painted.top);near(f.card.box.height*start.sy,painted.height);
    near(f.content.box.top+transform(f.latest(f.content).frames[0].transform).y,painted.contentTop);
    assert.equal(frame.timing.duration,250,'a fresh structural phase owns its own deadline');
    stale();assert.ok(f.active().includes(frame));assert.equal(f.surface.style.height,'500px');
    frame.onfinish();f.clean();
  }finally{f.controller.destroy();}
});

test('late font/intrinsic resize retargets within the original deadline instead of extending the morph',async()=>{
  const f=fixture();try{
    f.controller.update('loading');f.layout(600,false);f.controller.update('form');
    f.surface.paint=[1,0,0,.8,0,20];f.content.paint=[1,0,0,1,0,20];f.main.opacity=.4;
    f.clock(100);f.layout(620,false);f.fonts.emit('loadingdone');
    assert.equal(f.latest(f.surface).timing.duration,150);assert.equal(f.latest(f.main).frames[0].opacity,.4);
    assert.equal(f.latest(f.main).timing.delay,undefined);
    f.clock(220);f.layout(640,false);f.resize();assert.equal(f.latest(f.surface).timing.duration,30);
    f.clock(245);f.layout(650,false);f.resize();f.clean();
    // Resolving fonts later cannot restart a completed deadline or create a new phase.
    const count=f.allAnimations.length;f.resolveFonts();await Promise.resolve();assert.equal(f.allAnimations.length,count);
  }finally{f.controller.destroy();}
});

test('reduced motion and genuine viewport/keyboard/scroll changes settle immediately; unchanged resize does not',()=>{
  for(const event of ['reduced','window','keyboard','zoom','scroll','visual-pan','hidden','pagehide','pageshow']){
    const f=fixture();try{
      f.controller.update('form');f.layout(600);f.controller.update('challenge');const frame=f.latest(f.surface);
      f.win.emit('resize');assert.ok(f.active().includes(frame),'unchanged resize must not cancel');
      if(event==='reduced'){f.media.matches=true;f.media.emit('change');}
      if(event==='window'){f.win.innerWidth=700;f.win.emit('resize');}
      if(event==='keyboard'){f.visual.height=450;f.visual.emit('resize');}
      if(event==='zoom'){f.visual.scale=1.2;f.visual.emit('resize');}
      if(event==='scroll'){f.win.scrollY=24;f.win.emit('scroll');}
      if(event==='visual-pan'){f.visual.offsetTop=24;f.visual.emit('scroll');}
      if(event==='hidden'){f.document.visibilityState='hidden';f.document.emit('visibilitychange');}
      if(event==='pagehide'||event==='pageshow')f.win.emit(event);
      f.clean();
    }finally{f.controller.destroy();}
  }
  const f=fixture();try{f.media.matches=true;f.controller.update('loading');f.layout(600);f.controller.update('form');assert.equal(f.allAnimations.length,0);f.clean();}finally{f.controller.destroy();}
});

test('cancellation and partial animation assignment failure restore natural sizing',()=>{
  const f=fixture();try{
    f.controller.update('form');f.layout(600);f.controller.update('challenge');
    f.latest(f.surface).cancel();f.clean();
    f.content.rejectAnimation=true;f.layout(500);f.controller.update('invalid');f.clean();
  }finally{f.controller.destroy();}
});

test('destroy/StrictMode-style setup cleanup removes observers/listeners and rejects queued old deliveries',async()=>{
  const f=fixture(),initialListeners=f.listenerCount();assert.ok(initialListeners>0);f.controller.update('form');f.layout(600);f.controller.update('challenge');
  const stale=f.latest(f.surface).onfinish,observer=f.observers[0];
  f.controller.destroy();f.clean();assert.equal(f.listenerCount(),0);assert.equal(observer.disconnected,true);
  const count=f.allAnimations.length;f.layout(550);observer.deliver();stale();f.controller.update('late');
  f.resolveFonts();await Promise.resolve();assert.equal(f.allAnimations.length,count);f.clean();
  const second=f.create();try{
    second.update('form');assert.equal(f.allAnimations.length,count,'StrictMode replay starts with a fresh natural baseline');
    assert.equal(f.listenerCount(),initialListeners,'StrictMode replay adds exactly one set of listeners');assert.equal(f.observers.filter(o=>!o.disconnected).length,1);
    f.layout(650);second.update('challenge');const current=f.latest(f.surface);stale();assert.ok(f.active().includes(current));
  }finally{second.destroy();}
  f.clean();assert.equal(f.listenerCount(),0);assert.equal(f.observers.every(o=>o.disconnected),true);
});
