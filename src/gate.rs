use serde::Deserialize;

#[derive(Debug, Deserialize, Default)]
pub struct WindowDims {
    #[serde(default)]
    pub ow: i32,
    #[serde(default)]
    pub oh: i32,
}

#[derive(Debug, Deserialize)]
pub struct ClientReport {
    #[serde(default)]
    pub webdriver: bool,
    #[serde(default)]
    pub webgl: bool,
    #[serde(default)]
    pub renderer: String,
    #[serde(default)]
    pub canvas2d: bool,
    #[serde(default)]
    pub raf_ok: bool,
    #[serde(default)]
    pub hardware_concurrency: u32,
    #[serde(default)]
    pub languages: u32,
    #[serde(default)]
    pub plugins: u32,
    #[serde(default)]
    pub touch: bool,
    #[serde(default)]
    pub window: WindowDims,
}

pub const DENY_THRESHOLD: i32 = 50;
const AT_OUTER_W: i32 = 1074;
const AT_OUTER_H: i32 = 968;

pub fn score(r: &ClientReport) -> (i32, Vec<&'static str>) {
    let mut s = 0i32;
    let mut reasons: Vec<&'static str> = Vec::new();

    if r.webdriver {
        s += 45;
        reasons.push("navigator.webdriver=true");
    }
    if !r.webgl {
        s += 50;
        reasons.push("no-webgl");
    } else {
        let rl = r.renderer.to_ascii_lowercase();
        let software = ["swiftshader", "llvmpipe", "softpipe", "mesa offscreen", "software"]
            .iter()
            .any(|m| rl.contains(m));
        if software {
            s += 50;
            reasons.push("software-renderer");
        }
        if r.renderer.trim().is_empty() {
            s += 10;
            reasons.push("empty-renderer");
        }
    }
    if r.window.ow == AT_OUTER_W && r.window.oh == AT_OUTER_H {
        s += 50;
        reasons.push("archive-today-window");
    }
    if !r.raf_ok {
        s += 30;
        reasons.push("no-raf");
    }
    if !r.canvas2d {
        s += 20;
        reasons.push("no-canvas2d");
    }
    if r.hardware_concurrency == 0 {
        s += 10;
        reasons.push("hc=0");
    }
    if r.languages == 0 {
        s += 10;
        reasons.push("no-languages");
    }
    if r.plugins == 0 && !r.touch {
        s += 5;
        reasons.push("no-plugins");
    }
    (s, reasons)
}

pub fn gate_shell(diag: bool) -> String {
    SHELL_TEMPLATE.replace("{{DIAG}}", if diag { "true" } else { "false" })
}

const SHELL_TEMPLATE: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<meta name="color-scheme" content="dark light">
<title></title>
<style>html,body{height:100%;margin:0;background:Canvas}</style>
</head>
<body>
<script>
(function () {
  var DIAG = {{DIAG}};

  function djb2(str){var h=5381;for(var i=0;i<str.length;i++){h=((h<<5)+h)+str.charCodeAt(i);h=h&0xffffffff;}return (h>>>0).toString(16);}
  function nativeFn(fn){try{return /\[native code\]/.test(Function.prototype.toString.call(fn));}catch(e){return null;}}

  function checkRaf(){return new Promise(function(resolve){
    if(typeof requestAnimationFrame!=="function")return resolve({ok:false,deltas:[]});
    var n=0,last=performance.now(),deltas=[],done=false;
    var t=setTimeout(function(){if(!done){done=true;resolve({ok:false,deltas:deltas});}},900);
    function tick(ts){n++;deltas.push(+(ts-last).toFixed(2));last=ts;
      if(n>=3){done=true;clearTimeout(t);resolve({ok:deltas[1]>0&&deltas[1]<400,deltas:deltas});}
      else requestAnimationFrame(tick);}
    requestAnimationFrame(tick);
  });}

  function canvasFP(){try{
    var c=document.createElement("canvas");c.width=240;c.height=60;
    var x=c.getContext("2d");if(!x)return {ok:false};
    x.textBaseline="top";x.font="14px 'Arial'";
    x.fillStyle="#f60";x.fillRect(125,1,62,20);
    x.fillStyle="#069";x.fillText("gate \u26A1 0123",2,15);
    x.fillStyle="rgba(102,204,0,0.7)";x.fillText("gate \u26A1 0123",4,17);
    return {ok:true,hash:djb2(c.toDataURL())};
  }catch(e){return {ok:false,err:String(e)};}}

  function webglInfo(){var o={supported:false};try{
    var c=document.createElement("canvas");
    var gl=c.getContext("webgl")||c.getContext("experimental-webgl");
    if(!gl)return o;o.supported=true;
    o.vendor=gl.getParameter(gl.VENDOR);o.renderer=gl.getParameter(gl.RENDERER);
    o.version=gl.getParameter(gl.VERSION);o.glsl=gl.getParameter(gl.SHADING_LANGUAGE_VERSION);
    var d=gl.getExtension("WEBGL_debug_renderer_info");
    if(d){o.unmasked_vendor=gl.getParameter(d.UNMASKED_VENDOR_WEBGL);
          o.unmasked_renderer=gl.getParameter(d.UNMASKED_RENDERER_WEBGL);}
    o.max_texture=gl.getParameter(gl.MAX_TEXTURE_SIZE);
    var ex=gl.getSupportedExtensions()||[];o.ext_count=ex.length;
  }catch(e){o.error=String(e);}return o;}

  function audioFP(){return new Promise(function(res){try{
    var C=window.OfflineAudioContext||window.webkitOfflineAudioContext;if(!C)return res("none");
    var ctx=new C(1,5000,44100);var osc=ctx.createOscillator();osc.type="triangle";osc.frequency.value=10000;
    var comp=ctx.createDynamicsCompressor();osc.connect(comp);comp.connect(ctx.destination);osc.start(0);
    var to=setTimeout(function(){res("timeout");},1500);
    ctx.oncomplete=function(e){clearTimeout(to);var d=e.renderedBuffer.getChannelData(0),s=0;
      for(var i=0;i<d.length;i++)s+=Math.abs(d[i]);res(djb2(String(s)));};
    ctx.startRendering();
  }catch(e){res("err:"+e);}});}

  function webrtcProbe(){return new Promise(function(res){var ips={};try{
    var P=window.RTCPeerConnection||window.webkitRTCPeerConnection;if(!P)return res({supported:false});
    var pc=new P({iceServers:[{urls:"stun:stun.l.google.com:19302"}]});
    pc.createDataChannel("x");
    pc.onicecandidate=function(e){if(!e.candidate)return;var cand=e.candidate.candidate||"";
      var m=/([0-9]{1,3}(?:\.[0-9]{1,3}){3})/.exec(cand);
      if(m){var t=/typ srflx/.test(cand)?"srflx(public)":(/typ host/.test(cand)?"host(local)":"other");ips[m[1]]=t;}};
    pc.createOffer().then(function(o){return pc.setLocalDescription(o);}).catch(function(){});
    setTimeout(function(){try{pc.close();}catch(e){}res({supported:true,ips:ips});},1800);
  }catch(e){res({error:String(e)});}});}

  function automationMarkers(){var m=[];var keys=["__nightmare","_phantom","callPhantom","__phantomas",
    "_selenium","__selenium_unwrapped","__webdriver_evaluate","__driver_evaluate","__fxdriver_evaluate",
    "domAutomation","domAutomationController","__webdriver_script_fn","__$webdriverAsyncExecutor",
    "webdriver","__puppeteer_evaluation_script__"];
    keys.forEach(function(k){try{if(k in window)m.push("win:"+k);}catch(e){}});
    try{for(var k in document)if(k.indexOf("cdc_")===0||k.indexOf("$cdc_")===0)m.push("doc:"+k);}catch(e){}
    try{for(var k2 in window)if(k2.indexOf("cdc_")===0)m.push("win:"+k2);}catch(e){}
    return m;}

  function baseReport(rafInfo){
    var n=navigator,s=screen;
    var r={webdriver:n.webdriver===true,webgl:false,renderer:"",canvas2d:false,
      raf_ok:!!(rafInfo&&rafInfo.ok),hardware_concurrency:n.hardwareConcurrency||0,
      languages:(n.languages||[]).length,plugins:(n.plugins||[]).length,
      touch:("ontouchstart" in window)||(n.maxTouchPoints||0)>0,
      ua:n.userAgent,platform:n.platform,vendor:n.vendor,app_version:n.appVersion,
      language:n.language,languages_list:(n.languages||[]).slice(0,10),
      device_memory:n.deviceMemory||null,max_touch:n.maxTouchPoints||0,
      pdf_viewer:n.pdfViewerEnabled,cookie_enabled:n.cookieEnabled,dnt:n.doNotTrack,
      plugin_names:[],mime_count:(n.mimeTypes||{}).length||0,window_chrome:!!window.chrome,
      raf_deltas:rafInfo?rafInfo.deltas:[],
      screen:{w:s.width,h:s.height,aw:s.availWidth,ah:s.availHeight,depth:s.colorDepth,
              px:s.pixelDepth,dpr:window.devicePixelRatio,orient:(s.orientation||{}).type||null},
      window:{iw:window.innerWidth,ih:window.innerHeight,ow:window.outerWidth,oh:window.outerHeight},
      tz:(Intl.DateTimeFormat().resolvedOptions()||{}).timeZone||null,
      locale:(Intl.DateTimeFormat().resolvedOptions()||{}).locale||null,
      perf_now:typeof performance!=="undefined"&&!!performance.now,
      perm_query_native:nativeFn(n.permissions&&n.permissions.query),
      tostring_native:nativeFn(Function.prototype.toString),
      automation:automationMarkers(),canvas_fp:canvasFP(),webgl_info:webglInfo(),
      speech_voices:((window.speechSynthesis&&speechSynthesis.getVoices())||[]).length};
    try{r.plugin_names=Array.prototype.slice.call(n.plugins||[]).map(function(p){return p.name;}).slice(0,12);}catch(e){}
    if(n.connection)r.connection={effectiveType:n.connection.effectiveType,rtt:n.connection.rtt,
      downlink:n.connection.downlink,saveData:n.connection.saveData};
    r.webgl=r.webgl_info.supported===true;
    r.renderer=String(r.webgl_info.unmasked_renderer||r.webgl_info.renderer||"");
    r.canvas2d=r.canvas_fp.ok===true;
    return r;
  }

  function withTimeout(p,ms,fb){return Promise.race([p,new Promise(function(res){setTimeout(function(){res(fb);},ms);})]);}
  function augment(r){return Promise.all([
    withTimeout(audioFP(),1800,"timeout"),
    withTimeout(webrtcProbe(),2000,{timeout:true}),
    (function(){try{return withTimeout(navigator.permissions.query({name:"notifications"}).then(function(p){return p.state;}),800,"err");}catch(e){return Promise.resolve("err");}})()
  ]).then(function(a){r.audio_fp=a[0];r.webrtc=a[1];r.notif_permission_state=a[2];
    r.notif_permission=(typeof Notification!=="undefined")?Notification.permission:null;
    r.notif_mismatch=(r.notif_permission==="denied"&&(a[2]==="prompt"||a[2]==="default"));return r;});}

  function deny(){
    try{console.error("Failed to load resource: the server responded with a status of 403 (Forbidden)");}catch(e){}
    var blank="<!doctype html><meta name=color-scheme content=\"dark light\"><title></title><style>html,body{height:100%;margin:0;background:Canvas}</style>";
    try{document.open();document.write(blank);document.close();}catch(e){
      try{document.documentElement.innerHTML="<head><title></title></head><body style=\"background:Canvas\"></body>";}catch(e2){}}
  }

  function run(){
    var proto=location.protocol==="https:"?"wss:":"ws:";
    var ws;try{ws=new WebSocket(proto+"//"+location.host+"/__gate_ws");}catch(e){return deny();}
    var settled=false;
    var guard=setTimeout(function(){if(!settled){settled=true;try{ws.close();}catch(e){}deny();}},DIAG?9000:6000);
    ws.onopen=function(){
      checkRaf().then(function(rafInfo){
        var r=baseReport(rafInfo);
        var ready=DIAG?augment(r):Promise.resolve(r);
        ready.then(function(full){try{ws.send(JSON.stringify(full));}catch(e){}});
      });
    };
    ws.onmessage=function(ev){if(settled)return;var msg;try{msg=JSON.parse(ev.data);}catch(e){return;}
      settled=true;clearTimeout(guard);
      if(msg&&msg.ok&&msg.token){
        document.cookie="__gate="+msg.token+"; max-age=7776000; path=/; samesite=lax";
        try{ws.close();}catch(e){}location.reload();
      }else{try{ws.close();}catch(e){}deny();}};
    ws.onerror=function(){if(!settled){settled=true;clearTimeout(guard);deny();}};
    ws.onclose=function(){if(!settled){settled=true;clearTimeout(guard);deny();}};
  }

  if(document.readyState==="loading")document.addEventListener("DOMContentLoaded",run);else run();
})();
</script>
</body>
</html>"##;