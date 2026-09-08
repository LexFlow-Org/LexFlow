/** Reproducible visual regression for the real Toggle + SettingsPage and production CSS.
 * Native IPC uses explicit synthetic responses; no vault, licence registry or keychain is read.
 * Set LEXFLOW_PLAYWRIGHT_MODULE, LEXFLOW_CHROMIUM_EXECUTABLE and LEXFLOW_TOGGLE_DIR.
 * Optional LEXFLOW_TOGGLE_BEFORE points to a saved pre-fix Toggle.jsx for comparison.
 */
import fs from 'node:fs/promises';
import path from 'node:path';
import http from 'node:http';
import os from 'node:os';
import crypto from 'node:crypto';
import { pathToFileURL } from 'node:url';
const project = process.cwd();
const scratch = process.env.LEXFLOW_TOGGLE_DIR;
if (!scratch || !path.isAbsolute(scratch)) throw Error('LEXFLOW_TOGGLE_DIR must be absolute');
await fs.mkdir(scratch, { recursive: true });
const before = process.env.LEXFLOW_TOGGLE_BEFORE;
const { build } = await import(pathToFileURL(path.join(project, 'client/node_modules/vite/dist/node/index.js')));
const { chromium } = await import(pathToFileURL(process.env.LEXFLOW_PLAYWRIGHT_MODULE));
await fs.writeFile(path.join(scratch, 'index.html'), '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head><body><div id="root"></div><script type="module" src="/harness.jsx"></script></body></html>');
await fs.writeFile(path.join(scratch, 'harness.css'), `@import ${JSON.stringify(path.join(project,'client/src/index.css'))};\n@source ${JSON.stringify(path.join(project,'client/src'))};\n${before ? `@source ${JSON.stringify(before)};` : ''}\n`);
await fs.writeFile(path.join(scratch, 'harness.jsx'), `import React,{useState} from 'react';
import {createRoot} from 'react-dom/client';
import Toggle from ${JSON.stringify(path.join(project, 'client/src/components/Toggle.jsx'))};
${before ? `import Before from ${JSON.stringify(before)};` : 'const Before=Toggle;'}
import './harness.css';
window.__test={changes:[],invokes:[],errors:[]};
window.addEventListener('error',e=>window.__test.errors.push(e.message));
window.addEventListener('unhandledrejection',e=>window.__test.errors.push(String(e.reason)));
window.__TAURI_INTERNALS__={transformCallback:()=>1,unregisterCallback:()=>{},invoke:async(command,args)=>{
 window.__test.invokes.push({command,args});
 switch(command){
 case 'get_settings': return {privacyBlurEnabled:true,screenshotProtection:true,notifyEnabled:true,autolockMinutes:5,preavviso:30};
 case 'get_app_version':return '1.0.1';case 'get_platform':return 'macos';
 case 'check_bio':return true;case 'has_bio_saved':return false;
 case 'check_bio_status':return {available:false,reason:'build_not_authorized',deviceReady:true,appAuthorized:false};
 case 'get_vault_health':return null;case 'check_license':return {activated:false};
 case 'save_settings':case 'set_content_protection':return {success:true};
 case 'plugin:event|listen':return 1;case 'plugin:event|unlisten':return null;
 default:throw Error('Unexpected IPC: '+command);
 }
}};
const {default:SettingsPage}=await import(${JSON.stringify(path.join(project,'client/src/pages/SettingsPage.jsx'))});
const root=createRoot(document.getElementById('root'));
function Control({Component,name}){const [checked,setChecked]=useState(false);return <section data-case={name} className="glass-card" style={{padding:20,marginBottom:20}}><h2>{name==='before'?'Versione precedente':'Interruttore corretto'}</h2><Component checked={checked} onChange={value=>{window.__test.changes.push({name,value});setChecked(value)}} label={name==='before'?'Prima':'Privacy Blur'} description="Controllo dell’aspetto e accessibilità"/></section>}
window.mount=mode=>{window.__test.changes=[];root.render(mode==='settings'?<main style={{padding:16,maxWidth:1100,margin:'auto'}}><SettingsPage onLock={()=>{}}/></main>:<main style={{padding:20,maxWidth:580,margin:'auto'}}><h1>LexFlow · collaudo interruttori</h1>${before?'<Control Component={Before} name="before"/>':''}<Control Component={Toggle} name="after"/></main>)};
window.ready=true;
`);
await build({configFile:path.join(project,'client/vite.config.js'),root:scratch,resolve:{alias:{react:path.join(project,'client/node_modules/react'),'react-dom':path.join(project,'client/node_modules/react-dom'),'prop-types':path.join(project,'client/node_modules/prop-types')}},build:{outDir:path.join(scratch,'dist'),emptyOutDir:true,rollupOptions:{input:path.join(scratch,'index.html'),output:{manualChunks:()=>undefined}}}});
const server=http.createServer(async(req,res)=>{try{const url=new URL(req.url,'http://localhost');const file=path.resolve(scratch,'dist',url.pathname==='/'?'index.html':url.pathname.slice(1));if(!file.startsWith(path.join(scratch,'dist')+path.sep))throw Error('Invalid path');const body=await fs.readFile(file);res.writeHead(200,{'Content-Type':file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'text/html'});res.end(body)}catch{res.writeHead(404);res.end()}});
await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve)});
const origin='http://127.0.0.1:'+server.address().port;
let browser;
const report={date:new Date().toISOString(),environment:{platform:os.platform(),arch:os.arch(),node:process.version},method:'Real production CSS and Toggle/SettingsPage. Explicit synthetic IPC. Chromium viewport/font scaling/CSS zoom simulation; no native WebKit or mobile hardware claims.',geometry:[],interactions:[],settings:[],blockedRequests:[],errors:[]};
const hash=async file=>crypto.createHash('sha256').update(await fs.readFile(file)).digest('hex');
report.sources={};for(const relative of ['client/src/components/Toggle.jsx','client/src/index.css','client/src/pages/SettingsPage.jsx'])report.sources[relative]=await hash(path.join(project,relative));
if(before)report.beforeSha256=await hash(before);
const geometry=async locator=>locator.evaluate(button=>{const rect=el=>{const r=el.getBoundingClientRect();return {x:r.x,y:r.y,width:r.width,height:r.height,right:r.right,bottom:r.bottom}};const track=button.firstElementChild;const thumb=track.firstElementChild;const b=rect(button),t=rect(track),c=rect(thumb);return {button:b,track:t,thumb:c,insets:{left:c.x-t.x,right:t.right-c.right,top:c.y-t.y,bottom:t.bottom-c.bottom},name:button.getAttribute('aria-label')||document.getElementById(button.getAttribute('aria-labelledby'))?.textContent,checked:button.getAttribute('aria-checked')==='true'};});
const good=g=>Math.min(...Object.values(g.insets))>=-0.02 && g.button.width>=43.99 && g.button.height>=43.99;
async function contextFor(width,theme,font,zoom){const context=await browser.newContext({viewport:{width,height:1100},colorScheme:theme,reducedMotion:'reduce'});await context.route('**/*',route=>route.request().url().startsWith(origin+'/')?route.continue():(report.blockedRequests.push(route.request().url()),route.abort()));const page=await context.newPage();page.on('pageerror',error=>report.errors.push(String(error)));await page.goto(origin);await page.waitForFunction(()=>window.ready);await page.evaluate(({theme,font,zoom})=>{document.documentElement.dataset.theme=theme;document.documentElement.style.fontSize=font+'px';document.documentElement.style.zoom=String(zoom)}, {theme,font,zoom});return {context,page};}
try{
 browser=await chromium.launch({executablePath:process.env.LEXFLOW_CHROMIUM_EXECUTABLE,headless:true,args:['--disable-background-networking']});report.environment.browser=browser.version();
 for(const width of [360,768,1440])for(const theme of ['dark','light'])for(const font of [16,20])for(const zoom of [1,1.25]){
  const {context,page}=await contextFor(width,theme,font,zoom);await page.evaluate(()=>window.mount('toggles'));await page.locator('[data-case="after"] [role="switch"]').waitFor();
  for(const name of before?['before','after']:['after']){
   const toggle=page.locator('[data-case="'+name+'"] [role="switch"]');
   for(const checked of [false,true]){if(checked)await toggle.click();await page.waitForTimeout(30);const g=await geometry(toggle);report.geometry.push({width,theme,font,zoom,version:name,state:checked,...g,passed:good(g)});}
  }
  if(font===16&&zoom===1&&(width===360||width===1440))await page.screenshot({path:path.join(scratch,`toggles-${width}-${theme}.png`),fullPage:true});
  const toggle=page.locator('[data-case="after"] [role="switch"]');const row={width,theme,font,zoom,steps:[]};
  for(const action of ['click','Space','Enter','label']){const previous=await toggle.getAttribute('aria-checked');const count=await page.evaluate(()=>window.__test.changes.length);if(action==='click')await toggle.click();else if(action==='label')await page.locator('[data-case="after"] label').click();else {await toggle.focus();await page.keyboard.press(action);}await page.waitForTimeout(25);const changed=await toggle.getAttribute('aria-checked');const n=await page.evaluate(()=>window.__test.changes.length);row.steps.push({action,oneChange:n===count+1,valueToggled:previous!==changed});}
  await page.evaluate(()=>{document.activeElement?.blur();const b=document.createElement('button');b.id='focus-before-toggle';b.style.position='absolute';b.style.left='0';b.style.top='0';document.querySelector('[data-case="after"]').prepend(b);b.focus()});await page.keyboard.press('Tab');row.tabFocus=await toggle.evaluate(el=>document.activeElement===el);row.focusStyle=await toggle.evaluate(el=>({outline:getComputedStyle(el).outlineStyle,width:getComputedStyle(el).outlineWidth,shadow:getComputedStyle(el).boxShadow}));row.passed=row.tabFocus&&row.focusStyle.outline!=='none'&&parseFloat(row.focusStyle.width)*zoom>=1.99&&row.steps.every(s=>s.oneChange&&s.valueToggled);report.interactions.push(row);await context.close();
 }
 for(const width of [360,768,1440])for(const theme of ['dark','light'])for(const font of [16,20]){
  const {context,page}=await contextFor(width,theme,font,1);await page.evaluate(()=>window.mount('settings'));await page.getByRole('switch',{name:'Privacy Blur',exact:true}).waitFor();
  const row={width,theme,font,toggles:[]};
  for(const name of ['Privacy Blur','Blocco Screenshot','Avvisi Agenda e Scadenze']){const toggle=page.getByRole('switch',{name,exact:true});await toggle.scrollIntoViewIfNeeded();for(const checked of [true,false]){if(!checked)await toggle.click();await page.waitForTimeout(30);const g=await geometry(toggle);row.toggles.push({expectedName:name,expectedState:checked,...g,passed:good(g)&&g.name===name&&g.checked===checked});}}
  row.biometryDiagnostic=await page.getByText('Touch ID è rilevato su questo Mac.',{exact:false}).count()===1 && await page.getByText('firma Apple necessaria',{exact:false}).count()===1;
  row.horizontalOverflow=await page.evaluate(()=>Math.max(0,document.documentElement.scrollWidth-innerWidth));row.invokes=await page.evaluate(()=>window.__test.invokes.map(x=>x.command));row.errors=await page.evaluate(()=>window.__test.errors);row.passed=row.toggles.every(t=>t.passed)&&row.errors.length===0&&row.biometryDiagnostic&&row.horizontalOverflow===0;
  if(font===16&&(width===360||width===1440)){await page.getByRole('switch',{name:'Privacy Blur',exact:true}).scrollIntoViewIfNeeded();await page.screenshot({path:path.join(scratch,`settings-${width}-${theme}.png`)});}
  report.settings.push(row);await context.close();
 }
 report.summary={fixedGeometrySamples:report.geometry.filter(x=>x.version==='after').length,fixedGeometryFailed:report.geometry.filter(x=>x.version==='after'&&!x.passed).length,baselineOverflowSamples:report.geometry.filter(x=>x.version==='before'&&!x.passed).length,interactionProfiles:report.interactions.length,interactionFailed:report.interactions.filter(x=>!x.passed).length,settingsProfiles:report.settings.length,settingsFailed:report.settings.filter(x=>!x.passed).length,settingsGeometrySamples:report.settings.flatMap(x=>x.toggles).length,settingsOverflowProfiles:report.settings.filter(x=>x.horizontalOverflow>0).length};
 console.log(JSON.stringify(report.summary,null,2));
}finally{await fs.writeFile(path.join(scratch,'toggle-results.json'),JSON.stringify(report,null,2)+'\n');if(browser)await browser.close();await new Promise(resolve=>server.close(resolve));}
if(report.summary?.fixedGeometryFailed||report.summary?.interactionFailed||report.summary?.settingsFailed||report.errors.length)process.exitCode=1;
