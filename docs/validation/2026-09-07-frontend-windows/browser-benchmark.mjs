import fs from 'node:fs/promises';
import path from 'node:path';
import http from 'node:http';
import os from 'node:os';
import {chromium} from '/Users/pielongo/Sviluppo/la-via-del-gusto/front/node_modules/.pnpm/playwright-core@1.62.1/node_modules/playwright-core/index.mjs';
const scratch='/private/tmp/lexflow-validation-2026-09-07/frontend-windows';
const executablePath=path.join(os.homedir(),'Library/Caches/ms-playwright/chromium_headless_shell-1234/chrome-headless-shell-mac-arm64/chrome-headless-shell');
const server=http.createServer(async(req,res)=>{try{const url=new URL(req.url,'http://localhost');const name=url.pathname==='/'?'index.html':url.pathname.slice(1);const file=path.resolve(scratch,'dist',name);if(!file.startsWith(path.join(scratch,'dist')+path.sep))throw Error('invalid path');const body=await fs.readFile(file);res.writeHead(200,{'Content-Type':file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'text/html'});res.end(body)}catch{res.writeHead(404);res.end()}});
await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve)});
const url='http://127.0.0.1:'+server.address().port;
let browser;const results=[];
const rowCount=()=>[...document.querySelectorAll('button')].filter(b=>b.textContent.includes('Materia')&&b.textContent.includes('Riferimento')).length;
try{
 browser=await chromium.launch({executablePath,headless:true,args:['--disable-background-networking']});
 const report={environment:{platform:os.platform(),arch:os.arch(),cpu:os.cpus()[0]?.model,cpuCount:os.cpus().length,ramBytes:os.totalmem(),node:process.version,browser:browser.version(),playwright:'1.62.1'},method:'Production-mode isolated component harness; synthetic records; IPC mocked; mount-to-two-animation-frames excludes dataset generation and module loading; search includes 200ms debounce.',results};
 for(const profile of [{name:'desktop',viewport:{width:1440,height:1000},cpu:1},{name:'mobile-simulated',viewport:{width:360,height:800},cpu:4}])for(const pageName of ['practices','contacts'])for(const count of [1000,10000,50000])for(let run=0;run<3;run++){
  const context=await browser.newContext({viewport:profile.viewport});
  const blocked=[];await context.route('**/*',route=>route.request().url().startsWith(url)?route.continue():(blocked.push(route.request().url()),route.abort()));
  const page=await context.newPage();page.setDefaultTimeout(20000);
  const pageErrors=[];page.on('pageerror',e=>pageErrors.push(String(e)));
  const cdp=await context.newCDPSession(page);await cdp.send('Emulation.setCPUThrottlingRate',{rate:profile.cpu});
  const row={profile:profile.name,cpuSlowdown:profile.cpu,page:pageName,records:count,run:run+1};
  try{
   await page.goto(url);await page.waitForFunction(()=>window.ready);await page.evaluate(n=>window.prepare(n),count);
   await page.evaluate(name=>{window.__start=performance.now();window.mount(name)},pageName);
   if(pageName==='practices')await page.waitForFunction(()=>document.querySelectorAll('button').length>40);
   else await page.locator('button[aria-label^="Apri dettaglio"]').first().waitFor();
   Object.assign(row,await page.evaluate(async()=>{await new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r)));return {mountMs:performance.now()-window.__start,domNodes:document.querySelectorAll('*').length,heapBytes:performance.memory?.usedJSHeapSize,horizontalOverflowPx:Math.max(0,document.documentElement.scrollWidth-innerWidth)}}));
   row.styles=await page.evaluate(()=>({headingPx:parseFloat(getComputedStyle(document.querySelector('h1')).fontSize),grid:document.querySelector('.grid')?getComputedStyle(document.querySelector('.grid')).display:null}));
   if(pageName==='practices'&&(row.styles.headingPx<(profile.cpu===1?32:24)||row.styles.grid!=='grid'))throw Error('Harness CSS missing production utilities');
   row.initialRows=pageName==='practices'?await page.evaluate(rowCount):await page.locator('button[aria-label^="Apri dettaglio"]').count();
   if(pageName==='practices'&&row.initialRows!==50)throw Error('Initial practices not capped at50');
   if(pageName==='contacts'&&row.initialRows>30)throw Error('Contacts initial virtualization did not bound rows');
   if(run===0&&count===10000){await page.waitForTimeout(450);await page.screenshot({path:path.join(scratch,profile.name+'-'+pageName+'.png')});}
   const search=pageName==='practices'?page.getByLabel('Cerca fascicoli'):page.locator('input[placeholder^="Cerca per nome"]');
   await page.evaluate(()=>window.__searchStart=performance.now());await search.fill('niccolo ultimo');
   if(pageName==='practices'){
    await page.waitForFunction(()=>[...document.querySelectorAll('button')].filter(b=>b.textContent.includes('Materia')&&b.textContent.includes('Riferimento')).length===1&&document.body.textContent.includes('Niccolò Ultimo'));
   }else await page.waitForFunction(()=>document.querySelectorAll('button[aria-label^="Apri dettaglio"]').length===1&&document.body.textContent.includes('ZZZ Niccolò Ultimo'));
   row.searchMs=await page.evaluate(async()=>{await new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r)));return performance.now()-window.__searchStart});
   if(pageName==='practices'){await page.getByRole('button',{name:/Niccolò Ultimo/}).click();row.selectedCorrect=await page.evaluate(n=>window.__bench.selected==='synthetic-'+(n-1),count);if(!row.selectedCorrect)throw Error('Wrong selected record')}
   row.searchFoundLastRecord=true;
   await search.fill('');
   if(pageName==='practices')await page.waitForFunction(()=>[...document.querySelectorAll('button')].filter(b=>b.textContent.includes('Materia')&&b.textContent.includes('Riferimento')).length===50);
   else await page.waitForFunction(()=>document.querySelectorAll('button[aria-label^="Apri dettaglio"]').length>1);
   if(pageName==='practices'){await page.getByRole('button',{name:'Mostra altri 50'}).click();row.rowsAfterLoadMore=await page.evaluate(rowCount);if(row.rowsAfterLoadMore!==100)throw Error('Pagination did not render100')}
   row.longTasks=await page.evaluate(()=>window.__bench.longTasks);row.errors=pageErrors.concat(await page.evaluate(()=>window.__bench.errors));row.blockedExternalRequests=blocked;
   row.status=row.errors.length?'error':'passed';
  }catch(error){row.status='failed';row.error=String(error)}
  results.push(row);await fs.writeFile(path.join(scratch,'browser-results.json'),JSON.stringify(report,null,2)+'\n');
  console.log(JSON.stringify({profile:row.profile,page:pageName,n:count,run:run+1,status:row.status,mount:row.mountMs,search:row.searchMs,rows:row.initialRows,error:row.error}));
  await context.close();
 }
 // Open a detail in the actual virtualizer and measure mounted rows, focus and latency.
 for(const caseConfig of [{n:1000,cpu:1},{n:10000,cpu:1},{n:10000,cpu:4},{n:50000,cpu:4}]){const {n,cpu}=caseConfig;
  const context=await browser.newContext({viewport:{width:1440,height:1000}});const page=await context.newPage();page.setDefaultTimeout(20000);
  await page.goto(url);await page.waitForFunction(()=>window.ready);await page.evaluate(n=>{window.prepare(n);window.mount('contacts')},n);await page.locator('button[aria-label^="Apri dettaglio"]').first().waitFor();
  const cdp=await context.newCDPSession(page);await cdp.send('Emulation.setCPUThrottlingRate',{rate:cpu});
  const row={profile:cpu===1?'desktop':'desktop-cpu4x',page:'contacts-expansion',records:n,cpuSlowdown:cpu};
  try{await page.locator('button[aria-label^="Apri dettaglio"]').first().focus();await page.evaluate(()=>{window.__expandedStart=performance.now();document.querySelector('button[aria-label^="Apri dettaglio"]').click()});await page.getByRole('dialog').waitFor();Object.assign(row,await page.evaluate(async()=>{await new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r)));return {expandMs:performance.now()-window.__expandedStart,renderedContactRows:document.querySelectorAll('button[aria-label^="Apri dettaglio"]').length,domNodes:document.querySelectorAll('*').length,heapBytes:performance.memory?.usedJSHeapSize}}));if(row.renderedContactRows>30)throw Error('Opening detail mounted entire archive');row.focusInDialog=await page.evaluate(()=>document.activeElement?.matches('dialog'));if(n===10000&&cpu===1)await page.screenshot({path:path.join(scratch,'desktop-contact-detail-after.png')});await page.keyboard.press('Escape');row.focusRestored=await page.evaluate(()=>document.activeElement?.getAttribute('aria-label')?.startsWith('Apri dettaglio'));if(!row.focusInDialog||!row.focusRestored)throw Error('Detail focus broken');row.status='measured'}catch(error){row.status='failed';row.error=String(error)}
  results.push(row);console.log(JSON.stringify(row));await fs.writeFile(path.join(scratch,'browser-results.json'),JSON.stringify(report,null,2)+'\n');await context.close();
 }
}finally{if(browser)await browser.close();await new Promise(r=>server.close(r))}
