import React from 'react';
import {createRoot} from 'react-dom/client';
import PracticesList from "/Users/pielongo/Library/Mobile Documents/com~apple~CloudDocs/Scrivania/sviluppo applicazioni/LexFlow/client/src/pages/PracticesList.jsx";
import ContactsPage from "/Users/pielongo/Library/Mobile Documents/com~apple~CloudDocs/Scrivania/sviluppo applicazioni/LexFlow/client/src/pages/ContactsPage.jsx";
import ReportPage from "/Users/pielongo/Library/Mobile Documents/com~apple~CloudDocs/Scrivania/sviluppo applicazioni/LexFlow/client/src/pages/ReportPage.jsx";
import LoginScreen from "/Users/pielongo/Library/Mobile Documents/com~apple~CloudDocs/Scrivania/sviluppo applicazioni/LexFlow/client/src/components/LoginScreen.jsx";
import './harness.css';
const root=createRoot(document.getElementById('root'));
window.__bench={errors:[],invokes:[],longTasks:[],selected:null};
window.addEventListener('error', e=>window.__bench.errors.push(e.message));
window.addEventListener('unhandledrejection', e=>window.__bench.errors.push(String(e.reason)));
new PerformanceObserver(list=>window.__bench.longTasks.push(...list.getEntries().map(e=>({start:e.startTime,duration:e.duration})))).observe({type:'longtask',buffered:true});
window.__TAURI_INTERNALS__={invoke:async(command,args)=>{
 window.__bench.invokes.push(command);
 if(command==='vault_exists')return false;
 if(command==='check_bio')return false;
 if(command==='load_contacts')return window.__contacts;
 if(command==='load_time_logs')return [];
 if(command==='get_audit_log')return [];
 throw Error('Unexpected native command in synthetic harness: '+command);
}};
window.prepare=(n)=>{
 window.__practices=Array.from({length:n},(_,i)=>({id:'synthetic-'+i,client:i===n-1?'Niccolò Ultimo':('Cliente sintetico '+String(i).padStart(6,'0')),object:'Contratto sintetico '+i,code:'SYN-'+i,type:i%2?'civile':'penale',status:i%3?'active':'closed',clientId:'contact-'+i}));
 window.__contacts=Array.from({length:n},(_,i)=>({id:'contact-'+i,name:i===n-1?'ZZZ Niccolò Ultimo':('Cliente sintetico '+String(i).padStart(6,'0')),email:'sintetico'+i+'@example.invalid',type:'client',phone:'+390000000000',fiscalCode:'SYNTHETIC'+i}));
};
window.mount=(page)=>{
 window.__bench.longTasks=[];window.__bench.errors=[];window.__bench.selected=null;
 const props={practices:window.__practices,onSelect:id=>window.__bench.selected=id,onSelectPractice:id=>window.__bench.selected=id};
 const Page=page==='login'?LoginScreen:page==='contacts'?ContactsPage:page==='report'?ReportPage:PracticesList;
 root.render(<div style={{padding:24,maxWidth:1400,margin:'auto'}}><Page {...props}/></div>);
};
window.ready=true;
