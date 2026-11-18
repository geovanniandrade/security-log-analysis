/* Security Log Analysis — Threat intelligence enrichment (browser only)
 * No log data is transmitted. NVD request occurs only on explicit CVE submission.
 * MITRE mappings are heuristic leads, not confirmed ATT&CK technique attribution.
 */
(() => {
"use strict";
const byId = id => document.getElementById(id);
const MITRE = [
 {id:"T1110",title:"Brute Force",pattern:/failed password|invalid user|multiple (?:ssh |login |authentication )?fail|brute[\s-]?force|event id 4625|failed logon/i,why:"Falhas repetidas de autenticação podem indicar tentativa de adivinhar credenciais."},
 {id:"T1046",title:"Network Service Discovery",pattern:/port[\s-]?scan|network scanning|port sweep|service discovery|nmap/i,why:"Atividade de varredura ou descoberta de portas pode indicar reconhecimento."},
 {id:"T1071",title:"Application Layer Protocol",pattern:/suspicious dns|dns tunneling|suspicious http|c2 over https|command[\s-]?and[\s-]?control via (?:http|dns)/i,why:"Comunicações suspeitas por protocolos de aplicação merecem análise adicional."},
 {id:"T1059",title:"Command and Scripting Interpreter",pattern:/suspicious powershell|powershell encodedcommand|encoded powershell|suspicious command execution/i,why:"Uso suspeito de interpretadores de comando pode indicar execução."},
 {id:"T1098",title:"Account Manipulation",pattern:/event id 4720|event id 4728|new user account created|user added to privileged group|account manipulation/i,why:"Criação ou alteração de contas pode exigir verificação de autorização."},
 {id:"T1078",title:"Valid Accounts",pattern:/suspicious successful login|compromised account login|unexpected privileged logon|login from unusual location/i,why:"Um login aparentemente anômalo com conta válida exige contexto e validação."}
];
const nistBase=[
 "Registrar a origem dos logs, janela de tempo, fuso horário, responsáveis e limitações da coleta.",
 "Preservar evidências originais e verificar integridade quando aplicável.",
 "Validar hipóteses com eventos anteriores/posteriores e fontes independentes.",
 "Separar atividade suspeita de comprometimento confirmado; documentar hipóteses alternativas.",
 "Definir medidas de contenção e recuperação somente com autorização e avaliação de impacto.",
 "Registrar decisões, recomendações e melhorias de monitoramento."
];
let currentFindings=[];
let lastCVE=null;
function txt(tag,value,cls){const e=document.createElement(tag);if(cls)e.className=cls;e.textContent=String(value);return e}
function link(url,title){const a=document.createElement("a");a.href=url;a.textContent=title;a.target="_blank";a.rel="noopener noreferrer";a.className="intel-link";return a}
function readEvents(){try{return typeof data!=="undefined"&&Array.isArray(data)?data:[]}catch{return []}}
function findings(){
 const events=readEvents();const matches=[];
 for(const technique of MITRE){
  let hits=0;const examples=[];
  for(const event of events){
   const message=String(event.event||"");
   // Match only event description: platform name alone must not trigger a technique.
   if(!technique.pattern.test(message))continue;
   hits++;
   if(examples.length<3)examples.push({time:String(event.time||"—"),source:String(event.source||"—"),message:message.slice(0,170)});
  }
  if(hits)matches.push({...technique,hits,examples});
 }
 return matches;
}
function renderMitre(){
 const root=byId("intel-attack-results");if(!root)return;
 root.replaceChildren();const ev=readEvents();
 if(!ev.length){root.append(txt("p","Nenhum evento carregado. Importe logs ou utilize a demonstração na aba Analisar logs.","muted"));currentFindings=[];renderNist();return}
 currentFindings=findings();
 root.append(txt("p",ev.length+" eventos da sessão examinados; "+currentFindings.length+" hipóteses de técnica sugeridas.","status"));
 if(!currentFindings.length){root.append(txt("p","Nenhuma regra local encontrou padrão compatível. Isso não significa que o ambiente está livre de ameaças.","muted"))}
 const grid=document.createElement("div");grid.className="intel-findings";
 for(const item of currentFindings){
  const article=document.createElement("article");
  article.append(txt("h3",item.id+" — "+item.title));
  article.append(txt("p",item.why+" Ocorrências correspondentes: "+item.hits+".","muted"));
  article.append(link("https://attack.mitre.org/techniques/"+item.id+"/","Ver técnica no MITRE ATT&CK ↗"));
  const title=txt("p","Exemplos de correspondência nos eventos (trechos locais):","status");article.append(title);
  for(const ex of item.examples){article.append(txt("div",ex.time+" · "+ex.source+" · "+ex.message,"intel-evidence"))}
  article.append(txt("p","Hipótese orientativa, não é detecção confirmada.","status"));grid.append(article);
 }
 root.append(grid);
 renderNist();
}
function renderNist(){
 const root=byId("intel-nist-guidance");if(!root)return;root.replaceChildren();
 const list=document.createElement("ol");list.className="intel-list";
 const items=[...nistBase];
 if(currentFindings.some(x=>x.id==="T1110"))items.push("Para falhas de autenticação, correlacionar IP, usuário, host e eventuais logons bem-sucedidos.");
 if(currentFindings.some(x=>x.id==="T1046"))items.push("Para varreduras, distinguir inventário autorizado de reconhecimento não autorizado.");
 if(currentFindings.some(x=>x.id==="T1098"))items.push("Para mudanças de contas, consultar trilhas administrativas e solicitações aprovadas.");
 for(const item of items){list.append(txt("li",item))}
 root.append(list);
}
function status(msg){const el=byId("intel-cve-status");if(el)el.textContent=msg}
function showCve(vuln){
 const root=byId("intel-cve-result");root.replaceChildren();
 const cve=vuln?.cve;if(!cve){status("A resposta não contém registro CVE utilizável.");return}
 const id=String(cve.id||"");lastCVE={id,description:"",score:"",severity:""};
 const details=document.createElement("div");details.className="panel section";
 details.append(txt("h3",id));
 const desc=(cve.descriptions||[]).find(d=>d.lang==="pt")||(cve.descriptions||[]).find(d=>d.lang==="en");
 lastCVE.description=String(desc?.value||"Descrição indisponível");
 details.append(txt("p",lastCVE.description));
 const v31=cve.metrics?.cvssMetricV31?.[0]||cve.metrics?.cvssMetricV30?.[0]||cve.metrics?.cvssMetricV40?.[0]||cve.metrics?.cvssMetricV2?.[0];
 if(v31){lastCVE.score=String(v31.cvssData?.baseScore??"Não informado");lastCVE.severity=String(v31.cvssData?.baseSeverity||v31.baseSeverity||"Não informado")}
 details.append(txt("p","CVSS: "+(lastCVE.score||"Não disponível")+" · Severidade: "+(lastCVE.severity||"Não disponível"),"intel-score"));
 const dates=txt("p","Publicação: "+(cve.published||"—")+" · Última modificação: "+(cve.lastModified||"—"),"status");details.append(dates);
 const warn=txt("p","A existência desta CVE não prova que um host analisado é vulnerável. Confirme produto, versão, condições e aplicabilidade.","guide-hint");details.append(warn);
 details.append(link("https://nvd.nist.gov/vuln/detail/"+encodeURIComponent(id),"Abrir CVE na NVD ↗"));
 root.append(details);status("Consulta concluída. Apenas o identificador do CVE foi enviado.");
}
async function queryCve(e){
 e.preventDefault();
 const raw=byId("intel-cve-id").value.trim().toUpperCase();
 const root=byId("intel-cve-result");root.replaceChildren();lastCVE=null;
 if(!/^CVE-\d{4}-\d{4,}$/.test(raw)||raw.length>28){status("Informe um identificador válido, como CVE-2021-44228.");return}
 const submit=byId("intel-cve-submit");submit.disabled=true;
 status("Consultando NVD. Somente o identificador "+raw+" será enviado...");
 const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),13000);
 try{
  const url="https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="+encodeURIComponent(raw);
  const response=await fetch(url,{method:"GET",mode:"cors",credentials:"omit",signal:controller.signal,cache:"no-store",referrerPolicy:"no-referrer"});
  if(!response.ok)throw Error("HTTP "+response.status);
  const json=await response.json();
  const record=(json.vulnerabilities||[]).find(x=>x.cve?.id===raw);
  if(!record){status("Nenhum registro encontrado na resposta da NVD.");root.append(link("https://nvd.nist.gov/vuln/detail/"+raw,"Consultar identificador na NVD ↗"));return}
  showCve(record);
 }catch(err){
  status("Consulta direta indisponível (limite de API, CORS, rede ou tempo de resposta). Você pode consultar o CVE no site da NVD.");
  root.append(link("https://nvd.nist.gov/vuln/detail/"+raw,"Consultar "+raw+" na NVD ↗"));
 }finally{clearTimeout(timer);submit.disabled=false}
}
function addReport(){
 const field=byId("r-mitre"),actions=byId("r-actions"),response=byId("intel-report-status");
 if(!field||!actions)return;
 const fragments=currentFindings.map(x=>x.id+" — "+x.title+" (hipótese; "+x.hits+" correspondência(s); verificar evidências; https://attack.mitre.org/techniques/"+x.id+"/)");
 if(lastCVE)fragments.push("Consulta NVD: "+lastCVE.id+" | CVSS "+(lastCVE.score||"indisponível")+" | confirmar aplicabilidade (https://nvd.nist.gov/vuln/detail/"+lastCVE.id+")");
 if(!fragments.length){response.textContent="Nenhuma referência encontrada. Importe logs para gerar hipóteses MITRE ou consulte um CVE específico.";return}
 const block=fragments.join("\n");
 field.value=(field.value?field.value.trimEnd()+"\n\n":"")+"Referências de inteligência (a validar):\n"+block;
 const guidance="Referência de boas práticas: NIST SP 800-61 Rev. 3 — https://csrc.nist.gov/pubs/sp/800/61/r3/final";
 if(!actions.value.includes(guidance))actions.value=(actions.value?actions.value.trimEnd()+"\n\n":"")+guidance;
 response.textContent="Referências incluídas no formulário do relatório. Revise e valide as hipóteses antes de exportar.";
}
byId("intel-refresh")?.addEventListener("click",renderMitre);
byId("intel-cve-form")?.addEventListener("submit",queryCve);
byId("intel-add-report")?.addEventListener("click",addReport);
document.querySelector('[data-view="intel"]')?.addEventListener("click",renderMitre);
renderNist();
})();