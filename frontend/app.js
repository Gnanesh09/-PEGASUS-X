const $ = id => document.getElementById(id);
async function api(path, options={}) {
  const r = await fetch(path, {headers:{'Content-Type':'application/json'}, ...options});
  return r.json();
}
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function time(s){try{return new Date(s).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'})}catch{return ''}}
async function refresh(){
  try{
    const [status, events, rounds, health] = await Promise.all([
      api('/api/status'),api('/api/events?limit=70'),api('/api/rounds'),api('/api/health')
    ]);
    $('metricStatus').textContent=status.running?'RUNNING':'IDLE';
    $('metricRounds').textContent=rounds.length;
    $('metricMax').textContent=`of ${status.max_rounds} planned`;
    $('metricDetection').textContent=rounds.length?`${Math.round(rounds.filter(x=>['DEFENDED','DETECTED'].includes(x.outcome)).length/rounds.length*100)}%`:'—';
    $('graphStatus').textContent=status.graph_status;
    $('runState').textContent=status.running?`● AUTONOMOUS ${String(status.mode).toUpperCase()} ACTIVE`:'● SYSTEM IDLE';
    $('start').disabled=status.running;
    $('start').style.opacity=status.running?'.45':'1';
    $('dbBadge').textContent=health.live_lab_enabled?'LIVE LAB READY':(health.postgres_configured?'CONFIGURED':'OPTIONAL');
    $('modeHint').textContent=$('mode').value==='real_lab' ? (health.live_lab_enabled ? 'Live lab enabled: bounded PostgreSQL tests will run against the allowlisted VM.' : health.live_lab_message) : 'Simulation mode sends no database attack traffic.';
    $('events').innerHTML=events.length?events.map(e=>`<div class="event"><time>${time(e.timestamp)}</time><div><b>${esc(e.agent)}</b><p>${esc(e.message)}</p></div><span class="tag">${esc(e.kind)}</span></div>`).join(''):'<div class="empty">Waiting for simulation events…</div>';
    $('roundRows').innerHTML=rounds.length?rounds.map(r=>`<tr><td>#${r.round_no}</td><td>${esc(r.scenario)}</td><td class="success">${esc(r.outcome)}</td><td>${r.score}/100</td><td>${time(r.timestamp)}</td></tr>`).join(''):'<tr><td colspan="5" class="empty">No completed rounds yet.</td></tr>';
    const latest=await api('/api/report/latest');
    $('report').textContent=latest.report?JSON.stringify(latest.report,null,2):'Latest analyst report will appear here.';
  }catch(e){$('runState').textContent='● BACKEND CONNECTION ERROR';}
}
$('start').onclick=async()=>{try{const r=await api('/api/start',{method:'POST',body:JSON.stringify({max_rounds:Number($('rounds').value)||4,interval:Number($('interval').value)||3,mode:$('mode').value})});if(!r.started)alert(r.message||r.detail||'Could not start.');}catch(e){alert(e.message||'Could not start lab. Check .env and backend terminal.');}refresh();};
$('mode').onchange=refresh;
$('stop').onclick=async()=>{await api('/api/stop',{method:'POST'});refresh();};
$('reset').onclick=async()=>{if(confirm('Clear event history and round reports?')){const r=await api('/api/reset',{method:'POST'});alert(r.message||'Lab history reset');refresh();}};
$('checkDb').onclick=async()=>{ $('dbInfo').textContent='Checking connection…';const r=await api('/api/lab-check');$('dbInfo').textContent=r.connected?`App role: ${r.pegasus_app?.database||''}/${r.pegasus_app?.user||''} · Test role: ${r.pegasus_test?.database||''}/${r.pegasus_test?.user||''}`:r.message;$('dbBadge').textContent=r.connected?'CONNECTED':'NOT CONNECTED';};
refresh();setInterval(refresh,2000);



const AGENT_NAMES = ["red", "blue", "hunter", "defense", "analyst"];

function setAgentState(agentName, state) {
  const card = document.querySelector(
    `[data-agent="${agentName}"]`
  );

  if (!card) return;

  const status = card.querySelector(".agent-status");

  card.classList.remove(
    "is-active",
    "is-completed",
    "is-error"
  );

  if (state === "active") {
    card.classList.add("is-active");
    status.textContent = "EXECUTING";
  } else if (state === "completed") {
    card.classList.add("is-completed");
    status.textContent = "COMPLETED";
  } else if (state === "error") {
    card.classList.add("is-error");
    status.textContent = "ERROR";
  } else {
    status.textContent = "READY";
  }
}

function resetAgentNetwork() {
  AGENT_NAMES.forEach(name => setAgentState(name, "ready"));
}
