// Status bar: shows what the server is doing right now (bulk onboarding, fleet
// polls, backups, upgrades, adding a device…) with a progress bar or a running
// stripe, so "working" is never mistaken for "hung". It polls /activity — fast
// while something runs or a form is being submitted, slowly when idle — and
// keeps running while the browser waits for a slow POST to answer.
(function () {
  var bar = document.getElementById('sbar');
  if (!bar) return;
  var elTitle = document.getElementById('sbar-title'), elDetail = document.getElementById('sbar-detail'),
      elTrack = document.getElementById('sbar-track'), elFill = document.getElementById('sbar-fill'),
      elPct = document.getElementById('sbar-pct'), elMore = document.getElementById('sbar-more');
  var L = bar.dataset, pending = null, timer = null, stopped = false, busy = false;

  function secs(ms) { var s = Math.round(ms / 1000); return s < 60 ? s + 's' : Math.floor(s / 60) + 'm ' + (s % 60) + 's'; }

  function show(state, title, detail, pct, right, more, moreTip) {
    bar.className = 'sbar ' + state;
    elTitle.textContent = title || '';
    elDetail.textContent = detail || '';
    elPct.textContent = right || '';
    elMore.textContent = more || '';
    elMore.title = moreTip || '';
    if (pct === null) { elTrack.className = 'sbar-track ind'; elFill.style.width = ''; }
    else if (pct === undefined) { elTrack.className = 'sbar-track off'; }
    else { elTrack.className = 'sbar-track'; elFill.style.width = pct + '%'; }
  }

  function render(tasks) {
    var run = tasks.filter(function (t) { return t.running; });
    if (run.length) {
      var t = run[run.length - 1], right = t.elapsed;
      if (t.total > 0) {
        right = t.done + '/' + t.total + ' · ' + t.pct + '%' + (t.failed ? ' · ' + L.errors + ': ' + t.failed : '') + ' · ' + t.elapsed;
      }
      var more = run.length > 1 ? '+' + (run.length - 1) + ' ' + L.more : '';
      var tip = run.map(function (x) { return x.title + (x.total ? ' ' + x.done + '/' + x.total : ''); }).join('\n');
      show('run', t.title, t.detail, t.total > 0 ? t.pct : null, right, more, tip);
      return true;
    }
    if (pending) {
      show('run', pending.label || L.wait, L.wait, null, secs(Date.now() - pending.at));
      return true;
    }
    if (tasks.length) {
      var f = tasks[tasks.length - 1];
      if (f.err) { show('err', f.title, L.failed + ': ' + f.err, undefined, f.elapsed); }
      else {
        var d = L.done + (f.total ? ' — ' + f.done + '/' + f.total : '') + (f.failed ? ' · ' + L.errors + ': ' + f.failed : '');
        show(f.failed ? 'warn' : 'ok', f.title, d, undefined, f.elapsed);
      }
      return false;
    }
    show('idle', L.idle, '', undefined, '');
    return false;
  }

  function schedule(active) {
    clearTimeout(timer);
    if (stopped) return;
    timer = setTimeout(poll, active ? 900 : 5000);
  }

  function poll() {
    if (busy) return;
    if (document.hidden && !pending) { schedule(false); return; }
    busy = true;
    fetch('/activity', { cache: 'no-store', credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
      .then(function (r) {
        var ct = r.headers.get('Content-Type') || '';
        if (!r.ok || ct.indexOf('json') < 0) { stopped = true; return null; } // logged out
        return r.json();
      })
      .then(function (j) { busy = false; if (j) schedule(render(j.tasks || [])); })
      .catch(function () { busy = false; schedule(!!pending); }); // server restarting / network blip
  }

  // Any POST form: mark the pressed button busy and switch the bar to
  // "request in progress" immediately, before the server has answered.
  document.addEventListener('submit', function (e) {
    var f = e.target;
    if (e.defaultPrevented || !f || (f.method || '').toLowerCase() !== 'post' || f.hasAttribute('data-nobusy')) return;
    var b = e.submitter, label = '';
    if (b) {
      label = (b.textContent || '').replace(/\s+/g, ' ').trim();
      // After the event: a disabled-looking button must still be part of the submitted form data.
      setTimeout(function () { b.classList.add('busy'); }, 0);
    }
    pending = { at: Date.now(), label: label };
    render([]);
    clearTimeout(timer);
    busy = false;
    timer = setTimeout(poll, 300);
  });
  // Back/forward cache restore: the old "busy" state is stale.
  window.addEventListener('pageshow', function (e) {
    if (e.persisted) {
      pending = null;
      document.querySelectorAll('.btn.busy, button.busy').forEach(function (b) { b.classList.remove('busy'); });
      poll();
    }
  });
  document.addEventListener('visibilitychange', function () { if (!document.hidden) poll(); });
  poll();
})();
