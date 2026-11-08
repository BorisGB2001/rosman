// Enhances data tables: click-to-sort and drag-to-resize on every table with a
// header; plus a search box and a gear menu to show/hide columns on tables
// marked `.dtable` (a compact toolbar is injected automatically when the page
// does not already provide its own controls). Preferences are saved per table
// in localStorage. Progressive enhancement: tables work without it.
(function () {
  function store(key, val) { try { localStorage.setItem(key, JSON.stringify(val)); } catch (e) {} }
  function load(key, def) { try { var v = localStorage.getItem(key); return v ? JSON.parse(v) : def; } catch (e) { return def; } }

  function slug(s) { return (s || '').replace(/[^a-z0-9]+/gi, '_').replace(/^_+|_+$/g, '').toLowerCase(); }

  function tableId(table, idx) {
    if (table.id) return table.id;
    var id = 'auto_' + slug(location.pathname) + '_' + idx;
    table.id = id;
    return id;
  }

  function enhance(table, idx) {
    if (!table.tHead || !table.tHead.rows.length || !table.tBodies.length) return;
    var id = tableId(table, idx);
    var ths = Array.prototype.slice.call(table.tHead.rows[0].cells);
    if (!ths.length) return;
    var keys = ths.map(function (th, i) { return th.getAttribute('data-col') || ('c' + i); });
    var isData = table.classList.contains('dtable');

    // restore widths
    var widths = load('tw:' + id, {});
    ths.forEach(function (th, i) { if (widths[keys[i]]) th.style.width = widths[keys[i]] + 'px'; });

    // restore hidden columns (data tables only)
    var hidden = load('th:' + id, {});
    function applyHidden() {
      ths.forEach(function (th, i) {
        var hide = !!hidden[keys[i]];
        th.style.display = hide ? 'none' : '';
        Array.prototype.forEach.call(table.tBodies[0].rows, function (r) {
          if (r.cells[i]) r.cells[i].style.display = hide ? 'none' : '';
        });
      });
    }
    if (isData) applyHidden();

    // sorting
    function cellVal(tr, i) {
      var c = tr.cells[i]; if (!c) return '';
      var t = c.getAttribute('data-sort'); if (t !== null) return t;
      return c.textContent.trim();
    }
    function sortBy(i, dir) {
      var body = table.tBodies[0];
      var rows = Array.prototype.slice.call(body.rows);
      rows.sort(function (a, b) {
        var x = cellVal(a, i), y = cellVal(b, i);
        var nx = parseFloat(x), ny = parseFloat(y);
        var num = !isNaN(nx) && !isNaN(ny) && /^[-\d.]+/.test(x) && /^[-\d.]+/.test(y);
        var cmp = num ? (nx - ny) : x.localeCompare(y, undefined, { numeric: true });
        return dir === 'desc' ? -cmp : cmp;
      });
      rows.forEach(function (r) { body.appendChild(r); });
    }
    var sortState = {};
    ths.forEach(function (th, i) {
      if (th.getAttribute('data-nosort') !== null) return;
      th.style.cursor = 'pointer';
      th.addEventListener('click', function () {
        if (th._resizing) return;
        var dir = sortState.col === i && sortState.dir === 'asc' ? 'desc' : 'asc';
        sortState = { col: i, dir: dir };
        ths.forEach(function (t) { t.classList.remove('sort-asc', 'sort-desc'); });
        th.classList.add(dir === 'asc' ? 'sort-asc' : 'sort-desc');
        sortBy(i, dir);
      });
    });

    // resize handles
    ths.forEach(function (th, i) {
      var grip = document.createElement('span');
      grip.className = 'col-grip';
      th.appendChild(grip);
      var startX, startW;
      grip.addEventListener('mousedown', function (e) {
        e.preventDefault(); e.stopPropagation();
        th._resizing = true; startX = e.pageX; startW = th.offsetWidth;
        function mv(ev) { th.style.width = Math.max(40, startW + (ev.pageX - startX)) + 'px'; }
        function up() {
          document.removeEventListener('mousemove', mv);
          document.removeEventListener('mouseup', up);
          widths[keys[i]] = th.offsetWidth; store('tw:' + id, widths);
          setTimeout(function () { th._resizing = false; }, 50);
        }
        document.addEventListener('mousemove', mv);
        document.addEventListener('mouseup', up);
      });
      grip.addEventListener('click', function (e) { e.stopPropagation(); });
    });

    if (!isData) return; // search + column menu only for data tables

    // locate or inject controls
    var search = document.querySelector('[data-search-for="' + id + '"]');
    var gear = document.querySelector('[data-cols-for="' + id + '"]');
    if (!search && !gear) {
      var bar = document.createElement('div');
      bar.className = 'dtable-bar';
      var inp = document.createElement('input');
      inp.type = 'search'; inp.placeholder = '🔍'; inp.setAttribute('data-search-for', id);
      var g = document.createElement('button');
      g.type = 'button'; g.className = 'btn sm secondary gearbtn'; g.textContent = '⚙'; g.setAttribute('data-cols-for', id);
      bar.appendChild(inp); bar.appendChild(g);
      var wrap = table.closest('.scroll') || table;
      wrap.parentNode.insertBefore(bar, wrap);
      search = inp; gear = g;
    }

    if (gear) {
      var menu = document.createElement('div');
      menu.className = 'cols-menu'; menu.style.display = 'none';
      ths.forEach(function (th, i) {
        var label = (th.getAttribute('data-label') || th.textContent || keys[i]).trim();
        if (!label) label = 'col ' + (i + 1);
        var row = document.createElement('label');
        var cb = document.createElement('input'); cb.type = 'checkbox'; cb.checked = !hidden[keys[i]];
        cb.addEventListener('change', function () {
          if (cb.checked) delete hidden[keys[i]]; else hidden[keys[i]] = true;
          store('th:' + id, hidden); applyHidden();
        });
        row.appendChild(cb); row.appendChild(document.createTextNode(' ' + label));
        menu.appendChild(row);
      });
      gear.parentNode.style.position = 'relative';
      gear.parentNode.appendChild(menu);
      gear.addEventListener('click', function (e) {
        e.preventDefault();
        menu.style.display = menu.style.display === 'none' ? 'block' : 'none';
      });
      document.addEventListener('click', function (e) {
        if (!menu.contains(e.target) && e.target !== gear) menu.style.display = 'none';
      });
    }

    if (search) {
      search.addEventListener('input', function () {
        var q = search.value.toLowerCase();
        Array.prototype.forEach.call(table.tBodies[0].rows, function (r) {
          r.style.display = r.textContent.toLowerCase().indexOf(q) >= 0 ? '' : 'none';
        });
      });
    }
  }

  document.addEventListener('DOMContentLoaded', function () {
    var tables = document.querySelectorAll('.scroll > table, table.dtable');
    var seen = [];
    tables.forEach(function (t, i) {
      if (seen.indexOf(t) >= 0 || t.hasAttribute('data-noenhance')) return;
      seen.push(t);
      enhance(t, i);
    });
  });
})();
