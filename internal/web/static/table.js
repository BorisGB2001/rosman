// Enhances data tables: click-to-sort, drag-to-resize and drag-to-reorder
// columns on every table with a header; plus a search box and a gear menu to
// show/hide columns on `.dtable` tables (a compact toolbar is injected when the
// page provides none). Preferences are saved per table in localStorage.
// Progressive enhancement: tables work without it.
(function () {
  function store(key, val) { try { localStorage.setItem(key, JSON.stringify(val)); } catch (e) {} }
  function load(key, def) { try { var v = localStorage.getItem(key); return v ? JSON.parse(v) : def; } catch (e) { return def; } }
  function slug(s) { return (s || '').replace(/[^a-z0-9]+/gi, '_').replace(/^_+|_+$/g, '').toLowerCase(); }
  function tableId(table, idx) { if (table.id) return table.id; var id = 'auto_' + slug(location.pathname) + '_' + idx; table.id = id; return id; }

  function enhance(table, idx) {
    if (!table.tHead || !table.tHead.rows.length || !table.tBodies.length) return;
    var id = tableId(table, idx);
    var headRow = table.tHead.rows[0];
    var ths = Array.prototype.slice.call(headRow.cells);
    if (!ths.length) return;
    ths.forEach(function (th, i) { th.dataset.key = th.getAttribute('data-col') || ('c' + i); });
    var isData = table.classList.contains('dtable');

    function rows() { return [headRow].concat(Array.prototype.slice.call(table.tBodies[0].rows)); }
    function moveColumn(from, to) {
      if (from === to) return;
      rows().forEach(function (row) {
        if (from >= row.cells.length) return;
        var node = row.cells[from];
        var ref = row.cells[to];
        if (!node) return;
        if (!ref) { row.appendChild(node); return; }
        row.insertBefore(node, from < to ? ref.nextSibling : ref);
      });
    }
    function keyIndex(key) { for (var i = 0; i < headRow.cells.length; i++) if (headRow.cells[i].dataset.key === key) return i; return -1; }
    function saveOrder() {
      var order = Array.prototype.map.call(headRow.cells, function (c) { return c.dataset.key; });
      store('to:' + id, order);
    }

    // apply saved order
    var saved = load('to:' + id, null);
    if (saved && saved.length) {
      saved.forEach(function (key, pos) {
        var cur = keyIndex(key);
        if (cur >= 0 && cur !== pos) moveColumn(cur, pos);
      });
    }

    // restore widths (by key)
    var widths = load('tw:' + id, {});
    Array.prototype.forEach.call(headRow.cells, function (th) { if (widths[th.dataset.key]) th.style.width = widths[th.dataset.key] + 'px'; });

    // hidden columns (data tables)
    var hidden = load('th:' + id, {});
    function applyHidden() {
      Array.prototype.forEach.call(headRow.cells, function (th) {
        var i = th.cellIndex, hide = !!hidden[th.dataset.key];
        th.style.display = hide ? 'none' : '';
        Array.prototype.forEach.call(table.tBodies[0].rows, function (r) { if (r.cells[i]) r.cells[i].style.display = hide ? 'none' : ''; });
      });
    }
    if (isData) applyHidden();

    // sorting (uses live cellIndex, so it survives reordering)
    function cellVal(tr, i) { var c = tr.cells[i]; if (!c) return ''; var t = c.getAttribute('data-sort'); return t !== null ? t : c.textContent.trim(); }
    function sortBy(i, dir) {
      var body = table.tBodies[0], list = Array.prototype.slice.call(body.rows);
      list.sort(function (a, b) {
        var x = cellVal(a, i), y = cellVal(b, i), nx = parseFloat(x), ny = parseFloat(y);
        var num = !isNaN(nx) && !isNaN(ny) && /^[-\d.]+/.test(x) && /^[-\d.]+/.test(y);
        var cmp = num ? (nx - ny) : x.localeCompare(y, undefined, { numeric: true });
        return dir === 'desc' ? -cmp : cmp;
      });
      list.forEach(function (r) { body.appendChild(r); });
    }
    var sortState = {};
    ths.forEach(function (th) {
      if (th.getAttribute('data-nosort') === null) {
        th.style.cursor = 'pointer';
        th.addEventListener('click', function () {
          if (th._resizing || th._dragging) return;
          var dir = sortState.key === th.dataset.key && sortState.dir === 'asc' ? 'desc' : 'asc';
          sortState = { key: th.dataset.key, dir: dir };
          Array.prototype.forEach.call(headRow.cells, function (t) { t.classList.remove('sort-asc', 'sort-desc'); });
          th.classList.add(dir === 'asc' ? 'sort-asc' : 'sort-desc');
          sortBy(th.cellIndex, dir);
        });
      }

      // resize grip (width stored by key)
      var grip = document.createElement('span');
      grip.className = 'col-grip';
      th.appendChild(grip);
      grip.addEventListener('click', function (e) { e.stopPropagation(); });
      grip.addEventListener('mousedown', function (e) {
        e.preventDefault(); e.stopPropagation();
        th._resizing = true; th.draggable = false;
        var startX = e.pageX, startW = th.offsetWidth;
        function mv(ev) { th.style.width = Math.max(40, startW + (ev.pageX - startX)) + 'px'; }
        function up() {
          document.removeEventListener('mousemove', mv); document.removeEventListener('mouseup', up);
          widths[th.dataset.key] = th.offsetWidth; store('tw:' + id, widths);
          th.draggable = true;
          setTimeout(function () { th._resizing = false; }, 50);
        }
        document.addEventListener('mousemove', mv); document.addEventListener('mouseup', up);
      });

      // drag-to-reorder
      th.draggable = true;
      th.addEventListener('dragstart', function (e) {
        th._dragging = true;
        e.dataTransfer.effectAllowed = 'move';
        e.dataTransfer.setData('text/plain', th.dataset.key);
      });
      th.addEventListener('dragend', function () { setTimeout(function () { th._dragging = false; }, 50); Array.prototype.forEach.call(headRow.cells, function (t) { t.classList.remove('col-drop'); }); });
      th.addEventListener('dragover', function (e) { e.preventDefault(); e.dataTransfer.dropEffect = 'move'; th.classList.add('col-drop'); });
      th.addEventListener('dragleave', function () { th.classList.remove('col-drop'); });
      th.addEventListener('drop', function (e) {
        e.preventDefault(); th.classList.remove('col-drop');
        var srcKey = e.dataTransfer.getData('text/plain');
        var from = keyIndex(srcKey), to = th.cellIndex;
        if (from >= 0 && from !== to) { moveColumn(from, to); saveOrder(); }
      });
    });

    if (!isData) return;

    // search + column menu
    var search = document.querySelector('[data-search-for="' + id + '"]');
    var gear = document.querySelector('[data-cols-for="' + id + '"]');
    if (!search && !gear) {
      var bar = document.createElement('div'); bar.className = 'dtable-bar';
      var inp = document.createElement('input'); inp.type = 'search'; inp.placeholder = '🔍'; inp.setAttribute('data-search-for', id);
      var g = document.createElement('button'); g.type = 'button'; g.className = 'btn sm secondary gearbtn'; g.textContent = '⚙'; g.setAttribute('data-cols-for', id);
      bar.appendChild(inp); bar.appendChild(g);
      var wrap = table.closest('.scroll') || table;
      wrap.parentNode.insertBefore(bar, wrap);
      search = inp; gear = g;
    }
    if (gear) {
      var menu = document.createElement('div'); menu.className = 'cols-menu'; menu.style.display = 'none';
      ths.forEach(function (th) {
        var label = (th.getAttribute('data-label') || th.textContent || th.dataset.key).trim();
        if (!label) label = th.dataset.key;
        var row = document.createElement('label');
        var cb = document.createElement('input'); cb.type = 'checkbox'; cb.checked = !hidden[th.dataset.key];
        cb.addEventListener('change', function () {
          if (cb.checked) delete hidden[th.dataset.key]; else hidden[th.dataset.key] = true;
          store('th:' + id, hidden); applyHidden();
        });
        row.appendChild(cb); row.appendChild(document.createTextNode(' ' + label));
        menu.appendChild(row);
      });
      gear.parentNode.style.position = 'relative';
      gear.parentNode.appendChild(menu);
      gear.addEventListener('click', function (e) { e.preventDefault(); menu.style.display = menu.style.display === 'none' ? 'block' : 'none'; });
      document.addEventListener('click', function (e) { if (!menu.contains(e.target) && e.target !== gear) menu.style.display = 'none'; });
    }
    if (search) {
      search.addEventListener('input', function () {
        var q = search.value.toLowerCase();
        Array.prototype.forEach.call(table.tBodies[0].rows, function (r) { r.style.display = r.textContent.toLowerCase().indexOf(q) >= 0 ? '' : 'none'; });
      });
    }
  }

  document.addEventListener('DOMContentLoaded', function () {
    var seen = [];
    document.querySelectorAll('.scroll > table, table.dtable').forEach(function (t, i) {
      if (seen.indexOf(t) >= 0 || t.hasAttribute('data-noenhance')) return;
      seen.push(t); enhance(t, i);
    });
  });
})();
