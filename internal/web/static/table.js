// Enhances data tables: click-to-sort, drag-to-resize columns, a gear menu to
// show/hide columns, and a search box — with per-table preferences saved in
// localStorage. Progressive enhancement: tables work without it.
(function () {
  function store(key, val) { try { localStorage.setItem(key, JSON.stringify(val)); } catch (e) {} }
  function load(key, def) { try { var v = localStorage.getItem(key); return v ? JSON.parse(v) : def; } catch (e) { return def; } }

  function enhance(table) {
    var id = table.id || 'tbl';
    var ths = Array.prototype.slice.call(table.tHead ? table.tHead.rows[0].cells : []);
    if (!ths.length) return;

    // ---- column labels / keys ----
    var keys = ths.map(function (th, i) { return th.getAttribute('data-col') || ('c' + i); });

    // ---- restore widths ----
    var widths = load('tw:' + id, {});
    ths.forEach(function (th, i) { if (widths[keys[i]]) th.style.width = widths[keys[i]] + 'px'; });

    // ---- restore hidden columns ----
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
    applyHidden();

    // ---- sorting ----
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
      th.addEventListener('click', function (e) {
        if (th._resizing) return;
        var dir = sortState.col === i && sortState.dir === 'asc' ? 'desc' : 'asc';
        sortState = { col: i, dir: dir };
        ths.forEach(function (t) { t.classList.remove('sort-asc', 'sort-desc'); });
        th.classList.add(dir === 'asc' ? 'sort-asc' : 'sort-desc');
        sortBy(i, dir);
      });
    });

    // ---- resize handles ----
    ths.forEach(function (th, i) {
      var grip = document.createElement('span');
      grip.className = 'col-grip';
      th.appendChild(grip);
      var startX, startW;
      grip.addEventListener('mousedown', function (e) {
        e.preventDefault(); e.stopPropagation();
        th._resizing = true; startX = e.pageX; startW = th.offsetWidth;
        function mv(ev) {
          var w = Math.max(40, startW + (ev.pageX - startX));
          th.style.width = w + 'px';
        }
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

    // ---- gear: column show/hide ----
    var gear = document.querySelector('[data-cols-for="' + id + '"]');
    if (gear) {
      var menu = document.createElement('div');
      menu.className = 'cols-menu'; menu.style.display = 'none';
      ths.forEach(function (th, i) {
        var label = (th.getAttribute('data-label') || th.textContent || keys[i]).trim();
        if (!label) return;
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

    // ---- search ----
    var search = document.querySelector('[data-search-for="' + id + '"]');
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
    document.querySelectorAll('table.dtable').forEach(enhance);
  });
})();
