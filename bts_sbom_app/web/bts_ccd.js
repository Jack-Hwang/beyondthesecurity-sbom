/* bts_ccd.js — the Claude-client layout transform: the conversation becomes the CENTER column, the feature
 * panels move into a right-hand drawer, the section rail becomes a full-height dark rail (CCD "Code 탭 화면
 * 해부": 세션/탐색 레일 · 대화 본문 · 산출물 패널). Runs after bts_chat_panel.js; every move keeps node
 * identities, so the existing listeners and IDs keep working. The pre-CCD single-column layout stays available
 * via the "⇄ 판" toggle (body.ccd.nodrawer). */
(function () {
  'use strict';
  var body = document.querySelector('.body');
  var content = document.querySelector('.bts-content');
  var dock = document.getElementById('chatDock');
  var rail = document.getElementById('sideNav');
  if (!body || !content || !dock || !rail || body.classList.contains('ccd-done')) { return; }
  body.classList.add('ccd-done');

  // 1. two new columns: the conversation center and the feature drawer
  var center = document.createElement('div'); center.id = 'ccCenter';
  var drawer = document.createElement('div'); drawer.id = 'ccDrawer';

  // 2. the chat leaves the content column and becomes the center
  content.removeChild(dock);
  center.appendChild(dock);

  // 3. the feature panes (the whole content column) become the drawer
  drawer.appendChild(content);

  // 4. the rail is lifted to be column 1 of .body (it was buried inside the scan view's shell)
  var railParent = rail.parentElement;
  body.style.gridTemplateColumns = '';            // the inline 1fr would beat the CCD grid
  body.insertBefore(rail, body.firstElementChild);
  body.insertBefore(center, rail.nextElementSibling || null);
  body.insertBefore(drawer, center.nextElementSibling || null);

  // 5. the emptied wrappers (.view.view-scan > .scan.bts-shell) are hidden by CSS (.body.ccd > .view)

  // 6. drawer header: CCD-style bar with the pane title and the hide/show toggle
  var bar = document.createElement('div');
  bar.className = 'cc-drawer-bar';
  var title = document.createElement('span');
  title.className = 'cc-drawer-title';
  title.textContent = '🗂 기능 판';
  var spacer = document.createElement('span'); spacer.className = 'cc-spacer';
  var toggle = document.createElement('button');
  toggle.type = 'button';
  toggle.className = 'bts-mini';
  toggle.id = 'ccDrawerToggle';
  toggle.textContent = '⇄ 판 숨기기';
  toggle.title = '기능 판을 접고 대화를 넓힙니다 (다시 누르면 돌아옵니다)';
  toggle.addEventListener('click', function () {
    var hidden = body.classList.toggle('nodrawer');
    toggle.textContent = hidden ? '⇄ 판 보이기' : '⇄ 판 숨기기';
    center.classList.toggle('wide', hidden);
  });
  bar.appendChild(title); bar.appendChild(spacer); bar.appendChild(toggle);
  drawer.insertBefore(bar, drawer.firstElementChild);

  // 7. center header: CCD conversation header with the project name and a NEW button (fresh conversation)
  var chead = document.createElement('div');
  chead.className = 'cc-center-bar';
  var ctitle = document.createElement('span');
  ctitle.className = 'cc-center-title';
  ctitle.textContent = '💬 SBOM 어시스턴트';
  var projName = document.createElement('span');
  projName.className = 'cc-center-proj';
  function syncProj() {
    var sel = document.getElementById('projSel');
    projName.textContent = sel && sel.value ? '· ' + sel.value : '';
  }
  syncProj();
  document.getElementById('projSel').addEventListener('change', syncProj);
  document.addEventListener('bts:project', syncProj);
  var cspacer = document.createElement('span'); cspacer.className = 'cc-spacer';
  var fresh = document.createElement('button');
  fresh.type = 'button';
  fresh.className = 'bts-mini';
  fresh.id = 'ccNewChat';
  fresh.textContent = '＋ 새 대화';
  fresh.title = '이 프로젝트의 대화를 지우고 처음부터 (브라우저에만 저장된 대화입니다)';
  fresh.addEventListener('click', function () {
    var sel = document.getElementById('projSel');
    var key = 'bts-chat-' + ((sel && sel.value) || '(no project)');
    try { localStorage.removeItem(key); } catch (e) { /* storage unavailable: nothing to clear */ }
    document.dispatchEvent(new CustomEvent('bts:chat-new', { detail: { key: key } }));
  });
  chead.appendChild(ctitle); chead.appendChild(projName); chead.appendChild(cspacer); chead.appendChild(fresh);
  center.insertBefore(chead, center.firstElementChild);

  // 8. the chat panel picks the mode up by class
  dock.classList.add('as-center');
  body.classList.add('ccd');
})();
