/* ══════════════════════════════════════════════════════════
   AuctionVault — app.js
   Vanilla JS · No framework · No CDN
   All API routes preserved from main.py
══════════════════════════════════════════════════════════ */

'use strict';

// ── State ────────────────────────────────────────────────
let authToken = null;
let currentUser = null; // { username, role }
let allItems = [];
let currentFilter = 'all';
let currentSort = 'newest';
let searchQuery = '';
let countdownTimers = {};

// ── DOM Helpers ───────────────────────────────────────────
const $ = id => document.getElementById(id);
const qs = sel => document.querySelector(sel);
const qsa = sel => document.querySelectorAll(sel);

function setText(id, val) {
  const el = $(id);
  if (el) el.textContent = val;
}

function show(el) {
  if (typeof el === 'string') el = $(el);
  if (el) el.classList.remove('hidden');
}

function hide(el) {
  if (typeof el === 'string') el = $(el);
  if (el) el.classList.add('hidden');
}

function toggle(el, visible) {
  if (typeof el === 'string') el = $(el);
  if (!el) return;
  el.classList.toggle('hidden', !visible);
}

// ── Cookie helpers for refresh token ─────────────────────────
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
    return null;
}

function setCookie(name, value, maxAgeSeconds) {
    document.cookie = `${name}=${value}; path=/; max-age=${maxAgeSeconds}; SameSite=Lax; ${window.location.protocol === 'https:' ? 'Secure;' : ''}`;
}

function deleteCookie(name) {
    document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;`;
}

// ── Token refresh logic ─────────────────────────────────────
let refreshPromise = null;

async function refreshAccessToken() {
    if (refreshPromise) return refreshPromise;
    
    refreshPromise = (async () => {
        try {
            const response = await fetch('/refresh', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({}),
            });
            
            if (response.ok) {
                const data = await response.json();
                // Store access token in sessionStorage only (not localStorage)
                sessionStorage.setItem('av_access_token', data.access_token);
                // Refresh token is in HttpOnly cookie - secure!
                return data.access_token;
            }
        } catch (e) {
            console.error('Token refresh failed:', e);
        } finally {
            refreshPromise = null;
        }
        return null;
    })();
    
    return refreshPromise;
}


// ── Toast ─────────────────────────────────────────────────
function toast(msg, type = 'info', title = '') {
  const container = $('toast-container');
  if (!container) return;
  const t = document.createElement('div');
  t.className = `toast toast-${type}`;
  if (title) {
    const tTitle = document.createElement('div');
    tTitle.className = 'toast-title';
    tTitle.textContent = title;
    t.appendChild(tTitle);
  }
  const tMsg = document.createElement('div');
  tMsg.className = 'toast-msg';
  tMsg.textContent = msg;
  t.appendChild(tMsg);
  container.appendChild(t);
  requestAnimationFrame(() => t.classList.add('show'));
  setTimeout(() => {
    t.classList.remove('show');
    setTimeout(() => t.remove(), 350);
  }, 3800);
}

// ── JWT decode (safe, no verify) ─────────────────────────
function decodeJWT(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const payload = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const padded = payload + '='.repeat((4 - payload.length % 4) % 4);
    return JSON.parse(atob(padded));
  } catch {
    return null;
  }
}

function isTokenValid(token) {
  if (!token) return false;
  const payload = decodeJWT(token);
  if (!payload) return false;
  if (payload.exp && Date.now() / 1000 > payload.exp) return false;
  return true;
}

// ── Modified saveAuth (don't store tokens in localStorage) ──
function saveAuth(accessToken, role, username) {
    // Store access token in sessionStorage only (cleared on tab close)
    sessionStorage.setItem('av_access_token', accessToken);
    sessionStorage.setItem('av_role', role);
    sessionStorage.setItem('av_user', username);
    
    authToken = accessToken;
    currentUser = { username, role };
}

function loadAuth() {
    try {
        const token = sessionStorage.getItem('av_access_token');
        const role = sessionStorage.getItem('av_role');
        const username = sessionStorage.getItem('av_user');
        
        if (token && role && username) {
            // Quick validation (check expiration)
            const payload = decodeJWT(token);
            if (payload && payload.exp && Date.now() / 1000 < payload.exp) {
                authToken = token;
                currentUser = { username, role };
                return true;
            }
        }
    } catch { /* storage blocked */ }
    return false;
}

function clearAuth() {
    sessionStorage.removeItem('av_access_token');
    sessionStorage.removeItem('av_role');
    sessionStorage.removeItem('av_user');
    authToken = null;
    currentUser = null;
}

// ── API ───────────────────────────────────────────────────
// ── Modified apiFetch with auto-refresh ────────────────────
async function apiFetch(path, options = {}) {
    // Get token from sessionStorage (not localStorage for security)
    let token = sessionStorage.getItem('av_access_token');
    
    const makeRequest = async (requestToken) => {
        const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
        if (requestToken) headers['Authorization'] = `Bearer ${requestToken}`;
        
        const res = await fetch(path, { ...options, headers });
        
        if (res.status === 401) {
            // Try to refresh token
            const newToken = await refreshAccessToken();
            if (newToken) {
                // Retry with new token
                const retryHeaders = { 'Content-Type': 'application/json', ...(options.headers || {}) };
                retryHeaders['Authorization'] = `Bearer ${newToken}`;
                const retryRes = await fetch(path, { ...options, headers: retryHeaders });
                const retryData = await retryRes.json().catch(() => ({}));
                if (!retryRes.ok) throw { status: retryRes.status, detail: retryData.detail || 'Request failed' };
                return retryData;
            }
            // Refresh failed, redirect to login
            clearAuth();
            updateUIForAuth();
            throw { status: 401, detail: 'Session expired. Please log in again.' };
        }
        
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw { status: res.status, detail: data.detail || 'Request failed' };
        return data;
    };
    
    return makeRequest(token);
}


// ── UI State Machine ──────────────────────────────────────
function updateUIForAuth() {
  const loggedIn = !!(authToken && currentUser);

  // Navbar
  toggle('nav-actions-guest', !loggedIn);
  toggle('nav-actions-user', loggedIn);
  toggle('sidebar', loggedIn && isSidebarOpen());

  // Sections
  toggle('landing-section', !loggedIn);
  toggle('app-section', loggedIn);

  // Sidebar
  const sidebar = $('sidebar');
  if (sidebar) sidebar.classList.toggle('hidden', !loggedIn);

  if (loggedIn) {
    const { username, role } = currentUser;
    const initial = username.charAt(0).toUpperCase();

    // Navbar chip
    setText('nav-username', username);
    setText('nav-role', role);
    const navAvatar = $('nav-avatar');
    if (navAvatar) navAvatar.textContent = initial;

    // Sidebar
    setText('sb-username', username);
    setText('sb-role', role);
    const sbAvatar = $('sb-avatar');
    if (sbAvatar) sbAvatar.textContent = initial;

    // Role visibility
    const isSeller = role === 'Seller';
    const isBuyer = role === 'Buyer';
    qsa('.seller-only').forEach(el => toggle(el, isSeller));
    qsa('.buyer-only').forEach(el => toggle(el, isBuyer));
  }
}

let _sidebarOpen = false;
function isSidebarOpen() { return _sidebarOpen; }

function openSidebar() {
  _sidebarOpen = true;
  const sidebar = $('sidebar');
  const overlay = $('sidebar-overlay');
  if (sidebar) { sidebar.classList.remove('hidden'); sidebar.classList.add('open'); }
  if (overlay) { overlay.classList.remove('hidden'); overlay.classList.add('show'); }
  document.body.classList.add('sidebar-active');
}

function closeSidebar() {
  _sidebarOpen = false;
  const sidebar = $('sidebar');
  const overlay = $('sidebar-overlay');
  if (sidebar) { sidebar.classList.remove('open'); }
  if (overlay) { overlay.classList.remove('show'); }
  document.body.classList.remove('sidebar-active');
  // hide sidebar on mobile after animation
  setTimeout(() => {
    if (!_sidebarOpen && sidebar) {
      // Keep sidebar in DOM but visually closed; on mobile hide it
      if (window.innerWidth < 768) sidebar.classList.add('hidden');
    }
  }, 280);
}

// ── Views ─────────────────────────────────────────────────
const VIEWS = ['dashboard', 'auctions', 'my-bids'];

function showView(name) {
  VIEWS.forEach(v => {
    const el = $(`view-${v}`);
    if (el) el.classList.toggle('hidden', v !== name);
  });

  // Update sidebar active state
  qsa('.sidebar-item[data-view]').forEach(item => {
    item.classList.toggle('active', item.dataset.view === name);
  });

  // Load data for view
  if (name === 'dashboard') loadDashboard();
  else if (name === 'auctions') loadItems();
  else if (name === 'my-bids') loadMyBidsView();

  // On mobile, close sidebar after navigation
  if (window.innerWidth < 768) closeSidebar();
}

// ── Dashboard ─────────────────────────────────────────────
function updateWelcomeBanner() {
  if (!currentUser) return;
  const hour = new Date().getHours();
  const greeting = hour < 12 ? 'Good morning' : hour < 17 ? 'Good afternoon' : 'Good evening';
  setText('welcome-time-greeting', greeting);
  setText('welcome-username-display', currentUser.username);

  const isSeller = currentUser.role === 'Seller';
  setText('welcome-role-desc', isSeller
    ? 'Manage your listings and track your sales'
    : 'Discover auctions and place winning bids');

  const icon = isSeller ? '✦' : '◎';
  setText('wrb-icon', icon);
  setText('wrb-label', currentUser.role);
}

function updateStats(items) {
  const now = new Date();
  const active = items.filter(i => i.status === 'active');
  const closed = items.filter(i => i.status === 'closed');
  const highest = items.reduce((max, i) => Math.max(max, i.current_price), 0);
  const endingSoon = active.filter(i => i.time_remaining_seconds < 600).length;

  function animateCount(id, target, prefix = '', decimals = 0) {
    const el = $(id);
    if (!el) return;
    const duration = 600;
    const start = performance.now();
    const startVal = 0;
    function step(now) {
      const elapsed = now - start;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      const val = startVal + (target - startVal) * eased;
      el.textContent = prefix + (decimals > 0 ? val.toFixed(decimals) : Math.round(val));
      if (progress < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  animateCount('stat-active-val', active.length);
  animateCount('stat-closed-val', closed.length);
  animateCount('stat-highest-val', highest, '$', 0);
  animateCount('stat-ending-val', endingSoon);
}

async function loadDashboard() {
  updateWelcomeBanner();
  try {
    const items = await apiFetch('/items');
    allItems = items;
    updateStats(items);
    renderDashboardAuctions(items);
  } catch (e) {
    console.error('Dashboard load error', e);
  }
}

function renderDashboardAuctions(items) {
  const grid = $('dashboard-auctions-grid');
  if (!grid) return;
  // Show up to 4 most recent active, then closed
  const sorted = [...items].sort((a, b) => {
    if (a.status === 'active' && b.status !== 'active') return -1;
    if (b.status === 'active' && a.status !== 'active') return 1;
    return b.id - a.id;
  }).slice(0, 4);

  grid.innerHTML = '';
  if (sorted.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'empty-state';
    const icon = document.createElement('div');
    icon.className = 'empty-icon';
    icon.textContent = '◈';
    const title = document.createElement('div');
    title.className = 'empty-title';
    title.textContent = 'No auctions yet';
    const sub = document.createElement('div');
    sub.className = 'empty-sub';
    sub.textContent = currentUser?.role === 'Seller' ? 'Create your first auction to get started.' : 'Check back soon for new listings.';
    empty.appendChild(icon);
    empty.appendChild(title);
    empty.appendChild(sub);
    grid.appendChild(empty);
    return;
  }
  sorted.forEach((item, idx) => {
    const card = buildAuctionCard(item, idx);
    grid.appendChild(card);
  });
}

// ── Items / Auctions ──────────────────────────────────────
async function loadItems() {
  const grid = $('items-grid');
  if (!grid) return;
  grid.innerHTML = '';

  // Skeleton
  for (let i = 0; i < 3; i++) {
    const sk = document.createElement('div');
    sk.className = 'skeleton-card';
    sk.innerHTML = `
      <div class="skeleton-line h-16" style="width:60%;margin-bottom:12px"></div>
      <div class="skeleton-line h-12" style="width:90%;margin-bottom:8px"></div>
      <div class="skeleton-line h-12" style="width:75%;margin-bottom:20px"></div>
      <div class="skeleton-line h-28" style="width:45%;margin-bottom:14px"></div>
      <div class="skeleton-line h-40"></div>
    `;
    grid.appendChild(sk);
  }

  try {
    const items = await apiFetch('/items');
    allItems = items;
    renderItems();

    // Load seller payments
    if (currentUser?.role === 'Seller') {
      loadSellerPayments();
    }
  } catch (e) {
    grid.innerHTML = '';
    const empty = buildEmptyState('Failed to load auctions', 'Check your connection and try again.');
    grid.appendChild(empty);
    toast('Failed to load auctions', 'error');
  }
}

function renderItems() {
  const grid = $('items-grid');
  if (!grid) return;
  grid.innerHTML = '';

  let filtered = [...allItems];

  // Filter
  if (currentFilter !== 'all') {
    filtered = filtered.filter(i => i.status === currentFilter);
  }

  // Search
  if (searchQuery.trim()) {
    const q = searchQuery.toLowerCase();
    filtered = filtered.filter(i =>
      i.title.toLowerCase().includes(q) ||
      (i.description || '').toLowerCase().includes(q)
    );
  }

  // Sort
  filtered.sort((a, b) => {
    switch (currentSort) {
      case 'ending':
        if (a.status === 'active' && b.status !== 'active') return -1;
        if (b.status === 'active' && a.status !== 'active') return 1;
        return a.time_remaining_seconds - b.time_remaining_seconds;
      case 'price-high': return b.current_price - a.current_price;
      case 'price-low':  return a.current_price - b.current_price;
      default:           return b.id - a.id;
    }
  });

  if (filtered.length === 0) {
    grid.appendChild(buildEmptyState(
      searchQuery ? 'No results found' : 'No auctions here',
      searchQuery ? 'Try a different search term.' : 'Check back soon or create an auction.'
    ));
    return;
  }

  filtered.forEach((item, idx) => {
    const card = buildAuctionCard(item, idx);
    grid.appendChild(card);
  });

  startCountdowns();
}

function buildEmptyState(title, sub) {
  const div = document.createElement('div');
  div.className = 'empty-state';
  const icon = document.createElement('div');
  icon.className = 'empty-icon';
  icon.textContent = '◈';
  const t = document.createElement('div');
  t.className = 'empty-title';
  t.textContent = title;
  const s = document.createElement('div');
  s.className = 'empty-sub';
  s.textContent = sub;
  div.appendChild(icon);
  div.appendChild(t);
  div.appendChild(s);
  return div;
}

// ── Auction Card Builder ──────────────────────────────────
function buildAuctionCard(item, idx = 0) {
  const isActive = item.status === 'active';
  const isEnding = isActive && item.time_remaining_seconds < 600;
  const isBuyer = currentUser?.role === 'Buyer';
  const isSeller = currentUser?.role === 'Seller';
  const isWinner = item.highest_bidder_username === currentUser?.username;

  const card = document.createElement('div');
  card.className = `auction-card ${isActive ? 'auction-card--active' : 'auction-card--closed'}`;
  card.dataset.itemId = item.id;
  card.style.animationDelay = `${idx * 0.07}s`;

  // Top line accent
  const topLine = document.createElement('div');
  topLine.className = 'card-top-line';
  card.appendChild(topLine);

  // Header row
  const header = document.createElement('div');
  header.className = 'card-header';

  const badgeWrap = document.createElement('div');
  badgeWrap.style.display = 'flex';
  badgeWrap.style.gap = '6px';
  badgeWrap.style.flexWrap = 'wrap';

  const statusBadge = document.createElement('span');
  if (isEnding) {
    statusBadge.className = 'status-badge badge-ending';
    statusBadge.textContent = '⏱ Ending';
  } else if (isActive) {
    statusBadge.className = 'status-badge badge-active';
    statusBadge.textContent = 'Live';
  } else {
    statusBadge.className = 'status-badge badge-closed';
    statusBadge.textContent = 'Closed';
  }
  badgeWrap.appendChild(statusBadge);

  if (item.payment_status === 'paid') {
    const paidBadge = document.createElement('span');
    paidBadge.className = 'status-badge badge-paid';
    paidBadge.textContent = '✓ Paid';
    badgeWrap.appendChild(paidBadge);
  }
  header.appendChild(badgeWrap);

  const itemId = document.createElement('span');
  itemId.className = 'item-meta';
  itemId.textContent = `#${item.id}`;
  header.appendChild(itemId);
  card.appendChild(header);

  // Title
  const titleEl = document.createElement('div');
  titleEl.className = 'card-title';
  titleEl.textContent = item.title;
  card.appendChild(titleEl);

  // Description
  if (item.description) {
    const desc = document.createElement('div');
    desc.className = 'card-desc';
    desc.textContent = item.description;
    card.appendChild(desc);
  }

  // Price row
  const priceRow = document.createElement('div');
  priceRow.className = 'card-price-row';

  const priceBlock = document.createElement('div');
  priceBlock.className = 'price-block';
  const priceLabel = document.createElement('div');
  priceLabel.className = 'price-label';
  priceLabel.textContent = isActive ? 'Current Bid' : 'Final Price';
  const priceVal = document.createElement('div');
  priceVal.className = 'price-value';
  priceVal.textContent = `$${item.current_price.toFixed(2)}`;
  priceBlock.appendChild(priceLabel);
  priceBlock.appendChild(priceVal);
  priceRow.appendChild(priceBlock);

  const sellerMeta = document.createElement('div');
  sellerMeta.className = 'seller-meta';
  sellerMeta.textContent = `by #${item.seller_id}`;
  priceRow.appendChild(sellerMeta);
  card.appendChild(priceRow);

  // Countdown
  if (isActive) {
    const bar = document.createElement('div');
    bar.className = `countdown-bar${isEnding ? ' countdown-bar--urgent' : ''}`;
    bar.dataset.itemId = item.id;

    const label = document.createElement('div');
    label.className = 'countdown-label';
    label.textContent = 'Time Remaining';
    bar.appendChild(label);

    const time = document.createElement('div');
    time.className = 'countdown-time';
    time.dataset.ends = Date.now() + item.time_remaining_seconds * 1000;
    time.textContent = formatTime(item.time_remaining_seconds);
    bar.appendChild(time);

    if (isEnding) {
      const tag = document.createElement('span');
      tag.className = 'ending-soon-tag';
      tag.textContent = 'Ending!';
      bar.appendChild(tag);
    }
    card.appendChild(bar);
  }

  // Highest bidder / winner
  if (!isActive && item.status === 'closed') {
    const wb = document.createElement('div');
    wb.className = 'winner-block';
    if (item.highest_bidder_username) {
      const wt = document.createElement('div');
      wt.className = 'winner-title';
      wt.textContent = '🏆 Winner';
      const wn = document.createElement('div');
      wn.className = 'winner-name';
      wn.textContent = item.highest_bidder_username;
      const wp = document.createElement('div');
      wp.className = 'winner-price';
      wp.textContent = `Final price: $${item.current_price.toFixed(2)}`;
      wb.appendChild(wt);
      wb.appendChild(wn);
      wb.appendChild(wp);
    } else {
      wb.classList.add('no-winner');
      const noW = document.createElement('div');
      noW.className = 'winner-title';
      noW.textContent = 'No bids placed';
      wb.appendChild(noW);
    }
    card.appendChild(wb);
  } else if (isActive && item.highest_bidder_username) {
    const leader = document.createElement('div');
    leader.className = 'leader-block';
    leader.textContent = 'Leading: ';
    const strong = document.createElement('strong');
    strong.textContent = item.highest_bidder_username;
    leader.appendChild(strong);
    card.appendChild(leader);
  }

  // Bid form (buyers, active auctions)
  if (isActive && isBuyer) {
    const form = document.createElement('div');
    form.className = 'bid-form';

    const input = document.createElement('input');
    input.type = 'number';
    input.className = 'bid-input';
    input.placeholder = `Min $${(item.current_price + item.min_increment).toFixed(2)}`;
    input.min = (item.current_price + item.min_increment).toFixed(2);
    input.step = '0.01';
    input.dataset.itemId = item.id;
    form.appendChild(input);

    const bidBtn = document.createElement('button');
    bidBtn.className = 'btn-bid';
    bidBtn.textContent = 'Bid';
    bidBtn.dataset.itemId = item.id;
    bidBtn.dataset.action = 'bid';
    form.appendChild(bidBtn);
    card.appendChild(form);

    const hint = document.createElement('div');
    hint.className = 'bid-hint';
    hint.textContent = `Min increment: $${item.min_increment.toFixed(2)}`;
    card.appendChild(hint);
  }

  // Pay button (buyer who won, not yet paid)
  if (!isActive && isBuyer && isWinner && item.payment_status !== 'paid') {
    const payBtn = document.createElement('button');
    payBtn.className = 'btn btn-pay btn-full';
    payBtn.textContent = '💳 Complete Payment';
    payBtn.dataset.itemId = item.id;
    payBtn.dataset.action = 'pay';
    card.appendChild(payBtn);
  }

  if (!isActive && isBuyer && isWinner && item.payment_status === 'paid') {
    const paidLine = document.createElement('div');
    paidLine.className = 'paid-line';
    paidLine.textContent = '✓ Payment complete';
    card.appendChild(paidLine);
  }

  // Seller close button
  if (isActive && isSeller) {
    const closeBtn = document.createElement('button');
    closeBtn.className = 'btn btn-ghost btn-sm btn-full';
    closeBtn.style.marginTop = '8px';
    closeBtn.textContent = '⬛ Close Auction';
    closeBtn.dataset.itemId = item.id;
    closeBtn.dataset.action = 'close';
    card.appendChild(closeBtn);
  }

  // Bid history toggle
  const histBtn = document.createElement('button');
  histBtn.className = 'btn-history';
  histBtn.dataset.itemId = item.id;
  histBtn.dataset.action = 'toggle-history';
  const histSpan = document.createElement('span');
  histSpan.textContent = '◴ Bid History';
  const chevron = document.createElement('span');
  chevron.className = 'chevron';
  chevron.textContent = '▾';
  histBtn.appendChild(histSpan);
  histBtn.appendChild(chevron);
  card.appendChild(histBtn);

  const histPanel = document.createElement('div');
  histPanel.className = 'bid-history';
  histPanel.dataset.itemId = item.id;
  card.appendChild(histPanel);

  return card;
}

// ── Countdowns ────────────────────────────────────────────
function formatTime(secs) {
  if (secs <= 0) return '00:00:00';
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = Math.floor(secs % 60);
  if (h > 0) return `${h}h ${String(m).padStart(2,'0')}m`;
  return `${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`;
}

function startCountdowns() {
  // Clear existing
  Object.values(countdownTimers).forEach(clearInterval);
  countdownTimers = {};

  const interval = setInterval(() => {
    qsa('.countdown-time[data-ends]').forEach(el => {
      const ends = parseInt(el.dataset.ends, 10);
      const remaining = Math.max(0, (ends - Date.now()) / 1000);
      el.textContent = formatTime(remaining);

      const bar = el.closest('.countdown-bar');
      if (bar) {
        bar.classList.toggle('countdown-bar--urgent', remaining < 600 && remaining > 60);
        bar.classList.toggle('countdown-bar--critical', remaining <= 60);
      }
      if (remaining <= 0) {
        // Mark card as expired
        const card = el.closest('.auction-card');
        if (card) card.classList.add('auction-card--closed');
      }
    });
  }, 1000);
  countdownTimers['main'] = interval;
}

// ── Bid ───────────────────────────────────────────────────
async function placeBid(itemId, amount) {
  try {
    const res = await apiFetch(`/items/${itemId}/bid`, {
      method: 'POST',
      body: JSON.stringify({ amount: parseFloat(amount) }),
    });
    toast(`Bid of $${parseFloat(amount).toFixed(2)} placed!`, 'success', '✓ Bid Placed');
    await loadItems();
    return true;
  } catch (e) {
    toast(e.detail || 'Bid failed', 'error', 'Bid Failed');
    return false;
  }
}

// ── Bid History ───────────────────────────────────────────
async function loadBidHistory(itemId, panel) {
  panel.innerHTML = '';
  const heading = document.createElement('div');
  heading.className = 'history-heading';
  heading.textContent = 'Bid History';
  panel.appendChild(heading);

  try {
    const bids = await apiFetch(`/items/${itemId}/bids`);
    if (bids.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'history-empty';
      empty.textContent = 'No bids yet';
      panel.appendChild(empty);
      return;
    }
    bids.forEach(bid => {
      const row = document.createElement('div');
      row.className = 'history-row';

      const bidder = document.createElement('span');
      bidder.className = 'history-bidder';
      bidder.textContent = bid.bidder_username;
      row.appendChild(bidder);

      const amt = document.createElement('span');
      amt.className = 'history-amount';
      amt.textContent = `$${bid.amount.toFixed(2)}`;
      row.appendChild(amt);

      const time = document.createElement('span');
      time.className = 'history-time';
      time.textContent = new Date(bid.created_at + 'Z').toLocaleTimeString();
      row.appendChild(time);

      panel.appendChild(row);
    });
  } catch {
    const err = document.createElement('div');
    err.className = 'history-empty';
    err.textContent = 'Failed to load history';
    panel.appendChild(err);
  }
}

// ── Close Auction ─────────────────────────────────────────
async function closeAuction(itemId) {
  try {
    const res = await apiFetch(`/items/${itemId}/close`, { method: 'POST' });
    const winner = res.winner_username ? `Winner: ${res.winner_username}` : 'No winner';
    toast(`Auction closed. ${winner}`, 'success', 'Auction Closed');
    await loadItems();
  } catch (e) {
    toast(e.detail || 'Failed to close auction', 'error');
  }
}

// ── Create Auction ────────────────────────────────────────
async function handleCreateAuction(e) {
  e.preventDefault();
  const title = $('item-title')?.value.trim();
  const desc = $('item-desc')?.value.trim();
  const price = parseFloat($('item-price')?.value);
  const increment = parseFloat($('item-increment')?.value);
  const duration = parseInt($('item-duration')?.value, 10);

  if (!title || isNaN(price) || isNaN(duration) || isNaN(increment)) {
    toast('Please fill all required fields', 'error');
    return;
  }
  if (price <= 0 || increment <= 0 || duration <= 0) {
    toast('Price, increment and duration must be positive', 'error');
    return;
  }

  const btn = $('create-auction-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Launching…'; }

  try {
    await apiFetch('/items', {
      method: 'POST',
      body: JSON.stringify({
        title, description: desc,
        starting_price: price,
        min_increment: increment,
        duration_minutes: duration,
      }),
    });
    toast('Auction launched successfully!', 'success', '✦ Launched');
    const form = $('create-auction-form');
    if (form) form.reset();
    await loadItems();
    showView('auctions');
  } catch (e) {
    toast(e.detail || 'Failed to create auction', 'error');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = '✦ Launch Auction'; }
  }
}

// ── Checkout / Payment ────────────────────────────────────
async function openCheckout(itemId) {
  const modal = $('checkout-modal');
  const body = $('checkout-body');
  if (!modal || !body) return;

  body.innerHTML = '';
  show(modal);

  try {
    const checkout = await apiFetch(`/items/${itemId}/checkout`);

    if (!checkout.can_pay) {
      const msg = document.createElement('div');
      msg.className = 'empty-state';
      msg.style.padding = '24px 0';
      const t = document.createElement('div');
      t.className = 'empty-title';
      t.style.fontSize = '15px';
      t.textContent = checkout.message;
      msg.appendChild(t);
      body.appendChild(msg);
      return;
    }

    // Summary
    const summary = document.createElement('div');
    summary.className = 'checkout-summary';

    function addRow(label, value, cls = '') {
      const row = document.createElement('div');
      row.className = 'checkout-row';
      const l = document.createElement('span');
      l.className = 'checkout-label';
      l.textContent = label;
      const v = document.createElement('span');
      v.className = `checkout-value ${cls}`;
      v.textContent = value;
      row.appendChild(l);
      row.appendChild(v);
      summary.appendChild(row);
    }
    addRow('Item', checkout.title);
    addRow('Winner', checkout.winner_username);
    const totalRow = document.createElement('div');
    totalRow.className = 'checkout-row checkout-total';
    const tl = document.createElement('span');
    tl.className = 'checkout-label';
    tl.textContent = 'Total';
    const tv = document.createElement('span');
    tv.className = 'checkout-value';
    tv.style.fontFamily = 'var(--font-mono)';
    tv.style.fontSize = '22px';
    tv.style.color = 'var(--blue)';
    tv.textContent = `$${checkout.final_price.toFixed(2)}`;
    totalRow.appendChild(tl);
    totalRow.appendChild(tv);
    summary.appendChild(totalRow);
    body.appendChild(summary);

    const demoNotice = document.createElement('div');
    demoNotice.className = 'demo-notice';
    demoNotice.textContent = '⚠ Demo mode — no real charges will be made.';
    body.appendChild(demoNotice);

    // Payment methods
    const methodLabel = document.createElement('div');
    methodLabel.className = 'field-label';
    methodLabel.style.marginBottom = '8px';
    methodLabel.textContent = 'Payment Method';
    body.appendChild(methodLabel);

    const methodGrid = document.createElement('div');
    methodGrid.className = 'method-grid';

    const methods = [
      { id: 'demo_card', icon: '💳', label: 'Card' },
      { id: 'upi_demo', icon: '📱', label: 'UPI' },
      { id: 'wallet_demo', icon: '👛', label: 'Wallet' },
    ];
    let selectedMethod = null;

    methods.forEach(m => {
      const btn = document.createElement('button');
      btn.className = 'method-btn';
      btn.dataset.method = m.id;
      const icon = document.createElement('span');
      icon.className = 'method-icon';
      icon.textContent = m.icon;
      const label = document.createElement('span');
      label.textContent = m.label;
      btn.appendChild(icon);
      btn.appendChild(label);
      btn.addEventListener('click', () => {
        qsa('.method-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        selectedMethod = m.id;
        confirmBtn.disabled = false;
      });
      methodGrid.appendChild(btn);
    });
    body.appendChild(methodGrid);

    const confirmBtn = document.createElement('button');
    confirmBtn.id = 'pay-confirm-btn';
    confirmBtn.className = 'btn btn-primary btn-full';
    confirmBtn.style.marginTop = '14px';
    confirmBtn.textContent = `Pay $${checkout.final_price.toFixed(2)}`;
    confirmBtn.disabled = true;
    confirmBtn.addEventListener('click', async () => {
      if (!selectedMethod) return;
      confirmBtn.disabled = true;
      confirmBtn.textContent = 'Processing…';
      try {
        const result = await apiFetch('/payments', {
          method: 'POST',
          body: JSON.stringify({ item_id: itemId, method: selectedMethod }),
        });
        renderPaymentSuccess(body, result);
        await loadItems();
      } catch (e) {
        toast(e.detail || 'Payment failed', 'error');
        confirmBtn.disabled = false;
        confirmBtn.textContent = `Pay $${checkout.final_price.toFixed(2)}`;
      }
    });
    body.appendChild(confirmBtn);

  } catch (e) {
    const err = document.createElement('div');
    err.className = 'empty-state';
    err.style.padding = '24px 0';
    const t = document.createElement('div');
    t.className = 'empty-title';
    t.style.fontSize = '15px';
    t.textContent = e.detail || 'Could not load checkout';
    err.appendChild(t);
    body.appendChild(err);
  }
}

function renderPaymentSuccess(container, result) {
  container.innerHTML = '';
  const wrap = document.createElement('div');
  wrap.className = 'payment-success';

  const checkWrap = document.createElement('div');
  checkWrap.className = 'success-check';
  checkWrap.innerHTML = `<svg viewBox="0 0 52 52" fill="none" xmlns="http://www.w3.org/2000/svg">
    <circle cx="26" cy="26" r="25" stroke="currentColor" stroke-width="2"/>
    <path d="M14 27l8 8 16-16" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
  </svg>`;
  wrap.appendChild(checkWrap);

  const title = document.createElement('div');
  title.className = 'success-title';
  title.textContent = 'Payment Successful!';
  wrap.appendChild(title);

  const sub = document.createElement('div');
  sub.className = 'success-sub';
  sub.textContent = `You won "${result.item_title}"`;
  wrap.appendChild(sub);

  const ref = document.createElement('div');
  ref.className = 'success-ref';
  ref.textContent = `Ref: ${result.transaction_ref}`;
  wrap.appendChild(ref);

  const closeBtn = document.createElement('button');
  closeBtn.className = 'btn btn-ghost';
  closeBtn.textContent = 'Close';
  closeBtn.addEventListener('click', () => hide('checkout-modal'));
  wrap.appendChild(closeBtn);

  container.appendChild(wrap);
}

// ── Seller Payments ───────────────────────────────────────
async function loadSellerPayments() {
  const panel = $('seller-payments-panel');
  const list = $('seller-payments-list');
  if (!panel || !list) return;

  try {
    const payments = await apiFetch('/seller/payments');
    if (payments.length === 0) { hide(panel); return; }
    show(panel);
    list.innerHTML = '';
    payments.forEach(p => {
      const row = document.createElement('div');
      row.className = 'payment-row';

      const main = document.createElement('div');
      main.className = 'payment-main';
      const t = document.createElement('div');
      t.className = 'payment-title';
      t.textContent = p.item_title || `Item #${p.item_id}`;
      const sub = document.createElement('div');
      sub.className = 'payment-sub';
      sub.textContent = `from ${p.payer_username || '—'} · ${p.method}`;
      main.appendChild(t);
      main.appendChild(sub);
      row.appendChild(main);

      const side = document.createElement('div');
      side.className = 'payment-side';
      const amt = document.createElement('div');
      amt.className = 'payment-amt';
      amt.textContent = `$${p.amount.toFixed(2)}`;
      const ref = document.createElement('div');
      ref.className = 'payment-ref';
      ref.textContent = p.transaction_ref.slice(0, 20) + '…';
      side.appendChild(amt);
      side.appendChild(ref);
      row.appendChild(side);

      list.appendChild(row);
    });
  } catch {
    hide(panel);
  }
}

// ── My Bids View ──────────────────────────────────────────
async function loadMyBidsView() {
  const myPayList = $('my-payments-list');
  const myBidsGrid = $('my-bids-grid');

  if (myPayList) {
    myPayList.innerHTML = '';
    try {
      const payments = await apiFetch('/payments/me');
      if (payments.length === 0) {
        const empty = document.createElement('div');
        empty.className = 'history-empty';
        empty.textContent = 'No payments yet';
        myPayList.appendChild(empty);
      } else {
        payments.forEach(p => {
          const row = document.createElement('div');
          row.className = 'payment-row';
          const main = document.createElement('div');
          main.className = 'payment-main';
          const t = document.createElement('div');
          t.className = 'payment-title';
          t.textContent = p.item_title || `Item #${p.item_id}`;
          const sub = document.createElement('div');
          sub.className = 'payment-sub';
          sub.textContent = `${p.method} · ${new Date(p.created_at + 'Z').toLocaleDateString()}`;
          main.appendChild(t);
          main.appendChild(sub);
          row.appendChild(main);
          const side = document.createElement('div');
          side.className = 'payment-side';
          const amt = document.createElement('div');
          amt.className = 'payment-amt';
          amt.textContent = `$${p.amount.toFixed(2)}`;
          side.appendChild(amt);
          row.appendChild(side);
          myPayList.appendChild(row);
        });
      }
    } catch { /* silent */ }
  }

  if (myBidsGrid) {
    myBidsGrid.innerHTML = '';
    try {
      const items = await apiFetch('/items');
      allItems = items;
      const myItems = items.filter(i =>
        i.highest_bidder_username === currentUser?.username
      );
      if (myItems.length === 0) {
        myBidsGrid.appendChild(buildEmptyState('No auctions won yet', 'Bids you win will appear here.'));
      } else {
        myItems.forEach((item, idx) => {
          myBidsGrid.appendChild(buildAuctionCard(item, idx));
        });
      }
    } catch { /* silent */ }
  }
}

// ── Profile Modal ─────────────────────────────────────────
function openProfileModal() {
  if (!currentUser) return;
  const { username, role } = currentUser;
  const initial = username.charAt(0).toUpperCase();
  const isSeller = role === 'Seller';

  setText('profile-name-display', username);
  setText('profile-role-badge', role);
  setText('profile-account-type', isSeller ? 'Seller Account' : 'Buyer Account');

  const avatar = $('profile-avatar-letter');
  if (avatar) avatar.textContent = initial;

  // Role badge color
  const roleBadge = $('profile-role-badge');
  if (roleBadge) {
    roleBadge.style.background = isSeller
      ? 'linear-gradient(135deg, rgba(99,140,255,0.2), rgba(167,139,255,0.2))'
      : 'linear-gradient(135deg, rgba(52,211,153,0.15), rgba(56,217,245,0.15))';
    roleBadge.style.color = isSeller ? 'var(--violet)' : 'var(--green)';
  }

  // Capabilities
  const cap = $('profile-capabilities');
  if (cap) {
    cap.innerHTML = '';
    const caps = isSeller
      ? ['✦ Create and manage auction listings', '📋 View received payments', '⬛ Close auctions early']
      : ['◈ Browse all active auctions', '💰 Place bids on items', '💳 Checkout and pay for won auctions'];
    caps.forEach(c => {
      const item = document.createElement('div');
      item.className = 'cap-item';
      item.textContent = c;
      cap.appendChild(item);
    });
  }

  // Show/hide seller-only buttons in profile
  qsa('.profile-actions .seller-only').forEach(el => {
    toggle(el, isSeller);
  });

  show('profile-modal');
}

// ── Auth ──────────────────────────────────────────────────
async function handleLogin() {
  const username = $('login-username')?.value.trim();
  const password = $('login-password')?.value;
  const errEl = $('login-error');

  if (!username || !password) {
    showAuthError(errEl, 'Please enter username and password');
    return;
  }
  if (errEl) hide(errEl);

  const btn = $('login-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Signing in…'; }

  try {
    const res = await apiFetch('/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
    saveAuth(res.access_token, res.role, username);
    hide('auth-modal');
    updateUIForAuth();
    showView('dashboard');
    toast(`Welcome back, ${username}!`, 'success', '● Signed In');
  } catch (e) {
    showAuthError(errEl, e.detail || 'Login failed');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Sign In'; }
  }
}

async function handleRegister() {
  const username = $('reg-username')?.value.trim();
  const password = $('reg-password')?.value;
  const role = $('reg-role')?.value;
  const errEl = $('reg-error');

  if (!username || !password) {
    showAuthError(errEl, 'Please fill all fields');
    return;
  }
  if (errEl) hide(errEl);

  const btn = $('register-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Creating account…'; }

  try {
    const normalizedRole = String(role || '').toLowerCase() === 'seller' ? 'Seller' : 'Buyer';

    await apiFetch('/register', {
      method: 'POST',
      body: JSON.stringify({
        username,
        password,
        role: normalizedRole,
      }),
    });
    // Auto-login after register
    const res = await apiFetch('/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
    saveAuth(res.access_token, res.role, username);
    hide('auth-modal');
    updateUIForAuth();
    showView('dashboard');
    toast(`Welcome to AuctionVault, ${username}!`, 'success', '✦ Account Created');
  } catch (e) {
    showAuthError(errEl, e.detail || 'Registration failed');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Create Account'; }
  }
}

function showAuthError(el, msg) {
  if (!el) return;
  el.textContent = msg;
  show(el);
}

async function logout() {
    try {
        await fetch('/logout', { method: 'POST' });
    } catch (e) { /* ignore */ }
    
    clearAuth();
    deleteCookie('refresh_token');
    deleteCookie('access_token');
    
    Object.values(countdownTimers).forEach(clearInterval);
    countdownTimers = {};
    allItems = [];
    hide('profile-modal');
    closeSidebar();
    updateUIForAuth();
    toast('Signed out successfully', 'info', 'Goodbye');
}

// ── Auth Modal Tabs ───────────────────────────────────────
function switchTab(tab) {
  const slider = $('tab-slider');
  const loginPanel = $('panel-login');
  const regPanel = $('panel-register');
  const loginTab = $('tab-login');
  const regTab = $('tab-register');

  if (tab === 'login') {
    if (slider) slider.classList.remove('right');
    show(loginPanel); hide(regPanel);
    if (loginTab) loginTab.classList.add('active');
    if (regTab) regTab.classList.remove('active');
  } else {
    if (slider) slider.classList.add('right');
    hide(loginPanel); show(regPanel);
    if (regTab) regTab.classList.add('active');
    if (loginTab) loginTab.classList.remove('active');
  }
}

function openAuthModal(tab = 'login') {
  switchTab(tab);
  show('auth-modal');
  setTimeout(() => {
    const input = tab === 'login' ? $('login-username') : $('reg-username');
    if (input) input.focus();
  }, 100);
}

// ══════════════════════════════════════════════════════════
// EVENT LISTENERS
// ══════════════════════════════════════════════════════════
document.addEventListener('DOMContentLoaded', () => {

  // Load saved auth
  if (loadAuth()) {
    updateUIForAuth();
    showView('dashboard');
  } else {
    updateUIForAuth();
  }

  // ── Navbar ──────────────────────────────────────────────
  $('nav-login-btn')?.addEventListener('click', () => openAuthModal('login'));
  $('nav-register-btn')?.addEventListener('click', () => openAuthModal('register'));
  $('hero-get-started-btn')?.addEventListener('click', () => openAuthModal('register'));
  $('hero-sign-in-btn')?.addEventListener('click', () => openAuthModal('login'));
  $('nav-profile-btn')?.addEventListener('click', openProfileModal);
  $('brand-link')?.addEventListener('click', e => {
    e.preventDefault();
    if (currentUser) showView('dashboard');
    else window.scrollTo({ top: 0, behavior: 'smooth' });
  });

  // ── Sidebar toggle ──────────────────────────────────────
  $('sidebar-toggle')?.addEventListener('click', () => {
    if (_sidebarOpen) closeSidebar();
    else openSidebar();
  });
  $('sidebar-close')?.addEventListener('click', closeSidebar);
  $('sidebar-overlay')?.addEventListener('click', closeSidebar);

  // ── Sidebar nav items ───────────────────────────────────
  $('sb-dashboard')?.addEventListener('click', e => { e.preventDefault(); showView('dashboard'); });
  $('sb-auctions')?.addEventListener('click', e => { e.preventDefault(); showView('auctions'); });
  $('sb-create')?.addEventListener('click', e => { e.preventDefault(); showView('auctions'); setTimeout(() => $('seller-panel')?.scrollIntoView({ behavior: 'smooth' }), 100); });
  $('sb-my-bids')?.addEventListener('click', e => { e.preventDefault(); showView('my-bids'); });
  $('sb-profile')?.addEventListener('click', e => { e.preventDefault(); closeSidebar(); openProfileModal(); });
  $('sb-logout-btn')?.addEventListener('click', logout);

  // ── Auth modal ──────────────────────────────────────────
  $('auth-modal-close')?.addEventListener('click', () => hide('auth-modal'));
  $('auth-modal')?.addEventListener('click', e => { if (e.target === $('auth-modal')) hide('auth-modal'); });
  $('tab-login')?.addEventListener('click', () => switchTab('login'));
  $('tab-register')?.addEventListener('click', () => switchTab('register'));
  $('login-btn')?.addEventListener('click', handleLogin);
  $('register-btn')?.addEventListener('click', handleRegister);

  // Enter key in auth fields
  ['login-username','login-password'].forEach(id => {
    $(id)?.addEventListener('keydown', e => { if (e.key === 'Enter') handleLogin(); });
  });
  ['reg-username','reg-password'].forEach(id => {
    $(id)?.addEventListener('keydown', e => { if (e.key === 'Enter') handleRegister(); });
  });

  // ── Profile modal ───────────────────────────────────────
  $('profile-modal-close')?.addEventListener('click', () => hide('profile-modal'));
  $('profile-modal')?.addEventListener('click', e => { if (e.target === $('profile-modal')) hide('profile-modal'); });

  // Profile action buttons
  $('profile-modal')?.addEventListener('click', e => {
    const btn = e.target.closest('[data-profile-action]');
    if (!btn) return;
    const action = btn.dataset.profileAction;
    hide('profile-modal');
    switch (action) {
      case 'dashboard': showView('dashboard'); break;
      case 'browse':    showView('auctions');  break;
      case 'create':    showView('auctions'); setTimeout(() => $('seller-panel')?.scrollIntoView({ behavior: 'smooth' }), 100); break;
      case 'logout':    logout(); break;
    }
  });

  // ── Quick action cards (dashboard) ──────────────────────
  $('quick-actions-grid')?.addEventListener('click', e => {
    const card = e.target.closest('[data-action]');
    if (!card) return;
    const action = card.dataset.action;
    switch (action) {
      case 'browse':   showView('auctions'); break;
      case 'create':   showView('auctions'); setTimeout(() => $('seller-panel')?.scrollIntoView({ behavior: 'smooth' }), 100); break;
      case 'my-bids':  showView('my-bids'); break;
      case 'profile':  openProfileModal(); break;
    }
  });

  // Dashboard "View All" button
  document.addEventListener('click', e => {
    const btn = e.target.closest('[data-action="browse"]');
    if (!btn) return;
    const inApp = btn.closest('#app-section');
    if (inApp) showView('auctions');
  });

  // ── Create auction form ──────────────────────────────────
  $('create-auction-form')?.addEventListener('submit', handleCreateAuction);

  // ── Auction controls ─────────────────────────────────────
  $('search-input')?.addEventListener('input', e => {
    searchQuery = e.target.value;
    renderItems();
  });

  qsa('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      qsa('.filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentFilter = btn.dataset.filter;
      renderItems();
    });
  });

  $('sort-select')?.addEventListener('change', e => {
    currentSort = e.target.value;
    renderItems();
  });

  $('refresh-btn')?.addEventListener('click', loadItems);

  // ── Item grid delegation ──────────────────────────────────
  function handleItemGridClick(e) {
    // Bid
    const bidBtn = e.target.closest('[data-action="bid"]');
    if (bidBtn) {
      const itemId = bidBtn.dataset.itemId;
      const card = bidBtn.closest('.auction-card');
      const input = card?.querySelector(`input[data-item-id="${itemId}"]`);
      if (!input || !input.value) { toast('Enter a bid amount', 'error'); return; }
      const amount = parseFloat(input.value);
      if (isNaN(amount) || amount <= 0) { toast('Invalid amount', 'error'); return; }
      placeBid(itemId, amount);
      return;
    }

    // Pay
    const payBtn = e.target.closest('[data-action="pay"]');
    if (payBtn) {
      openCheckout(payBtn.dataset.itemId);
      return;
    }

    // Close auction
    const closeBtn = e.target.closest('[data-action="close"]');
    if (closeBtn) {
      if (confirm('Close this auction now?')) closeAuction(closeBtn.dataset.itemId);
      return;
    }

    // Toggle bid history
    const histBtn = e.target.closest('[data-action="toggle-history"]');
    if (histBtn) {
      const itemId = histBtn.dataset.itemId;
      const card = histBtn.closest('.auction-card');
      const panel = card?.querySelector(`.bid-history[data-item-id="${itemId}"]`);
      if (!panel) return;
      const isOpen = panel.classList.contains('open');
      if (!isOpen) {
        panel.classList.add('open');
        histBtn.classList.add('open');
        loadBidHistory(itemId, panel);
      } else {
        panel.classList.remove('open');
        histBtn.classList.remove('open');
      }
    }
  }

  $('items-grid')?.addEventListener('click', handleItemGridClick);
  $('dashboard-auctions-grid')?.addEventListener('click', handleItemGridClick);
  $('my-bids-grid')?.addEventListener('click', handleItemGridClick);

  // ── Checkout modal ────────────────────────────────────────
  $('checkout-modal-close')?.addEventListener('click', () => hide('checkout-modal'));
  $('checkout-modal')?.addEventListener('click', e => { if (e.target === $('checkout-modal')) hide('checkout-modal'); });

  // ── Escape key ────────────────────────────────────────────
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
      if (!$('auth-modal')?.classList.contains('hidden')) { hide('auth-modal'); return; }
      if (!$('profile-modal')?.classList.contains('hidden')) { hide('profile-modal'); return; }
      if (!$('checkout-modal')?.classList.contains('hidden')) { hide('checkout-modal'); return; }
      if (_sidebarOpen) closeSidebar();
    }
  });
});
