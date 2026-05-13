// ═══════════════════════════════════════════════════════════
// AuctionVault — frontend
// All user-controlled strings rendered via textContent only.
// ═══════════════════════════════════════════════════════════

let currentToken = null;
let currentUser  = null;   // { id?, username, role }
let isSubmitting = false;
let allItems     = [];
let activeFilter = "all";
let activeSearch = "";
let activeSort   = "ending";
let pendingCheckoutItemId = null;
let selectedMethod = "demo_card";

const countdownIntervals = {};

// ─── DOM READY ────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  wireStaticListeners();
  const savedToken = localStorage.getItem("auction_token");
  if (savedToken) initApp(savedToken);
  else showLoggedOut();
});

function wireStaticListeners() {
  // Navbar
  on("nav-login-btn",    "click", () => openAuthModal("login"));
  on("nav-register-btn", "click", () => openAuthModal("register"));
  on("logout-btn",       "click", logout);
  on("nav-payments-btn", "click", openPaymentsPanel);

  // Hero CTAs
  on("hero-login-btn",    "click", () => openAuthModal("login"));
  on("hero-register-btn", "click", () => openAuthModal("register"));
  on("hero-explore-btn",  "click", handleExplore);
  on("hero-sell-btn",     "click", handleStartSelling);

  // Auth modal
  on("auth-close-btn", "click", closeAuthModal);
  on("auth-overlay",   "click", (e) => { if (e.target.id === "auth-overlay") closeAuthModal(); });
  on("tab-login",      "click", () => showAuthTab("login"));
  on("tab-register",   "click", () => showAuthTab("register"));
  on("login-form",     "submit", login);
  on("register-form",  "submit", register);

  // Seller form
  on("add-item-form", "submit", addItem);

  // Dashboard controls
  on("search-input", "input", (e) => { activeSearch = e.target.value.trim().toLowerCase(); renderItems(); });
  on("sort-select",  "change", (e) => { activeSort = e.target.value; renderItems(); });
  document.querySelectorAll(".filter-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      activeFilter = btn.dataset.filter;
      renderItems();
    });
  });

  // Checkout modal
  on("checkout-close-btn", "click", closeCheckoutModal);
  on("checkout-overlay",   "click", (e) => { if (e.target.id === "checkout-overlay") closeCheckoutModal(); });
  on("payment-done-btn",   "click", () => { closeCheckoutModal(); loadItems(); });
  on("pay-confirm-btn",    "click", confirmPayment);
  document.querySelectorAll(".method-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".method-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      selectedMethod = btn.dataset.method;
    });
  });

  // Payments panel
  on("payments-close-btn", "click", () => qs("#payments-panel").classList.add("hidden"));

  // Esc closes modals
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") { closeAuthModal(); closeCheckoutModal(); }
  });
}

const qs = (sel) => document.querySelector(sel);
function on(id, evt, handler) {
  const el = document.getElementById(id);
  if (el) el.addEventListener(evt, handler);
}

// ─── TOAST ────────────────────────────────────────────────
function toast(message, type = "info", ttl = 3500) {
  const wrap = qs("#toast-container");
  if (!wrap) return;
  const t = document.createElement("div");
  t.className = "toast toast-" + type;
  t.textContent = message;        // textContent — XSS safe
  wrap.appendChild(t);
  requestAnimationFrame(() => t.classList.add("show"));
  setTimeout(() => {
    t.classList.remove("show");
    setTimeout(() => t.remove(), 300);
  }, ttl);
}

function showAuthError(message) {
  const el = qs("#auth-error");
  el.textContent = message;
  el.classList.remove("hidden");
}
function clearAuthError() {
  const el = qs("#auth-error");
  el.textContent = "";
  el.classList.add("hidden");
}

function extractError(data, statusCode) {
  if (statusCode === 422) return "Restricted.";
  if (data && typeof data.detail === "string") return data.detail;
  return "An error occurred";
}

// ─── AUTH MODAL ───────────────────────────────────────────
function openAuthModal(tab = "login") {
  if (currentUser) return; // already logged in
  qs("#auth-overlay").classList.remove("hidden");
  showAuthTab(tab);
}
function closeAuthModal() {
  qs("#auth-overlay").classList.add("hidden");
  clearAuthError();
}
function showAuthTab(tab) {
  clearAuthError();
  const isLogin = tab === "login";
  qs("#tab-login").classList.toggle("active", isLogin);
  qs("#tab-register").classList.toggle("active", !isLogin);
  qs("#tab-login").setAttribute("aria-selected", isLogin);
  qs("#tab-register").setAttribute("aria-selected", !isLogin);
  qs("#panel-login").classList.toggle("hidden", !isLogin);
  qs("#panel-register").classList.toggle("hidden", isLogin);
  const slider = qs("#tab-slider");
  if (slider) slider.classList.toggle("right", !isLogin);
}

// ─── HERO HANDLERS ────────────────────────────────────────
function handleExplore() {
  if (!currentUser) {
    toast("Please login to view and bid on auctions", "info");
    openAuthModal("login");
    return;
  }
  qs("#app-section").scrollIntoView({ behavior: "smooth" });
}
function handleStartSelling() {
  if (!currentUser) {
    openAuthModal("register");
    setTimeout(() => {
      const sel = qs("#reg-role");
      if (sel) sel.value = "Seller";
      toast("Register as a Seller to list auctions", "info");
    }, 50);
    return;
  }
  if (currentUser.role !== "Seller") {
    toast("Seller account required to create auctions", "error");
    return;
  }
  const panel = qs("#seller-panel");
  if (panel) panel.scrollIntoView({ behavior: "smooth" });
}

// ─── AUTH ─────────────────────────────────────────────────
async function register(event) {
  event.preventDefault();
  if (isSubmitting) return;
  isSubmitting = true;
  clearAuthError();

  const username = qs("#reg-username").value.trim();
  const password = qs("#reg-password").value;
  const role     = qs("#reg-role").value;

  if (!role) { showAuthError("Please select a role"); isSubmitting = false; return; }

  try {
    const r = await fetch("/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password, role }),
    });
    const data = await r.json();
    if (!r.ok) { showAuthError(extractError(data, r.status)); return; }
    toast("Account created — please sign in", "success");
    qs("#register-form").reset();
    showAuthTab("login");
    qs("#login-username").value = username;
    qs("#login-password").focus();
  } catch (_) {
    showAuthError("Network error");
  } finally {
    isSubmitting = false;
  }
}

async function login(event) {
  event.preventDefault();
  if (isSubmitting) return;
  isSubmitting = true;
  clearAuthError();

  const username = qs("#login-username").value.trim();
  const password = qs("#login-password").value;

  try {
    const r = await fetch("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    const data = await r.json();
    if (!r.ok) { showAuthError(extractError(data, r.status)); return; }
    localStorage.setItem("auction_token", data.access_token);
    closeAuthModal();
    initApp(data.access_token);
    toast("Welcome back, " + username, "success");
  } catch (_) {
    showAuthError("Network error");
  } finally {
    isSubmitting = false;
  }
}

function initApp(token) {
  currentToken = token;
  try {
    const decoded = jwt_decode(token);
    currentUser = { username: decoded.sub, role: decoded.role };
  } catch (_) { logout(); return; }

  // Navbar swap
  qs("#nav-actions").classList.add("hidden");
  qs("#nav-user").classList.remove("hidden");
  qs("#nav-username").textContent  = currentUser.username;
  qs("#nav-role-badge").textContent = currentUser.role;
  qs("#nav-avatar").textContent    = currentUser.username.charAt(0).toUpperCase();

  // App dashboard
  qs("#app-section").classList.remove("hidden");
  qs("#seller-panel").classList.toggle("hidden", currentUser.role !== "Seller");

  loadItems();
}

function showLoggedOut() {
  qs("#nav-actions").classList.remove("hidden");
  qs("#nav-user").classList.add("hidden");
  qs("#app-section").classList.add("hidden");
  qs("#seller-panel").classList.add("hidden");
  qs("#payments-panel").classList.add("hidden");
}

function logout() {
  Object.values(countdownIntervals).forEach(clearInterval);
  Object.keys(countdownIntervals).forEach(k => delete countdownIntervals[k]);
  localStorage.removeItem("auction_token");
  currentToken = null;
  currentUser  = null;
  allItems = [];
  qs("#login-form").reset();
  qs("#register-form").reset();
  showLoggedOut();
  toast("Signed out", "info");
}

// ─── ITEMS ────────────────────────────────────────────────
async function loadItems() {
  try {
    const r = await fetch("/items");
    if (!r.ok) { toast("Failed to load auctions", "error"); return; }
    allItems = await r.json();
    renderItems();
    updateStats();
  } catch (_) { toast("Network error", "error"); }
}

function updateStats() {
  const active  = allItems.filter(i => i.status === "active").length;
  const closed  = allItems.filter(i => i.status === "closed").length;
  const top     = allItems.reduce((m, i) => Math.max(m, i.current_price || 0), 0);
  const ending  = allItems.filter(i => i.status === "active" && i.time_remaining_seconds < 600).length;
  qs("#stat-active-val").textContent = active;
  qs("#stat-closed-val").textContent = closed;
  qs("#stat-top-bid").textContent    = top > 0 ? "$" + top.toFixed(0) : "—";
  qs("#stat-ending").textContent     = ending;
}

function applyFilters(items) {
  let out = items.slice();
  if (activeFilter !== "all") out = out.filter(i => i.status === activeFilter);
  if (activeSearch)
    out = out.filter(i =>
      (i.title || "").toLowerCase().includes(activeSearch) ||
      (i.description || "").toLowerCase().includes(activeSearch)
    );
  switch (activeSort) {
    case "price-desc": out.sort((a, b) => b.current_price - a.current_price); break;
    case "price-asc":  out.sort((a, b) => a.current_price - b.current_price); break;
    case "newest":     out.sort((a, b) => b.id - a.id); break;
    case "ending":
    default:
      out.sort((a, b) => {
        if (a.status !== b.status) return a.status === "active" ? -1 : 1;
        return a.time_remaining_seconds - b.time_remaining_seconds;
      });
  }
  return out;
}

function renderItems() {
  Object.values(countdownIntervals).forEach(clearInterval);
  Object.keys(countdownIntervals).forEach(k => delete countdownIntervals[k]);

  const container = qs("#items-container");
  container.replaceChildren();
  const items = applyFilters(allItems);

  if (items.length === 0) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = "No auctions match your view.";
    container.appendChild(empty);
    return;
  }
  items.forEach((item, idx) => container.appendChild(buildItemCard(item, idx)));
}

function buildItemCard(item, index) {
  const isClosed = item.status === "closed";
  const isBuyer  = currentUser && currentUser.role === "Buyer";
  const isWinner = currentUser && item.highest_bidder_username === currentUser.username;
  const isPaid   = item.payment_status === "paid";

  const card = document.createElement("div");
  card.className = "item-card" + (isClosed ? " item-card--closed" : "");
  card.style.animationDelay = (index * 0.06) + "s";

  const badge = document.createElement("span");
  badge.className = "status-badge " + (isClosed ? "badge-closed" : "badge-active");
  badge.textContent = isClosed ? "Closed" : "Active";
  card.appendChild(badge);

  if (isClosed && isPaid) {
    const paid = document.createElement("span");
    paid.className = "status-badge badge-paid";
    paid.textContent = "Paid";
    card.appendChild(paid);
  }

  const title = document.createElement("div");
  title.className = "item-title";
  title.textContent = item.title;
  card.appendChild(title);

  const desc = document.createElement("div");
  desc.className = "item-description";
  desc.textContent = item.description || "No description";
  card.appendChild(desc);

  const price = document.createElement("div");
  price.className = "item-price";
  price.textContent = "$" + item.current_price.toFixed(2);
  card.appendChild(price);

  const meta = document.createElement("div");
  meta.className = "item-meta";
  meta.textContent = "Seller ID: " + item.seller_id;
  card.appendChild(meta);

  if (!isClosed) {
    const countdown = document.createElement("div");
    countdown.className = "countdown";
    card.appendChild(countdown);
    startCountdown(item.id, item.time_remaining_seconds, countdown);
  } else {
    const endInfo = document.createElement("div");
    endInfo.className = "item-meta";
    const endDate = new Date(item.end_time + "Z");
    endInfo.textContent = "Ended: " + endDate.toLocaleString();
    card.appendChild(endInfo);
  }

  // Winner / leader info
  if (isClosed) {
    const winnerBox = document.createElement("div");
    winnerBox.className = "winner-box";
    if (item.highest_bidder_username) {
      const trophy = document.createElement("span");
      trophy.textContent = "🏆 Winner: ";
      const w = document.createElement("strong");
      w.textContent = item.highest_bidder_username;
      winnerBox.appendChild(trophy); winnerBox.appendChild(w);
      const fp = document.createElement("div");
      fp.className = "winner-price";
      fp.textContent = "Final price: $" + item.current_price.toFixed(2);
      winnerBox.appendChild(fp);
    } else {
      winnerBox.textContent = "No bids placed";
      winnerBox.className += " no-winner";
    }
    card.appendChild(winnerBox);
  } else if (item.highest_bidder_username) {
    const leader = document.createElement("div");
    leader.className = "item-meta";
    leader.textContent = "Leading: " + item.highest_bidder_username;
    card.appendChild(leader);
  }

  // Bid form (active + buyer)
  if (isBuyer && !isClosed) {
    const bidForm = document.createElement("div");
    bidForm.className = "bid-form";
    const bidInput = document.createElement("input");
    bidInput.type = "number"; bidInput.placeholder = "Your bid ($)"; bidInput.step = "0.01";
    const minBid = item.current_price + (item.min_increment || 0.01);
    bidInput.min = minBid.toFixed(2);

    const bidBtn = document.createElement("button");
    bidBtn.type = "button"; bidBtn.className = "btn-bid"; bidBtn.textContent = "Place Bid";
    bidBtn.addEventListener("click", () => placeBid(item.id, bidInput.value, item.current_price, item.min_increment));

    bidForm.appendChild(bidInput); bidForm.appendChild(bidBtn);
    card.appendChild(bidForm);

    if (item.min_increment > 0) {
      const hint = document.createElement("div");
      hint.className = "bid-hint";
      hint.textContent = "Min increment: $" + item.min_increment.toFixed(2);
      card.appendChild(hint);
    }
  }

  // Pay Now (closed + winner + unpaid)
  if (isClosed && isWinner && !isPaid) {
    const payBtn = document.createElement("button");
    payBtn.type = "button";
    payBtn.className = "btn btn-primary btn-pay";
    payBtn.textContent = "💳 Pay Now — $" + item.current_price.toFixed(2);
    payBtn.addEventListener("click", () => openCheckout(item.id));
    card.appendChild(payBtn);
  }
  if (isClosed && isWinner && isPaid) {
    const done = document.createElement("div");
    done.className = "paid-line";
    done.textContent = "✓ Payment completed";
    card.appendChild(done);
  }

  // Bid history toggle
  const historySection = document.createElement("div");
  historySection.className = "bid-history hidden";

  const historyBtn = document.createElement("button");
  historyBtn.type = "button";
  historyBtn.className = "btn-history";
  historyBtn.textContent = "View Bid History";
  historyBtn.addEventListener("click", () => toggleBidHistory(item.id, historySection, historyBtn));
  card.appendChild(historyBtn);
  card.appendChild(historySection);

  return card;
}

// ─── COUNTDOWN ────────────────────────────────────────────
function startCountdown(itemId, initialSeconds, el) {
  if (countdownIntervals[itemId]) clearInterval(countdownIntervals[itemId]);
  let remaining = Math.max(0, Math.floor(initialSeconds));
  function tick() {
    if (remaining <= 0) {
      clearInterval(countdownIntervals[itemId]); delete countdownIntervals[itemId];
      el.textContent = "Auction ended — refreshing…";
      el.className = "countdown countdown--urgent";
      setTimeout(loadItems, 1200);
      return;
    }
    const h = Math.floor(remaining / 3600);
    const m = Math.floor((remaining % 3600) / 60);
    const s = remaining % 60;
    const parts = [];
    if (h > 0) parts.push(h + "h");
    parts.push(String(m).padStart(2, "0") + "m");
    parts.push(String(s).padStart(2, "0") + "s");
    el.textContent = "⏱ " + parts.join(" ");
    el.className = "countdown" + (remaining < 300 ? " countdown--urgent" : "");
    remaining--;
  }
  tick();
  countdownIntervals[itemId] = setInterval(tick, 1000);
}

// ─── ADD ITEM ─────────────────────────────────────────────
async function addItem(event) {
  event.preventDefault();
  if (isSubmitting) return;
  isSubmitting = true;

  const body = {
    title: qs("#item-title").value.trim(),
    description: qs("#item-description").value.trim(),
    starting_price: parseFloat(qs("#item-price").value),
    duration_minutes: parseInt(qs("#item-duration").value, 10),
    min_increment: parseFloat(qs("#item-increment").value) || 0.01,
  };

  try {
    const r = await fetch("/items", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer " + currentToken },
      body: JSON.stringify(body),
    });
    const data = await r.json();
    if (!r.ok) { toast(extractError(data, r.status), "error"); return; }
    toast("Auction launched", "success");
    qs("#add-item-form").reset();
    qs("#item-duration").value = "60";
    qs("#item-increment").value = "1.00";
    loadItems();
  } catch (_) { toast("Network error", "error"); }
  finally { isSubmitting = false; }
}

// ─── BID ──────────────────────────────────────────────────
async function placeBid(itemId, bidValue, currentPrice, minIncrement) {
  if (isSubmitting) return;
  isSubmitting = true;

  const amount = parseFloat(bidValue);
  const inc = minIncrement || 0.01;
  if (!amount || amount <= 0) { toast("Enter a valid bid amount", "error"); isSubmitting = false; return; }
  if (amount < currentPrice + inc) {
    toast("Bid must be at least $" + (currentPrice + inc).toFixed(2), "error");
    isSubmitting = false; return;
  }
  try {
    const r = await fetch("/items/" + itemId + "/bid", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer " + currentToken },
      body: JSON.stringify({ amount }),
    });
    const data = await r.json();
    if (!r.ok) { toast(extractError(data, r.status), "error"); return; }
    toast(data.message || "Bid placed", "success");
    loadItems();
  } catch (_) { toast("Network error", "error"); }
  finally { isSubmitting = false; }
}

// ─── BID HISTORY ──────────────────────────────────────────
async function toggleBidHistory(itemId, section, btn) {
  if (!section.classList.contains("hidden")) {
    section.classList.add("hidden");
    btn.textContent = "View Bid History"; return;
  }
  btn.textContent = "Loading…";
  await loadBidHistory(itemId, section);
  section.classList.remove("hidden");
  btn.textContent = "Hide Bid History";
}

async function loadBidHistory(itemId, section) {
  section.replaceChildren();
  try {
    const r = await fetch("/items/" + itemId + "/bids");
    if (!r.ok) {
      const msg = document.createElement("p");
      msg.textContent = "Bid history is not available yet.";
      section.appendChild(msg); return;
    }
    const bids = await r.json();
    if (bids.length === 0) {
      const msg = document.createElement("p");
      msg.className = "history-empty"; msg.textContent = "No bids yet.";
      section.appendChild(msg); return;
    }
    const heading = document.createElement("div");
    heading.className = "history-heading";
    heading.textContent = "Bid History (" + bids.length + ")";
    section.appendChild(heading);
    bids.forEach(bid => {
      const row = document.createElement("div"); row.className = "history-row";
      const b = document.createElement("span"); b.className = "history-bidder"; b.textContent = bid.bidder_username;
      const a = document.createElement("span"); a.className = "history-amount"; a.textContent = "$" + bid.amount.toFixed(2);
      const t = document.createElement("span"); t.className = "history-time";
      t.textContent = new Date(bid.created_at + "Z").toLocaleString();
      row.appendChild(b); row.appendChild(a); row.appendChild(t);
      section.appendChild(row);
    });
  } catch (_) {
    const msg = document.createElement("p");
    msg.textContent = "Network error loading bid history.";
    section.appendChild(msg);
  }
}

// ─── CHECKOUT / PAYMENT ───────────────────────────────────
async function openCheckout(itemId) {
  if (!currentToken) { toast("Please sign in", "error"); return; }
  pendingCheckoutItemId = itemId;
  selectedMethod = "demo_card";
  document.querySelectorAll(".method-btn").forEach((b, i) => b.classList.toggle("active", i === 0));
  qs("#payment-success").classList.add("hidden");
  qs("#checkout-body").classList.remove("hidden");
  qs("#demo-name").value = "";
  qs("#checkout-overlay").classList.remove("hidden");

  qs("#checkout-item-title").textContent = "Loading…";
  qs("#checkout-winner").textContent     = "—";
  qs("#checkout-amount").textContent     = "$—";

  try {
    const r = await fetch("/items/" + itemId + "/checkout", {
      headers: { Authorization: "Bearer " + currentToken },
    });
    const data = await r.json();
    if (!r.ok) {
      toast(extractError(data, r.status), "error");
      closeCheckoutModal(); return;
    }
    qs("#checkout-item-title").textContent = data.title;
    qs("#checkout-winner").textContent     = data.winner_username || "—";
    qs("#checkout-amount").textContent     = "$" + data.final_price.toFixed(2);
    if (!data.can_pay) {
      toast(data.message || "Payment not available", "info");
      qs("#pay-confirm-btn").disabled = true;
    } else {
      qs("#pay-confirm-btn").disabled = false;
    }
  } catch (_) {
    toast("Network error", "error");
    closeCheckoutModal();
  }
}

function closeCheckoutModal() {
  qs("#checkout-overlay").classList.add("hidden");
  pendingCheckoutItemId = null;
}

async function confirmPayment() {
  if (!pendingCheckoutItemId || isSubmitting) return;
  isSubmitting = true;
  const btn = qs("#pay-confirm-btn");
  btn.disabled = true;
  try {
    const r = await fetch("/payments", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer " + currentToken },
      body: JSON.stringify({
        item_id: pendingCheckoutItemId,
        method: selectedMethod,
        demo_name: qs("#demo-name").value.trim() || null,
      }),
    });
    const data = await r.json();
    if (!r.ok) { toast(extractError(data, r.status), "error"); btn.disabled = false; return; }
    qs("#checkout-body").classList.add("hidden");
    qs("#payment-success").classList.remove("hidden");
    qs("#payment-success-sub").textContent = "Paid $" + data.amount.toFixed(2) + " via " + data.method.replace("_", " ");
    qs("#payment-success-ref").textContent = data.transaction_ref;
    toast("Payment successful", "success");
  } catch (_) {
    toast("Network error", "error");
    btn.disabled = false;
  } finally { isSubmitting = false; }
}

// ─── PAYMENTS HISTORY ─────────────────────────────────────
async function openPaymentsPanel() {
  if (!currentUser) return;
  const panel = qs("#payments-panel");
  const list  = qs("#payments-list");
  const isSeller = currentUser.role === "Seller";
  qs("#payments-title").textContent = isSeller ? "Payments Received" : "Payment History";
  qs("#payments-sub").textContent   = isSeller
    ? "Demo payments collected on your auctions"
    : "Your recent demo transactions";
  panel.classList.remove("hidden");
  list.replaceChildren();
  const loading = document.createElement("div"); loading.className = "empty-state"; loading.textContent = "Loading…";
  list.appendChild(loading);

  const url = isSeller ? "/seller/payments" : "/payments/me";
  try {
    const r = await fetch(url, { headers: { Authorization: "Bearer " + currentToken } });
    if (!r.ok) { list.replaceChildren(); const e = document.createElement("div"); e.className="empty-state"; e.textContent="Could not load payments."; list.appendChild(e); return; }
    const rows = await r.json();
    list.replaceChildren();
    if (rows.length === 0) {
      const e = document.createElement("div"); e.className="empty-state";
      e.textContent = "No payments yet."; list.appendChild(e); return;
    }
    rows.forEach(p => list.appendChild(buildPaymentRow(p, isSeller)));
    panel.scrollIntoView({ behavior: "smooth" });
  } catch (_) {
    list.replaceChildren();
    const e = document.createElement("div"); e.className="empty-state"; e.textContent="Network error."; list.appendChild(e);
  }
}

function buildPaymentRow(p, isSeller) {
  const row = document.createElement("div"); row.className = "payment-row";

  const left = document.createElement("div"); left.className = "payment-main";
  const t = document.createElement("div"); t.className = "payment-title"; t.textContent = p.item_title || ("Item #" + p.item_id);
  const sub = document.createElement("div"); sub.className = "payment-sub";
  sub.textContent = (isSeller ? "Paid by " + (p.payer_username || "—") + " · " : "")
    + p.method.replace("_", " ")
    + " · " + new Date((p.paid_at || p.created_at) + "Z").toLocaleString();
  left.appendChild(t); left.appendChild(sub);

  const right = document.createElement("div"); right.className = "payment-side";
  const amt = document.createElement("div"); amt.className = "payment-amt"; amt.textContent = "$" + p.amount.toFixed(2);
  const ref = document.createElement("div"); ref.className = "payment-ref mono"; ref.textContent = p.transaction_ref;
  const st  = document.createElement("span"); st.className = "status-badge badge-paid"; st.textContent = p.status.toUpperCase();
  right.appendChild(amt); right.appendChild(ref); right.appendChild(st);

  row.appendChild(left); row.appendChild(right);
  return row;
}
