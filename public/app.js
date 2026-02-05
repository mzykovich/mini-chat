  const statusEl = document.getElementById("status");
  const authBox = document.getElementById("authBox");
  const loginScreen = document.getElementById("loginScreen");
  const appInterface = document.getElementById("appInterface");
  const meBox = document.getElementById("meBox");
  const meNameEl = document.getElementById("meName");
  const meEmailEl = document.getElementById("meEmail");
  const meRoleEl = document.getElementById("meRole");
  const logoutBtn = document.getElementById("logoutBtn");
  const notifyBtn = document.getElementById("notifyBtn");

  const tabLogin = document.getElementById("tabLogin");
  const tabRegister = document.getElementById("tabRegister");
  const loginForm = document.getElementById("loginForm");
  const registerForm = document.getElementById("registerForm");

  const loginEmail = document.getElementById("loginEmail");
  const loginPass = document.getElementById("loginPass");
  const loginBtn = document.getElementById("loginBtn");
  const loginMsg = document.getElementById("loginMsg");

  const regName = document.getElementById("regName");
  const regEmail = document.getElementById("regEmail");
  const regPass = document.getElementById("regPass");
  const regInvite = document.getElementById("regInvite");
  const regPosition = document.getElementById("regPosition");
  const registerBtn = document.getElementById("registerBtn");
  const registerMsg = document.getElementById("registerMsg");

  
  const regAck = document.getElementById(\"regAck\");
const channelsCard = document.getElementById("channelsCard");
  const channelsEl = document.getElementById("channels");
  const channelsSearch = document.getElementById("channelsSearch");
  const addChannelBtn = document.getElementById("addChannelBtn");

  const dmCard = document.getElementById("dmCard");
  const dmListEl = document.getElementById("dmList");
  const newDmBtn = document.getElementById("newDmBtn");
  const dmSearch = document.getElementById("dmSearch");
  const dmUserSelect = document.getElementById("dmUserSelect");
  const dmOpenBtn = document.getElementById("dmOpenBtn");
  const dmPickerRow = document.getElementById("dmPickerRow");
  const dmUserPickInput = document.getElementById("dmUserPickInput");
  const dmUserPickMenu = document.getElementById("dmUserPickMenu");
  const dmUserPickSearch = document.getElementById("dmUserPickSearch");
  const dmUserPickList = document.getElementById("dmUserPickList");

  // people directory
  const peopleCard = document.getElementById("peopleCard");
  const refreshPeopleBtn = document.getElementById("refreshPeopleBtn");
  const peopleSearch = document.getElementById("peopleSearch");
  const peopleList = document.getElementById("peopleList");

  const sidebarModeWorkTab = document.getElementById("sidebarModeWork");
  const sidebarModePersonalTab = document.getElementById("sidebarModePersonal");

  const titleEl = document.getElementById("title");
  const hintEl = document.getElementById("hint");
  const mobileBackBtn = document.getElementById("mobileBackBtn");

  const log = document.getElementById("log");
  const text = document.getElementById("text");
  const sendBtn = document.getElementById("send");
  const fileInput = document.getElementById("file");
  const fileBtn = document.getElementById("fileBtn");
  const attachPreview = document.getElementById("attachPreview");
  const attachPreviewText = document.getElementById("attachPreviewText");
  const attachRemoveBtn = document.getElementById("attachRemoveBtn");

  const openAdminBtn = document.getElementById("openAdminBtn");
  const adminCard = document.getElementById("adminModal");
  const closeAdminBtn = document.getElementById("closeAdminBtn");

  // admin
  const rolesList = document.getElementById("rolesList");
  const usersList = document.getElementById("usersList");
  const adminUserPickInput = document.getElementById("adminUserPickInput");
  const adminUserPickMenu = document.getElementById("adminUserPickMenu");
  const adminUserPickSearch = document.getElementById("adminUserPickSearch");
  const adminUserPickList = document.getElementById("adminUserPickList");
  const auditList = document.getElementById("auditList");
  const newRoleName = document.getElementById("newRoleName");
  const newRoleDisplay = document.getElementById("newRoleDisplay");
  const createRoleBtn = document.getElementById("createRoleBtn");
  const newChannelName = document.getElementById("newChannelName");
  const newChannelPublic = document.getElementById("newChannelPublic");
  const createChannelBtn = document.getElementById("createChannelBtn");
  const accessChannel = document.getElementById("accessChannel");
  const editChannelName = document.getElementById("editChannelName");
  const editChannelPrivacy = document.getElementById("editChannelPrivacy");
  const saveChannelPropsBtn = document.getElementById("saveChannelPropsBtn");
  const deleteChannelBtn = document.getElementById("deleteChannelBtn");
  const channelPropsMsg = document.getElementById("channelPropsMsg");
  const loadAccessBtn = document.getElementById("loadAccessBtn");
  const accessRoles = document.getElementById("accessRoles");
  const accessRolesInput = document.getElementById("accessRolesInput");
  const accessRolesMenu = document.getElementById("accessRolesMenu");
  const accessRolesSearch = document.getElementById("accessRolesSearch");
  const accessUsers = document.getElementById("accessUsers");
  const accessUsersInput = document.getElementById("accessUsersInput");
  const accessUsersMenu = document.getElementById("accessUsersMenu");
  const accessUsersSearch = document.getElementById("accessUsersSearch");
  const saveAccessBtn = document.getElementById("saveAccessBtn");
  const accessMsg = document.getElementById("accessMsg");

  // admin DM audit
  const dmAuditSelect = document.getElementById("dmAuditSelect");
  const dmAuditLoadBtn = document.getElementById("dmAuditLoadBtn");
  const dmAuditLog = document.getElementById("dmAuditLog");
  const dmAuditMessages = document.getElementById("dmAuditMessages");

  // admin invites
  const inviteMaxUses = document.getElementById("inviteMaxUses");
  const inviteExpiresHours = document.getElementById("inviteExpiresHours");
  const inviteCreateBtn = document.getElementById("inviteCreateBtn");
  const inviteMsg = document.getElementById("inviteMsg");
  const invitesList = document.getElementById("invitesList");
  const inviteQuick1 = document.getElementById("inviteQuick1");
  const inviteQuick24 = document.getElementById("inviteQuick24");
  const inviteQuick10 = document.getElementById("inviteQuick10");

  const adminTabs = [...document.querySelectorAll("[data-admin-tab]")];
  const adminViews = {
    roles: document.getElementById("adminRoles"),
    users: document.getElementById("adminUsers"),
    channels: document.getElementById("adminChannels"),
    audit: document.getElementById("adminAudit"),
    dms: document.getElementById("adminDms"),
    settings: document.getElementById("adminSettings"),
    invites: document.getElementById("adminInvites"),
  };

  let me = null;
  let ws = null;

  // NEW: разрешить регистрацию первого пользователя (узнаем с сервера)
  let allowFirstRegistration = false;
  let hasInviteParam = false;

  let channels = [];             // {id,name,isPublic,unreadCount,lastMessageId}
  let dmChats = [];              // {id,otherUser,unreadCount,lastMessageId,last...}

  let activeMode = "channel";    // channel | dm
  let activeChannelId = null;
  let activeDmChatId = null;
  let activeDmOther = null;

  let roles = [];
  let users = [];
  let adminAllChannels = [];
  let adminSelectedUserId = null;

  // people
  let people = [];

  let sidebarMode = "work"; // work | personal

  const MOBILE_LAYOUT_MAX = 900;
  const mobileLayoutMq = window.matchMedia(`(max-width:${MOBILE_LAYOUT_MAX}px)`);

  function isMobileLayout() {
    return Boolean(mobileLayoutMq && mobileLayoutMq.matches);
  }

  function setMobileChatOpen(isOpen) {
    if (!appInterface) return;
    const open = Boolean(isOpen && isMobileLayout());
    appInterface.classList.toggle("mobile-chat-open", open);
    if (mobileBackBtn) mobileBackBtn.classList.toggle("hidden", !open);
  }

  function onMobileLayoutChange() {
    if (!isMobileLayout()) setMobileChatOpen(false);
  }

  if (mobileBackBtn) mobileBackBtn.onclick = () => setMobileChatOpen(false);
  if (mobileLayoutMq && typeof mobileLayoutMq.addEventListener === "function") {
    mobileLayoutMq.addEventListener("change", onMobileLayoutChange);
  } else if (mobileLayoutMq && typeof mobileLayoutMq.addListener === "function") {
    mobileLayoutMq.addListener(onMobileLayoutChange);
  }

  function applySidebarMode() {
    const isWork = (sidebarMode === "work");
    if (sidebarModeWorkTab && sidebarModePersonalTab) {
      sidebarModeWorkTab.classList.toggle("active", isWork);
      sidebarModePersonalTab.classList.toggle("active", !isWork);
    }
    if (channelsCard) channelsCard.classList.toggle("hidden", !isWork);
    if (peopleCard) peopleCard.classList.toggle("hidden", !isWork);
    if (dmCard) dmCard.classList.toggle("hidden", isWork);
  }

  function setSidebarMode(mode) {
    sidebarMode = (mode === "personal") ? "personal" : "work";
    applySidebarMode();
  }

  if (sidebarModeWorkTab) sidebarModeWorkTab.onclick = () => setSidebarMode("work");
  if (sidebarModePersonalTab) sidebarModePersonalTab.onclick = () => setSidebarMode("personal");

  // attachments
  let pendingAttachment = null; // {id,name,mime,url,isImage,size}

  // presence + receipts
  let onlineUserIds = new Set();
  // messageId -> {readCount,total}
  let receiptByMessageId = new Map();
  // messageId -> fromId (нужно чтобы показывать receipt только для твоих)
  let messageFromId = new Map();
  // messageId -> text (для редактирования)
  let messageTextById = new Map();

  function updateHeaderStatus() {
    // Канал: показываем сколько пользователей онлайн в целом (на сервере)
    if (activeMode === "channel") {
      if (activeChannelId) {
        hintEl.textContent = `онлайн: ${onlineUserIds.size}`;
      }
      return;
    }
    // DM: показываем онлайн/оффлайн собеседника
    if (activeMode === "dm") {
      if (activeDmOther && activeDmOther.id) {
        const isOn = onlineUserIds.has(Number(activeDmOther.id));
        hintEl.textContent = isOn ? "в сети" : "не в сети";
      }
      return;
    }
    // default
    // hintEl.textContent stays as is
  }

  function esc(s) {
    return String(s || "").replace(/[&<>"']/g, c => ({
      "&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"
    }[c]));
  }


/* =======================
   Уведомления (Вариант А)
   - Работают, пока вкладка/браузер открыты
   - Показываем уведомление, когда страница не активна (document.hidden)
   - По умолчанию выключены, включаются кнопкой (сохранение в localStorage)
======================= */
const NOTIF_KEY = "corpchat_notifications_enabled";
let notificationsEnabled = (localStorage.getItem(NOTIF_KEY) === "1");

function updateNotifyBtnUI() {
  if (!notifyBtn) return;
  notifyBtn.classList.toggle("hidden", !me); // показываем только после входа
  notifyBtn.classList.toggle("notif-on", !!notificationsEnabled);
  notifyBtn.classList.toggle("notif-off", !notificationsEnabled);
  notifyBtn.style.opacity = "1";
  notifyBtn.title = notificationsEnabled ? "Уведомления: включены" : "Уведомления: выключены";
}

async function ensureNotificationPermission() {
  if (!("Notification" in window)) return false;
  if (Notification.permission === "granted") return true;
  if (Notification.permission === "denied") return false;
  const p = await Notification.requestPermission();
  return p === "granted";
}

async function toggleNotifications() {
  if (!("Notification" in window)) {
    alert("Уведомления не поддерживаются этим браузером.");
    return;
  }
  if (!notificationsEnabled) {
    const ok = await ensureNotificationPermission();
    if (!ok) {
      alert("Нужно разрешить уведомления в браузере.");
      notificationsEnabled = false;
      localStorage.setItem(NOTIF_KEY, "0");
      updateNotifyBtnUI();
    if (addChannelBtn) {
      const canManage = me && (me.isSuperadmin || me.systemRole === "OWNER" || me.systemRole === "ADMIN");
      addChannelBtn.style.display = canManage ? "inline-flex" : "none";
    }

      return;
    }
    notificationsEnabled = true;
    localStorage.setItem(NOTIF_KEY, "1");
  } else {
    notificationsEnabled = false;
    localStorage.setItem(NOTIF_KEY, "0");
  }
  updateNotifyBtnUI();
}

function maybeNotify({ title, body, tag }) {
  try {
    if (!notificationsEnabled) return;
    if (!("Notification" in window)) return;
    if (Notification.permission !== "granted") return;
    // показываем только когда вкладка не активна
    if (!document.hidden) return;
    new Notification(title, { body, tag });
  } catch {}
}

  async function api(path, opts) {
    const res = await fetch(path, { credentials: "include", ...opts });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || data.ok === false) throw new Error(data.message || data.code || "Request failed");
    return data;
  }

  function dotHtml(isOn, userId, msgId) {
    const uid = userId ? ` data-uid="${Number(userId)}"` : "";
    const mid = msgId ? ` data-mid="${Number(msgId)}"` : "";
    return `<span class="dot ${isOn ? "on" : "off"}"${uid}${mid}></span>`;
  }

  function updateLogPresenceDots() {
    const dots = log.querySelectorAll(".dot[data-uid]");
    for (const d of dots) {
      const uid = Number(d.getAttribute("data-uid") || 0);
      const on = onlineUserIds.has(uid);
      d.classList.toggle("on", on);
      d.classList.toggle("off", !on);
    }
  }


  function badgeHtml(n) {
    if (!n || n <= 0) return "";
    const t = (n > 9) ? "9+" : String(n);
    return `<span class="badge">${t}</span>`;
  }


  function updateAttachPreview() {
    if (!pendingAttachment) {
      attachPreview.classList.add("hidden");
      attachPreviewText.textContent = "";
      return;
    }
    attachPreview.classList.remove("hidden");
    const sz = pendingAttachment.size ? ` (${Math.round(pendingAttachment.size/1024)} KB)` : "";
    attachPreviewText.textContent = `Прикреплено: ${pendingAttachment.name}${sz}`;
  }

  function renderAttachmentHtml(att) {
    if (!att || !att.url) return "";
    const name = esc(att.name || "file");
    const url = esc(att.url);
    const mime = String(att.mime || "");
    const isImg = Boolean(att.isImage || mime.startsWith("image/"));
    if (isImg) {
      return `<div class="attach"><a href="${url}" target="_blank" rel="noopener"><img src="${url}" alt="${name}"/></a><div class="muted">${name}</div></div>`;
    }
    return `<div class="attach"><a href="${url}" target="_blank" rel="noopener">📎 ${name}</a></div>`;
  }


  async function createInviteAndCopy(maxUses, expiresInHours) {
    inviteMsg.textContent = "";
    inviteCreateBtn.disabled = true;
    try {
      const resp = await api("/api/admin/invites", {
        method: "POST",
        headers: { "Content-Type":"application/json" },
        body: JSON.stringify({ maxUses, expiresInHours })
      });
      const token = resp.invite?.token;
      if (!token) throw new Error("Не удалось создать инвайт");
      const link = `${location.origin}/?invite=${token}`;

      try {
        await navigator.clipboard.writeText(link);
        inviteMsg.textContent = "✅ Инвайт создан и ссылка скопирована";
      } catch {
        inviteMsg.textContent = "✅ Инвайт создан. Скопируй ссылку: " + link;
      }

      await refreshAdmin();
    } catch (e) {
      inviteMsg.textContent = "❌ " + String(e.message || e);
    } finally {
      inviteCreateBtn.disabled = false;
    }
  }


  function setAuthMode(mode) {
        // NEW: регистрация разрешена по инвайту, либо для первого пользователя, либо по ?register=1 (временный bootstrap)
    const allowRegister = hasInviteParam || allowFirstRegistration || location.search.includes("register=1");
    if (!allowRegister && mode === "register") {
      return;
    }


    if (mode === "login") {
      tabLogin.classList.add("active");
      tabRegister.classList.remove("active");
      loginForm.classList.remove("hidden");
      registerForm.classList.add("hidden");
    } else {
      tabRegister.classList.add("active");
      tabLogin.classList.remove("active");
      registerForm.classList.remove("hidden");
      loginForm.classList.add("hidden");
    }
  }
  tabLogin.onclick = () => setAuthMode("login");
  tabRegister.onclick = () => setAuthMode("register");

  let screenSwapNonce = 0;
  function showScreen(el, nonce) {
    if (!el) return;
    el.classList.remove("hidden");
    el.classList.add("is-hidden");
    requestAnimationFrame(() => {
      if (nonce !== screenSwapNonce) return;
      el.classList.remove("is-hidden");
    });
  }

  function hideScreen(el, nonce) {
    if (!el) return Promise.resolve();
    if (el.classList.contains("hidden")) {
      el.classList.add("is-hidden");
      return Promise.resolve();
    }
    if (el.classList.contains("is-hidden")) {
      el.classList.add("hidden");
      return Promise.resolve();
    }

    el.classList.add("is-hidden");
    return new Promise((resolve) => {
      let done = false;
      const finish = () => {
        if (done) return;
        done = true;
        el.removeEventListener("transitionend", onEnd);
        if (nonce === screenSwapNonce) el.classList.add("hidden");
        resolve();
      };
      const onEnd = (e) => {
        if (e.target !== el) return;
        finish();
      };
      el.addEventListener("transitionend", onEnd);
      setTimeout(finish, 320);
    });
  }

  function swapScreens(showEl, hideEl) {
    const nonce = ++screenSwapNonce;
    showScreen(showEl, nonce);
    return hideScreen(hideEl, nonce);
  }

  function swapScreensAfterHide(showEl, hideEl) {
    const nonce = ++screenSwapNonce;
    return hideScreen(hideEl, nonce).then(() => {
      if (nonce !== screenSwapNonce) return;
      showScreen(showEl, nonce);
    });
  }

  async function uiLoggedOut() {
    me = null;
    await swapScreensAfterHide(loginScreen, appInterface);

    titleEl.textContent = "—";
    hintEl.textContent = "Сначала войди/зарегистрируйся";
    text.disabled = true;
    sendBtn.disabled = true;
    fileBtn.disabled = true;
    pendingAttachment = null;
    updateAttachPreview();
    log.innerHTML = "";

    onlineUserIds = new Set();
    receiptByMessageId = new Map();
    messageFromId = new Map();
    messageTextById = new Map();
    messageTextById = new Map();
    activeMode = "channel";
    activeChannelId = null;
    activeDmChatId = null;
    sidebarMode = "work";
    applySidebarMode();
    setMobileChatOpen(false);

    if (ws) { try { ws.close(); } catch {} }
    ws = null;

    // регистрация только по инвайту
    tabRegister.classList.toggle("hidden", !hasInviteParam);

  }

  function uiLoggedIn() {
    swapScreens(appInterface, loginScreen);
    meBox.classList.remove("hidden");
    logoutBtn.classList.remove("hidden");
    channelsCard.classList.remove("hidden");
    dmCard.classList.remove("hidden");
    peopleCard.classList.remove("hidden");
    applySidebarMode();

    hintEl.textContent = "Выбери канал или DM слева";
    text.disabled = false;
    sendBtn.disabled = false;
    fileBtn.disabled = false;

    meNameEl.textContent = me.displayName;
    meEmailEl.textContent = me.email;
    meRoleEl.textContent = me.systemRole;

    const canAdmin = (me.systemRole === "OWNER" || me.systemRole === "ADMIN" || me.isSuperadmin);
    openAdminBtn.classList.toggle("hidden", !canAdmin);
    updateNotifyBtnUI();
    adminSettingsTab.classList.toggle("hidden", !me.isSuperadmin);
    applyAdminTabPermissions();
    setMobileChatOpen(false);
  }

  function applyAdminTabPermissions() {
    const canOwnerView = (me && (me.systemRole === "OWNER" || me.isSuperadmin));
    // OWNER/SUPERADMIN: все вкладки
    // ADMIN: без "Аудит" и "DM аудит"
    const hideForAdmin = new Set(["audit", "dms"]);
    for (const t of adminTabs) {
      const tab = t.dataset.adminTab;
      if (!tab) continue;
      const shouldHide = (!canOwnerView && hideForAdmin.has(tab));
      t.classList.toggle("hidden", shouldHide);
      // also hide corresponding view if needed
      if (adminViews[tab]) adminViews[tab].classList.toggle("hidden", shouldHide || !t.classList.contains("active"));
    }

    // если текущая активная вкладка недоступна — переключим на roles
    const activeTabEl = adminTabs.find(t => t.classList.contains("active"));
    const activeTab = activeTabEl ? activeTabEl.dataset.adminTab : null;
    if (activeTab && !canOwnerView && hideForAdmin.has(activeTab)) {
      setAdminTab("roles");
    }
  }


  if (notifyBtn) notifyBtn.onclick = () => toggleNotifications();
  if (addChannelBtn) addChannelBtn.onclick = async () => {
    if (!me) return;
    const canManage = me.isSuperadmin || me.systemRole === "OWNER" || me.systemRole === "ADMIN";
    if (!canManage) return;
    const raw = prompt("Название канала:", "new-channel");
    if (!raw) return;
    const isPublic = confirm("Сделать канал публичным?\nОК = публичный, Отмена = приватный");
    try {
      await api("/api/admin/channels", {
        method: "POST",
        headers: { "Content-Type":"application/json" },
        body: JSON.stringify({ name: raw, isPublic })
      });
      await refreshChannels();
    } catch (e) {
      alert("Не удалось создать канал: " + (e?.message || e));
    }
  };

  logoutBtn.onclick = async () => {
    try { await api("/api/logout", { method: "POST" }); } catch {}
    await uiLoggedOut();
    statusEl.textContent = "Вышел";
  };

  async function loadPositions() {
    const data = await api("/api/positions");
    regPosition.innerHTML = "";
    for (const p of data.positions) {
      const opt = document.createElement("option");
      opt.value = String(p.id);
      opt.textContent = p.displayName;
      regPosition.appendChild(opt);
    }
  }

  async function refreshChannels() {
    const data = await api("/api/channels");
    channels = data.channels || [];
    renderChannels();
  }


  async function refreshPeople() {
    const data = await api("/api/users");
    people = data.users || [];
    renderPeople();
  }

  function renderPeople() {
    const q = String(peopleSearch.value || "").trim().toLowerCase();
    const list = (people || []).filter(u => {
      if (!q) return true;
      return (String(u.displayName||"").toLowerCase().includes(q) || String(u.email||"").toLowerCase().includes(q));
    });

    peopleList.innerHTML = "";
    for (const u of list) {
      const isOn = u.isSuperadmin ? true : onlineUserIds.has(Number(u.id));
      const el = document.createElement("div");
      el.className = "item";
      const inactive = (u.isActive === false) ? " <span class='pill danger'>inactive</span>" : "";
      el.innerHTML = `
        <div class="leftline" style="min-width:0;">
          ${dotHtml(isOn)}
          <div class="truncate"><b>${esc(u.displayName)}</b>${inactive}<div class="muted truncate">${esc(u.email)}</div></div>
        </div>
      `;
      el.onclick = async () => {
        // открыть/создать DM
        const opened = await api("/api/dm/open", {
          method: "POST",
          headers: { "Content-Type":"application/json" },
          body: JSON.stringify({ userId: Number(u.id) })
        });
        await refreshDmList();
      await refreshPeople();
        const chat = dmChats.find(c => Number(c.id) === Number(opened.chatId));
        if (chat) openDmChat(chat.id, chat.otherUser, true);
        else openDmChat(opened.chatId, { id: Number(u.id), displayName: u.displayName, email: u.email }, true);
      };
      peopleList.appendChild(el);
    }
  }

  async function refreshDmList() {
    const data = await api("/api/dm");
    dmChats = data.chats || [];
    renderDmListUI();
  }

  loginBtn.onclick = async () => {
    loginMsg.textContent = "";
    loginBtn.disabled = true;
    try {
      const data = await api("/api/login", {
        method: "POST",
        headers: { "Content-Type":"application/json" },
        body: JSON.stringify({ email: loginEmail.value, password: loginPass.value })
      });
      me = data.me;
      statusEl.textContent = "Вошёл";
      uiLoggedIn();
      await initWs();
      await refreshChannels();
      await refreshDmList();
      await refreshPeople();
    } catch (e) {
      loginMsg.textContent = String(e.message || e);
    } finally {
      loginBtn.disabled = false;
    }
  };

  registerBtn.onclick = async () => {
    if (regAck && !regAck.checked) {
      registerMsg.textContent = "Нужно принять условие о просмотре сообщений.";
      return;
    }
registerMsg.textContent = "";
    registerBtn.disabled = true;
    try {
      const data = await api("/api/register", {
        method: "POST",
        headers: { "Content-Type":"application/json" },
        body: JSON.stringify({
          displayName: regName.value,
          email: regEmail.value,
          password: regPass.value,
          positionRoleId: Number(regPosition.value),
          inviteToken: (document.getElementById('regInvite')?.value || '').trim()
        })
      });
      me = data.me;
      statusEl.textContent = "Зарегистрирован";
      uiLoggedIn();
      await initWs();
      await refreshChannels();
      await refreshDmList();
      await refreshPeople();
    } catch (e) {
      registerMsg.textContent = String(e.message || e);
    } finally {
      registerBtn.disabled = false;
    }
  };


  function renderDeleteButton(msgId) {
    const btn = document.getElementById(`delbtn_${msgId}`);
    if (!btn) return;

    const fromId = Number(messageFromId.get(msgId) || 0);
    const isMine = me && fromId === Number(me.id);
    btn.classList.toggle("hidden", !isMine);

    btn.onclick = async () => {
      if (!confirm("Удалить сообщение?")) return;
      if (!ws || ws.readyState !== 1) return;

      if (activeMode === "channel" && activeChannelId) {
        ws.send(JSON.stringify({ type: "delete", messageId: Number(msgId) }));
      } else if (activeMode === "dm" && activeDmChatId) {
        ws.send(JSON.stringify({ type: "dm_delete", messageId: Number(msgId) }));
      }
    };
  }


  function renderEditButton(msgId) {
    const btn = document.getElementById(`editbtn_${msgId}`);
    if (!btn) return;

    const fromId = Number(messageFromId.get(msgId) || 0);
    const isMine = me && fromId === Number(me.id);
    btn.classList.toggle("hidden", !isMine);

    btn.onclick = async () => {
      const cur = (messageTextById.get(Number(msgId)) || "").trim();
      const next = prompt("Изменить сообщение:", cur);
      if (next === null) return;
      const t = String(next).trim().slice(0, 2000);
      if (!t) return;

      if (!ws || ws.readyState !== 1) return;

      if (activeMode === "channel" && activeChannelId) {
        ws.send(JSON.stringify({ type: "edit", messageId: Number(msgId), text: t }));
      } else if (activeMode === "dm" && activeDmChatId) {
        ws.send(JSON.stringify({ type: "dm_edit", messageId: Number(msgId), text: t }));
      }
    };
  }

  function renderReceipt(msgId) {
    const el = document.getElementById(`rc_${msgId}`);
    if (!el) return;

    // receipts показываем только на твоих сообщениях
    const fromId = Number(messageFromId.get(msgId) || 0);
    const isMine = me && fromId === Number(me.id);
    if (!isMine) {
      el.textContent = "";
      el.classList.add("dim");
      return;
    }

    el.classList.remove("dim");

    const r = receiptByMessageId.get(msgId);
    if (!r || !r.total) {
      el.textContent = "✓";
      return;
    }

    // чтобы не путать: readCount включает и тебя, это нормально (реально прочитал = ты тоже)
    if (r.readCount >= r.total) {
      el.textContent = "✓✓";
    } else {
      el.textContent = `✓ ${r.readCount}/${r.total}`;
    }
  }

  
  function findMsgRootById(msgId) {
    return document.getElementById(`msg_${msgId}`);
  }

  function updateMessageInDom(msgId, patch) {
    const root = findMsgRootById(msgId);
    if (!root) return;

    const bubble = root.querySelector(".bubble");
    const metaText = root.querySelector(".meta .truncate");

    if (patch.deleted) {
      messageTextById.set(Number(msgId), "");
      if (bubble) bubble.innerHTML = '<span class="muted">🗑 Сообщение удалено</span>';
      const actions = root.querySelector(".msg-actions");
      if (actions) actions.remove();
      // remove attachment
      const att = root.querySelector(".attach");
      if (att) att.remove();
    }

    if (patch.text !== undefined) {
      messageTextById.set(Number(msgId), String(patch.text || ""));
      if (bubble) bubble.textContent = String(patch.text || "");
    }

    if (patch.edited) {
      if (metaText && !metaText.textContent.includes("(edited)")) metaText.textContent += " • (edited)";
    }
  }

function addMsg(m) {
    messageFromId.set(m.id, Number(m.fromId));
    messageTextById.set(Number(m.id), m.deletedAt ? "" : String(m.text || ""));
    if (m.read) receiptByMessageId.set(m.id, m.read);

    const div = document.createElement("div");
    div.className = "msg";
    div.id = `msg_${m.id}`;

    const at = new Date(m.at).toLocaleTimeString([], {hour:"2-digit", minute:"2-digit"});
    const isOn = onlineUserIds.has(Number(m.fromId));

    div.innerHTML = `
      <div class="meta">
        <span style="display:flex; gap:8px; align-items:center;">
          ${dotHtml(isOn, m.fromId, m.id)}
          <span class="truncate">${esc(m.from)} • ${at}${m.editedAt ? " • (edited)" : ""}</span>
        </span>
        <span style="display:flex; align-items:center; gap:8px;">
          <span class="receipt" id="rc_${m.id}"></span>
        </span>
      </div>
      <div class="bubble-wrap">
        ${m.deletedAt ? `<div class="bubble muted">🗑 Сообщение удалено</div>` : `<div class="bubble">${esc(m.text)}</div>`}
        ${m.deletedAt ? "" : `
          <span class="msg-actions">
            <button class="msg-action hidden" id="editbtn_${m.id}" title="Редактировать">✎</button>
            <button class="msg-action hidden danger" id="delbtn_${m.id}" title="Удалить">🗑</button>
          </span>
        `}
      </div>
      ${(!m.deletedAt && m.attachment) ? renderAttachmentHtml(m.attachment) : ""}
    `;
    log.appendChild(div);
    renderReceipt(m.id);
    renderEditButton(m.id);
    renderDeleteButton(m.id);
    log.scrollTop = log.scrollHeight;
  }

  function renderChannels() {
    channelsEl.innerHTML = "";
    const q = String(channelsSearch?.value || "").trim().toLowerCase();
    const canManage = me && (me.isSuperadmin || me.systemRole === "OWNER" || me.systemRole === "ADMIN");

    for (const ch of channels) {
      if (q && !String(ch.name || "").toLowerCase().includes(q)) continue;
      const active = (activeMode === "channel" && ch.id === activeChannelId);
      const el = document.createElement("div");
      el.className = "item" + (active ? " active" : "");

      const name = ch.name + (ch.isPublic ? "" : " 🔒");
      const unread = badgeHtml(ch.unreadCount);

      el.innerHTML = `
        <div class="leftline">
          <span class="hash-icon" aria-hidden="true">
            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-hash-icon lucide-hash"><line x1="4" x2="20" y1="9" y2="9"/><line x1="4" x2="20" y1="15" y2="15"/><line x1="10" x2="8" y1="3" y2="21"/><line x1="16" x2="14" y1="3" y2="21"/></svg>
          </span>
          <span class="truncate">${esc(name)}</span>
        </div>
        ${unread}
      `;

      if (canManage) {
        const del = document.createElement("button");
        del.className = "icon-btn";
        del.title = "Удалить канал";
        del.textContent = "🗑";
        del.style.marginLeft = "8px";
        del.onclick = async (ev) => {
          ev.stopPropagation();
          if (!confirm(`Удалить канал #${ch.name}?`)) return;
          try {
            await api(`/api/admin/channels/${ch.id}`, { method: "DELETE" });
            await refreshChannels();
          } catch (e) {
            alert("Не удалось удалить: " + (e?.message || e));
          }
        };
        el.appendChild(del);
      }

      el.onclick = () => joinChannel(ch.id, ch.name, true);
      channelsEl.appendChild(el);
    }
  }

  function renderDmListUI() {
    dmListEl.innerHTML = "";
    const q = String(dmSearch?.value || "").trim().toLowerCase();
    for (const c of dmChats) {
      const dn = String(c?.otherUser?.displayName || "").toLowerCase();
      const em = String(c?.otherUser?.email || "").toLowerCase();
      if (q && !(dn.includes(q) || em.includes(q))) continue;
      const isOn = onlineUserIds.has(Number(c.otherUser.id));
      const active = (activeMode === "dm" && Number(c.id) === Number(activeDmChatId));
      const el = document.createElement("div");
      el.className = "item" + (active ? " active" : "");

      const last = c.last ? ` — ${c.last.text}` : "";
      const unread = badgeHtml(c.unreadCount);

      el.innerHTML = `
        <div class="leftline" style="min-width:0;">
          ${dotHtml(isOn)}
          <div class="truncate"><b>${esc(c.otherUser.displayName)}</b><span class="muted">${esc(last).slice(0, 40)}${(last.length>40)?"…":""}</span></div>
        </div>
        ${unread}
      `;
      el.onclick = () => openDmChat(c.id, c.otherUser, true);
      dmListEl.appendChild(el);
    }
  }

  async function joinChannel(id, name, openMobile) {
    activeMode = "channel";
    activeChannelId = id;
    activeDmChatId = null;
    activeDmOther = null;
    setSidebarMode("work");

    titleEl.textContent = "#" + name;
    hintEl.textContent = "";
    updateHeaderStatus();
    updateHeaderStatus();
    log.innerHTML = "";
    receiptByMessageId = new Map();
    messageFromId = new Map();
    messageTextById = new Map();
    messageTextById = new Map();

    renderChannels();
    renderDmListUI();

    if (ws && ws.readyState === 1) {
      ws.send(JSON.stringify({ type: "join", channelId: id }));
    }
    if (openMobile) setMobileChatOpen(true);
  }

  async function openDmChat(chatId, otherUser, openMobile) {
    activeMode = "dm";
    activeDmChatId = Number(chatId);
    activeDmOther = otherUser || null;
    activeChannelId = null;
    setSidebarMode("personal");

    titleEl.textContent = `DM: ${otherUser ? otherUser.displayName : ("#" + chatId)}`;
    hintEl.textContent = "";
    updateHeaderStatus();
    log.innerHTML = "";
    receiptByMessageId = new Map();
    messageFromId = new Map();
    messageTextById = new Map();
    messageTextById = new Map();

    renderChannels();
    renderDmListUI();

    if (ws && ws.readyState === 1) {
      ws.send(JSON.stringify({ type: "dm_join", chatId: Number(chatId) }));
    }
    if (openMobile) setMobileChatOpen(true);
  }



  attachRemoveBtn.onclick = () => {
    pendingAttachment = null;
    updateAttachPreview();
    hintEl.textContent = "";
    updateAttachPreview();
  };

  fileBtn.onclick = () => {
    if (fileInput) fileInput.click();
  };

  fileInput.addEventListener("change", async () => {
    const f = fileInput.files && fileInput.files[0];
    if (!f) return;
    // limit client-side ~2MB
    if (f.size > 2 * 1024 * 1024) {
      alert("Файл слишком большой (до 2MB).");
      fileInput.value = "";
      return;
    }
    hintEl.textContent = "Загрузка файла…";
    try {
      const b64 = await new Promise((resolve, reject) => {
        const r = new FileReader();
        r.onload = () => {
          const res = String(r.result || "");
          // res is data:*;base64,....
          const comma = res.indexOf(",");
          resolve(comma >= 0 ? res.slice(comma + 1) : res);
        };
        r.onerror = () => reject(new Error("file read failed"));
        r.readAsDataURL(f);
      });

      const up = await api("/api/attachments", {
        method: "POST",
        headers: { "Content-Type":"application/json" },
        body: JSON.stringify({ name: f.name, mime: f.type || "application/octet-stream", dataBase64: b64 })
      });

      pendingAttachment = up.attachment;
      hintEl.textContent = `📎 Прикреплено: ${pendingAttachment.name}`;
      updateAttachPreview();
    } catch (e) {
      pendingAttachment = null;
    updateAttachPreview();
      alert("Ошибка загрузки файла: " + String(e.message || e));
      hintEl.textContent = "";
    } finally {
      fileInput.value = "";
    }
  });

  sendBtn.onclick = () => sendMessage();
  text.addEventListener("keydown", (e) => { if (e.key === "Enter") sendMessage(); });

  function sendReadChannelIfPossible(messageId) {
    if (!ws || ws.readyState !== 1) return;
    if (!activeChannelId || !messageId) return;
    ws.send(JSON.stringify({ type: "read", channelId: activeChannelId, lastReadMessageId: messageId }));
  }

  function isLogNearBottom() {
    const threshold = 80; // px
    return (log.scrollHeight - log.scrollTop - log.clientHeight) < threshold;
  }

  function getLastRenderedMessageId() {
    // try to read last receipt span id rc_123
    const spans = log.querySelectorAll("[id^='rc_']");
    if (!spans.length) return 0;
    const last = spans[spans.length - 1].id;
    const id = Number(String(last).replace("rc_", ""));
    return Number.isFinite(id) ? id : 0;
  }

  function maybeMarkRead() {
    if (!isLogNearBottom()) return;
    const lastId = getLastRenderedMessageId();
    if (!lastId) return;
    if (activeMode === "channel" && activeChannelId) sendReadChannelIfPossible(lastId);
    if (activeMode === "dm" && activeDmChatId) sendReadDmIfPossible(lastId);
  }

  function sendReadDmIfPossible(messageId) {
    if (!ws || ws.readyState !== 1) return;
    if (!activeDmChatId || !messageId) return;
    ws.send(JSON.stringify({ type: "dm_read", chatId: activeDmChatId, lastReadMessageId: messageId }));
  }

  function sendMessage() {
    const t = text.value.trim();
    if (!t) return;
    if (!ws || ws.readyState !== 1) return;

    if (activeMode === "channel") {
      if (!activeChannelId) return;
      ws.send(JSON.stringify({ type: "chat", text: t, attachmentId: pendingAttachment ? pendingAttachment.id : 0 }));
    } else if (activeMode === "dm") {
      if (!activeDmChatId) return;
      ws.send(JSON.stringify({ type: "dm_chat", text: t, attachmentId: pendingAttachment ? pendingAttachment.id : 0 }));
    } else return;

    text.value = "";
    pendingAttachment = null;
    updateAttachPreview();
    hintEl.textContent = "";
    updateAttachPreview();
    text.focus();
  }

  async function initWs() {
    if (ws) { try { ws.close(); } catch {} }
    const wsProto = location.protocol === "https:" ? "wss" : "ws";
    ws = new WebSocket(`${wsProto}://${location.host}`);

    ws.addEventListener("open", () => { statusEl.textContent = "✅ WebSocket подключен"; });
    ws.addEventListener("close", () => { statusEl.textContent = "⚠️ WebSocket отключен"; });

    ws.addEventListener("message", async (ev) => {
      const msg = JSON.parse(ev.data);

      if (msg.type === "init") {
        me = msg.me;
        channels = msg.channels || [];
        onlineUserIds = new Set((msg.onlineUserIds || []).map(Number));
        renderChannels();

        if (channels.length) { joinChannel(channels[0].id, channels[0].name); updateHeaderStatus(); }
        else {
          titleEl.textContent = "Нет доступных каналов";
          hintEl.textContent = "Попроси администратора выдать доступ";
        }

        await refreshDmList();
      await refreshPeople();
        return;
      }

      if (msg.type === "presence_update") {
        const uid = Number(msg.userId);
        if (msg.online) onlineUserIds.add(uid);
        else onlineUserIds.delete(uid);

        // перерисуем списки чтобы точки online обновились
        renderDmListUI();
        updateHeaderStatus();
        // в логах точка обновится только для новых сообщений — пока ок
        return;
      }

      if (msg.type === "refresh_lists") {
        await refreshChannels();
        await refreshDmList();
      await refreshPeople();
        return;
      }


      if (msg.type === "channel_updated") {
        await refreshChannels();
        if (!adminCard.classList.contains("hidden")) { try { await refreshAdmin(); } catch {} }
        return;
      }

      if (msg.type === "channel_deleted") {
        await refreshChannels();
        if (activeMode === "channel" && Number(activeChannelId) === Number(msg.channelId)) {
          activeChannelId = null;
          titleEl.textContent = "—";
          hintEl.textContent = "Канал удалён";
          log.innerHTML = "";
          if (channels.length) joinChannel(channels[0].id, channels[0].name);
        }
        if (!adminCard.classList.contains("hidden")) { try { await refreshAdmin(); } catch {} }
        return;
      }

      if (msg.type === "channel_notice") {
        await refreshChannels();
        return;
      }

      if (msg.type === "dm_notice") {
        await refreshDmList();
      await refreshPeople();
        return;
      }

      if (msg.type === "history") {
        if (activeMode !== "channel") return;
        if (msg.channelId !== activeChannelId) return;

        const messages = msg.messages || [];
        for (const m of messages) addMsg(m);

        maybeMarkRead();
        await refreshChannels();
        return;
      }

      if (msg.type === "chat") {
        if (activeMode !== "channel") return;
        if (msg.channelId !== activeChannelId) return;

        if (me && Number(msg.message.fromId) !== Number(me.id)) {
          maybeNotify({ title: `#${titleEl.textContent.replace("#","")}`, body: `${msg.message.from}: ${msg.message.text}`, tag: `ch_${msg.channelId}` });
        }

        addMsg(msg.message);
        maybeMarkRead();
        await refreshChannels();
        return;
      }

      // НОВОЕ: батч обновление receipts для хвоста
      if (msg.type === "read_progress_batch") {
        if (activeMode !== "channel") return;
        if (msg.channelId !== activeChannelId) return;

        for (const it of (msg.items || [])) {
          receiptByMessageId.set(Number(it.messageId), { readCount: Number(it.readCount), total: Number(it.total) });
          renderReceipt(Number(it.messageId));
        }
        return;
      }

      // DM history
      if (msg.type === "dm_history") {
        if (activeMode !== "dm") return;
        if (Number(msg.chatId) !== Number(activeDmChatId)) return;

        if (msg.otherUser) {
          activeDmOther = msg.otherUser;
          titleEl.textContent = `DM: ${activeDmOther.displayName}`;
          updateHeaderStatus();
        }

        const messages = msg.messages || [];
        for (const m of messages) addMsg(m);

        maybeMarkRead();
        await refreshDmList();
      await refreshPeople();
        return;
      }

      if (msg.type === "dm_chat") {
        if (activeMode !== "dm") {
          await refreshDmList();
      await refreshPeople();
          return;
        }
        if (Number(msg.chatId) !== Number(activeDmChatId)) {
          await refreshDmList();
      await refreshPeople();
          return;
        }

        addMsg(msg.message);
        maybeMarkRead();
        await refreshDmList();
      await refreshPeople();
        return;
      }


      if (msg.type === "dm_read_progress_batch") {
        if (activeMode !== "dm") return;
        if (Number(msg.chatId) !== Number(activeDmChatId)) return;

        for (const it of (msg.items || [])) {
          receiptByMessageId.set(Number(it.messageId), { readCount: Number(it.readCount), total: Number(it.total) });
          renderReceipt(Number(it.messageId));
        }
        return;
      }

      if (msg.type === "dm_read_progress") {
        if (activeMode !== "dm") return;
        if (Number(msg.chatId) !== Number(activeDmChatId)) return;

        receiptByMessageId.set(Number(msg.messageId), msg.read);
        renderReceipt(Number(msg.messageId));
        return;
      }


      
      
      if (msg.type === "message_edited") {
        if (activeMode !== "channel") return;
        if (msg.channelId !== activeChannelId) return;
        updateMessageInDom(Number(msg.messageId), { text: msg.text, edited: true });
        return;
      }

      if (msg.type === "dm_message_edited") {
        if (activeMode !== "dm") return;
        if (Number(msg.chatId) !== Number(activeDmChatId)) return;
        updateMessageInDom(Number(msg.messageId), { text: msg.text, edited: true });
        return;
      }

if (msg.type === "message_deleted") {
        if (activeMode !== "channel") return;
        if (msg.channelId !== activeChannelId) return;
        updateMessageInDom(Number(msg.messageId), { deleted: true });
        return;
      }

      if (msg.type === "dm_message_deleted") {
        if (activeMode !== "dm") return;
        if (Number(msg.chatId) !== Number(activeDmChatId)) return;
        updateMessageInDom(Number(msg.messageId), { deleted: true });
        return;
      }


      if (msg.type === "error") {
        alert(msg.message || msg.code || "Error");
      }
    });
  }


  refreshPeopleBtn.onclick = async () => {
    try { await refreshPeople(); } catch {}
  };
  peopleSearch.addEventListener("input", () => renderPeople());
  if (channelsSearch) channelsSearch.addEventListener("input", () => renderChannels());
  if (dmSearch) dmSearch.addEventListener("input", () => renderDmListUI());

  /* =======================
     DM create flow
  ======================= */
  let dmCreateUsers = [];
  let dmSelectedUserId = null;
  const dmNewBtnPlusHtml = newDmBtn ? newDmBtn.innerHTML : "";
  const dmNewBtnCloseHtml = `
    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-x-icon lucide-x">
      <path d="M18 6 6 18"/><path d="m6 6 12 12"/>
    </svg>
  `;

  function renderDmUserPicker() {
    if (!dmUserPickList || !dmUserPickInput || !dmOpenBtn) return;

    const selected = (dmCreateUsers || []).find(u => Number(u.id) === Number(dmSelectedUserId)) || null;
    if (!selected) dmSelectedUserId = null;

    dmUserPickInput.value = selected
      ? `${selected.displayName} — ${selected.email}`
      : "Выбери пользователя…";

    dmOpenBtn.disabled = !dmSelectedUserId;

    dmUserPickList.innerHTML = (dmCreateUsers || []).map(u => {
      const isSel = Number(u.id) === Number(dmSelectedUserId);
      const inactive = u.isActive === false ? ` <span class="pill danger">inactive</span>` : "";
      return `
        <div class="multi-picker-item${isSel ? " selected" : ""}" data-dm-user-pick="${u.id}">
          <div class="multi-picker-left" style="min-width:0;">
            <div style="font-weight:bold; overflow:hidden; text-overflow:ellipsis;">
              ${esc(u.displayName)} <span class="pill">${esc(u.systemRole)}</span>${inactive}
            </div>
            <div class="muted" style="font-size:11px; overflow:hidden; text-overflow:ellipsis;">${esc(u.email)}</div>
          </div>
        </div>
      `;
    }).join("") || `<div class="muted" style="padding:8px;">Нет пользователей</div>`;
  }

  function setDmPickerOpen(isOpen) {
    if (!dmPickerRow) return;
    dmPickerRow.classList.toggle("hidden", !isOpen);
    if (newDmBtn) newDmBtn.innerHTML = isOpen ? dmNewBtnCloseHtml : dmNewBtnPlusHtml;
    if (!isOpen) {
      dmSelectedUserId = null;
      if (dmUserPickMenu) dmUserPickMenu.classList.add("hidden");
      if (dmUserPickSearch) dmUserPickSearch.value = "";
      renderDmUserPicker();
    }
  }

  newDmBtn.onclick = async () => {
    const isOpen = dmPickerRow && !dmPickerRow.classList.contains("hidden");
    if (isOpen) {
      setDmPickerOpen(false);
      return;
    }

    if (!dmCreateUsers.length) {
      const data = await api("/api/users");
      dmCreateUsers = data.users || [];
    }
    setDmPickerOpen(true);
    renderDmUserPicker();

    if (dmUserPickMenu) {
      openAccessMenu(dmUserPickMenu);
      if (dmUserPickSearch) {
        dmUserPickSearch.value = "";
        filterPickerList(dmUserPickList, "");
        try { dmUserPickSearch.focus(); } catch {}
      }
    }
  };

  dmOpenBtn.onclick = async () => {
    const uid = Number(dmSelectedUserId || 0);
    if (!uid) return;
    const opened = await api("/api/dm/open", {
      method: "POST",
      headers: { "Content-Type":"application/json" },
      body: JSON.stringify({ userId: uid })
    });
    await refreshDmList();

    const chat = dmChats.find(c => Number(c.id) === Number(opened.chatId));
    if (chat) openDmChat(chat.id, chat.otherUser, true);
    else openDmChat(opened.chatId, null, true);

    setDmPickerOpen(false);
  };

  /* =======================
     Admin UI (как раньше)
  ======================= */
  function setAdminTab(tab) {
    for (const t of adminTabs) t.classList.toggle("active", t.dataset.adminTab === tab);
    for (const k of Object.keys(adminViews)) adminViews[k].classList.toggle("hidden", k !== tab);
  }
  adminTabs.forEach(t => t.onclick = () => setAdminTab(t.dataset.adminTab));

  let adminModalNonce = 0;
  function openAdminModal() {
    if (!adminCard) return;
    const nonce = ++adminModalNonce;
    adminCard.classList.remove("hidden");
    adminCard.classList.add("is-hidden");
    requestAnimationFrame(() => {
      if (nonce !== adminModalNonce) return;
      adminCard.classList.remove("is-hidden");
    });
  }

  function closeAdminModal() {
    if (!adminCard) return;
    const nonce = ++adminModalNonce;

    if (adminCard.classList.contains("hidden")) {
      adminCard.classList.add("is-hidden");
      return;
    }

    adminCard.classList.add("is-hidden");

    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      adminCard.removeEventListener("transitionend", onEnd);
      if (nonce === adminModalNonce) adminCard.classList.add("hidden");
    };
    const onEnd = (e) => {
      if (e.target !== adminCard) return;
      finish();
    };
    adminCard.addEventListener("transitionend", onEnd);
    setTimeout(finish, 320);
  }

  openAdminBtn.onclick = async () => {
    openAdminModal();
    applyAdminTabPermissions();
    await refreshAdmin();
  };
  closeAdminBtn.onclick = () => closeAdminModal();

  function countChecked(selector) {
    return [...document.querySelectorAll(selector)].filter(x => x.checked).length;
  }

  function updateAccessCounts() {
    if (accessRolesInput) accessRolesInput.value = `Выбрано: ${countChecked("[data-access-role]")}`;
    if (accessUsersInput) accessUsersInput.value = `Выбрано: ${countChecked("[data-access-user]")}`;
  }

  function filterPickerList(listEl, query) {
    const q = String(query || "").trim().toLowerCase();
    const items = [...listEl.querySelectorAll(".multi-picker-item")];
    for (const it of items) {
      const text = String(it.textContent || "").toLowerCase();
      it.classList.toggle("hidden", Boolean(q) && !text.includes(q));
    }
  }

  function closeAccessMenus() {
    if (accessRolesMenu) accessRolesMenu.classList.add("hidden");
    if (accessUsersMenu) accessUsersMenu.classList.add("hidden");
    if (adminUserPickMenu) adminUserPickMenu.classList.add("hidden");
    if (dmUserPickMenu) dmUserPickMenu.classList.add("hidden");
  }

  function openAccessMenu(menuEl) {
    closeAccessMenus();
    if (!menuEl) return;
    menuEl.classList.remove("hidden");
  }

  if (accessRolesInput && accessRolesMenu && accessRoles) {
    accessRolesInput.onclick = (e) => {
      e.stopPropagation();
      if (accessRolesMenu.classList.contains("hidden")) {
        openAccessMenu(accessRolesMenu);
        if (accessRolesSearch) {
          accessRolesSearch.value = "";
          filterPickerList(accessRoles, "");
          try { accessRolesSearch.focus(); } catch {}
        }
      }
      else closeAccessMenus();
    };
    accessRolesMenu.onclick = (e) => e.stopPropagation();
    if (accessRolesSearch) {
      accessRolesSearch.addEventListener("input", () => filterPickerList(accessRoles, accessRolesSearch.value));
    }
    accessRoles.addEventListener("change", (e) => {
      const t = e.target;
      if (!(t instanceof HTMLInputElement)) return;
      if (t.type !== "checkbox") return;
      const item = t.closest(".multi-picker-item");
      if (item) item.classList.toggle("selected", t.checked);
      updateAccessCounts();
    });
  }

  if (accessUsersInput && accessUsersMenu && accessUsers) {
    accessUsersInput.onclick = (e) => {
      e.stopPropagation();
      if (accessUsersMenu.classList.contains("hidden")) {
        openAccessMenu(accessUsersMenu);
        if (accessUsersSearch) {
          accessUsersSearch.value = "";
          filterPickerList(accessUsers, "");
          try { accessUsersSearch.focus(); } catch {}
        }
      }
      else closeAccessMenus();
    };
    accessUsersMenu.onclick = (e) => e.stopPropagation();
    if (accessUsersSearch) {
      accessUsersSearch.addEventListener("input", () => filterPickerList(accessUsers, accessUsersSearch.value));
    }
    accessUsers.addEventListener("change", (e) => {
      const t = e.target;
      if (!(t instanceof HTMLInputElement)) return;
      if (t.type !== "checkbox") return;
      const item = t.closest(".multi-picker-item");
      if (item) item.classList.toggle("selected", t.checked);
      updateAccessCounts();
    });
  }

  if (adminUserPickInput && adminUserPickMenu && adminUserPickList) {
    adminUserPickInput.onclick = (e) => {
      e.stopPropagation();
      if (adminUserPickMenu.classList.contains("hidden")) {
        openAccessMenu(adminUserPickMenu);
        if (adminUserPickSearch) {
          adminUserPickSearch.value = "";
          filterPickerList(adminUserPickList, "");
          try { adminUserPickSearch.focus(); } catch {}
        }
      } else {
        closeAccessMenus();
      }
    };
    adminUserPickMenu.onclick = (e) => e.stopPropagation();
    if (adminUserPickSearch) {
      adminUserPickSearch.addEventListener("input", () => filterPickerList(adminUserPickList, adminUserPickSearch.value));
    }
    adminUserPickList.addEventListener("click", (e) => {
      const t = e.target;
      if (!(t instanceof HTMLElement)) return;
      const item = t.closest("[data-admin-user-pick]");
      if (!item) return;
      const userId = Number(item.dataset.adminUserPick || 0);
      if (!userId) return;
      adminSelectedUserId = userId;
      closeAccessMenus();
      renderAdminUserPicker();
      renderSelectedAdminUser();
    });
  }

  if (dmUserPickInput && dmUserPickMenu && dmUserPickList) {
    dmUserPickInput.onclick = (e) => {
      e.stopPropagation();
      if (dmUserPickMenu.classList.contains("hidden")) {
        openAccessMenu(dmUserPickMenu);
        if (dmUserPickSearch) {
          dmUserPickSearch.value = "";
          filterPickerList(dmUserPickList, "");
          try { dmUserPickSearch.focus(); } catch {}
        }
      } else {
        closeAccessMenus();
      }
    };
    dmUserPickMenu.onclick = (e) => e.stopPropagation();
    if (dmUserPickSearch) {
      dmUserPickSearch.addEventListener("input", () => filterPickerList(dmUserPickList, dmUserPickSearch.value));
    }
    dmUserPickList.addEventListener("click", (e) => {
      const t = e.target;
      if (!(t instanceof HTMLElement)) return;
      const item = t.closest("[data-dm-user-pick]");
      if (!item) return;
      const userId = Number(item.dataset.dmUserPick || 0);
      if (!userId) return;
      dmSelectedUserId = userId;
      closeAccessMenus();
      renderDmUserPicker();
    });
  }

  document.addEventListener("click", () => closeAccessMenus());
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeAccessMenus();
  });

  function renderAdminUserPicker() {
    if (!adminUserPickList || !adminUserPickInput) return;

    const selected = (users || []).find(u => Number(u.id) === Number(adminSelectedUserId)) || null;
    if (!selected) adminSelectedUserId = null;

    adminUserPickInput.value = selected
      ? `${selected.displayName} — ${selected.email}`
      : "Выбери сотрудника…";

    adminUserPickList.innerHTML = (users || []).map(u => {
      const isSel = Number(u.id) === Number(adminSelectedUserId);
      const inactive = u.isActive === false ? ` <span class="pill danger">inactive</span>` : "";
      return `
        <div class="multi-picker-item${isSel ? " selected" : ""}" data-admin-user-pick="${u.id}">
          <div class="multi-picker-left" style="min-width:0;">
            <div style="font-weight:bold; overflow:hidden; text-overflow:ellipsis;">
              ${esc(u.displayName)} <span class="pill">${esc(u.systemRole)}</span>${inactive}
            </div>
            <div class="muted" style="font-size:11px; overflow:hidden; text-overflow:ellipsis;">${esc(u.email)}</div>
          </div>
        </div>
      `;
    }).join("") || `<div class="muted" style="padding:8px;">Нет пользователей</div>`;
  }

  function renderSelectedAdminUser() {
    if (!usersList) return;

    const us = (users || []).find(u => Number(u.id) === Number(adminSelectedUserId)) || null;
    if (!us) {
      usersList.innerHTML = `<div class="muted">Выбери сотрудника выше, чтобы редактировать.</div>`;
      return;
    }

    usersList.innerHTML = `
      <div class="card" style="margin-top:10px;">
        <div><b>${esc(us.displayName)}</b> <span class="pill">${esc(us.systemRole)}</span> ${us.isActive === false ? "<span class=\"pill danger\">inactive</span>" : ""}</div>
        <div class="muted">${esc(us.email)}</div>
        <div class="muted" id="userRoles_${us.id}">Роли: …</div>
        <div class="row" style="flex-wrap:wrap;">
          <button data-user-deactivate="${us.id}" class="danger">Деактивировать</button>
          <button data-user-activate="${us.id}">Активировать</button>
          <button data-user-resetpass="${us.id}">Сброс пароля</button>
        </div>
        <div class="muted" id="userAdminMsg_${us.id}"></div>

        <div class="row">
          <select data-user-role-select="${us.id}"><option value="">Выдать роль…</option>
            ${(roles || []).map(r => `<option value="${r.id}">${esc(r.displayName)}</option>`).join("")}
          </select>
          <button data-user-role-btn="${us.id}">Выдать</button>
        </div>

        <div class="row" style="flex-wrap:wrap;">
          <button class="danger" data-user-role-remove-open="${us.id}">Снять роль…</button>
          <select class="hidden" data-user-role-remove-select="${us.id}"><option value="">Выбери роль</option></select>
          <button class="hidden danger" data-user-role-remove-btn="${us.id}">Снять</button>
        </div>
      </div>
    `;

    (async () => {
      try {
        const ur = await api(`/api/admin/users/${us.id}/roles`);
        const list = ur.roles || [];
        const label = document.getElementById(`userRoles_${us.id}`);
        if (label) label.textContent = "Роли: " + (list.map(x => x.displayName).join(", ") || "—");
        const selRemove = document.querySelector(`[data-user-role-remove-select="${us.id}"]`);
        if (selRemove) {
          selRemove.innerHTML = `<option value="">Выбери роль для снятия</option>` + list.map(x => `<option value="${x.id}">${esc(x.displayName)}</option>`).join("");
        }
      } catch {}
    })();

    const btnAdd = document.querySelector(`[data-user-role-btn="${us.id}"]`);
    const selAdd = document.querySelector(`[data-user-role-select="${us.id}"]`);
    if (btnAdd && selAdd) {
      btnAdd.onclick = async () => {
        const roleId = Number(selAdd.value || 0);
        if (!roleId) return;
        await api(`/api/admin/users/${us.id}/roles`, { method: "POST", headers: { "Content-Type":"application/json" }, body: JSON.stringify({ roleId })});
        await refreshAdmin();
      };
    }

    const openRemove = document.querySelector(`[data-user-role-remove-open="${us.id}"]`);
    const selRemove = document.querySelector(`[data-user-role-remove-select="${us.id}"]`);
    const btnRemove = document.querySelector(`[data-user-role-remove-btn="${us.id}"]`);
    if (openRemove && selRemove && btnRemove) {
      openRemove.onclick = () => { selRemove.classList.toggle("hidden"); btnRemove.classList.toggle("hidden"); };
      btnRemove.onclick = async () => {
        const roleId = Number(selRemove.value || 0);
        if (!roleId) return;
        await api(`/api/admin/users/${us.id}/roles/${roleId}`, { method: "DELETE" });
        await refreshAdmin();
      };
    }

    const btnDeact = document.querySelector(`[data-user-deactivate="${us.id}"]`);
    const btnAct = document.querySelector(`[data-user-activate="${us.id}"]`);
    const btnReset = document.querySelector(`[data-user-resetpass="${us.id}"]`);
    const adminMsg = document.getElementById(`userAdminMsg_${us.id}`);

    if (btnDeact && adminMsg) {
      btnDeact.onclick = async () => {
        adminMsg.textContent = "";
        try {
          await api(`/api/admin/users/${us.id}/deactivate`, { method: "POST" });
          adminMsg.textContent = "✅ Пользователь деактивирован";
          await refreshAdmin();
          await refreshPeople();
        } catch (e) {
          adminMsg.textContent = "❌ " + String(e.message || e);
        }
      };
    }
    if (btnAct && adminMsg) {
      btnAct.onclick = async () => {
        adminMsg.textContent = "";
        try {
          await api(`/api/admin/users/${us.id}/activate`, { method: "POST" });
          adminMsg.textContent = "✅ Пользователь активирован";
          await refreshAdmin();
          await refreshPeople();
        } catch (e) {
          adminMsg.textContent = "❌ " + String(e.message || e);
        }
      };
    }
    if (btnReset && adminMsg) {
      btnReset.onclick = async () => {
        adminMsg.textContent = "";
        try {
          const r = await api(`/api/admin/users/${us.id}/reset_password`, { method: "POST" });
          adminMsg.textContent = `✅ Новый временный пароль: ${r.tempPassword} (сообщи сотруднику)`;
        } catch (e) {
          adminMsg.textContent = "❌ " + String(e.message || e);
        }
      };
    }
  }

  function renderAccessPickers() {
    accessRoles.innerHTML = roles.map(r => `
      <label class="multi-picker-item">
        <div class="multi-picker-left">
          <div style="font-weight:bold; min-width:0; overflow:hidden; text-overflow:ellipsis;">${esc(r.displayName)}</div>
        </div>
        <input type="checkbox" class="multi-picker-checkbox" data-access-role="${r.id}" />
      </label>
    `).join("");

    accessUsers.innerHTML = users.map(u => `
      <label class="multi-picker-item">
        <div class="multi-picker-left" style="min-width:0;">
          <div style="font-weight:bold; overflow:hidden; text-overflow:ellipsis;">${esc(u.displayName)}</div>
          <div class="muted" style="font-size:11px; overflow:hidden; text-overflow:ellipsis;">${esc(u.email)}</div>
        </div>
        <input type="checkbox" class="multi-picker-checkbox" data-access-user="${u.id}" />
      </label>
    `).join("");
    updateAccessCounts();
  }


  function loadChannelPropsToUI(channelId) {
    const ch = (adminAllChannels || []).find(c => Number(c.id) === Number(channelId));
    if (!ch) return;
    editChannelName.value = ch.name;
    editChannelPrivacy.value = ch.isPublic ? "true" : "false";
    channelPropsMsg.textContent = "";
    const canDelete = me && me.systemRole === "OWNER";
    deleteChannelBtn.classList.toggle("hidden", !canDelete);
  }

  async function loadChannelAccessToUI(channelId) {
    const a = await api(`/api/admin/channels/${channelId}/access`);
    const roleSet = new Set((a.roleIds || []).map(Number));
    const userSet = new Set((a.userIds || []).map(Number));
    
    [...document.querySelectorAll("[data-access-role]")].forEach(chk => {
      chk.checked = roleSet.has(Number(chk.dataset.accessRole));
      const item = chk.closest(".multi-picker-item");
      if (item) item.classList.toggle("selected", chk.checked);
    });
    
    [...document.querySelectorAll("[data-access-user]")].forEach(chk => {
      chk.checked = userSet.has(Number(chk.dataset.accessUser));
      const item = chk.closest(".multi-picker-item");
      if (item) item.classList.toggle("selected", chk.checked);
    });

    updateAccessCounts();
    accessMsg.textContent = "✅ Доступ загружен";
  }

  async function refreshAdmin() {
    const r = await api("/api/admin/roles");
    roles = r.roles || [];
    rolesList.innerHTML = roles.map(x => `<div><code>${esc(x.name)}</code> — ${esc(x.displayName)} (id:${x.id})</div>`).join("");

    const u = await api("/api/admin/users");
    users = u.users || [];
    renderAdminUserPicker();
    renderSelectedAdminUser();

    const ch = await api("/api/admin/channels");
    adminAllChannels = ch.channels || [];
    if (adminAllChannels.length) loadChannelPropsToUI(Number(accessChannel.value));
    accessChannel.innerHTML = adminAllChannels.map(c => `<option value="${c.id}">#${esc(c.name)}${c.isPublic ? "" : " 🔒"}</option>`).join("");
    renderAccessPickers();
    if (adminAllChannels.length) await loadChannelAccessToUI(Number(accessChannel.value));

    try {
      const a = await api("/api/audit");
      auditList.innerHTML = (a.logs || []).map(l => `
        <div class="card" style="margin-top:10px;">
          <div><b>${esc(l.action)}</b> <span class="muted">${esc(new Date(l.at).toLocaleString())}</span></div>
          <div class="muted">actor: ${esc(l.actor.displayName)} (${esc(l.actor.email)})</div>
          <div class="muted"><code>${esc(JSON.stringify(l.meta))}</code></div>
        </div>
      `).join("");
    } catch {
      auditList.innerHTML = `<div class="muted">Аудит доступен только OWNER/SUPERADMIN</div>`;
    }

    try {
      const d = await api("/api/admin/dm/chats");
      const chats = d.chats || [];
      dmAuditSelect.innerHTML = chats.map(c => {
        const last = c.last ? ` — ${esc(c.last.text).slice(0, 30)}${c.last.text.length > 30 ? "…" : ""}` : "";
        return `<option value="${c.id}">${esc(c.a.displayName)} ↔ ${esc(c.b.displayName)}${last}</option>`;
      }).join("");
      dmAuditLog.textContent = chats.length ? "Выбери диалог и нажми «Открыть»." : "Пока нет личных диалогов.";
      dmAuditMessages.innerHTML = "";
    } catch {
      dmAuditSelect.innerHTML = `<option value="">Недоступно</option>`;
      dmAuditLog.textContent = "DM аудит доступен только OWNER/SUPERADMIN";
      dmAuditMessages.innerHTML = "";
    }

    // invites
    try {
      const invs = await api("/api/admin/invites");
      const list = invs.invites || [];
      invitesList.innerHTML = list.map(it => {
        const link = `${location.origin}/?invite=${it.token}`;
        const exp = it.expiresAt ? new Date(it.expiresAt).toLocaleString() : "—";
        const used = `${it.usedCount}/${it.maxUses}`;
        const revoked = it.isRevoked ? " <span class=\"pill danger\">отозван</span>" : "";
        return `
          <div class="card" style="margin-top:10px;">
            <div style="display:flex; justify-content:space-between; gap:8px; align-items:center;">
              <div class="truncate"><b>Инвайт</b>${revoked} <span class="muted">использовано: ${used} • истекает: ${esc(exp)}</span></div>
              <div style="display:flex; gap:6px;">
                <button data-invite-copy="${it.token}">Копировать ссылку</button>
                <button class="danger" data-invite-revoke="${it.id}" ${it.isRevoked ? "disabled" : ""}>Отозвать</button>
              </div>
            </div>
            <div class="small"><code>${esc(link)}</code></div>
          </div>
        `;
      }).join("") || `<div class="muted">Пока нет инвайтов. Создай первый.</div>`;

      // bind buttons
      [...document.querySelectorAll("[data-invite-copy]")].forEach(btn => {
        btn.onclick = async () => {
          const t = btn.dataset.inviteCopy;
          const link = `${location.origin}/?invite=${t}`;
          try { await navigator.clipboard.writeText(link); inviteMsg.textContent = "✅ Ссылка скопирована"; }
          catch { inviteMsg.textContent = "Скопируй вручную: " + link; }
        };
      });

      [...document.querySelectorAll("[data-invite-revoke]")].forEach(btn => {
        btn.onclick = async () => {
          const id = Number(btn.dataset.inviteRevoke || 0);
          if (!id) return;
          await api(`/api/admin/invites/${id}`, { method: "DELETE" });
          inviteMsg.textContent = "✅ Инвайт отозван";
          await refreshAdmin();
        };
      });
    } catch {
      invitesList.innerHTML = `<div class="muted">Инвайты доступны только ADMIN/OWNER</div>`;
    }

    applyAdminTabPermissions();
 

    if (me && me.isSuperadmin) {
      try {
        const s = await api("/api/admin/settings/attachments");
        const mb = Math.round(Number(s.maxAttachmentBytes || 0) / (1024 * 1024));
        maxFileMb.value = String(mb || 2);
        settingsMsg.textContent = `Текущий лимит: ${mb} MB`;
      } catch {
        settingsMsg.textContent = "Не удалось загрузить настройки";
      }
    }

  }

  createRoleBtn.onclick = async () => {
    createRoleBtn.disabled = true;
    try {
      await api("/api/admin/roles", { method: "POST", headers: { "Content-Type":"application/json" }, body: JSON.stringify({ name: newRoleName.value, displayName: newRoleDisplay.value })});
      newRoleName.value = "";
      newRoleDisplay.value = "";
      await refreshAdmin();
    } catch (e) { alert(String(e.message || e)); }
    finally { createRoleBtn.disabled = false; }
  };

  createChannelBtn.onclick = async () => {
    createChannelBtn.disabled = true;
    try {
      await api("/api/admin/channels", { method: "POST", headers: { "Content-Type":"application/json" }, body: JSON.stringify({ name: newChannelName.value, isPublic: newChannelPublic.value === "true" })});
      newChannelName.value = "";
      await refreshAdmin();
      await refreshChannels();
    } catch (e) { alert(String(e.message || e)); }
    finally { createChannelBtn.disabled = false; }
  };

  loadAccessBtn.onclick = async () => {
    loadChannelPropsToUI(Number(accessChannel.value));
    accessMsg.textContent = "";
    try { await loadChannelAccessToUI(Number(accessChannel.value)); }
    catch (e) { accessMsg.textContent = "❌ " + String(e.message || e); }
  };

  accessChannel.onchange = async () => {
    loadChannelPropsToUI(Number(accessChannel.value));
    accessMsg.textContent = "";
    try { await loadChannelAccessToUI(Number(accessChannel.value)); } catch {}
  };


  saveChannelPropsBtn.onclick = async () => {
    channelPropsMsg.textContent = "";
    saveChannelPropsBtn.disabled = true;
    try {
      const channelId = Number(accessChannel.value || 0);
      const name = String(editChannelName.value || "").trim();
      const isPublic = (editChannelPrivacy.value === "true");
      if (!channelId) throw new Error("Выбери канал");
      if (!name) throw new Error("Название не может быть пустым");

      await api(`/api/admin/channels/${channelId}`, {
        method: "PATCH",
        headers: { "Content-Type":"application/json" },
        body: JSON.stringify({ name, isPublic })
      });

      channelPropsMsg.textContent = "✅ Сохранено";
      await refreshAdmin();
      await refreshChannels();
    } catch (e) {
      channelPropsMsg.textContent = "❌ " + String(e.message || e);
    } finally {
      saveChannelPropsBtn.disabled = false;
    }
  };

  deleteChannelBtn.onclick = async () => {
    channelPropsMsg.textContent = "";
    const channelId = Number(accessChannel.value || 0);
    if (!channelId) return;
    if (!confirm("Удалить канал? Он исчезнет у всех пользователей.")) return;

    deleteChannelBtn.disabled = true;
    try {
      await api(`/api/admin/channels/${channelId}`, { method: "DELETE" });
      channelPropsMsg.textContent = "✅ Канал удалён";
      await refreshAdmin();
      await refreshChannels();

      if (activeMode === "channel" && Number(activeChannelId) === Number(channelId)) {
        activeChannelId = null;
        titleEl.textContent = "—";
        hintEl.textContent = "Канал удалён";
        log.innerHTML = "";
      }
    } catch (e) {
      channelPropsMsg.textContent = "❌ " + String(e.message || e);
    } finally {
      deleteChannelBtn.disabled = false;
    }
  };

  saveAccessBtn.onclick = async () => {
    accessMsg.textContent = "";
    saveAccessBtn.disabled = true;
    try {
      const channelId = Number(accessChannel.value || 0);
      const roleIds = [...document.querySelectorAll("[data-access-role]")].filter(x => x.checked).map(x => Number(x.dataset.accessRole));
      const userIds = [...document.querySelectorAll("[data-access-user]")].filter(x => x.checked).map(x => Number(x.dataset.accessUser));
      await api(`/api/admin/channels/${channelId}/access`, { method: "POST", headers: { "Content-Type":"application/json" }, body: JSON.stringify({ roleIds, userIds })});
      accessMsg.textContent = "✅ Доступ сохранён";
      await refreshChannels();
    } catch (e) {
      accessMsg.textContent = "❌ " + String(e.message || e);
    } finally {
      saveAccessBtn.disabled = false;
    }
  };


  inviteCreateBtn.onclick = async () => {
    const maxUses = Number(inviteMaxUses.value || 1);
    const expiresInHours = Number(inviteExpiresHours.value || 0);
    await createInviteAndCopy(maxUses, expiresInHours);
    inviteMaxUses.value = "";
    inviteExpiresHours.value = "";
  };

  inviteQuick1.onclick = async () => {
    inviteMaxUses.value = "1";
    inviteExpiresHours.value = "0";
    await createInviteAndCopy(1, 0);
  };
  inviteQuick24.onclick = async () => {
    inviteMaxUses.value = "1";
    inviteExpiresHours.value = "24";
    await createInviteAndCopy(1, 24);
  };
  inviteQuick10.onclick = async () => {
    inviteMaxUses.value = "10";
    inviteExpiresHours.value = "0";
    await createInviteAndCopy(10, 0);
  };



  saveMaxFileBtn.onclick = async () => {
    settingsMsg.textContent = "";
    const mb = Number(maxFileMb.value || 0);
    if (!mb || mb < 0.05 || mb > 50) {
      settingsMsg.textContent = "Введите значение от 0.05 до 50 MB";
      return;
    }
    saveMaxFileBtn.disabled = true;
    try {
      const bytes = Math.floor(mb * 1024 * 1024);
      const r = await api("/api/admin/settings/attachments", {
        method: "POST",
        headers: { "Content-Type":"application/json" },
        body: JSON.stringify({ maxAttachmentBytes: bytes })
      });
      const newMb = Math.round(Number(r.maxAttachmentBytes) / (1024*1024));
      settingsMsg.textContent = `✅ Сохранено: ${newMb} MB`;
    } catch (e) {
      settingsMsg.textContent = "❌ " + String(e.message || e);
    } finally {
      saveMaxFileBtn.disabled = false;
    }
  };

  dmAuditLoadBtn.onclick = async () => {
    const chatId = Number(dmAuditSelect.value || 0);
    if (!chatId) return;
    dmAuditLog.textContent = "Загрузка…";
    dmAuditMessages.innerHTML = "";
    try {
      const data = await api(`/api/admin/dm/chats/${chatId}/messages`);
      const msgs = data.messages || [];
      dmAuditLog.textContent = `Сообщений: ${msgs.length}. Просмотр залогирован в аудит.`;
      dmAuditMessages.innerHTML = msgs.map(m => {
        const at = new Date(m.at).toLocaleString();
        return `
          <div class="card" style="margin-top:10px;">
            <div class="muted">${esc(m.from)} (${esc(m.fromEmail)}) • ${esc(at)}</div>
            <div>${esc(m.text)}</div>
          </div>
        `;
      }).join("");
    } catch (e) {
      dmAuditLog.textContent = "❌ " + String(e.message || e);
    }
  };


  log.addEventListener("scroll", () => {
    maybeMarkRead();
  });
  window.addEventListener("focus", () => {
    maybeMarkRead();
  });

  /* =======================
     Boot
  ======================= */
  (async () => {
    // NEW: узнаём, можно ли регистрировать первого пользователя без инвайта
    try {
      const bs = await api("/api/bootstrap");
      allowFirstRegistration = !!bs.allowFirstRegistration;
    } catch {}

    try {
      // invite from URL: ?invite=TOKEN
      const params = new URLSearchParams(location.search);
      const inv = params.get("invite");
      hasInviteParam = Boolean(inv);

      // если инвайта нет — скрываем вкладку регистрации (чтобы никто не пытался регаться)
      tabRegister.classList.toggle("hidden", !hasInviteParam);

      const regInvEl = document.getElementById("regInvite");
      if (hasInviteParam && regInvEl) {
        regInvEl.value = inv;
        setAuthMode("register");
      } else {
        setAuthMode("login");
      updateNotifyBtnUI();
      }

      await loadPositions();

      const meResp = await api("/api/me");
      me = meResp.me;
      statusEl.textContent = "Сессия активна";
      uiLoggedIn();
      await initWs();
      await refreshChannels();
      await refreshDmList();
      await refreshPeople();
    } catch {
      statusEl.textContent = "Нужно войти";
      await uiLoggedOut();
      setAuthMode("login");
    }
  })();
