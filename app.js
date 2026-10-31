// cloak — encrypts a URL client-side (AES-GCM, Web Crypto) and packs the
// ciphertext into a URL fragment. Fragments never leave the browser, so this
// works from any static host with no backend and nothing is ever stored.
//
// Two formats, tagged by the first byte of the payload:
//   0x01 plain — the key ships inside the link. Any browser that opens it
//                decrypts and redirects instantly. A human reading the raw
//                string just sees noise; only code that runs the same
//                unpacking steps gets the destination back.
//   0x02 pass  — the key is derived from a passphrase (PBKDF2) that is
//                never in the link. Opening it prompts for that passphrase.

(() => {
  const app = document.getElementById('app');
  const live = document.getElementById('live');

  const MAGIC_PLAIN = 0x01;
  const MAGIC_PASS = 0x02;
  const MAGIC_STUDYSPACE_PLAIN = 0x03;
  const MAGIC_STUDYSPACE_PASS = 0x04;
  const PBKDF2_ITERATIONS = 250000;

  const b64 = {
    encode(bytes) {
      let bin = '';
      for (const b of bytes) bin += String.fromCharCode(b);
      return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    },
    decode(str) {
      str = str.replace(/-/g, '+').replace(/_/g, '/');
      while (str.length % 4) str += '=';
      const bin = atob(str);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      return bytes;
    },
  };

  function toBase64Url(str) {
    return b64.encode(new TextEncoder().encode(str));
  }

  function concatBytes(...arrs) {
    const len = arrs.reduce((n, a) => n + a.length, 0);
    const out = new Uint8Array(len);
    let off = 0;
    for (const a of arrs) { out.set(a, off); off += a.length; }
    return out;
  }

  function deriveKey(passphrase, salt, usage) {
    return crypto.subtle.importKey('raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey'])
      .then((baseKey) => crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
        baseKey, { name: 'AES-GCM', length: 256 }, false, [usage],
      ));
  }

  async function cloak(rawUrl, passphrase, isStudySpace = false) {
    const data = new TextEncoder().encode(rawUrl);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    let key, header, extra;

    if (passphrase) {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      key = await deriveKey(passphrase, salt, 'encrypt');
      header = new Uint8Array([isStudySpace ? MAGIC_STUDYSPACE_PASS : MAGIC_PASS]);
      extra = salt;
    } else {
      key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
      header = new Uint8Array([isStudySpace ? MAGIC_STUDYSPACE_PLAIN : MAGIC_PLAIN]);
      extra = new Uint8Array(await crypto.subtle.exportKey('raw', key));
    }

    const cipherBytes = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data));
    const payload = concatBytes(header, extra, iv, cipherBytes);
    const base = location.origin + location.pathname;
    return `${base}#c=${b64.encode(payload)}`;
  }

  async function uncloak(payloadB64, passphrase) {
    const bytes = b64.decode(payloadB64);
    const magic = bytes[0];
    const isStudySpace = (magic === MAGIC_STUDYSPACE_PLAIN || magic === MAGIC_STUDYSPACE_PASS);

    if (magic === MAGIC_PLAIN || magic === MAGIC_STUDYSPACE_PLAIN) {
      const rawKey = bytes.slice(1, 33);
      const iv = bytes.slice(33, 45);
      const cipherBytes = bytes.slice(45);
      const key = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['decrypt']);
      const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, cipherBytes);
      return { url: new TextDecoder().decode(plain), isStudySpace };
    }

    if (magic === MAGIC_PASS || magic === MAGIC_STUDYSPACE_PASS) {
      const salt = bytes.slice(1, 17);
      const iv = bytes.slice(17, 29);
      const cipherBytes = bytes.slice(29);
      const key = await deriveKey(passphrase, salt, 'decrypt');
      const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, cipherBytes);
      return { url: new TextDecoder().decode(plain), isStudySpace };
    }

    throw new Error('unrecognized format');
  }

  function needsPassphrase(payloadB64) {
    const bytes = b64.decode(payloadB64);
    return bytes[0] === MAGIC_PASS || bytes[0] === MAGIC_STUDYSPACE_PASS;
  }

  // ── views ──

  const views = ['compose', 'opening', 'prompt', 'failed'];
  function showView(name) {
    for (const v of views) {
      document.getElementById(`view-${v}`).hidden = v !== name;
    }
    app.dataset.state = name;
  }

  function announce(msg) { live.textContent = msg; }

  function toast(msg) {
    const el = document.createElement('div');
    el.className = 'toast';
    el.textContent = msg;
    document.body.appendChild(el);
    setTimeout(() => {
      el.classList.add('out');
      setTimeout(() => el.remove(), 520);
    }, 1400);
  }

  function isSafeUrl(str) {
    try {
      const u = new URL(str);
      return u.protocol === 'http:' || u.protocol === 'https:';
    } catch {
      return false;
    }
  }

  // ── compose ──

  const urlInput = document.getElementById('url-input');
  const passToggle = document.getElementById('pass-toggle');
  const passWrap = document.getElementById('pass-wrap');
  const passInput = document.getElementById('pass-input');
  const studyspaceToggle = document.getElementById('studyspace-toggle');
  const cloakBtn = document.getElementById('cloak-btn');
  const composeErr = document.getElementById('compose-err');
  const result = document.getElementById('result');
  const cloakOutput = document.getElementById('cloak-output');
  const copyBtn = document.getElementById('copy-btn');
  const openBtn = document.getElementById('open-btn');

  passToggle.addEventListener('change', () => {
    passWrap.hidden = !passToggle.checked;
    if (passToggle.checked) passInput.focus();
  });

  function setComposeError(msg) {
    composeErr.textContent = msg;
    composeErr.hidden = !msg;
  }

  async function runCloak() {
    const raw = urlInput.value.trim();
    setComposeError('');
    result.hidden = true;

    if (!raw) return;
    if (!isSafeUrl(raw)) {
      setComposeError('That needs to be a full http:// or https:// link.');
      return;
    }
    if (passToggle.checked && !passInput.value) {
      setComposeError('Enter a passphrase, or turn that option off.');
      return;
    }
    if (!window.isSecureContext || !crypto.subtle) {
      setComposeError('This page needs to be served over https (or localhost) to encrypt anything.');
      return;
    }

    cloakBtn.disabled = true;
    try {
      const isSS = studyspaceToggle ? studyspaceToggle.checked : false;
      const link = await cloak(raw, passToggle.checked ? passInput.value : null, isSS);
      cloakOutput.value = link;
      openBtn.href = link;
      result.hidden = false;
      announce('Cloaked link ready.');
    } catch (e) {
      setComposeError('Something went wrong encrypting that link.');
    } finally {
      cloakBtn.disabled = false;
    }
  }

  cloakBtn.addEventListener('click', runCloak);
  urlInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') runCloak(); });
  passInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') runCloak(); });

  copyBtn.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(cloakOutput.value);
    } catch {
      cloakOutput.select();
      document.execCommand('copy');
    }
    toast('Copied');
  });

  // ── incoming cloaked link ──

  const promptInput = document.getElementById('prompt-input');
  const promptBtn = document.getElementById('prompt-btn');
  const promptErr = document.getElementById('prompt-err');
  const failedMsg = document.getElementById('failed-msg');
  const failedReset = document.getElementById('failed-reset');

  function redirectTo(url, isStudySpace = false) {
    if (!isSafeUrl(url)) {
      failedMsg.textContent = 'This link decoded to something that is not a normal web address.';
      showView('failed');
      return;
    }
    if (isStudySpace) {
      const gateway = localStorage.getItem('studyspace_gateway') || 'https://stdy.space';
      location.replace(`${gateway}/reference/ext/${toBase64Url(url)}`);
    } else {
      location.replace(url);
    }
  }

  function parseIncomingPayload() {
    const h = location.hash;
    if (h.startsWith('#c=')) return h.slice(3);
    return null;
  }

  let pendingPayload = null;

  async function handleIncoming(payload) {
    showView('opening');
    let flagged;
    try {
      flagged = needsPassphrase(payload);
    } catch {
      failedMsg.textContent = 'This cloaked link is broken or was tampered with.';
      showView('failed');
      return;
    }

    if (flagged) {
      pendingPayload = payload;
      showView('prompt');
      promptInput.focus();
      return;
    }

    try {
      const res = await uncloak(payload);
      redirectTo(res.url, res.isStudySpace);
    } catch {
      failedMsg.textContent = 'This cloaked link is broken or was tampered with.';
      showView('failed');
    }
  }

  async function tryUnlock() {
    if (!pendingPayload) return;
    const passphrase = promptInput.value;
    if (!passphrase) return;
    promptErr.hidden = true;
    promptBtn.disabled = true;
    try {
      const res = await uncloak(pendingPayload, passphrase);
      redirectTo(res.url, res.isStudySpace);
    } catch {
      promptErr.hidden = false;
      promptInput.select();
    } finally {
      promptBtn.disabled = false;
    }
  }

  const promptForm = document.getElementById('prompt-form');
  if (promptForm) {
    promptForm.addEventListener('submit', (e) => {
      e.preventDefault();
      tryUnlock();
    });
  }

  promptBtn.addEventListener('click', tryUnlock);
  promptInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') tryUnlock(); });
  promptInput.addEventListener('change', () => {
    if (promptInput.value.length > 0) tryUnlock();
  });

  failedReset.addEventListener('click', () => {
    history.replaceState(null, '', location.pathname);
    showView('compose');
  });

  // ── boot ──

  const incoming = parseIncomingPayload();
  if (incoming) {
    handleIncoming(incoming);
  } else {
    showView('compose');
  }

  // Landing on a cloaked link while this exact page is already open (e.g.
  // pasted into an open tab) only changes the hash — no fresh load, so the
  // boot check above never runs. Catch that case too.
  window.addEventListener('hashchange', () => {
    const payload = parseIncomingPayload();
    if (payload) handleIncoming(payload);
  });
})();
