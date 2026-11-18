/* ==================================================================
   SITE GUARD - ONE FILE FOR THE WHOLE PUBLIC SITE.

   It does three jobs, and every public page loads this same file:

     1. THE WALL.  robots.txt is a policy; this is the speed bump for the
        crawlers that ignore it. It matches AI training bots, AI answer
        engines, SEO harvesters and the REA / mitmproxy campaign against
        trusted apps. A real buyer on a real browser is never affected -
        the list is matched on explicit agent signatures only, and headless
        detection is deliberately NOT used because it breaks legitimate QA
        and is trivial to spoof.

     2. THE ISSUER.  The licence issuer runs behind a tunnel that rotates,
        so no address can be baked into a page. This file finds it exactly
        the way the apps find it: cached address -> the site's SIGNED
        issuer.json -> the SIGNED ntfy discovery list, verified in the
        browser with the embedded RSA public key. An unsigned or forged
        list is thrown away. The key below is the trust anchor.

     3. THE VISIT LOG.  Every page view is recorded at the issuer with the
        address, the agent string and the page - no cookies, no
        identifiers. The issuer flags AI agents from the agent string it
        receives itself, so the flag cannot be faked by the page.

   Honest limit: this cannot stop a scraper that reads the raw HTML over
   HTTP. That needs an edge (custom domain + Cloudflare WAF); until that
   exists the protection is policy + wall + monitoring.
   ================================================================== */
(function () {
  'use strict';

  var ISSUER_PUBLIC_KEY = 'MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAnRYUvN9Ke82NcgoF39OjDPY+8/h8yfsbRiuIpSIlOndy5eIZKBdj7G6XEG8zgKVV+15zpu0GXAKQWhvdZOeZb32h12bCBO9gfebjNCiBJzSxCYW9Ps799peqVij7s0fPRWGrgkabgYGbIukEx0XRwN0TE1wgTAemOyNOdHQVur3ZkPyO8L9zxjBk6GzQnLpimEFRmLkdcBnJRKawKgYKDwGwyhKgFfU9ABSeSKMtmwa/qALcYExySPM2GQ7KObRoVrojxwYrVfXuVlV46rN+e0PQaL899lxoxIcVpOZtE41X9Pglfv6oL+MHUCv17Cs7XsuvP6JuJ/XjnXkLBO8zVO9bBQ2ENjJA4IB8qU6FeekbBDZqMAwMbm/0fUdBSR83zcJlk8/jJjM04LXthrMvPvy9pTjzoYDG4axNoJqPTP9GXyhyvD3TsuwfuJ9FXsX24xKXTGX4Jf3Weh4vC3zM8poGR2QQGUbTY5FhhZxp6RRFYLwLYMnlA4BCsP4X2akJAgMBAAE=';
  var DISCOVERY = 'https://ntfy.sh/ghvst-issuer-05cc917f7c984f228d88/json?poll=1&since=all';
  var CACHED_ISSUER = 'ghvst.issuer';

  /* The agent signatures. Matched as substrings of the lowercased agent
     string. Explicit signatures only - no headless, no "empty UA" guess:
     a false positive locks a paying buyer out. */
  var AGENTS = [
    'gptbot', 'chatgpt-user', 'oai-searchbot', 'claudebot', 'claude-web',
    'claude-bot', 'anthropic-ai', 'ccbot', 'perplexitybot', 'perplexity-user',
    'google-extended', 'applebot-extended', 'bytespider', 'diffbot',
    'omgilibot', 'meta-externalagent', 'timpibot', 'webzio-extended', 'youbot',
    'imagesiftbot', 'cohere-ai', 'amazonbot', 'facebookbot', 'scrapy',
    'semrushbot', 'ahrefsbot', 'mj12bot', 'dotbot', 'blexbot', 'dataforseobot',
    'seznambot', 'ia_archiver', 'petalbot', 'youbot', 'neevbot', 'siderbot',
    'browserling', 'puppeteer', 'playwright', 'headlesschrome', 'selenium',
    'puppeteer', 'curl/', 'wget/', 'python-requests', 'python-urllib',
    'go-http-client', 'java/', 'okhttp', 'axios/', 'node-fetch',
    'rea-agents', 'morluto', 'archiveexplorer',
    'mitmproxy', 'mitmweb', 'mitmdump', 'charles', 'fiddler', 'zaproxy',
    'burpsuite', 'httpcanary', 'pcapdroid', 'frida', 'jadx', 'apktool',
    'ghidra', 'objection', 'xposed'
  ];

  function uaString() {
    return ((navigator && navigator.userAgent) || '').toLowerCase();
  }

  function isAgent(ua) {
    ua = String(ua || uaString()).toLowerCase();
    for (var i = 0; i < AGENTS.length; i++) {
      if (ua.indexOf(AGENTS[i]) !== -1) return true;
    }
    return false;
  }

  /* ------------------------------------------------------------------ wall */
  function wall() {
    var ld = document.getElementById('ldjson');
    if (ld && ld.parentNode) { ld.parentNode.removeChild(ld); }

    // THE WALL MUST ACTUALLY STOP THE PAGE.
    //
    // MEASURED, not assumed: writing the wall with document.open() /
    // document.write() / document.close() does NOT stop the parser. The parser
    // keeps consuming the rest of the source and appends every card, price and
    // pay link to the same document. A headless Edge dump proved it - the wall
    // message was in the DOM AND all 71 data-paypal anchors and the whole
    // storefront were still there. An agent read the wall and the shop anyway.
    //
    // The only thing that genuinely stops the parser is LEAVING the document.
    // So the wall navigates to wall.html, which carries the same message and
    // nothing else. The old document is aborted, the storefront is never
    // finished, and the agent is left with one page that has no prices and no
    // links on it.
    var wallUrl = 'wall.html';
    try {
      wallUrl = new URL('wall.html', document.baseURI).href;
    } catch (e) { /* the relative path is the fallback */ }

    try { window.stop(); } catch (e) { /* no subresource loads after this */ }

    try {
      window.location.replace(wallUrl);
    } catch (e) { /* fall through to the write-and-wipe path */ }

    // BELT AND BRACES. If the navigation is refused (a sandboxed frame, a
    // blocked redirect), the document is still wiped: the wall is written and
    // the page content is removed as soon as the parser hands over.
    var html =
      '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
      '<meta name="viewport" content="width=device-width, initial-scale=1">' +
      '<title>Not available to automated agents</title>' +
      '<style>html,body{margin:0;padding:0;background:#08050f;color:#e8eaf2;' +
      'font-family:system-ui,-apple-system,Segoe UI,sans-serif}</style></head><body>' +
      '<div style="max-width:640px;margin:12vh auto;padding:32px;line-height:1.7">' +
      '<h1 style="font-size:22px;margin:0 0 14px">This page is not available to automated agents.</h1>' +
      '<p style="font-size:15px;color:#a9b0c6">You are reading this with an automated crawler. ' +
      'The RDX storefront publishes real prices, real features and real download links for paid ' +
      'software, and automated harvesting of it is not permitted.</p>' +
      '<p style="font-size:15px;color:#a9b0c6">If you are a person on a normal browser and you saw ' +
      'this by mistake, the products are still here - email or WhatsApp ' +
      '<a style="color:#9fe8ff" href="https://wa.me/18684357698">+1-868-435-7698</a> and we will ' +
      'walk you through it.</p></div></body></html>';
    try {
      document.open();
      document.write(html);
      document.close();
    } catch (e) { /* the wipe below still runs */ }

    function wipe() {
      try {
        document.documentElement.innerHTML =
          '<head><meta charset="utf-8"><title>Not available to automated agents</title></head>' +
          '<body style="background:#08050f;color:#e8eaf2;font-family:system-ui,sans-serif;padding:32px">' +
          '<h1 style="font-size:22px">This page is not available to automated agents.</h1></body>';
      } catch (e) { /* nothing else can be done from here */ }
    }
    try { window.addEventListener('load', wipe); } catch (e) { /* no load event */ }
    try { setTimeout(wipe, 0); } catch (e) { /* no timers */ }
  }

  /* ------------------------------------------------------------- the issuer */
  function b64bytes(text) {
    var raw = atob(text.replace(/-/g, '+').replace(/_/g, '/'));
    var out = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out;
  }

  function issuerKey() {
    if (!window.crypto || !window.crypto.subtle) return Promise.resolve(null);
    return window.crypto.subtle.importKey(
      'spki', b64bytes(ISSUER_PUBLIC_KEY),
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']
    ).catch(function () { return null; });
  }

  /* The site file's "signed" field is the envelope. It is read defensively:
     a string is used as-is, and an array is scanned for the first entry that
     is a real GVST1 envelope - a file written by an older publisher must not
     be able to break discovery. */
  function envelopeOf(doc) {
    if (!doc) return '';
    var value = doc.signed;
    if (typeof value === 'string') return value;
    if (Object.prototype.toString.call(value) === '[object Array]') {
      for (var i = 0; i < value.length; i++) {
        var item = String(value[i] || '');
        if (item.indexOf('GVST1.') === 0) return item;
      }
    }
    return '';
  }

  /* The discovery document is GVST1.<payload>.<signature> exactly as the app reads it. */
  function verifyList(envelope, key) {
    var parts = String(envelope || '').trim().split('.');
    if (parts.length !== 3 || parts[0] !== 'GVST1') return Promise.resolve(null);
    var payload = atob(parts[1].replace(/-/g, '+').replace(/_/g, '/'));
    var fields = payload.split('|');
    if (fields.length < 5 || fields[1] !== 'issuer-manifest') return Promise.resolve(null);
    var now = Math.floor(Date.now() / 1000);
    if (parseInt(fields[3], 10) > now + 300) return Promise.resolve(null);
    if (parseInt(fields[4], 10) < now) return Promise.resolve(null);
    var body;
    try { body = JSON.parse(atob(fields[2].replace(/-/g, '+').replace(/_/g, '/'))); }
    catch (e) { return Promise.resolve(null); }
    return window.crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5', key, b64bytes(parts[2]),
      new TextEncoder().encode(payload)
    ).then(function (ok) {
      return ok && body && body.urls && body.urls.length ? body.urls : null;
    }).catch(function () { return null; });
  }

  function alive(base, timeoutMs) {
    /* A health check with its own deadline. A tunnel that has died can hang on
       DNS for longer than a buyer is willing to wait, and a promise that never
       settles is worse than a promise that says no. */
    var ctrl = (typeof AbortController !== 'undefined') ? new AbortController() : null;
    var options = { cache: 'no-store' };
    if (ctrl) options.signal = ctrl.signal;
    var timer = null;
    if (ctrl && timeoutMs) {
      timer = setTimeout(function () { try { ctrl.abort(); } catch (e) {} }, timeoutMs);
    }
    return fetch(base.replace(/\/$/, '') + '/health', options)
      .then(function (r) { return r.ok ? base.replace(/\/$/, '') : null; })
      .catch(function () { return null; })
      .then(function (value) {
        if (timer) clearTimeout(timer);
        return value;
      });
  }

  function firstAlive(list) {
    list = (list || []).filter(Boolean);
    if (!list.length) return Promise.resolve(null);
    /* THE FIRST ADDRESS THAT ANSWERS WINS.
       Promise.all waited for EVERY address, so one dead tunnel stalled the
       whole thing - the visit ping never fired and a paid buyer sat on a
       receipt page that could not reach the issuer. A race with a deadline
       fixes both. */
    return new Promise(function (resolve) {
      var pending = list.length;
      var settled = false;
      list.forEach(function (base) {
        alive(base, 7000).then(function (hit) {
          if (settled) return;
          if (hit) { settled = true; resolve(hit); return; }
          pending -= 1;
          if (pending === 0) { settled = true; resolve(null); }
        });
      });
    });
  }

  var issuerPromise = null;
  function findIssuer() {
    if (issuerPromise) return issuerPromise;
    var cached = '';
    try { cached = window.localStorage.getItem(CACHED_ISSUER) || ''; } catch (e) {}
    issuerPromise = firstAlive([cached]).then(function (hit) {
      if (hit) return hit;
      return fetch('issuer.json', { cache: 'no-store' })
        .then(function (r) { return r.ok ? r.json() : null; })
        .catch(function () { return null; })
        .then(function (doc) {
          /* The site file carries a SIGNED envelope. An unsigned list is ignored
             on purpose: a page that is about to send a buyer's transaction id to
             whatever address it picks must only use a signed address. */
          var envelope = envelopeOf(doc);
          if (!envelope) return null;
          return issuerKey().then(function (key) {
            if (!key) return null;
            return verifyList(envelope, key);
          }).then(function (urls) {
            return firstAlive(urls);
          });
        })
        .then(function (hit2) {
          if (hit2) return hit2;
          /* The signed ntfy list is the fallback, and the only one that survives
             a tunnel change without this page being rebuilt. */
          return fetch(DISCOVERY, { cache: 'no-store' })
            .then(function (r) { return r.ok ? r.json() : []; })
            .catch(function () { return []; })
            .then(function (messages) {
              var text = '';
              for (var i = (messages || []).length - 1; i >= 0; i--) {
                if (messages[i] && messages[i].message) { text = messages[i].message; break; }
              }
              if (!text) return null;
              return issuerKey().then(function (key) {
                if (!key) return null;
                return verifyList(text, key);
              }).then(function (urls) {
                return firstAlive(urls);
              });
            });
        });
    }).then(function (base) {
      if (base) { try { window.localStorage.setItem(CACHED_ISSUER, base); } catch (e) {} }
      return base;
    });
    return issuerPromise;
  }

  /* ------------------------------------------------------------ visit log */
  /* Silent. A visitor never sees it, a crawler never blocks on it, and a
     failure here never breaks the page. */
  function track(page, product) {
    try {
      var params = new URLSearchParams(window.location.search);
      var ref = document.referrer || '';
      findIssuer().then(function (base) {
        if (!base) return;
        return fetch(base + '/visit', {
          method: 'POST',
          mode: 'cors',
          keepalive: true,
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            page: String(page || window.location.pathname || '').slice(0, 300),
            ref: String(ref).slice(0, 300),
            product: String(product || params.get('product') || '').slice(0, 120)
          })
        }).catch(function () {});
      }).catch(function () {});
    } catch (e) { /* never let logging break a page */ }
  }

  var G = {
    AGENTS: AGENTS,
    isAgent: isAgent,
    wall: wall,
    findIssuer: findIssuer,
    track: track
  };

  window.GHVST_GUARD = G;

  /* The wall runs first, before any page content is parsed, so an agent
     never sees the copy. The visit log runs for everyone else. */
  if (isAgent(uaString())) {
    wall();
  } else {
    track(document.documentElement.getAttribute('data-page') ||
          (window.location.pathname || '').replace(/\/+$/, '') || '/');
  }
})();
