/* WCrypt - tiny ES5 encryption used by "add playlist from phone".
 * Shared by the TV app (app/js/lib/wcrypt.js) and the phone page (web/add.html loads this same file).
 * Scheme: keystream = SHA-256(secret:nonce:i) blocks XOR plaintext, integrity tag = SHA-256("mac":secret:nonce:cipher).
 * The secret only travels inside the QR code (URL #fragment), never to the relay server. */
(function (g) {
  'use strict';
  var K = [], H0 = [];
  (function () {
    function isPrime(x) { for (var i = 2; i * i <= x; i++) if (x % i === 0) return false; return true; }
    function frac(x) { return ((x - Math.floor(x)) * 4294967296) | 0; }
    for (var n = 2, c = 0; c < 64; n++) {
      if (!isPrime(n)) continue;
      if (c < 8) H0[c] = frac(Math.pow(n, 1 / 2));
      K[c++] = frac(Math.pow(n, 1 / 3));
    }
  })();

  function ror(x, n) { return (x >>> n) | (x << (32 - n)); }

  function sha256(bytes) {
    var m = bytes.slice(), bl = bytes.length * 8, H = H0.slice(), w = [], i, t;
    m.push(0x80);
    while (m.length % 64 !== 56) m.push(0);
    m.push(0, 0, 0, 0, (bl >>> 24) & 255, (bl >>> 16) & 255, (bl >>> 8) & 255, bl & 255);
    for (i = 0; i < m.length; i += 64) {
      for (t = 0; t < 16; t++) w[t] = (m[i + t * 4] << 24) | (m[i + t * 4 + 1] << 16) | (m[i + t * 4 + 2] << 8) | m[i + t * 4 + 3];
      for (t = 16; t < 64; t++) {
        var x = w[t - 15], y = w[t - 2];
        w[t] = (w[t - 16] + (ror(x, 7) ^ ror(x, 18) ^ (x >>> 3)) + w[t - 7] + (ror(y, 17) ^ ror(y, 19) ^ (y >>> 10))) | 0;
      }
      var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], gg = H[6], h = H[7];
      for (t = 0; t < 64; t++) {
        var t1 = (h + (ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)) + ((e & f) ^ (~e & gg)) + K[t] + w[t]) | 0;
        var t2 = ((ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) | 0;
        h = gg; gg = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
      H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + gg) | 0; H[7] = (H[7] + h) | 0;
    }
    var out = [];
    for (i = 0; i < 8; i++) out.push((H[i] >>> 24) & 255, (H[i] >>> 16) & 255, (H[i] >>> 8) & 255, H[i] & 255);
    return out;
  }

  function utf8(s) { var b = unescape(encodeURIComponent(s)), a = []; for (var i = 0; i < b.length; i++) a.push(b.charCodeAt(i)); return a; }
  function fromUtf8(a) { var s = ''; for (var i = 0; i < a.length; i++) s += String.fromCharCode(a[i]); return decodeURIComponent(escape(s)); }
  function b64(a) { var s = ''; for (var i = 0; i < a.length; i++) s += String.fromCharCode(a[i]); return btoa(s); }
  function unb64(s) { var b = atob(s), a = []; for (var i = 0; i < b.length; i++) a.push(b.charCodeAt(i)); return a; }
  function hex(a) { var s = ''; for (var i = 0; i < a.length; i++) s += (a[i] < 16 ? '0' : '') + a[i].toString(16); return s; }
  function stream(secret, nonce, len) {
    var out = [], i = 0;
    while (out.length < len) out = out.concat(sha256(utf8(secret + ':' + nonce + ':' + (i++))));
    return out.slice(0, len);
  }
  function mac(secret, nonce, c) { return hex(sha256(utf8('mac:' + secret + ':' + nonce + ':' + c))).slice(0, 32); }
  function rand(n) {
    var chars = 'abcdefghijkmnpqrstuvwxyz23456789', r = null, a = [], i; // 32 chars -> no modulo bias
    var cr = g.crypto || g.msCrypto;
    if (cr && cr.getRandomValues) { r = new Uint8Array(n); cr.getRandomValues(r); }
    for (i = 0; i < n; i++) a.push(chars.charAt((r ? r[i] : Math.floor(Math.random() * 256)) % 32));
    return a.join('');
  }

  g.WCrypt = {
    sha256: sha256, utf8: utf8, hex: hex, rand: rand,
    encrypt: function (secret, obj) {
      var p = utf8(JSON.stringify(obj)), n = rand(12), ks = stream(secret, n, p.length), c = [];
      for (var i = 0; i < p.length; i++) c.push(p[i] ^ ks[i]);
      var cb = b64(c);
      return JSON.stringify({ v: 1, n: n, c: cb, m: mac(secret, n, cb) });
    },
    decrypt: function (secret, text) {
      var o = JSON.parse(text);
      if (!o || o.v !== 1 || mac(secret, o.n, o.c) !== o.m) throw new Error('Invalid message');
      var c = unb64(o.c), ks = stream(secret, o.n, c.length), p = [];
      for (var i = 0; i < c.length; i++) p.push(c[i] ^ ks[i]);
      return JSON.parse(fromUtf8(p));
    }
  };
})(typeof window !== 'undefined' ? window : this);
