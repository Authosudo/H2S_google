/* ==========================================================================
 * PII SENTINEL — Client-Side Data Protection Engine & Application Controller
 * 100% client-side, zero network calls, zero external dependencies.
 * Engine is structured as a pure UMD-style module (createPIIEngine) so it runs
 * identically in Node.js (module.exports), browser main thread (window.PIIEngine),
 * and inside an inline Blob Web Worker.
 * ========================================================================== */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.PIIEngine = factory();
  }
})(typeof globalThis !== 'undefined' ? globalThis : typeof window !== 'undefined' ? window : this, function createPIIEngine() {
  'use strict';

  // --- Verhoeff Tables (used for 12-digit Aadhaar checksum validation) ---
  var VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
  ];
  var VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
  ];

  function verhoeffCheck(numStr) {
    if (!/^\d{12}$/.test(numStr)) return false;
    var c = 0;
    for (var i = 0; i < numStr.length; i++) {
      var digit = numStr.charCodeAt(numStr.length - 1 - i) - 48;
      c = VERHOEFF_D[c][VERHOEFF_P[i % 8][digit]];
    }
    return c === 0;
  }

  function luhnCheck(digits) {
    if (typeof digits !== 'string' || !/^[0-9]{13,19}$/.test(digits)) return false;
    if (/^(\d)\1+$/.test(digits)) return false;
    var sum = 0;
    var shouldDouble = false;
    for (var i = digits.length - 1; i >= 0; i--) {
      var d = digits.charCodeAt(i) - 48;
      if (shouldDouble) {
        d *= 2;
        if (d > 9) d -= 9;
      }
      sum += d;
      shouldDouble = !shouldDouble;
    }
    return sum % 10 === 0;
  }

  function detectCardBrand(digits) {
    var len = digits.length;
    if (/^4\d+$/.test(digits) && (len === 13 || len === 16 || len === 19)) return 'Visa';
    if (/^3[47]\d+$/.test(digits) && len === 15) return 'Amex';
    var p2 = parseInt(digits.slice(0, 2), 10);
    var p3 = parseInt(digits.slice(0, 3), 10);
    var p4 = parseInt(digits.slice(0, 4), 10);
    var p6 = parseInt(digits.slice(0, 6), 10);
    if (len === 16 && ((p2 >= 51 && p2 <= 55) || (p4 >= 2221 && p4 <= 2720))) return 'Mastercard';
    // Maestro Debit Cards (common in India & Europe, 13-19 digits)
    if (len >= 13 && len <= 19 && (
      p4 === 5018 || p4 === 5020 || p4 === 5038 || p4 === 5893 ||
      p4 === 6304 || p4 === 6759 || (p4 >= 6761 && p4 <= 6763) || p4 === 6771
    )) {
      return 'Maestro';
    }
    // RuPay Debit & Credit Cards (must check before generic Discover/JCB ranges)
    if ((len === 16 || len === 19) && (
      (p2 === 60 && p4 !== 6011) || p2 === 81 || p2 === 82 ||
      (p4 >= 6521 && p4 <= 6530) || p3 === 508 || p3 === 353 || p3 === 356
    )) {
      return 'RuPay';
    }
    if ((len === 16 || len === 19) && (
      p4 === 6011 ||
      (p6 >= 622126 && p6 <= 622925) ||
      (p3 >= 644 && p3 <= 649) ||
      p2 === 65
    )) {
      return 'Discover';
    }
    if (len >= 14 && len <= 19 && ((p3 >= 300 && p3 <= 305) || p4 === 3095 || p2 === 36 || p2 === 38 || p2 === 39)) {
      return 'Diners Club';
    }
    if (len >= 16 && len <= 19 && (p4 >= 3528 && p4 <= 3589)) {
      return 'JCB';
    }
    if (len >= 16 && len <= 19 && p2 === 62) {
      return 'UnionPay';
    }
    return null;
  }

  var PAN_HOLDER_TYPES = {
    P: 'Individual', C: 'Company', H: 'HUF', F: 'Firm', A: 'AOP',
    T: 'Trust', B: 'BOI', L: 'Local Authority', J: 'Artificial Juridical Person', G: 'Government'
  };

  var KNOWN_UPI_HANDLES = {
    upi: 1, okicici: 1, okhdfcbank: 1, okaxis: 1, oksbi: 1, ybl: 1, ibl: 1, axl: 1,
    paytm: 1, ptm: 1, apl: 1, fbl: 1, icici: 1, sbi: 1, hdfc: 1, axisbank: 1,
    kotak: 1, indus: 1, federal: 1, barodampay: 1, jupiteraxis: 1, slice: 1, freecharge: 1, airpay: 1
  };

  var TYPE_PRIORITY = {
    EMAIL: 1,
    UPI: 2,
    PAYMENT_CARD: 3,
    AADHAAR: 4,
    PAN: 5,
    GSTIN: 6,
    IFSC: 7,
    PHONE: 8,
    IPV4: 9,
    AADHAAR_UNVERIFIED: 10,
    PASSPORT: 11,
    VOTER_ID: 12,
    VEHICLE: 13,
    BANK_ACCOUNT: 14,
    DOB: 15
  };

  var PSEUDONYM_PREFIX = {
    EMAIL: 'USER',
    PHONE: 'PHONE',
    PAN: 'PAN',
    AADHAAR: 'AADHAAR',
    AADHAAR_UNVERIFIED: 'AADHAAR_UNVERIFIED',
    PAYMENT_CARD: 'CARD',
    IPV4: 'IP',
    UPI: 'UPI',
    IFSC: 'IFSC',
    GSTIN: 'GSTIN',
    PASSPORT: 'PASSPORT',
    VOTER_ID: 'VOTER',
    VEHICLE: 'VEHICLE',
    BANK_ACCOUNT: 'BANK',
    DOB: 'DOB'
  };

  var DEFAULT_CATEGORIES = {
    EMAIL: true,
    PHONE: true,
    IPV4: true,
    PAN: true,
    AADHAAR: true,
    AADHAAR_UNVERIFIED: false,
    PAYMENT_CARD: true,
    UPI: true,
    IFSC: true,
    GSTIN: true,
    PASSPORT: false,
    VOTER_ID: false,
    VEHICLE: false,
    BANK_ACCOUNT: true,
    DOB: true
  };

  var CATEGORY_META = {
    EMAIL: { label: 'Email', group: 'Contact', weight: 6 },
    PHONE: { label: 'Phone (IN)', group: 'Contact', weight: 7 },
    IPV4: { label: 'IPv4 Address', group: 'Network', weight: 4 },
    PAN: { label: 'Indian PAN', group: 'Government ID', weight: 14 },
    AADHAAR: { label: 'Indian Aadhaar', group: 'Government ID', weight: 18 },
    AADHAAR_UNVERIFIED: { label: 'Aadhaar-like (checksum failed)', group: 'Government ID', weight: 5 },
    PAYMENT_CARD: { label: 'Payment Card', group: 'Financial', weight: 20 },
    UPI: { label: 'UPI ID', group: 'Financial', weight: 8 },
    IFSC: { label: 'Bank IFSC', group: 'Financial', weight: 6 },
    GSTIN: { label: 'Indian GSTIN', group: 'Government ID', weight: 10 },
    PASSPORT: { label: 'Indian Passport', group: 'Government ID', weight: 14 },
    VOTER_ID: { label: 'Voter ID (EPIC)', group: 'Government ID', weight: 12 },
    VEHICLE: { label: 'Vehicle Reg.', group: 'Government ID', weight: 7 },
    BANK_ACCOUNT: { label: 'Bank Account', group: 'Financial', weight: 15 },
    DOB: { label: 'Date of Birth', group: 'Personal', weight: 6 }
  };

  var POLICY_PRESETS = {
    dpdp: {
      name: 'India DPDP Act 2023',
      description: 'Focuses on personal & digital identifiers under India DPDP Act: Emails, Phones, Aadhaar, PAN, Passport, Voter ID, DOB, UPI, Bank Accounts, Vehicle.',
      categories: {
        EMAIL: true, PHONE: true, IPV4: true, PAN: true, AADHAAR: true, AADHAAR_UNVERIFIED: false,
        PAYMENT_CARD: true, UPI: true, IFSC: true, GSTIN: false, PASSPORT: true, VOTER_ID: true, VEHICLE: true,
        BANK_ACCOUNT: true, DOB: true
      }
    },
    pcidss: {
      name: 'PCI-DSS (Cards & Financial)',
      description: 'Targets payment cardholder & banking data: Luhn-valid Payment Cards, Bank Accounts, IFSC, UPI IDs.',
      categories: {
        EMAIL: false, PHONE: false, IPV4: false, PAN: false, AADHAAR: false, AADHAAR_UNVERIFIED: false,
        PAYMENT_CARD: true, UPI: true, IFSC: true, GSTIN: false, PASSPORT: false, VOTER_ID: false, VEHICLE: false,
        BANK_ACCOUNT: true, DOB: false
      }
    },
    gdpr: {
      name: 'GDPR-Style Personal Data',
      description: 'Broad personal & online identifiers: Emails, Phones, IPv4, DOB, Gov IDs, Payment Cards.',
      categories: {
        EMAIL: true, PHONE: true, IPV4: true, PAN: true, AADHAAR: true, AADHAAR_UNVERIFIED: false,
        PAYMENT_CARD: true, UPI: false, IFSC: false, GSTIN: false, PASSPORT: true, VOTER_ID: true, VEHICLE: true,
        BANK_ACCOUNT: false, DOB: true
      }
    },
    devlogs: {
      name: 'Developer Logs / Safe for AI',
      description: 'Sanitizes secrets & customer PII in stack traces/logs before pasting into AI tools: Emails, Phones, IPs, Payment Cards, PAN, Aadhaar, UPI, IFSC, Bank Accounts, GSTIN.',
      categories: {
        EMAIL: true, PHONE: true, IPV4: true, PAN: true, AADHAAR: true, AADHAAR_UNVERIFIED: false,
        PAYMENT_CARD: true, UPI: true, IFSC: true, GSTIN: true, PASSPORT: false, VOTER_ID: false, VEHICLE: false,
        BANK_ACCOUNT: true, DOB: true
      }
    },
    all: {
      name: 'All Detectors (Max)',
      description: 'Enables every verified detector including Passport, Voter ID, Vehicle, and strict KYC/Financial patterns.',
      categories: {
        EMAIL: true, PHONE: true, IPV4: true, PAN: true, AADHAAR: true, AADHAAR_UNVERIFIED: false,
        PAYMENT_CARD: true, UPI: true, IFSC: true, GSTIN: true, PASSPORT: true, VOTER_ID: true, VEHICLE: true,
        BANK_ACCOUNT: true, DOB: true
      }
    }
  };

  function getDefaultEnabledCategories() {
    var copy = {};
    for (var k in DEFAULT_CATEGORIES) {
      if (Object.prototype.hasOwnProperty.call(DEFAULT_CATEGORIES, k)) {
        copy[k] = DEFAULT_CATEGORIES[k];
      }
    }
    return copy;
  }

  function createPseudonymSession() {
    return { counters: {}, map: {} };
  }

  function normalizeForPseudonym(type, value) {
    var v = String(value || '').trim();
    if (type === 'EMAIL' || type === 'UPI') return v.toLowerCase();
    if (type === 'PHONE') {
      var digits = v.replace(/\D/g, '');
      if (digits.length === 12 && digits.slice(0, 2) === '91') digits = digits.slice(2);
      else if (digits.length === 11 && digits.charAt(0) === '0') digits = digits.slice(1);
      return digits;
    }
    if (type === 'PAYMENT_CARD' || type === 'CARD' || type === 'AADHAAR' || type === 'AADHAAR_UNVERIFIED' || type === 'BANK_ACCOUNT') {
      return v.replace(/\D/g, '');
    }
    if (type === 'PAN' || type === 'IFSC' || type === 'GSTIN' || type === 'PASSPORT' || type === 'VOTER_ID' || type === 'VEHICLE') {
      return v.replace(/[\s-]+/g, '').toUpperCase();
    }
    return v;
  }

  function pad2(n) {
    return n < 10 ? '0' + n : String(n);
  }

  function getPseudonym(session, type, value) {
    var categoryKey = type === 'AADHAAR_UNVERIFIED' ? 'AADHAAR_UNVERIFIED' : type;
    var norm = normalizeForPseudonym(type, value);
    var mapKey = categoryKey + '::' + norm;
    if (Object.prototype.hasOwnProperty.call(session.map, mapKey)) {
      return session.map[mapKey];
    }
    var prefix = PSEUDONYM_PREFIX[categoryKey] || categoryKey;
    var nextCount = (session.counters[prefix] || 0) + 1;
    session.counters[prefix] = nextCount;
    var token = prefix + '_' + pad2(nextCount);
    session.map[mapKey] = token;
    return token;
  }

  function exportPseudonymMapping(session) {
    if (!session || !session.map) return { version: 1, entries: [] };
    var entries = [];
    for (var k in session.map) {
      if (!Object.prototype.hasOwnProperty.call(session.map, k)) continue;
      var idx = k.indexOf('::');
      entries.push({
        type: k.slice(0, idx),
        normalizedOriginal: k.slice(idx + 2),
        pseudonym: session.map[k]
      });
    }
    return {
      version: 1,
      warning: 'Contains sensitive PII mappings. Store securely and never distribute with sanitized files.',
      entries: entries
    };
  }

  function restoreFromMapping(sanitizedText, mappingObj) {
    if (typeof sanitizedText !== 'string' || !mappingObj || !Array.isArray(mappingObj.entries)) {
      return { restoredText: sanitizedText || '', restoredCount: 0 };
    }
    var lookup = Object.create(null);
    var tokens = [];
    for (var i = 0; i < mappingObj.entries.length; i++) {
      var e = mappingObj.entries[i];
      if (e && e.pseudonym && typeof e.normalizedOriginal === 'string') {
        lookup[e.pseudonym] = e.normalizedOriginal;
        tokens.push(e.pseudonym.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
      }
    }
    if (tokens.length === 0) return { restoredText: sanitizedText, restoredCount: 0 };
    tokens.sort(function (a, b) { return b.length - a.length; });
    var re = new RegExp('\\b(' + tokens.join('|') + ')\\b', 'g');
    var count = 0;
    var restored = sanitizedText.replace(re, function (match) {
      count++;
      return Object.prototype.hasOwnProperty.call(lookup, match) ? lookup[match] : match;
    });
    return { restoredText: restored, restoredCount: count };
  }

  function detectPII(text, options) {
    if (typeof text !== 'string' || text.length === 0) return [];
    var opts = options || {};
    var enabled = opts.enabledCategories || DEFAULT_CATEGORIES;
    var candidates = [];

    // 1. EMAIL
    if (enabled.EMAIL !== false) {
      var emailRe = /(?<![A-Za-z0-9._%+-])([A-Za-z0-9](?:[A-Za-z0-9._%+-]*[A-Za-z0-9])?@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,})(?![A-Za-z0-9_%+-])/g;
      var m;
      while ((m = emailRe.exec(text)) !== null) {
        var val = m[1];
        if (val.indexOf('..') !== -1) continue;
        candidates.push({
          type: 'EMAIL',
          value: val,
          start: m.index,
          end: m.index + val.length,
          confidence: 0.96,
          validator: 'RFC-like syntax',
          reason: 'Valid email address format with domain and TLD'
        });
      }
    }

    // 2. UPI ID (e.g., name@okicici, 9876543210@ybl; emails win via higher priority)
    if (enabled.UPI) {
      var upiRe = /(?<![A-Za-z0-9._%+-])([A-Za-z0-9._-]{2,}@([A-Za-z0-9]{2,}))(?![A-Za-z0-9._-])/g;
      var um;
      while ((um = upiRe.exec(text)) !== null) {
        var uVal = um[1];
        var psp = um[2].toLowerCase();
        var isKnown = Boolean(KNOWN_UPI_HANDLES[psp]);
        // Avoid matching pure email-like domains unless no dot after @ (already ensured by [A-Za-z0-9]{2,})
        // Require either known PSP handle or UPI context nearby
        var lineStart = text.lastIndexOf('\n', um.index) + 1;
        var ctxBefore = text.slice(Math.max(lineStart, um.index - 24), um.index).toLowerCase();
        var hasUpiCtx = /\b(upi|vpa|pay|gpay|phonepe|paytm|bhim)\b/.test(ctxBefore);
        if (!isKnown && !hasUpiCtx) continue;
        candidates.push({
          type: 'UPI',
          value: uVal,
          start: um.index,
          end: um.index + uVal.length,
          confidence: isKnown ? 0.92 : 0.78,
          validator: isKnown ? 'Known UPI PSP handle' : 'UPI context + VPA syntax',
          reason: isKnown ? 'Matches VPA syntax with known UPI handle @' + psp : 'VPA syntax near UPI payment keyword'
        });
      }
    }

    // 3. PAYMENT_CARD (Luhn + brand BIN, card grouping, or explicit card context; horizontal separators only)
    if (enabled.PAYMENT_CARD !== false && enabled.CARD !== false) {
      var sep = '(?:[ \\t\\u00A0]+|[-\\u2013\\u2014])';
      var cardRe = new RegExp('(?<![\\dA-Za-z]|\\d[./_])(\\d{4}' + sep + '\\d{4}' + sep + '\\d{4}' + sep + '\\d{1,4}(?:' + sep + '\\d{1,3})?|\\d{4}' + sep + '\\d{6}' + sep + '\\d{4,5}|[0-9]{13,19})(?![\\dA-Za-z]|[./_]\\d)', 'g');
      var cm;
      while ((cm = cardRe.exec(text)) !== null) {
        var cVal = cm[1];
        var isGrouped = /[ \t\u00A0\-\u2013\u2014]/.test(cVal);
        var cDigits = cVal.replace(/[ \t\u00A0\-\u2013\u2014]/g, '');
        if (!/^[0-9]{13,19}$/.test(cDigits)) continue;
        var brand = luhnCheck(cDigits) ? detectCardBrand(cDigits) : null;
        var validatorLabel = 'Luhn + Network Prefix';

        // If a 17-19 digit grouped match swallowed a trailing expiry/CVV, fall back to the 16-digit card prefix
        if (!brand && cDigits.length > 16) {
          var trimRe = new RegExp('^(\\d{4}' + sep + '\\d{4}' + sep + '\\d{4}' + sep + '\\d{4})' + sep + '\\d{1,3}$');
          var trimmedMatch = cVal.match(trimRe);
          if (trimmedMatch) {
            var baseVal = trimmedMatch[1];
            var baseDigits = baseVal.replace(/[ \t\u00A0\-\u2013\u2014]/g, '');
            if (luhnCheck(baseDigits)) {
              cVal = baseVal;
              cDigits = baseDigits;
              brand = detectCardBrand(cDigits);
            }
          }
        }

        // Fallback: Luhn-valid 13-19 digit number with standard card grouping (e.g. 1111 2222 3333 4444) or card keyword context
        if (!brand && luhnCheck(cDigits)) {
          var cLineStart = text.lastIndexOf('\n', cm.index) + 1;
          var cCtx = text.slice(Math.max(cLineStart, cm.index - 40), cm.index);
          var hasCtx = /\b(?:credit|debit|payment\s*card|card|cc|visa|mastercard|rupay|maestro|amex|discover)\b/i.test(cCtx);
          if (isGrouped || hasCtx) {
            brand = 'Payment Card';
            validatorLabel = hasCtx ? 'Luhn + Card Context' : 'Luhn + Card Format';
          }
        }

        if (!brand) continue;
        candidates.push({
          type: 'PAYMENT_CARD',
          value: cVal,
          start: cm.index,
          end: cm.index + cVal.length,
          confidence: validatorLabel === 'Luhn + Network Prefix' ? 0.99 : 0.91,
          validator: validatorLabel,
          reason: 'Luhn valid, ' + brand + ' pattern, ' + cDigits.length + ' digits (format check only; credit/debit type not inferred)',
          meta: { brand: brand, digits: cDigits.length }
        });
      }
    }

    // 4. INDIAN AADHAAR (12 digits, starts 2-9, Verhoeff checksum, horizontal separators only)
    if (enabled.AADHAAR !== false || enabled.AADHAAR_UNVERIFIED === true) {
      var aadhaarRe = /(?<![\dA-Za-z])([2-9]\d{3})([ \t\u00A0\-\u2013]?)(\d{4})\2(\d{4})(?![\dA-Za-z])/g;
      var am;
      while ((am = aadhaarRe.exec(text)) !== null) {
        var aVal = am[0];
        if (/[\r\n]/.test(aVal)) continue;
        var aDigits = aVal.replace(/[\s-]/g, '');
        var isVerhoeff = verhoeffCheck(aDigits);
        if (isVerhoeff && enabled.AADHAAR !== false) {
          candidates.push({
            type: 'AADHAAR',
            value: aVal,
            start: am.index,
            end: am.index + aVal.length,
            confidence: 0.97,
            validator: 'Verhoeff checksum',
            reason: '12-digit number starting with ' + aDigits.charAt(0) + ', Verhoeff checksum valid'
          });
        } else if (!isVerhoeff && enabled.AADHAAR_UNVERIFIED === true) {
          candidates.push({
            type: 'AADHAAR_UNVERIFIED',
            value: aVal,
            start: am.index,
            end: am.index + aVal.length,
            confidence: 0.35,
            validator: 'Verhoeff failed',
            reason: 'Aadhaar-like (checksum failed): 12 digits starting 2-9 but Verhoeff check failed'
          });
        }
      }
    }

    // 5. INDIAN GSTIN (15 chars: 2-digit state + 10-char PAN + entity + Z + check)
    if (enabled.GSTIN) {
      var gstinRe = /(?<![A-Za-z0-9])((?:0[1-9]|[12]\d|3[0-8]|97)[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z])(?![A-Za-z0-9])/g;
      var gm;
      while ((gm = gstinRe.exec(text)) !== null) {
        var gVal = gm[1];
        var embeddedHolder = gVal.charAt(5); // 4th char of embedded PAN
        if (!PAN_HOLDER_TYPES[embeddedHolder]) continue;
        candidates.push({
          type: 'GSTIN',
          value: gVal,
          start: gm.index,
          end: gm.index + gVal.length,
          confidence: 0.95,
          validator: 'GSTIN state + PAN structure',
          reason: 'Valid 15-char GSTIN (state ' + gVal.slice(0, 2) + ', PAN holder ' + embeddedHolder + ', Z-marker)'
        });
      }
    }

    // 6. INDIAN PAN ([A-Z]{5}[0-9]{4}[A-Z], 4th char holder code)
    if (enabled.PAN !== false) {
      var panRe = /(?<![A-Za-z0-9])([A-Za-z]{5}[0-9]{4}[A-Za-z])(?![A-Za-z0-9])/g;
      var pm;
      while ((pm = panRe.exec(text)) !== null) {
        var pVal = pm[1];
        var upper = pVal.toUpperCase();
        var holderChar = upper.charAt(3);
        var holderDesc = PAN_HOLDER_TYPES[holderChar];
        if (!holderDesc) continue;
        var isAllUpper = pVal === upper;
        candidates.push({
          type: 'PAN',
          value: pVal,
          start: pm.index,
          end: pm.index + pVal.length,
          confidence: isAllUpper ? 0.95 : 0.65,
          validator: 'PAN structure + holder code',
          reason: (isAllUpper ? 'Uppercase PAN' : 'Lowercase PAN match (reduced confidence)') +
            ' with holder code ' + holderChar + ' (' + holderDesc + ')'
        });
      }
    }

    // 7. IFSC CODE ([A-Z]{4}0[A-Z0-9]{6})
    if (enabled.IFSC) {
      var ifscRe = /(?<![A-Za-z0-9])([A-Z]{4}0[A-Z0-9]{6})(?![A-Za-z0-9])/g;
      var im;
      while ((im = ifscRe.exec(text)) !== null) {
        var iVal = im[1];
        candidates.push({
          type: 'IFSC',
          value: iVal,
          start: im.index,
          end: im.index + iVal.length,
          confidence: 0.91,
          validator: 'RBI IFSC 11-char structure',
          reason: '4-letter bank code (' + iVal.slice(0, 4) + '), reserved 0 at index 5, 6-char branch code'
        });
      }
    }

    // 8. INDIAN PHONE (+91 / 91 / 0 optional prefix, 10 digits starting 6-9, horizontal separators only)
    if (enabled.PHONE !== false) {
      var phoneRe = /(?<![\dA-Za-z])((?:\+?91[ \t-]?|0)?(?:[6-9]\d{4}[ \t-]?\d{5}|[6-9]\d{2}[ \t-]?\d{3}[ \t-]?\d{4}))(?![\dA-Za-z])/g;
      var phm;
      while ((phm = phoneRe.exec(text)) !== null) {
        var phVal = phm[1];
        if (/[\r\n]/.test(phVal)) continue;
        var phDigits = phVal.replace(/\D/g, '');
        if (phDigits.length === 12 && phDigits.slice(0, 2) === '91') phDigits = phDigits.slice(2);
        else if (phDigits.length === 11 && phDigits.charAt(0) === '0') phDigits = phDigits.slice(1);
        if (phDigits.length !== 10 || !/^[6-9]/.test(phDigits)) continue;
        var prevChar = phm.index > 0 ? text.charAt(phm.index - 1) : '';
        var nextChar = phm.index + phVal.length < text.length ? text.charAt(phm.index + phVal.length) : '';
        var prevBeforeDot = phm.index > 1 ? text.charAt(phm.index - 2) : '';
        var nextAfterDot = phm.index + phVal.length + 1 < text.length ? text.charAt(phm.index + phVal.length + 1) : '';
        if ((prevChar === '.' && /\d/.test(prevBeforeDot)) || (nextChar === '.' && /\d/.test(nextAfterDot))) continue;
        candidates.push({
          type: 'PHONE',
          value: phVal,
          start: phm.index,
          end: phm.index + phVal.length,
          confidence: /^\+91/.test(phVal) ? 0.95 : 0.88,
          validator: 'Indian mobile format',
          reason: '10-digit Indian mobile number starting with ' + phDigits.charAt(0)
        });
      }
    }

    // 9. IPv4
    if (enabled.IPV4 !== false) {
      var octet = '(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]\\d|\\d)';
      var ipRe = new RegExp('(?<![\\dA-Za-z]|\\d\\.)(' + octet + '\\.' + octet + '\\.' + octet + '\\.' + octet + ')(?![\\dA-Za-z]|\\.\\d)', 'g');
      var ipm;
      while ((ipm = ipRe.exec(text)) !== null) {
        candidates.push({
          type: 'IPV4',
          value: ipm[1],
          start: ipm.index,
          end: ipm.index + ipm[1].length,
          confidence: 0.94,
          validator: 'Strict IPv4 octet range',
          reason: '4 octets in 0-255 range without leading-zero ambiguity or extra segments'
        });
      }
    }

    // 10. INDIAN PASSPORT ([A-PR-WY][1-9]\d{6})
    if (enabled.PASSPORT) {
      var passRe = /(?<![A-Za-z0-9])([A-PR-WY][1-9]\d{6})(?![A-Za-z0-9])/g;
      var pasm;
      while ((pasm = passRe.exec(text)) !== null) {
        candidates.push({
          type: 'PASSPORT',
          value: pasm[1],
          start: pasm.index,
          end: pasm.index + pasm[1].length,
          confidence: 0.82,
          validator: 'Indian Passport 8-char format',
          reason: 'Valid passport series letter followed by non-zero digit and 6 digits'
        });
      }
    }

    // 11. VOTER ID / EPIC ([A-Z]{3}\d{7})
    if (enabled.VOTER_ID) {
      var voterRe = /(?<![A-Za-z0-9])([A-Z]{3}\d{7})(?![A-Za-z0-9])/g;
      var vm;
      while ((vm = voterRe.exec(text)) !== null) {
        candidates.push({
          type: 'VOTER_ID',
          value: vm[1],
          start: vm.index,
          end: vm.index + vm[1].length,
          confidence: 0.84,
          validator: 'EPIC 10-char format',
          reason: '3 uppercase alpha prefix + 7 numeric digits'
        });
      }
    }

    // 12. VEHICLE REGISTRATION (Indian state plate e.g., MH 12 AB 1234)
    if (enabled.VEHICLE) {
      var vehRe = /(?<![A-Za-z0-9])([A-Z]{2}[\s-]?\d{1,2}[\s-]?[A-Z]{1,3}[\s-]?\d{4})(?![A-Za-z0-9])/g;
      var vem;
      while ((vem = vehRe.exec(text)) !== null) {
        if (/[\r\n]/.test(vem[1])) continue;
        candidates.push({
          type: 'VEHICLE',
          value: vem[1],
          start: vem.index,
          end: vem.index + vem[1].length,
          confidence: 0.85,
          validator: 'Indian RTO plate format',
          reason: 'State code + RTO district + series + 4-digit registration'
        });
      }
    }

    // 13. BANK ACCOUNT NUMBER (Context-keyword gated, 9-18 digits)
    if (enabled.BANK_ACCOUNT) {
      var bankRe = /(?<![\dA-Za-z])(\d{9,18})(?![\dA-Za-z])/g;
      var bm;
      while ((bm = bankRe.exec(text)) !== null) {
        var bVal = bm[1];
        var bLineStart = text.lastIndexOf('\n', bm.index) + 1;
        var bCtx = text.slice(Math.max(bLineStart, bm.index - 45), bm.index);
        if (!/\b(?:account|acct|a\/c|acc\s*no\.?|bank(?:\s+account)?|beneficiary|iban)\s*(?:number|no\.?|id)?\s*[:=\-#]?\s*$/i.test(bCtx)) continue;
        candidates.push({
          type: 'BANK_ACCOUNT',
          value: bVal,
          start: bm.index,
          end: bm.index + bVal.length,
          confidence: 0.86,
          validator: 'Context-gated 9-18 digits',
          reason: '9-18 digit sequence immediately preceded by banking/account keyword'
        });
      }
    }

    // 14. DATE OF BIRTH (Context-keyword gated)
    if (enabled.DOB) {
      var dobRe = /(?<![\dA-Za-z])((?:19|20)\d{2}[-/](?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12]\d|3[01])|(?:0[1-9]|[12]\d|3[01])[-/](?:0[1-9]|1[0-2])[-/](?:19|20)\d{2})(?![\dA-Za-z])/g;
      var dm;
      while ((dm = dobRe.exec(text)) !== null) {
        var dVal = dm[1];
        var dLineStart = text.lastIndexOf('\n', dm.index) + 1;
        var dCtx = text.slice(Math.max(dLineStart, dm.index - 36), dm.index);
        if (!/\b(?:dob|d\.o\.b\.?|date\s+of\s+birth|birth\s*date|born(?:\s+on)?|birthday)\s*[:=\-]?\s*(?:is\s+)?$/i.test(dCtx)) continue;
        candidates.push({
          type: 'DOB',
          value: dVal,
          start: dm.index,
          end: dm.index + dVal.length,
          confidence: 0.90,
          validator: 'Context-gated date format',
          reason: 'Calendar date immediately preceded by DOB/birth keyword'
        });
      }
    }

    return resolveOverlaps(candidates);
  }

  function resolveOverlaps(candidates) {
    if (candidates.length <= 1) return candidates.slice();
    var sorted = candidates.slice().sort(function (a, b) {
      var pa = TYPE_PRIORITY[a.type] || 99;
      var pb = TYPE_PRIORITY[b.type] || 99;
      if (pa !== pb) return pa - pb;
      var lenDiff = (b.end - b.start) - (a.end - a.start);
      if (lenDiff !== 0) return lenDiff;
      return a.start - b.start;
    });

    var buckets = Object.create(null);
    var accepted = [];
    for (var i = 0; i < sorted.length; i++) {
      var cand = sorted[i];
      var bStart = cand.start >> 8;
      var bEnd = (cand.end > cand.start ? cand.end - 1 : cand.start) >> 8;
      var overlaps = false;

      for (var b = bStart; b <= bEnd && !overlaps; b++) {
        var list = buckets[b];
        if (!list) continue;
        for (var j = 0; j < list.length; j++) {
          var acc = list[j];
          if (cand.start < acc.end && acc.start < cand.end) {
            overlaps = true;
            break;
          }
        }
      }

      if (!overlaps) {
        accepted.push(cand);
        for (var b2 = bStart; b2 <= bEnd; b2++) {
          if (!buckets[b2]) buckets[b2] = [];
          buckets[b2].push(cand);
        }
      }
    }

    accepted.sort(function (a, b) { return a.start - b.start; });
    return accepted;
  }

  function maskDigitsKeepingLast(value, keepLastCount, maskChar) {
    var totalDigits = 0;
    for (var i = 0; i < value.length; i++) {
      if (value.charCodeAt(i) >= 48 && value.charCodeAt(i) <= 57) totalDigits++;
    }
    var digitsToMask = Math.max(0, totalDigits - keepLastCount);
    var out = '';
    var seenDigits = 0;
    for (var j = 0; j < value.length; j++) {
      var ch = value.charAt(j);
      if (ch >= '0' && ch <= '9') {
        out += seenDigits < digitsToMask ? maskChar : ch;
        seenDigits++;
      } else {
        out += ch;
      }
    }
    return out;
  }

  function partialMask(type, value) {
    if (type === 'PAYMENT_CARD' || type === 'CARD' || type === 'AADHAAR' || type === 'AADHAAR_UNVERIFIED' || type === 'BANK_ACCOUNT') {
      return maskDigitsKeepingLast(value, 4, 'X');
    }
    if (type === 'PAN') return 'XXXXX' + value.slice(5, 9) + 'X';
    if (type === 'PHONE') {
      var m = value.match(/^(\+?91[\s-]?|0)?(.*)$/);
      var prefix = (m && m[1]) ? m[1] : '';
      var rest = (m && m[2]) ? m[2] : value;
      return prefix + maskDigitsKeepingLast(rest, 4, '*');
    }
    if (type === 'EMAIL' || type === 'UPI') {
      var atIdx = value.indexOf('@');
      if (atIdx <= 0) return '***';
      var local = value.slice(0, atIdx);
      var domain = value.slice(atIdx);
      var visible = local.length > 2 ? local.slice(0, 2) : local.slice(0, 1);
      return visible + '***' + domain;
    }
    if (type === 'IPV4') return value.split('.')[0] + '.***.***.***';
    if (type === 'IFSC') return value.slice(0, 5) + 'XXXXXX';
    if (type === 'GSTIN') return value.slice(0, 2) + 'XXXXXXXXXX' + value.slice(12);
    if (type === 'PASSPORT') return value.charAt(0) + '*****' + value.slice(-2);
    if (type === 'VOTER_ID') return value.slice(0, 3) + '*****' + value.slice(-2);
    if (type === 'VEHICLE') return value.slice(0, 2) + '**' + value.slice(-2);
    if (type === 'DOB') {
      return value.replace(/^\d{4}([-/])\d{2}\1\d{2}$/, 'XXXX$1XX$1XX')
        .replace(/^\d{2}([-/])\d{2}\1(\d{4})$/, 'XX$1XX$1$2');
    }
    return '[REDACTED]';
  }

  function redactText(text, detections, options, session) {
    if (typeof text !== 'string') text = '';
    var opts = options || {};
    var mode = opts.mode || 'full';
    var labelType = Boolean(opts.labelType);
    var activeSession = session || createPseudonymSession();

    if (!detections || detections.length === 0) {
      return { sanitizedText: text, replacements: [], session: activeSession };
    }

    var sorted = detections.slice().sort(function (a, b) { return a.start - b.start; });
    var parts = [];
    var replacements = [];
    var cursor = 0;
    var outLen = 0;

    for (var i = 0; i < sorted.length; i++) {
      var det = sorted[i];
      if (det.start < cursor) continue;
      var plain = text.slice(cursor, det.start);
      parts.push(plain);
      outLen += plain.length;

      var rep;
      if (mode === 'partial') rep = partialMask(det.type, det.value);
      else if (mode === 'pseudonym') rep = getPseudonym(activeSession, det.type, det.value);
      else rep = labelType ? '[REDACTED:' + det.type + ']' : '[REDACTED]';

      var newStart = outLen;
      parts.push(rep);
      outLen += rep.length;
      var newEnd = outLen;

      replacements.push({
        index: i,
        type: det.type,
        originalLength: det.value.length,
        replacement: rep,
        start: det.start,
        end: det.end,
        newStart: newStart,
        newEnd: newEnd,
        confidence: det.confidence,
        validator: det.validator,
        reason: det.reason,
        normalizedKey: normalizeForPseudonym(det.type, det.value)
      });

      cursor = det.end;
    }

    parts.push(text.slice(cursor));
    return { sanitizedText: parts.join(''), replacements: replacements, session: activeSession };
  }

  function calculateRiskScore(detections, afterSanitization) {
    if (!detections || detections.length === 0) {
      return { score: 0, label: 'Low', beforeScore: 0, afterScore: 0 };
    }
    var raw = 0;
    for (var i = 0; i < detections.length; i++) {
      var meta = CATEGORY_META[detections[i].type];
      raw += meta ? meta.weight : 6;
    }
    var beforeScore = Math.min(100, Math.round(raw));
    var afterScore = afterSanitization ? 0 : beforeScore;
    var label = beforeScore >= 75 ? 'Critical' : beforeScore >= 50 ? 'High' : beforeScore >= 25 ? 'Medium' : 'Low';
    return { score: beforeScore, label: label, beforeScore: beforeScore, afterScore: afterScore };
  }

  function summarizeDetections(detections) {
    var byType = {};
    var uniqueSets = {};
    var confidenceRange = {};

    for (var i = 0; i < detections.length; i++) {
      var d = detections[i];
      byType[d.type] = (byType[d.type] || 0) + 1;
      if (!uniqueSets[d.type]) uniqueSets[d.type] = Object.create(null);
      uniqueSets[d.type][normalizeForPseudonym(d.type, d.value)] = true;
      if (!confidenceRange[d.type]) confidenceRange[d.type] = { min: d.confidence, max: d.confidence };
      else {
        if (d.confidence < confidenceRange[d.type].min) confidenceRange[d.type].min = d.confidence;
        if (d.confidence > confidenceRange[d.type].max) confidenceRange[d.type].max = d.confidence;
      }
    }

    var uniqueByType = {};
    for (var k in uniqueSets) {
      if (Object.prototype.hasOwnProperty.call(uniqueSets, k)) {
        uniqueByType[k] = Object.keys(uniqueSets[k]).length;
      }
    }

    return {
      total: detections.length,
      byType: byType,
      uniqueByType: uniqueByType,
      confidenceRange: confidenceRange,
      risk: calculateRiskScore(detections, true)
    };
  }

  function analyzeAndRedact(text, options, session) {
    var detections = detectPII(text, options);
    var result = redactText(text, detections, options, session);
    var counts = summarizeDetections(detections);
    return {
      detections: detections,
      sanitizedText: result.sanitizedText,
      replacements: result.replacements,
      session: result.session,
      counts: counts
    };
  }

  // --- RFC 4180 CSV Parser, Header Signals & Formula-Injection-Safe Serializer ---
  function parseCSV(input) {
    var text = String(input || '');
    if (text.charCodeAt(0) === 0xFEFF) text = text.slice(1);
    var rows = [];
    var row = [];
    var field = '';
    var inQuotes = false;

    for (var i = 0; i < text.length; i++) {
      var ch = text.charAt(i);
      if (inQuotes) {
        if (ch === '"') {
          if (i + 1 < text.length && text.charAt(i + 1) === '"') {
            field += '"';
            i++;
          } else {
            inQuotes = false;
          }
        } else {
          field += ch;
        }
      } else {
        if (ch === '"') inQuotes = true;
        else if (ch === ',') { row.push(field); field = ''; }
        else if (ch === '\r') {
          if (i + 1 < text.length && text.charAt(i + 1) === '\n') i++;
          row.push(field); rows.push(row); row = []; field = '';
        } else if (ch === '\n') {
          row.push(field); rows.push(row); row = []; field = '';
        } else {
          field += ch;
        }
      }
    }
    if (field.length > 0 || row.length > 0) {
      row.push(field);
      rows.push(row);
    }
    return rows;
  }

  function inferCSVHeaderSignal(headerName) {
    var h = String(headerName || '').trim().toLowerCase();
    if (!h) return 'None';
    if (/(e-?mail|mail)/.test(h)) return 'EMAIL';
    if (/(phone|mobile|contact|tel)/.test(h)) return 'PHONE';
    if (/(aadhaar|aadhar|uid)/.test(h)) return 'AADHAAR';
    if (/\bpan\b|pan_no|pan_number/.test(h)) return 'PAN';
    if (/(card|cc|visa|pan_card)/.test(h)) return 'CARD';
    if (/(ip|ip_addr|ipv4)/.test(h)) return 'IPV4';
    if (/(upi|vpa)/.test(h)) return 'UPI';
    if (/(ifsc)/.test(h)) return 'IFSC';
    if (/(gst|gstin)/.test(h)) return 'GSTIN';
    if (/(dob|birth)/.test(h)) return 'DOB';
    if (/(account|iban|bank)/.test(h)) return 'BANK_ACCOUNT';
    if (/(passport)/.test(h)) return 'PASSPORT';
    if (/(voter|epic)/.test(h)) return 'VOTER_ID';
    return 'None';
  }

  function profileCSVColumns(csvText, options) {
    var rows = parseCSV(csvText);
    if (rows.length === 0) return [];
    var header = rows[0];
    var cols = [];
    for (var c = 0; c < header.length; c++) {
      cols.push({
        index: c,
        name: header[c] || ('Column ' + (c + 1)),
        headerSignal: inferCSVHeaderSignal(header[c]),
        entityCount: 0,
        types: {}
      });
    }
    for (var r = 1; r < rows.length; r++) {
      var row = rows[r];
      for (var c2 = 0; c2 < cols.length; c2++) {
        var val = row[c2] || '';
        if (!val) continue;
        var dets = detectPII(val, options);
        cols[c2].entityCount += dets.length;
        for (var d = 0; d < dets.length; d++) {
          cols[c2].types[dets[d].type] = (cols[c2].types[dets[d].type] || 0) + 1;
        }
      }
    }
    return cols;
  }

  function neutralizeCSVFormula(cell) {
    var s = String(cell == null ? '' : cell);
    if (/^[=+\-@\t\r]/.test(s)) return "'" + s;
    return s;
  }

  function escapeCSVCell(cell) {
    var safe = neutralizeCSVFormula(cell);
    if (/[",\r\n]/.test(safe)) return '"' + safe.replace(/"/g, '""') + '"';
    return safe;
  }

  function serializeCSV(rows) {
    var lines = [];
    for (var i = 0; i < rows.length; i++) {
      var r = rows[i];
      var cells = [];
      for (var j = 0; j < r.length; j++) cells.push(escapeCSVCell(r[j]));
      lines.push(cells.join(','));
    }
    return lines.join('\r\n');
  }

  function sanitizeCSV(csvText, options, session, includedColumns) {
    var rows = parseCSV(csvText);
    if (rows.length === 0) {
      return {
        sanitizedCSV: '', rows: [], detectionsCount: 0, byType: {},
        session: session || createPseudonymSession()
      };
    }

    var activeSession = session || createPseudonymSession();
    var header = rows[0];
    var outRows = [header.slice()];
    var totalDetections = 0;
    var byType = {};

    for (var r = 1; r < rows.length; r++) {
      var origRow = rows[r];
      var newRow = [];
      for (var c = 0; c < origRow.length; c++) {
        var cellVal = origRow[c];
        var shouldSanitize = !includedColumns || includedColumns[c] !== false;
        if (shouldSanitize && cellVal) {
          var res = analyzeAndRedact(cellVal, options, activeSession);
          newRow.push(res.sanitizedText);
          totalDetections += res.detections.length;
          for (var t in res.counts.byType) {
            if (Object.prototype.hasOwnProperty.call(res.counts.byType, t)) {
              byType[t] = (byType[t] || 0) + res.counts.byType[t];
            }
          }
        } else {
          newRow.push(cellVal);
        }
      }
      outRows.push(newRow);
    }

    return {
      sanitizedCSV: serializeCSV(outRows),
      rows: outRows,
      detectionsCount: totalDetections,
      byType: byType,
      session: activeSession
    };
  }

  var SAMPLES = {
    server_log: [
      '2026-11-27T09:14:02.418Z INFO  [auth-svc] Login attempt user=Rahul.Sharma+dev@example.com from 192.168.1.100 (session_id=ord-9910284756102938)',
      '2026-11-27T09:14:04.011Z WARN  [billing-gw] Card charge retry card=4111 1111 1111 1111 failed; fallback card=5555-5555-5555-4444 (tracking=8842190037112204, bad_luhn=4111111111111112)',
      '2026-11-27T09:14:05.774Z ERROR [kyc-worker] Timeout verifying PAN ABCPE1234F for phone +91 9876543210; retry via 09876543210; bad_pan=ABCXE1234F',
      '2026-11-27T09:14:07.129Z INFO  [kyc-worker] Aadhaar vault token received: 2345 6789 0124; secondary 3456-7890-1238; bad_chk=2345 6789 0125; malformed_ip=999.1.1.1 ver=1.2.3.4.5',
      '2026-11-27T09:14:09.503Z DEBUG [payout-svc] UPI rahul.sharma@okicici IFSC HDFC0001234 account 00412988371234; GSTIN 27ABCPE1234F1Z5',
      '2026-11-27T09:14:11.112Z DEBUG [support-sync] Notified RAHUL.SHARMA+DEV@EXAMPLE.COM and priya.nair@acme-corp.in on +91-98765-43210 (Amex 3782 822463 10005, gateway 10.24.8.14)'
    ].join('\n'),
    support_ticket: [
      'Ticket #SUP-40921 | Priority: HIGH | Order: 7420193847561029 (16-digit order ref, not a card)',
      'From: ananya.iyer@example.org (alt: ANANYA.IYER@EXAMPLE.ORG)',
      'Hi team, my payment on 4111 1111 1111 1111 via UPI ananya@okaxis was charged twice from IP 172.16.42.9.',
      'Please call me back on +91 9123456789 or 9123456789. My PAN is BNZPM2501F and Aadhaar is 4567 8901 2341.',
      'Refund IFSC SBIN0000300, bank account 309188273645. Note: courier tracking 5519002837461920, build 2.4.10.18.1.'
    ].join('\n'),
    resume: [
      'AARAV MEHTA — Senior Cloud Engineer (Fictional Profile)',
      'Email: aarav.mehta@example.in | Phone: +91-98201-55443 / 09820155443 | DOB: 1994-08-15',
      'Portfolio server: 203.0.113.45 | Tax ID (PAN): CHTPM8821K | Aadhaar (KYC): 5678-9012-3458',
      'Corporate card: 3782 822463 10005 | GitHub ref ID: 6620193847561920',
      'References: kavita.rao@example.net (+91 9876543210)'
    ].join('\n'),
    clinical_note: [
      'CLINICAL INTAKE NOTE (FICTIONAL DATA ONLY) — Encounter ID: 9012837465192837',
      'Patient: Meera Deshmukh | DOB: 12/05/1988 | Contact: +91 9765432109 | Email: meera.d+clinic@example.org',
      'Insurance / Co-pay Card (Mastercard): 5555 5555 5555 4444 | PAN: DKLPM4412R',
      'National ID (Aadhaar): 6789 0123 4560 | Caregiver phone: 9765432109',
      'Telehealth terminal IP: 198.51.100.22 | Invalid test IP: 256.10.1.1'
    ].join('\n'),
    sample_csv: [
      'Employee,Email,Phone,PAN,Aadhaar,Card,Notes',
      '"Sharma, Rahul",rahul@example.com,+91 9876543210,ABCPE1234F,2345 6789 0124,4111 1111 1111 1111,"Login IP 192.168.1.100\nOrder 9910284756102938"',
      '"Iyer, Ananya",ananya@example.org,9876543210,BNZPM2501F,3456-7890-1238,5555 5555 5555 4444,=HYPERLINK("http://bad.example")'
    ].join('\r\n')
  };

  function runSelfTests() {
    var results = [];
    function check(name, fn) {
      try {
        fn();
        results.push({ name: name, pass: true, detail: 'OK' });
      } catch (e) {
        results.push({ name: name, pass: false, detail: e && e.message ? e.message : 'Failed' });
      }
    }
    function ok(cond, msg) { if (!cond) throw new Error(msg || 'Assertion failed'); }

    check('Email syntax & boundaries', function () {
      var d = detectPII('Contact (User+1@Example.COM). Bad: a@b').filter(function (x) { return x.type === 'EMAIL'; });
      ok(d.length === 1 && d[0].value === 'User+1@Example.COM');
    });
    check('Luhn rejects random 16-digit numbers', function () {
      var d = detectPII('4111111111111111 9910284756102938 4111111111111112').filter(function (x) { return x.type === 'PAYMENT_CARD'; });
      ok(d.length === 1 && d[0].meta.brand === 'Visa');
    });
    check('Verhoeff Aadhaar validation & default OFF for bad checksum', function () {
      var d = detectPII('2345 6789 0124 2345 6789 0125 1234 5678 9012');
      ok(d.filter(function (x) { return x.type === 'AADHAAR'; }).length === 1);
      ok(d.filter(function (x) { return x.type === 'AADHAAR_UNVERIFIED'; }).length === 0);
    });
    check('PAN 4th holder check', function () {
      var d = detectPII('ABCPE1234F ABCDE1234F').filter(function (x) { return x.type === 'PAN'; });
      ok(d.length === 1 && d[0].value === 'ABCPE1234F');
    });
    check('Strict IPv4 octet & dotted-version guard', function () {
      var d = detectPII('192.168.1.100 999.1.1.1 1.2.3.4.5').filter(function (x) { return x.type === 'IPV4'; });
      ok(d.length === 1 && d[0].value === '192.168.1.100');
    });
    check('Overlap priority (Card > Phone, Email > UPI/IP)', function () {
      var d = detectPII('4111 1111 1111 1111 user@192.168.1.1.com');
      ok(d.length === 2 && d[0].type === 'PAYMENT_CARD' && d[1].type === 'EMAIL');
    });
    check('Consistent pseudonymization across phone formats', function () {
      var s = createPseudonymSession();
      var out = analyzeAndRedact('+91 9876543210 | 09876543210 | +91-98765-43210', { mode: 'pseudonym' }, s).sanitizedText;
      ok(out === 'PHONE_01 | PHONE_01 | PHONE_01');
    });
    check('CSV formula-injection neutralization', function () {
      var out = sanitizeCSV('Col\n=CMD()', { mode: 'full' });
      ok(out.sanitizedCSV.indexOf("'=CMD()") !== -1);
    });

    var passed = results.filter(function (r) { return r.pass; }).length;
    return { passed: passed, total: results.length, results: results };
  }

  return {
    _factorySource: createPIIEngine.toString(),
    DEFAULT_CATEGORIES: DEFAULT_CATEGORIES,
    CATEGORY_META: CATEGORY_META,
    POLICY_PRESETS: POLICY_PRESETS,
    SAMPLES: SAMPLES,
    getDefaultEnabledCategories: getDefaultEnabledCategories,
    createPseudonymSession: createPseudonymSession,
    normalizeForPseudonym: normalizeForPseudonym,
    exportPseudonymMapping: exportPseudonymMapping,
    restoreFromMapping: restoreFromMapping,
    luhnCheck: luhnCheck,
    verhoeffCheck: verhoeffCheck,
    detectCardBrand: detectCardBrand,
    detectPII: detectPII,
    redactText: redactText,
    analyzeAndRedact: analyzeAndRedact,
    summarizeDetections: summarizeDetections,
    calculateRiskScore: calculateRiskScore,
    parseCSV: parseCSV,
    profileCSVColumns: profileCSVColumns,
    serializeCSV: serializeCSV,
    sanitizeCSV: sanitizeCSV,
    neutralizeCSVFormula: neutralizeCSVFormula,
    runSelfTests: runSelfTests
  };
});

/* ==========================================================================
 * Browser UI Controller (only runs on main index.html)
 * ========================================================================== */
(function initBrowserApp() {
  if (typeof window === 'undefined' || typeof document === 'undefined') return;
  var Engine = window.PIIEngine;
  if (!Engine) return;

  var MAX_FILE_BYTES = 5 * 1024 * 1024;
  var WORKER_THRESHOLD_CHARS = 50000;

  var state = {
    rawText: '',
    sourceName: 'Pasted text',
    sourceType: 'text',
    fileSizeBytes: 0,
    mode: 'pseudonym',
    preset: 'custom',
    theme: 'light',
    labelType: false,
    onlyChangedLines: false,
    enabledCategories: Engine.getDefaultEnabledCategories(),
    session: Engine.createPseudonymSession(),
    lastResult: null,
    csvColumns: [],
    includedCsvColumns: {},
    activityLog: [],
    worker: null,
    workerFailed: false,
    debounceTimer: null,
    tourStep: -1
  };

  function $(id) {
    return document.getElementById(id);
  }

  function loadSettings() {
    var hasSavedTheme = false;
    try {
      var saved = localStorage.getItem('pii_sentinel_ui_settings');
      if (saved) {
        var parsed = JSON.parse(saved);
        if (parsed && parsed.enabledCategories) {
          for (var k in state.enabledCategories) {
            if (Object.prototype.hasOwnProperty.call(parsed.enabledCategories, k)) {
              state.enabledCategories[k] = Boolean(parsed.enabledCategories[k]);
            } else if (k === 'PAYMENT_CARD' && Object.prototype.hasOwnProperty.call(parsed.enabledCategories, 'CARD')) {
              state.enabledCategories.PAYMENT_CARD = Boolean(parsed.enabledCategories.CARD);
            }
          }
        }
        if (parsed && (parsed.mode === 'full' || parsed.mode === 'partial' || parsed.mode === 'pseudonym')) {
          state.mode = parsed.mode;
        }
        if (parsed && (parsed.theme === 'light' || parsed.theme === 'dark')) {
          state.theme = parsed.theme;
          hasSavedTheme = true;
        }
      }
    } catch (_) {}
    if (!hasSavedTheme && window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
      state.theme = 'dark';
    }
  }

  function saveSettings() {
    try {
      localStorage.setItem('pii_sentinel_ui_settings', JSON.stringify({
        mode: state.mode,
        theme: state.theme,
        enabledCategories: state.enabledCategories
      }));
    } catch (_) {}
  }

  function applyTheme(theme) {
    state.theme = theme === 'dark' ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', state.theme);
    var btn = $('btnThemeToggle');
    var label = $('themeToggleLabel');
    if (btn) btn.setAttribute('aria-pressed', state.theme === 'dark' ? 'true' : 'false');
    if (label) label.textContent = state.theme === 'dark' ? 'Light Mode' : 'Dark Mode';
  }

  function initWorker() {
    if (state.workerFailed) return null;
    if (typeof Worker === 'undefined' || typeof Blob === 'undefined' || typeof URL === 'undefined' || !Engine._factorySource) {
      state.workerFailed = true;
      updateWorkerBadge();
      return null;
    }
    if (state.worker) return state.worker;
    try {
      var workerSource = [
        'var PIIEngine = (' + Engine._factorySource + ')();',
        'self.onmessage = function(e) {',
        '  var msg = e.data;',
        '  try {',
        '    var out = PIIEngine.analyzeAndRedact(msg.text, msg.options, msg.session);',
        '    self.postMessage({ id: msg.id, ok: true, result: out });',
        '  } catch (err) {',
        '    self.postMessage({ id: msg.id, ok: false, error: err && err.message ? err.message : "Worker error" });',
        '  }',
        '};'
      ].join('\n');
      var blob = new Blob([workerSource], { type: 'application/javascript' });
      var blobUrl = URL.createObjectURL(blob);
      var worker = new Worker(blobUrl);
      URL.revokeObjectURL(blobUrl);
      state.worker = worker;
      updateWorkerBadge();
      return worker;
    } catch (_) {
      state.workerFailed = true;
      updateWorkerBadge();
      return null;
    }
  }

  function updateWorkerBadge() {
    var el = $('workerStatusText');
    if (!el) return;
    el.textContent = state.workerFailed ? 'Main-thread fallback active' : 'Inline Blob Web Worker ready';
  }

  function showToast(message, variant) {
    var container = $('toastContainer');
    if (!container) return;
    while (container.children.length >= 2) {
      container.removeChild(container.firstChild);
    }
    var toast = document.createElement('div');
    toast.className = 'toast ' + (variant ? 'toast-' + variant : 'toast-info');
    toast.setAttribute('role', 'status');
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(function () {
      toast.classList.add('toast-hide');
      setTimeout(function () {
        if (toast.parentNode) toast.parentNode.removeChild(toast);
      }, 250);
    }, 3200);
  }

  function formatBytes(bytes) {
    if (!bytes) return '0 B';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
  }

  function formatTimestamp(d) {
    var pad = function (n) { return n < 10 ? '0' + n : String(n); };
    return pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
  }

  function addActivityLog(actionType, result) {
    var counts = result ? result.counts : { total: 0, byType: {} };
    var cats = Object.keys(counts.byType || {});
    var presetLabel = Engine.POLICY_PRESETS[state.preset] ? Engine.POLICY_PRESETS[state.preset].name : 'Custom';
    state.activityLog.unshift({
      time: formatTimestamp(new Date()),
      source: state.sourceName || 'Pasted text',
      entities: counts.total || 0,
      categories: cats.length ? cats.join(', ') : 'None',
      mode: state.mode,
      preset: presetLabel,
      action: actionType
    });
    if (state.activityLog.length > 100) state.activityLog.pop();
    renderActivityLog();
    var lastEl = $('overviewLastAction');
    if (lastEl) lastEl.textContent = actionType;
  }

  function animateStatValue(el, target) {
    if (!el) return;
    el.textContent = String(target);
  }

  function renderStatCards(counts) {
    var byType = counts ? counts.byType : {};
    var total = counts ? counts.total : 0;
    var govIds = (byType.PAN || 0) + (byType.AADHAAR || 0) + (byType.AADHAAR_UNVERIFIED || 0) +
      (byType.GSTIN || 0) + (byType.PASSPORT || 0) + (byType.VOTER_ID || 0) + (byType.VEHICLE || 0);
    var aadhaarCount = (byType.AADHAAR || 0) + (byType.AADHAAR_UNVERIFIED || 0);
    var otherCount = (byType.UPI || 0) + (byType.IFSC || 0) + (byType.GSTIN || 0) +
      (byType.PASSPORT || 0) + (byType.VOTER_ID || 0) + (byType.VEHICLE || 0) +
      (byType.BANK_ACCOUNT || 0) + (byType.DOB || 0);
    animateStatValue($('statTotal'), total);
    animateStatValue($('statEmails'), byType.EMAIL || 0);
    animateStatValue($('statPhones'), byType.PHONE || 0);
    animateStatValue($('statPan'), byType.PAN || 0);
    animateStatValue($('statAadhaar'), aadhaarCount);
    animateStatValue($('statGovIds'), govIds);
    animateStatValue($('statCards'), byType.PAYMENT_CARD || 0);
    animateStatValue($('statIPs'), byType.IPV4 || 0);
    animateStatValue($('statOther'), otherCount);
    var ovMode = $('overviewMode');
    if (ovMode) {
      ovMode.textContent = state.mode === 'full' ? 'Full Mask' : state.mode === 'partial' ? 'Partial Mask' : 'Pseudonymize';
    }
    var ovProtected = $('overviewProtected');
    if (ovProtected) ovProtected.textContent = String(total);
  }

  function renderRiskGauge(counts) {
    var risk = (counts && counts.risk) ? counts.risk : { beforeScore: 0, afterScore: 0, label: 'Low' };
    var valEl = $('riskScoreValue');
    var lblEl = $('riskScoreLabel');
    var arcEl = $('riskArcFill');
    var beforeBar = $('riskBeforeBar');
    var afterBar = $('riskAfterBar');
    var beforeText = $('riskBeforeText');
    var afterText = $('riskAfterText');

    if (valEl) valEl.textContent = String(risk.beforeScore);
    if (lblEl) {
      lblEl.textContent = risk.label + ' Risk';
      lblEl.className = 'risk-badge risk-' + risk.label.toLowerCase();
    }
    if (arcEl) {
      var totalLen = 157; // semicircle path length pi*50
      var offset = totalLen - (totalLen * risk.beforeScore) / 100;
      arcEl.style.strokeDashoffset = String(offset);
      arcEl.style.stroke = risk.beforeScore >= 75 ? '#EF4444' : risk.beforeScore >= 50 ? '#F97316' : risk.beforeScore >= 25 ? '#F59E0B' : '#22C55E';
    }
    if (beforeBar) beforeBar.style.width = risk.beforeScore + '%';
    if (afterBar) afterBar.style.width = risk.afterScore + '%';
    if (beforeText) beforeText.textContent = risk.beforeScore + '/100';
    if (afterText) afterText.textContent = risk.afterScore + '/100';
  }

  function buildLinesWithSpans(text, spans) {
    var lines = text.split('\n');
    var lineRecords = [];
    var offset = 0;
    var spanIdx = 0;

    for (var l = 0; l < lines.length; l++) {
      var lineText = lines[l];
      var lineStart = offset;
      var lineEnd = offset + lineText.length;
      var lineSpans = [];

      while (spanIdx < spans.length && spans[spanIdx].end <= lineStart) spanIdx++;
      var k = spanIdx;
      while (k < spans.length && spans[k].start < lineEnd) {
        var sp = spans[k];
        var relStart = Math.max(0, sp.start - lineStart);
        var relEnd = Math.min(lineText.length, sp.end - lineStart);
        if (relEnd > relStart) {
          lineSpans.push({
            idx: sp.idx, type: sp.type, relStart: relStart, relEnd: relEnd,
            reason: sp.reason, confidence: sp.confidence, validator: sp.validator
          });
        }
        if (sp.end <= lineEnd) k++;
        else break;
      }

      lineRecords.push({ lineNumber: l + 1, text: lineText, spans: lineSpans, hasChanges: lineSpans.length > 0 });
      offset = lineEnd + 1;
    }
    return lineRecords;
  }

  function createEmptyStateNode(message) {
    var wrap = document.createElement('div');
    wrap.className = 'empty-state';
    var p = document.createElement('p');
    p.textContent = message;
    wrap.appendChild(p);
    return wrap;
  }

  function renderDiffPanel(container, lineRecords, isSanitizedSide) {
    if (!container) return;
    while (container.firstChild) container.removeChild(container.firstChild);

    if (!state.rawText) {
      container.appendChild(createEmptyStateNode(isSanitizedSide
        ? 'Your cleaned, ready-to-share text will appear here.'
        : 'Your original text with highlighted private details will appear here.'));
      return;
    }

    var frag = document.createDocumentFragment();
    var shownLines = 0;

    for (var i = 0; i < lineRecords.length; i++) {
      var rec = lineRecords[i];
      if (state.onlyChangedLines && !rec.hasChanges) continue;
      shownLines++;

      var row = document.createElement('div');
      row.className = 'diff-line' + (rec.hasChanges ? ' diff-line-changed' : '');
      row.setAttribute('data-line', String(rec.lineNumber));

      var ln = document.createElement('span');
      ln.className = 'diff-ln';
      ln.textContent = String(rec.lineNumber);
      row.appendChild(ln);

      var content = document.createElement('span');
      content.className = 'diff-text';

      var cursor = 0;
      for (var s = 0; s < rec.spans.length; s++) {
        var sp = rec.spans[s];
        if (sp.relStart > cursor) {
          content.appendChild(document.createTextNode(rec.text.slice(cursor, sp.relStart)));
        }
        var mark = document.createElement('mark');
        mark.className = (isSanitizedSide ? 'diff-chip' : 'pii-mark') + ' pii-type-' + sp.type;
        mark.setAttribute('data-idx', String(sp.idx));
        mark.setAttribute('tabindex', '0');
        mark.setAttribute('title', sp.type + ' (' + Math.round(sp.confidence * 100) + '%): ' + sp.reason);
        mark.textContent = rec.text.slice(sp.relStart, sp.relEnd);
        content.appendChild(mark);
        cursor = sp.relEnd;
      }
      if (cursor < rec.text.length) content.appendChild(document.createTextNode(rec.text.slice(cursor)));
      if (rec.text.length === 0) content.appendChild(document.createTextNode(' '));

      row.appendChild(content);
      frag.appendChild(row);
    }

    if (shownLines === 0) {
      container.appendChild(createEmptyStateNode('No changed lines detected in the current input.'));
      return;
    }

    container.appendChild(frag);
  }

  function renderDiff(result) {
    var leftPanel = $('diffOriginal');
    var rightPanel = $('diffSanitized');
    var summaryEl = $('diffSummary');

    var detections = result ? result.detections : [];
    var replacements = result ? result.replacements : [];
    var sanitizedText = result ? result.sanitizedText : '';

    var leftSpans = detections.map(function (d, i) {
      return { idx: i, type: d.type, start: d.start, end: d.end, reason: d.reason, confidence: d.confidence, validator: d.validator };
    });
    var rightSpans = replacements.map(function (r) {
      return { idx: r.index, type: r.type, start: r.newStart, end: r.newEnd, reason: r.reason, confidence: r.confidence, validator: r.validator };
    });

    var leftLines = buildLinesWithSpans(state.rawText, leftSpans);
    var rightLines = buildLinesWithSpans(sanitizedText, rightSpans);

    var affectedLines = 0;
    for (var i = 0; i < leftLines.length; i++) if (leftLines[i].hasChanges) affectedLines++;

    if (summaryEl) {
      summaryEl.textContent = detections.length + ' private items found · ' + replacements.length + ' replaced · ' + affectedLines + ' lines updated';
    }

    renderDiffPanel(leftPanel, leftLines, false);
    renderDiffPanel(rightPanel, rightLines, true);
  }

  function renderAuditTable(result) {
    var tbody = $('auditTableBody');
    if (!tbody) return;
    while (tbody.firstChild) tbody.removeChild(tbody.firstChild);

    var detections = result ? result.detections : [];
    if (detections.length === 0) {
      var trEmpty = document.createElement('tr');
      var tdEmpty = document.createElement('td');
      tdEmpty.colSpan = 6;
      tdEmpty.className = 'table-empty';
      tdEmpty.textContent = state.rawText ? 'No PII entities detected under current category settings.' : 'No data analyzed yet.';
      trEmpty.appendChild(tdEmpty);
      tbody.appendChild(trEmpty);
      return;
    }

    var counts = result.counts;
    var order = ['EMAIL', 'PHONE', 'PAN', 'AADHAAR', 'AADHAAR_UNVERIFIED', 'PAYMENT_CARD', 'IPV4', 'UPI', 'IFSC', 'GSTIN', 'PASSPORT', 'VOTER_ID', 'VEHICLE', 'BANK_ACCOUNT', 'DOB'];
    var totalOcc = 0;
    var totalUnique = 0;

    for (var i = 0; i < order.length; i++) {
      var type = order[i];
      var occ = counts.byType[type] || 0;
      if (occ === 0) continue;
      var uniq = counts.uniqueByType[type] || 0;
      var range = counts.confidenceRange[type];
      totalOcc += occ;
      totalUnique += uniq;

      var tr = document.createElement('tr');
      var tdType = document.createElement('td');
      var badge = document.createElement('span');
      badge.className = 'type-pill pii-type-' + type;
      badge.textContent = (Engine.CATEGORY_META[type] && Engine.CATEGORY_META[type].label) || type;
      tdType.appendChild(badge);
      tr.appendChild(tdType);

      var tdOcc = document.createElement('td'); tdOcc.textContent = String(occ); tr.appendChild(tdOcc);
      var tdUniq = document.createElement('td'); tdUniq.textContent = String(uniq); tr.appendChild(tdUniq);
      var tdDet = document.createElement('td'); tdDet.textContent = 'Detected'; tr.appendChild(tdDet);
      var tdRed = document.createElement('td'); tdRed.textContent = 'Redacted (' + state.mode + ')'; tr.appendChild(tdRed);
      var tdConf = document.createElement('td');
      var minP = Math.round(range.min * 100);
      var maxP = Math.round(range.max * 100);
      tdConf.textContent = minP === maxP ? minP + '%' : minP + '% - ' + maxP + '%';
      tr.appendChild(tdConf);

      tbody.appendChild(tr);
    }

    var trTotal = document.createElement('tr');
    trTotal.className = 'audit-total-row';
    var cells = ['Total', String(totalOcc), String(totalUnique), 'Active', state.mode.toUpperCase(), '--'];
    for (var c = 0; c < cells.length; c++) {
      var td = document.createElement('td');
      td.textContent = cells[c];
      trTotal.appendChild(td);
    }
    tbody.appendChild(trTotal);
  }

  function renderCSVIntelligence() {
    var wrap = $('csvIntelligenceWrap');
    var tbody = $('csvColumnsBody');
    if (!wrap || !tbody) return;

    if (state.sourceType !== 'csv' || !state.rawText) {
      wrap.hidden = true;
      return;
    }

    wrap.hidden = false;
    while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
    var opts = { enabledCategories: state.enabledCategories };
    var cols = Engine.profileCSVColumns(state.rawText, opts);
    state.csvColumns = cols;

    for (var i = 0; i < cols.length; i++) {
      var col = cols[i];
      if (typeof state.includedCsvColumns[col.index] !== 'boolean') {
        state.includedCsvColumns[col.index] = true;
      }
      var tr = document.createElement('tr');

      var tdInc = document.createElement('td');
      var cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.checked = state.includedCsvColumns[col.index];
      cb.setAttribute('data-csv-col', String(col.index));
      cb.addEventListener('change', function (e) {
        var idx = parseInt(e.target.getAttribute('data-csv-col'), 10);
        state.includedCsvColumns[idx] = e.target.checked;
        addActivityLog('CSV column filter updated', state.lastResult);
      });
      tdInc.appendChild(cb);
      tr.appendChild(tdInc);

      var tdName = document.createElement('td'); tdName.textContent = col.name; tr.appendChild(tdName);
      var tdSig = document.createElement('td'); tdSig.textContent = col.headerSignal; tr.appendChild(tdSig);
      var tdCount = document.createElement('td'); tdCount.textContent = String(col.entityCount); tr.appendChild(tdCount);
      var tdTypes = document.createElement('td');
      var tKeys = Object.keys(col.types);
      tdTypes.textContent = tKeys.length ? tKeys.join(', ') : 'Clean';
      tr.appendChild(tdTypes);

      tbody.appendChild(tr);
    }
  }

  function renderActivityLog() {
    var tbody = $('activityLogBody');
    var ovRuns = $('overviewRuns');
    if (ovRuns) ovRuns.textContent = String(state.activityLog.length);
    if (!tbody) return;
    while (tbody.firstChild) tbody.removeChild(tbody.firstChild);

    if (state.activityLog.length === 0) {
      var trEmpty = document.createElement('tr');
      var tdEmpty = document.createElement('td');
      tdEmpty.colSpan = 7;
      tdEmpty.className = 'table-empty';
      tdEmpty.textContent = 'No processing runs recorded in this session yet.';
      trEmpty.appendChild(tdEmpty);
      tbody.appendChild(trEmpty);
      return;
    }

    for (var i = 0; i < state.activityLog.length; i++) {
      var item = state.activityLog[i];
      var tr = document.createElement('tr');
      var vals = [item.time, item.source, item.entities + ' entities', item.categories, item.mode, item.preset || 'Custom', item.action];
      for (var j = 0; j < vals.length; j++) {
        var td = document.createElement('td');
        td.textContent = vals[j];
        tr.appendChild(td);
      }
      tbody.appendChild(tr);
    }
  }

  function updateExportButtonsState() {
    var hasInput = state.rawText.length > 0;
    var btns = ['btnDownloadPrimary', 'btnCopySanitized', 'btnDownloadTxt', 'btnDownloadCsv', 'btnDownloadAudit'];
    for (var i = 0; i < btns.length; i++) {
      var el = $(btns[i]);
      if (!el) continue;
      el.disabled = !hasInput;
      el.title = hasInput ? '' : 'Enter or load text before exporting';
    }
    var mapBtn = $('btnDownloadMapping');
    if (mapBtn) {
      var hasMap = Object.keys(state.session.map).length > 0;
      mapBtn.disabled = !hasMap;
    }
    var hintEl = $('exportEmptyHint');
    if (hintEl) hintEl.hidden = hasInput;
  }

  function updateInputMeta() {
    var charEl = $('charCount');
    var fileEl = $('fileMeta');
    if (charEl) charEl.textContent = state.rawText.length.toLocaleString() + ' chars';
    if (fileEl) fileEl.textContent = state.sourceName + (state.fileSizeBytes ? ' (' + formatBytes(state.fileSizeBytes) + ')' : '');
  }

  var workerJobId = 0;

  function updateStatusBanner(result) {
    var banner = $('statusBanner');
    if (!banner) return;
    if (!state.rawText || !state.rawText.trim()) {
      banner.className = 'status-banner status-empty';
      banner.textContent = 'Step 1: Paste text or upload a .txt / .csv file above — or click "Load Sample Text" to try a demo.';
      return;
    }
    var count = result && result.detections ? result.detections.length : 0;
    var hasCards = result && result.detections ? result.detections.some(function (d) { return d.type === 'PAYMENT_CARD'; }) : false;
    var inspector = $('detectionInspector');
    if (inspector && !hasCards && state.enabledCategories.PAYMENT_CARD !== false) {
      var hasGrouped16 = /\b\d{4}[ \t\u00A0\-\u2013\u2014]+\d{4}[ \t\u00A0\-\u2013\u2014]+\d{4}[ \t\u00A0\-\u2013\u2014]+\d{4}\b/.test(state.rawText);
      var hasCardKwDigits = /\b(?:credit|debit|card|cc)\b[^.\n]{0,20}\b\d{13,19}\b/i.test(state.rawText);
      if (hasGrouped16 || hasCardKwDigits) {
        inspector.textContent = 'Note: A 13–19 digit card-like number failed the Luhn checksum, so it was intentionally ignored. Try a Luhn-valid card number (e.g. 4111 1111 1111 1111).';
      } else {
        inspector.textContent = 'Tip: Click any highlighted word below to see why it was flagged.';
      }
    } else if (inspector && count > 0) {
      inspector.textContent = 'Tip: Click any highlighted word below to see why it was flagged.';
    }
    if (count > 0) {
      banner.className = 'status-banner status-success';
      banner.textContent = 'Success: Found and protected ' + count + ' sensitive ' +
        (count === 1 ? 'item' : 'items') + ' on your device. Compare the text below or click "Download Protected File".';
    } else {
      banner.className = 'status-banner status-neutral';
      banner.textContent = 'Checked your text — no sensitive details matched the current rules.';
    }
  }

  function applyResult(result, actionLabel) {
    var loadingEl = $('processingIndicator');
    state.lastResult = result;
    if (result && result.session) state.session = result.session;

    if (loadingEl) loadingEl.hidden = true;
    updateStatusBanner(result);
    renderStatCards(result.counts);
    renderRiskGauge(result.counts);
    renderDiff(result);
    renderAuditTable(result);
    renderCSVIntelligence();
    updateExportButtonsState();
    updateInputMeta();

    if (state.rawText.length > 0 && actionLabel) {
      addActivityLog(actionLabel, result);
    }
  }

  function runProcessing(actionLabel) {
    var loadingEl = $('processingIndicator');
    var opts = {
      mode: state.mode,
      labelType: state.labelType,
      enabledCategories: state.enabledCategories
    };

    if (state.rawText.length >= WORKER_THRESHOLD_CHARS) {
      var worker = initWorker();
      if (worker) {
        if (loadingEl) loadingEl.hidden = false;
        var myId = ++workerJobId;
        worker.onmessage = function (ev) {
          if (!ev.data || ev.data.id !== myId) return;
          if (ev.data.ok) applyResult(ev.data.result, actionLabel);
          else applyResult(Engine.analyzeAndRedact(state.rawText, opts, state.session), actionLabel);
        };
        worker.onerror = function () {
          state.workerFailed = true;
          state.worker = null;
          updateWorkerBadge();
          applyResult(Engine.analyzeAndRedact(state.rawText, opts, state.session), actionLabel);
        };
        worker.postMessage({ id: myId, text: state.rawText, options: opts, session: state.session });
        return;
      }
    }

    applyResult(Engine.analyzeAndRedact(state.rawText, opts, state.session), actionLabel);
  }

  function scheduleProcessing(actionLabel) {
    clearTimeout(state.debounceTimer);
    var loadingEl = $('processingIndicator');
    if (loadingEl && state.rawText.length > WORKER_THRESHOLD_CHARS) loadingEl.hidden = false;
    state.debounceTimer = setTimeout(function () {
      runProcessing(actionLabel);
    }, 150);
  }

  function downloadBlob(content, filename, mimeType) {
    var blob = new Blob([content], { type: mimeType });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  function getTimestampSlug() {
    var d = new Date();
    var pad = function (n) { return n < 10 ? '0' + n : String(n); };
    return d.getFullYear() + pad(d.getMonth() + 1) + pad(d.getDate()) + '_' +
      pad(d.getHours()) + pad(d.getMinutes()) + pad(d.getSeconds());
  }

  function getSanitizedCSVOutput() {
    var opts = {
      mode: state.mode,
      labelType: state.labelType,
      enabledCategories: state.enabledCategories
    };
    return Engine.sanitizeCSV(state.rawText, opts, state.session, state.includedCsvColumns);
  }

  function showExportSuccess(message) {
    var el = $('exportSuccessBanner');
    if (!el) return;
    if (!message) {
      el.hidden = true;
      el.textContent = '';
      return;
    }
    el.hidden = false;
    el.textContent = message;
  }

  function handlePrimaryDownload() {
    if (!state.lastResult || !state.rawText) return;
    if (state.sourceType === 'csv') {
      var csvOut = getSanitizedCSVOutput();
      var base = state.sourceName.replace(/\.csv$/i, '');
      downloadBlob(csvOut.sanitizedCSV, 'sanitized_' + base + '.csv', 'text/csv;charset=utf-8');
      addActivityLog('Export CSV (1-click)', state.lastResult);
      var csvMsg = 'Protected CSV downloaded (' + csvOut.detectionsCount + ' items redacted).';
      showExportSuccess(csvMsg);
      showToast(csvMsg, 'success');
    } else {
      downloadBlob(state.lastResult.sanitizedText, 'sanitized_' + getTimestampSlug() + '.txt', 'text/plain;charset=utf-8');
      addActivityLog('Export TXT (1-click)', state.lastResult);
      var txtMsg = 'Protected document downloaded (' + state.lastResult.detections.length + ' items redacted).';
      showExportSuccess(txtMsg);
      showToast(txtMsg, 'success');
    }
  }

  function setInputError(msg) {
    var errEl = $('inputErrorBanner');
    if (!errEl) return;
    if (!msg) {
      errEl.hidden = true;
      errEl.textContent = '';
    } else {
      errEl.hidden = false;
      errEl.textContent = msg;
    }
  }

  function handleFileUpload(file) {
    if (!file) return;
    setInputError('');
    var name = file.name || 'uploaded.txt';
    var lower = name.toLowerCase();
    var isTxt = lower.endsWith('.txt') || lower.endsWith('.log') || file.type === 'text/plain';
    var isCsv = lower.endsWith('.csv') || file.type === 'text/csv';

    if (!isTxt && !isCsv) {
      var typeMsg = 'Unsupported file "' + name + '". Please choose a .txt or .csv file.';
      setInputError(typeMsg);
      showToast(typeMsg, 'error');
      return;
    }
    if (file.size > MAX_FILE_BYTES) {
      var sizeMsg = 'File "' + name + '" is too large (' + formatBytes(file.size) + '). Maximum allowed size is 5 MB.';
      setInputError(sizeMsg);
      showToast(sizeMsg, 'error');
      return;
    }

    var loadingEl = $('processingIndicator');
    if (loadingEl) loadingEl.hidden = false;

    var reader = new FileReader();
    reader.onload = function (ev) {
      var content = String(ev.target.result || '');
      if (content.indexOf('\u0000') !== -1) {
        if (loadingEl) loadingEl.hidden = true;
        var binMsg = 'The file "' + name + '" appears to contain binary data and cannot be safely parsed as text.';
        setInputError(binMsg);
        showToast(binMsg, 'error');
        return;
      }
      state.rawText = content;
      state.sourceName = name;
      state.sourceType = isCsv ? 'csv' : 'txt';
      state.fileSizeBytes = file.size;
      state.includedCsvColumns = {};
      state.session = Engine.createPseudonymSession();
      showExportSuccess('');
      var editor = $('inputEditor');
      if (editor) editor.value = state.rawText;
      runProcessing('Loaded ' + name);
      showToast('Loaded ' + name + ' (' + formatBytes(file.size) + ')', 'success');
    };
    reader.onerror = function () {
      if (loadingEl) loadingEl.hidden = true;
      setInputError('Could not read "' + name + '" from your computer.');
      showToast('Failed to read file locally.', 'error');
    };
    reader.readAsText(file);
  }

  function applyPolicyPreset(presetKey) {
    var preset = Engine.POLICY_PRESETS[presetKey];
    if (!preset) return;
    state.preset = presetKey;
    for (var k in state.enabledCategories) {
      if (Object.prototype.hasOwnProperty.call(preset.categories, k)) {
        state.enabledCategories[k] = Boolean(preset.categories[k]);
      }
    }
    syncCategoryCheckboxes();
    saveSettings();
    var descEl = $('presetDescription');
    if (descEl) descEl.textContent = preset.name + ': ' + preset.description;

    var presetBtns = document.querySelectorAll('[data-preset]');
    for (var i = 0; i < presetBtns.length; i++) {
      presetBtns[i].classList.toggle('preset-active', presetBtns[i].getAttribute('data-preset') === presetKey);
    }

    runProcessing('Preset: ' + preset.name);
    showToast('Applied policy: ' + preset.name, 'info');
  }

  function syncCategoryCheckboxes() {
    var catCheckboxes = document.querySelectorAll('[data-category-toggle]');
    for (var c = 0; c < catCheckboxes.length; c++) {
      var cb = catCheckboxes[c];
      var cat = cb.getAttribute('data-category-toggle');
      cb.checked = Boolean(state.enabledCategories[cat]);
    }
  }

  function highlightCounterpart(idx, active) {
    var marks = document.querySelectorAll('[data-idx="' + idx + '"]');
    for (var i = 0; i < marks.length; i++) {
      if (active) marks[i].classList.add('diff-linked-active');
      else marks[i].classList.remove('diff-linked-active');
    }
  }

  function wireDiffSyncAndHover() {
    var left = $('diffOriginal');
    var right = $('diffSanitized');
    if (!left || !right) return;

    var syncing = false;
    function syncScroll(src, dst) {
      if (syncing) return;
      syncing = true;
      dst.scrollTop = src.scrollTop;
      dst.scrollLeft = src.scrollLeft;
      requestAnimationFrame(function () { syncing = false; });
    }

    left.addEventListener('scroll', function () { syncScroll(left, right); });
    right.addEventListener('scroll', function () { syncScroll(right, left); });

    function bindPanelInteractions(panel) {
      panel.addEventListener('mouseover', function (e) {
        var target = e.target.closest('[data-idx]');
        if (target) highlightCounterpart(target.getAttribute('data-idx'), true);
      });
      panel.addEventListener('mouseout', function (e) {
        var target = e.target.closest('[data-idx]');
        if (target) highlightCounterpart(target.getAttribute('data-idx'), false);
      });
      panel.addEventListener('click', function (e) {
        var target = e.target.closest('[data-idx]');
        if (!target) return;
        var idx = parseInt(target.getAttribute('data-idx'), 10);
        if (state.lastResult && state.lastResult.detections[idx]) {
          var det = state.lastResult.detections[idx];
          var inspector = $('detectionInspector');
          if (inspector) {
            inspector.textContent = 'Flagged as ' + det.type + ' (' + Math.round(det.confidence * 100) +
              '% confidence via ' + det.validator + '): ' + det.reason;
          }
        }
      });
    }
    bindPanelInteractions(left);
    bindPanelInteractions(right);
  }

  function setCopyFeedback(btn, originalLabel) {
    if (!btn) return;
    btn.textContent = 'Copied!';
    setTimeout(function () { btn.textContent = originalLabel; }, 1400);
  }

  // --- Guided Demo Tour (Tier 2) ---
  var TOUR_STEPS = [
    {
      title: 'Step 1 of 5 — Load Realistic Noisy Data',
      body: 'Click "Load Sample Noisy Text" (or choose Server log, Support ticket, Resume, Clinical note) to test realistic mixed PII alongside invalid 16-digit tracking IDs and bad checksums.',
      targetId: 'section-input',
      action: function () {
        if (!state.rawText && $('btnLoadSample')) $('btnLoadSample').click();
      }
    },
    {
      title: 'Step 2 of 5 — Inspect Live Side-by-Side Diff',
      body: 'Hover or click any highlighted entity to link original and sanitized segments and inspect exact validator reasoning ("Luhn valid", "Verhoeff checksum", etc.).',
      targetId: 'section-diff'
    },
    {
      title: 'Step 3 of 5 — Switch Modes & Policy Presets',
      body: 'Compare Full Mask, Partial Mask, and Consistent Pseudonymization (where repeated emails/phones map to the same USER_01 / PHONE_01 token), or apply DPDP / PCI-DSS presets.',
      targetId: 'section-input'
    },
    {
      title: 'Step 4 of 5 — Audit, Risk Drop & Privacy Proof',
      body: 'Verify the Risk Gauge drops to 0/100 after sanitization, inspect the Privacy Proof panel (CSP + 0 network requests), and confirm raw PII is never shown in the Audit table.',
      targetId: 'section-audit'
    },
    {
      title: 'Step 5 of 5 — 1-Click Safe Export',
      body: 'Download the sanitized TXT/CSV or Audit CSV directly from memory via Blob URLs with automatic CSV formula-injection neutralization.',
      targetId: 'section-export'
    }
  ];

  function renderTourStep() {
    var modal = $('tourBanner');
    if (!modal) return;
    if (state.tourStep < 0 || state.tourStep >= TOUR_STEPS.length) {
      modal.hidden = true;
      return;
    }
    var step = TOUR_STEPS[state.tourStep];
    if (step.action) step.action();
    modal.hidden = false;
    $('tourTitle').textContent = step.title;
    $('tourBody').textContent = step.body;
    $('btnTourNext').textContent = state.tourStep === TOUR_STEPS.length - 1 ? 'Finish Tour' : 'Next Step';
    var target = $(step.targetId);
    if (target && target.scrollIntoView) {
      target.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  }

  function runFooterSelfTests() {
    var res = Engine.runSelfTests();
    var badge = $('selfTestBadge');
    var list = $('selfTestModalList');
    if (badge) {
      badge.textContent = 'Engine self-test: ' + res.passed + '/' + res.total + ' passed';
      badge.classList.toggle('badge-fail', res.passed !== res.total);
    }
    if (list) {
      while (list.firstChild) list.removeChild(list.firstChild);
      for (var i = 0; i < res.results.length; i++) {
        var r = res.results[i];
        var li = document.createElement('li');
        li.className = r.pass ? 'self-test-pass' : 'self-test-fail';
        li.textContent = (r.pass ? 'PASS: ' : 'FAIL: ') + r.name + (r.pass ? '' : ' (' + r.detail + ')');
        list.appendChild(li);
      }
    }
  }

  function openModal(id) {
    var m = $(id);
    if (m) m.hidden = false;
  }

  function closeModals() {
    var modals = document.querySelectorAll('.modal-backdrop');
    for (var i = 0; i < modals.length; i++) modals[i].hidden = true;
  }

  function wireEvents() {
    var editor = $('inputEditor');
    if (editor) {
      var onEditorUpdate = function () {
        setInputError('');
        state.rawText = editor.value;
        state.sourceName = 'Pasted text';
        state.sourceType = 'text';
        state.fileSizeBytes = new Blob([state.rawText]).size;
        scheduleProcessing('Text edit');
      };
      editor.addEventListener('input', onEditorUpdate);
      editor.addEventListener('change', onEditorUpdate);
    }

    var btnLoadSample = $('btnLoadSample');
    var sampleSelect = $('sampleScenario');
    if (btnLoadSample) {
      btnLoadSample.addEventListener('click', function () {
        setInputError('');
        var key = sampleSelect ? sampleSelect.value : 'server_log';
        var sample = Engine.SAMPLES[key] || Engine.SAMPLES.server_log;
        state.rawText = sample;
        state.sourceName = 'sample_' + key + '.txt';
        state.sourceType = 'txt';
        state.fileSizeBytes = new Blob([sample]).size;
        state.session = Engine.createPseudonymSession();
        if (editor) editor.value = sample;
        runProcessing('Loaded sample (' + key + ')');
        showToast('Sample text loaded and protected locally', 'info');
      });
    }

    if ($('btnLoadSampleCsv')) {
      $('btnLoadSampleCsv').addEventListener('click', function () {
        setInputError('');
        state.rawText = Engine.SAMPLES.sample_csv;
        state.sourceName = 'sample_employees.csv';
        state.sourceType = 'csv';
        state.fileSizeBytes = new Blob([state.rawText]).size;
        state.includedCsvColumns = {};
        state.session = Engine.createPseudonymSession();
        if (editor) editor.value = state.rawText;
        runProcessing('Loaded sample CSV');
        showToast('Sample CSV loaded — check columns in Step 2', 'info');
      });
    }

    var fileTxt = $('fileInputTxt');
    var fileCsv = $('fileInputCsv');
    if ($('btnUploadTxt') && fileTxt) {
      $('btnUploadTxt').addEventListener('click', function () { fileTxt.click(); });
      fileTxt.addEventListener('change', function () {
        if (fileTxt.files && fileTxt.files[0]) handleFileUpload(fileTxt.files[0]);
        fileTxt.value = '';
      });
    }
    if ($('btnUploadCsv') && fileCsv) {
      $('btnUploadCsv').addEventListener('click', function () { fileCsv.click(); });
      fileCsv.addEventListener('change', function () {
        if (fileCsv.files && fileCsv.files[0]) handleFileUpload(fileCsv.files[0]);
        fileCsv.value = '';
      });
    }

    var dropZone = $('dropZone');
    if (dropZone) {
      dropZone.addEventListener('dragover', function (e) { e.preventDefault(); dropZone.classList.add('drag-over'); });
      dropZone.addEventListener('dragleave', function () { dropZone.classList.remove('drag-over'); });
      dropZone.addEventListener('drop', function (e) {
        e.preventDefault();
        dropZone.classList.remove('drag-over');
        if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]) handleFileUpload(e.dataTransfer.files[0]);
      });
    }

    function focusWorkspace() {
      var inputSection = $('section-input');
      if (inputSection && inputSection.scrollIntoView) {
        inputSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
      if (editor) editor.focus();
    }

    if ($('btnStartProtecting')) $('btnStartProtecting').addEventListener('click', focusWorkspace);
    if ($('btnGetStarted')) $('btnGetStarted').addEventListener('click', focusWorkspace);
    if ($('btnExploreFeatures')) {
      $('btnExploreFeatures').addEventListener('click', function () {
        var feat = $('features');
        if (feat && feat.scrollIntoView) feat.scrollIntoView({ behavior: 'smooth', block: 'start' });
      });
    }
    if ($('btnMobileNav')) {
      $('btnMobileNav').addEventListener('click', function () {
        var nav = $('headerNav');
        if (!nav) return;
        var open = nav.classList.toggle('nav-open');
        $('btnMobileNav').setAttribute('aria-expanded', open ? 'true' : 'false');
      });
    }

    if ($('btnClear')) {
      $('btnClear').addEventListener('click', function () {
        if (!state.rawText) return;
        if (!window.confirm('Clear current text and erase in-memory pseudonym labels?')) return;
        setInputError('');
        showExportSuccess('');
        state.rawText = '';
        state.sourceName = 'Pasted text';
        state.sourceType = 'text';
        state.fileSizeBytes = 0;
        state.includedCsvColumns = {};
        state.lastResult = null;
        state.session = Engine.createPseudonymSession();
        if (editor) editor.value = '';
        if (fileTxt) fileTxt.value = '';
        if (fileCsv) fileCsv.value = '';
        var inspector = $('detectionInspector');
        if (inspector) inspector.textContent = 'Tip: Click any highlighted word below to see why the tool detected it.';
        runProcessing();
        showToast('Document cleared and temporary label map erased', 'info');
      });
    }

    if ($('btnResetMapping')) {
      $('btnResetMapping').addEventListener('click', function () {
        state.session = Engine.createPseudonymSession();
        runProcessing('Reset mapping');
        showToast('Pseudonymization counters reset', 'info');
      });
    }

    var modeRadios = document.querySelectorAll('input[name="redactionMode"]');
    for (var i = 0; i < modeRadios.length; i++) {
      if (modeRadios[i].value === state.mode) modeRadios[i].checked = true;
      modeRadios[i].addEventListener('change', function (e) {
        state.mode = e.target.value;
        saveSettings();
        var labelToggleWrap = $('labelTypeWrap');
        if (labelToggleWrap) labelToggleWrap.hidden = state.mode !== 'full';
        runProcessing('Mode: ' + state.mode);
      });
    }
    var labelToggleWrap = $('labelTypeWrap');
    if (labelToggleWrap) labelToggleWrap.hidden = state.mode !== 'full';

    var chkLabelType = $('chkLabelType');
    if (chkLabelType) {
      chkLabelType.addEventListener('change', function () {
        state.labelType = chkLabelType.checked;
        runProcessing('Toggled label type');
      });
    }

    var chkOnlyChanged = $('chkOnlyChanged');
    if (chkOnlyChanged) {
      chkOnlyChanged.addEventListener('change', function () {
        state.onlyChangedLines = chkOnlyChanged.checked;
        renderDiff(state.lastResult);
      });
    }

    var presetBtns = document.querySelectorAll('[data-preset]');
    for (var p = 0; p < presetBtns.length; p++) {
      presetBtns[p].addEventListener('click', function (e) {
        applyPolicyPreset(e.currentTarget.getAttribute('data-preset'));
      });
    }

    var catCheckboxes = document.querySelectorAll('[data-category-toggle]');
    syncCategoryCheckboxes();
    for (var c = 0; c < catCheckboxes.length; c++) {
      catCheckboxes[c].addEventListener('change', function (e) {
        var key = e.target.getAttribute('data-category-toggle');
        state.enabledCategories[key] = e.target.checked;
        state.preset = 'custom';
        saveSettings();
        runProcessing('Category toggle: ' + key);
      });
    }

    if ($('btnDownloadPrimary')) $('btnDownloadPrimary').addEventListener('click', handlePrimaryDownload);
    if ($('btnDownloadTxt')) {
      $('btnDownloadTxt').addEventListener('click', function () {
        if (!state.lastResult || !state.rawText) return;
        downloadBlob(state.lastResult.sanitizedText, 'sanitized_' + getTimestampSlug() + '.txt', 'text/plain;charset=utf-8');
        addActivityLog('Export TXT', state.lastResult);
        var msg = 'Sanitized .TXT downloaded (' + state.lastResult.detections.length + ' items redacted).';
        showExportSuccess(msg);
        showToast(msg, 'success');
      });
    }
    if ($('btnDownloadCsv')) {
      $('btnDownloadCsv').addEventListener('click', function () {
        if (!state.lastResult || !state.rawText) return;
        var out = state.sourceType === 'csv'
          ? getSanitizedCSVOutput().sanitizedCSV
          : Engine.serializeCSV([['Line', 'Sanitized Content']].concat(
              state.lastResult.sanitizedText.split('\n').map(function (line, idx) { return [String(idx + 1), line]; })
            ));
        downloadBlob(out, 'sanitized_' + getTimestampSlug() + '.csv', 'text/csv;charset=utf-8');
        addActivityLog('Export CSV', state.lastResult);
        var msg = 'Sanitized .CSV downloaded safely (spreadsheet formula protection applied).';
        showExportSuccess(msg);
        showToast(msg, 'success');
      });
    }
    if ($('btnDownloadAudit')) {
      $('btnDownloadAudit').addEventListener('click', function () {
        if (!state.lastResult || !state.rawText) return;
        var rows = [['Entity Type', 'Start Offset', 'End Offset', 'Confidence', 'Masked Preview', 'Redaction Mode']];
        var reps = state.lastResult.replacements;
        for (var r = 0; r < reps.length; r++) {
          var item = reps[r];
          rows.push([item.type, String(item.start), String(item.end), Math.round(item.confidence * 100) + '%', item.replacement, state.mode]);
        }
        downloadBlob(Engine.serializeCSV(rows), 'audit_report_' + getTimestampSlug() + '.csv', 'text/csv;charset=utf-8');
        addActivityLog('Export Audit CSV', state.lastResult);
        var msg = 'Audit report (.CSV) downloaded — contains counts and masked previews only.';
        showExportSuccess(msg);
        showToast(msg, 'success');
      });
    }

    if ($('btnDownloadMapping')) {
      $('btnDownloadMapping').addEventListener('click', function () {
        var payload = Engine.exportPseudonymMapping(state.session);
        downloadBlob(JSON.stringify(payload, null, 2), 'pseudonym_mapping_SENSITIVE_' + getTimestampSlug() + '.json', 'application/json');
        addActivityLog('Export Reversible Mapping JSON', state.lastResult);
        showToast('Sensitive mapping JSON downloaded — store securely offline', 'info');
      });
    }

    var restoreInput = $('fileInputMapping');
    if ($('btnRestoreMapping') && restoreInput) {
      $('btnRestoreMapping').addEventListener('click', function () { restoreInput.click(); });
      restoreInput.addEventListener('change', function () {
        var f = restoreInput.files && restoreInput.files[0];
        restoreInput.value = '';
        if (!f) return;
        var reader = new FileReader();
        reader.onload = function (ev) {
          try {
            var parsed = JSON.parse(String(ev.target.result || '{}'));
            var currentOut = state.lastResult ? state.lastResult.sanitizedText : state.rawText;
            var res = Engine.restoreFromMapping(currentOut, parsed);
            state.rawText = res.restoredText;
            if (editor) editor.value = res.restoredText;
            runProcessing('Restored ' + res.restoredCount + ' tokens');
            showToast('Restored ' + res.restoredCount + ' pseudonymized tokens locally', 'success');
          } catch (_) {
            showToast('Invalid mapping JSON file.', 'error');
          }
        };
        reader.readAsText(f);
      });
    }

    if ($('btnCopySanitized')) {
      $('btnCopySanitized').addEventListener('click', function (e) {
        if (!state.lastResult || !state.rawText) return;
        var btn = e.currentTarget;
        navigator.clipboard.writeText(state.lastResult.sanitizedText).then(function () {
          setCopyFeedback(btn, 'Copy Protected Text');
          showExportSuccess('Protected text copied to clipboard.');
          showToast('Protected text copied to clipboard', 'success');
        }).catch(function () { showToast('Clipboard permission denied', 'error'); });
      });
    }
    if ($('btnCopyOriginalPanel')) {
      $('btnCopyOriginalPanel').addEventListener('click', function (e) {
        if (!state.rawText) return;
        var btn = e.currentTarget;
        navigator.clipboard.writeText(state.rawText).then(function () { setCopyFeedback(btn, 'Copy'); });
      });
    }
    if ($('btnCopySanitizedPanel')) {
      $('btnCopySanitizedPanel').addEventListener('click', function (e) {
        if (!state.lastResult || !state.rawText) return;
        var btn = e.currentTarget;
        navigator.clipboard.writeText(state.lastResult.sanitizedText).then(function () { setCopyFeedback(btn, 'Copy'); });
      });
    }

    if ($('btnClearLog')) {
      $('btnClearLog').addEventListener('click', function () {
        state.activityLog = [];
        renderActivityLog();
        showToast('Activity log cleared', 'info');
      });
    }
    if ($('btnExportLogJson')) {
      $('btnExportLogJson').addEventListener('click', function () {
        downloadBlob(JSON.stringify(state.activityLog, null, 2), 'activity_log_' + getTimestampSlug() + '.json', 'application/json');
      });
    }
    if ($('btnExportLogCsv')) {
      $('btnExportLogCsv').addEventListener('click', function () {
        var rows = [['Timestamp', 'Source', 'Entities', 'Categories', 'Mode', 'Preset', 'Action']];
        for (var i = 0; i < state.activityLog.length; i++) {
          var l = state.activityLog[i];
          rows.push([l.time, l.source, String(l.entities), l.categories, l.mode, l.preset || 'Custom', l.action]);
        }
        downloadBlob(Engine.serializeCSV(rows), 'activity_log_' + getTimestampSlug() + '.csv', 'text/csv;charset=utf-8');
      });
    }

    // Tier 2 & 3 interactive controls
    if ($('btnGuidedDemo')) {
      $('btnGuidedDemo').addEventListener('click', function () {
        state.tourStep = 0;
        renderTourStep();
      });
    }
    if ($('btnTourNext')) {
      $('btnTourNext').addEventListener('click', function () {
        state.tourStep++;
        if (state.tourStep >= TOUR_STEPS.length) state.tourStep = -1;
        renderTourStep();
      });
    }
    if ($('btnTourClose')) {
      $('btnTourClose').addEventListener('click', function () {
        state.tourStep = -1;
        renderTourStep();
      });
    }

    if ($('btnThemeToggle')) {
      $('btnThemeToggle').addEventListener('click', function () {
        applyTheme(state.theme === 'dark' ? 'light' : 'dark');
        saveSettings();
      });
    }
    if ($('btnShortcuts')) $('btnShortcuts').addEventListener('click', function () { openModal('shortcutsModal'); });
    if ($('selfTestBadge')) $('selfTestBadge').addEventListener('click', function () { openModal('selfTestModal'); });
    if ($('btnPrintAudit')) $('btnPrintAudit').addEventListener('click', function () { window.print(); });

    var closeBtns = document.querySelectorAll('[data-close-modal]');
    for (var m = 0; m < closeBtns.length; m++) {
      closeBtns[m].addEventListener('click', closeModals);
    }

    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') {
        closeModals();
        if (state.tourStep >= 0) { state.tourStep = -1; renderTourStep(); }
        return;
      }
      if (e.key === '?' && document.activeElement !== editor) {
        openModal('shortcutsModal');
      } else if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        runProcessing('Manual re-scan');
        showToast('Re-scanned locally', 'info');
      } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'd') {
        e.preventDefault();
        handlePrimaryDownload();
      }
    });

    wireDiffSyncAndHover();
  }

  function initPrivacyMonitor() {
    var netCounter = $('networkRequestCount');
    var cspDisplay = $('cspPolicyDisplay');
    var onlineEl = $('offlineStatusText');
    var metaCsp = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
    if (cspDisplay && metaCsp) cspDisplay.textContent = metaCsp.getAttribute('content');

    function updateOnline() {
      if (!onlineEl) return;
      onlineEl.textContent = navigator.onLine
        ? 'Online (CSP blocks all outbound data; try disabling Wi-Fi)'
        : 'Offline mode verified — running 100% locally';
    }
    updateOnline();
    window.addEventListener('online', updateOnline);
    window.addEventListener('offline', updateOnline);

    if (netCounter && typeof PerformanceObserver !== 'undefined') {
      var externalRequests = 0;
      try {
        var obs = new PerformanceObserver(function (list) {
          var entries = list.getEntries();
          for (var i = 0; i < entries.length; i++) {
            var it = entries[i].initiatorType;
            if (it === 'fetch' || it === 'xmlhttprequest' || it === 'beacon') externalRequests++;
          }
          netCounter.textContent = String(externalRequests);
        });
        obs.observe({ entryTypes: ['resource'] });
      } catch (_) {
        netCounter.textContent = '0';
      }
    }
    updateWorkerBadge();
  }

  document.addEventListener('DOMContentLoaded', function () {
    if (!$('inputEditor')) return;
    loadSettings();
    applyTheme(state.theme);
    wireEvents();
    initPrivacyMonitor();
    runFooterSelfTests();
    runProcessing();
    renderActivityLog();
  });
})();
