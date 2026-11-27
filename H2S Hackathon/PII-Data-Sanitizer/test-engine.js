'use strict';

const assert = require('assert');
const Engine = require('./script.js');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    passed++;
    console.log('PASS:', name);
  } catch (err) {
    failed++;
    console.error('FAIL:', name, '->', err.message);
  }
}

// 1. Email tests
test('1. Email detection: valid, uppercase, plus addressing, adjacent punctuation, invalid', () => {
  const input = 'Contact (Rahul.Sharma+dev@Example.COM), or backup@company.co.in. Bad: user@nodot, @missing.com, a..b@test.com.';
  const dets = Engine.detectPII(input).filter(d => d.type === 'EMAIL');
  assert.deepStrictEqual(dets.map(d => d.value), ['Rahul.Sharma+dev@Example.COM', 'backup@company.co.in']);
});

// 2. Indian phone tests
test('2. Indian phone: +91, 0-prefix, bare 10 digits, hyphen/space variants; rejects 0-5 starts', () => {
  const input = 'Valid: +91 9876543210, 9876543210, 09876543210, +91-98765-43210, 91 8123456789. Invalid: 5123456789, 1234567890, 04123456789.';
  const dets = Engine.detectPII(input).filter(d => d.type === 'PHONE');
  assert.deepStrictEqual(dets.map(d => d.value), ['+91 9876543210', '9876543210', '09876543210', '+91-98765-43210', '91 8123456789']);
});

// 3. PAN tests
test('3. PAN: valid uppercase, invalid 4th char rejected, lowercase gets lower confidence', () => {
  const input = 'Valid: ABCPE1234F. Bad4th: ABCDE1234F. Lower: abcpe1234f.';
  const dets = Engine.detectPII(input).filter(d => d.type === 'PAN');
  assert.strictEqual(dets.length, 2);
  assert.strictEqual(dets[0].value, 'ABCPE1234F');
  assert.ok(dets[0].confidence >= 0.9);
  assert.strictEqual(dets[1].value, 'abcpe1234f');
  assert.ok(dets[1].confidence < dets[0].confidence);
});

// 4. Aadhaar tests
test('4. Aadhaar: Verhoeff-valid accepted; checksum-fail OFF by default, low conf when ON; leading 0/1 rejected', () => {
  const input = 'Valid: 2345 6789 0124, 3456-7890-1238. BadChecksum: 2345 6789 0125. BadStart: 1234 5678 9012, 0123 4567 8901.';
  const defDets = Engine.detectPII(input);
  assert.deepStrictEqual(defDets.filter(d => d.type === 'AADHAAR').map(d => d.value), ['2345 6789 0124', '3456-7890-1238']);
  assert.strictEqual(defDets.filter(d => d.type === 'AADHAAR_UNVERIFIED').length, 0);

  const optsOn = { enabledCategories: Object.assign({}, Engine.getDefaultEnabledCategories(), { AADHAAR_UNVERIFIED: true }) };
  const allDets = Engine.detectPII(input, optsOn);
  const unverified = allDets.filter(d => d.type === 'AADHAAR_UNVERIFIED');
  assert.strictEqual(unverified.length, 1);
  assert.strictEqual(unverified[0].value, '2345 6789 0125');
  assert.ok(unverified[0].confidence < 0.5);
});

// 5. IPv4 tests
test('5. IPv4: 192.168.1.100 accepted; 256.1.1.1, 999.1.1.1, 1.2.3, 1.2.3.4.5, 192.168.01.1 rejected', () => {
  const input = 'OK: 192.168.1.100, 10.0.0.1. Bad: 256.1.1.1, 999.1.1.1, 1.2.3, 1.2.3.4.5, 192.168.01.1.';
  const dets = Engine.detectPII(input).filter(d => d.type === 'IPV4');
  assert.deepStrictEqual(dets.map(d => d.value), ['192.168.1.100', '10.0.0.1']);
});

// 6. Luhn & Payment Card tests
test('6. PAYMENT_CARD: valid formats accepted; letters/unsupported separators/Luhn failures rejected', () => {
  const input = [
    'Valid: 4111111111111111, (4111 1111 1111 1111), "4111-1111-1111-1111", 4242424242424242, 4242 4242 4242 4242, 5555555555554444, 5555-5555-5555-4444.',
    'Extra: 3782 822463 10005, 4111  1111  1111  1111, 4111 1111 1111 1111 12/28, 4111 1111 1111 1111 123, Debit 5085001234567894, Maestro 5018000000000009, 1111 2222 3333 4444.',
    'Reject: 4111111111111112, 1234567890123456, 4242424242424241, 9910284756102938, 4111A11111111111, 4111/1111/1111/1111, 4111.1111.1111.1111, 4111_1111_1111_1111.'
  ].join('\n');
  const dets = Engine.detectPII(input).filter(d => d.type === 'PAYMENT_CARD');
  assert.deepStrictEqual(dets.map(d => d.value), [
    '4111111111111111',
    '4111 1111 1111 1111',
    '4111-1111-1111-1111',
    '4242424242424242',
    '4242 4242 4242 4242',
    '5555555555554444',
    '5555-5555-5555-4444',
    '3782 822463 10005',
    '4111  1111  1111  1111',
    '4111 1111 1111 1111',
    '4111 1111 1111 1111',
    '5085001234567894',
    '5018000000000009',
    '1111 2222 3333 4444'
  ]);
  assert.strictEqual(dets[0].meta.brand, 'Visa');
  assert.strictEqual(dets[5].meta.brand, 'Mastercard');
  assert.strictEqual(dets[7].meta.brand, 'Amex');
  assert.strictEqual(dets[11].meta.brand, 'RuPay');
  assert.strictEqual(dets[12].meta.brand, 'Maestro');
});

// 7. Overlap resolution
test('7. Overlap: card not reported as phone/Aadhaar; email domain not reported as IP/UPI', () => {
  const input = 'Card 4111 1111 1111 1111 and user@192.168.1.100.com and pay rahul@okicici';
  const dets = Engine.detectPII(input);
  assert.strictEqual(dets.length, 3);
  assert.strictEqual(dets[0].type, 'PAYMENT_CARD');
  assert.strictEqual(dets[1].type, 'EMAIL');
  assert.strictEqual(dets[2].type, 'UPI');
});

// 8. Redaction mode exact outputs
test('8. Full / Partial / Pseudonymize outputs match exact expected strings', () => {
  const sample = 'Email rahul@gmail.com Phone +91 9876543210 PAN ABCPE1234F Aadhaar 2345 6789 0124 Card 4111 1111 1111 1111 IP 192.168.1.100';
  assert.strictEqual(
    Engine.analyzeAndRedact(sample, { mode: 'full' }).sanitizedText,
    'Email [REDACTED] Phone [REDACTED] PAN [REDACTED] Aadhaar [REDACTED] Card [REDACTED] IP [REDACTED]'
  );
  assert.strictEqual(
    Engine.analyzeAndRedact(sample, { mode: 'full', labelType: true }).sanitizedText,
    'Email [REDACTED:EMAIL] Phone [REDACTED:PHONE] PAN [REDACTED:PAN] Aadhaar [REDACTED:AADHAAR] Card [REDACTED:PAYMENT_CARD] IP [REDACTED:IPV4]'
  );
  assert.strictEqual(
    Engine.analyzeAndRedact(sample, { mode: 'partial' }).sanitizedText,
    'Email ra***@gmail.com Phone +91 ******3210 PAN XXXXX1234X Aadhaar XXXX XXXX 0124 Card XXXX XXXX XXXX 1111 IP 192.***.***.***'
  );
  assert.strictEqual(
    Engine.analyzeAndRedact(sample, { mode: 'pseudonym' }).sanitizedText,
    'Email USER_01 Phone PHONE_01 PAN PAN_01 Aadhaar AADHAAR_01 Card CARD_01 IP IP_01'
  );
});

// 9. Pseudonym consistency & reset
test('9. Pseudonym consistency across formats; per-category counters; reset behavior', () => {
  const session = Engine.createPseudonymSession();
  const txt = 'a@b.com A@B.COM +91 9876543210 9876543210 09876543210 +91-98765-43210';
  const r1 = Engine.analyzeAndRedact(txt, { mode: 'pseudonym' }, session);
  assert.strictEqual(r1.sanitizedText, 'USER_01 USER_01 PHONE_01 PHONE_01 PHONE_01 PHONE_01');
  const r2 = Engine.analyzeAndRedact('other@b.com +91 9123456789', { mode: 'pseudonym' }, session);
  assert.strictEqual(r2.sanitizedText, 'USER_02 PHONE_02');
  const fresh = Engine.createPseudonymSession();
  assert.strictEqual(Engine.analyzeAndRedact('other@b.com', { mode: 'pseudonym' }, fresh).sanitizedText, 'USER_01');
});

// 10. Original input never mutated
test('10. Original input string never mutated', () => {
  const input = 'rahul@gmail.com 9876543210';
  const copy = input.slice();
  Engine.analyzeAndRedact(input, { mode: 'full' });
  assert.strictEqual(input, copy);
});

// 11. Empty & whitespace
test('11. Empty and whitespace-only input handled cleanly', () => {
  assert.deepStrictEqual(Engine.detectPII(''), []);
  assert.deepStrictEqual(Engine.detectPII('   \n\t  '), []);
  const res = Engine.analyzeAndRedact('   \n  ', { mode: 'pseudonym' });
  assert.strictEqual(res.sanitizedText, '   \n  ');
  assert.strictEqual(res.detections.length, 0);
});

// 12. CSV parsing, formula injection, column preservation & column exclusion
test('12. CSV: quoted commas, embedded newline, formula neutralization, column structure & include/exclude', () => {
  const csv = 'Name,Note,Email\r\n"Doe, Jane","line1\n+91 9876543210",jane@example.com\r\n=CMD(),"@SUM(1,2)",bob@example.org';
  const out = Engine.sanitizeCSV(csv, { mode: 'full' }, null, { 0: true, 1: false, 2: true });
  assert.strictEqual(out.rows.length, 3);
  assert.strictEqual(out.rows[0].length, 3);
  assert.ok(out.sanitizedCSV.includes("'=CMD()"));
  assert.ok(out.sanitizedCSV.includes("'@SUM(1,2)"));
  // Column 1 (Note) was excluded, Column 2 (Email) was redacted
  assert.ok(out.sanitizedCSV.includes('9876543210'));
  assert.ok(!out.sanitizedCSV.includes('jane@example.com'));
});

// 13. Audit report has zero raw PII
test('13. Audit export rows contain zero raw PII values', () => {
  const sample = Engine.SAMPLES.server_log;
  const res = Engine.analyzeAndRedact(sample, { mode: 'pseudonym' });
  const auditRows = res.replacements.map(r => [r.type, r.start, r.end, r.confidence, r.replacement, 'pseudonym']);
  const auditCsv = Engine.serializeCSV(auditRows);
  assert.strictEqual(auditCsv.includes('Rahul.Sharma'), false);
  assert.strictEqual(auditCsv.includes('9876543210'), false);
  assert.strictEqual(auditCsv.includes('4111'), false);
});

// 14. Diff one-to-one mapping
test('14. Diff replacements align one-to-one with detections', () => {
  const input = 'Mail rahul@gmail.com and IP 192.168.1.100 end';
  const res = Engine.analyzeAndRedact(input, { mode: 'pseudonym' });
  assert.strictEqual(res.replacements.length, res.detections.length);
  for (const rep of res.replacements) {
    assert.strictEqual(res.sanitizedText.slice(rep.newStart, rep.newEnd), rep.replacement);
  }
});

// 15. Performance on 1 MB input
test('15. Performance: 1 MB input completes quickly (< 2000 ms)', () => {
  const chunk = '2026-11-27 INFO user=rahul@example.com ip=192.168.1.100 phone=+91 9876543210 pan=ABCPE1234F card=4111111111111111\n';
  const big = chunk.repeat(Math.ceil((1024 * 1024) / chunk.length));
  const t0 = Date.now();
  const res = Engine.analyzeAndRedact(big, { mode: 'pseudonym' });
  const dt = Date.now() - t0;
  assert.ok(res.detections.length > 0);
  assert.ok(dt < 2000, 'Took too long: ' + dt + 'ms');
});

// 16. Tier 2 extra detectors & context-gating
test('16. Tier 2 detectors: IFSC, GSTIN, Passport, Voter, Vehicle, context-gated Bank Account & DOB', () => {
  const input = 'IFSC HDFC0001234 GSTIN 27ABCPE1234F1Z5 Passport K1234567 Voter ABC1234567 Vehicle MH 12 AB 1234 Bank Account 00412988371234 DOB: 1994-08-15 LogDate: 2026-11-27 OrderRef: 991028475610';
  const dets = Engine.detectPII(input, { enabledCategories: Engine.POLICY_PRESETS.all.categories });
  const types = dets.map(d => d.type);
  assert.ok(types.includes('IFSC'));
  assert.ok(types.includes('GSTIN'));
  assert.ok(types.includes('PASSPORT'));
  assert.ok(types.includes('VOTER_ID'));
  assert.ok(types.includes('VEHICLE'));
  assert.ok(types.includes('BANK_ACCOUNT'));
  assert.ok(types.includes('DOB'));
  // LogDate without DOB keyword and OrderRef without bank keyword must NOT be flagged
  assert.strictEqual(dets.filter(d => d.value === '2026-11-27').length, 0);
  assert.strictEqual(dets.filter(d => d.value === '991028475610').length, 0);
});

// 17. Reversible pseudonymization round-trip & Risk Score drop
test('17. Reversible pseudonym mapping restores placeholders and risk drops to 0', () => {
  const session = Engine.createPseudonymSession();
  const input = 'Contact rahul@example.com PAN ABCPE1234F';
  const res = Engine.analyzeAndRedact(input, { mode: 'pseudonym' }, session);
  assert.ok(res.counts.risk.beforeScore > 0);
  assert.strictEqual(res.counts.risk.afterScore, 0);
  const exported = Engine.exportPseudonymMapping(session);
  const restored = Engine.restoreFromMapping(res.sanitizedText, exported);
  assert.strictEqual(restored.restoredText, 'Contact rahul@example.com PAN ABCPE1234F');
});

// 18. Noisy sample sanitization check across all 3 modes
test('18. Noisy samples: zero raw PII survives in any mode, invalid 16-digit IDs untouched', () => {
  const rawPiiTokens = [
    'Rahul.Sharma+dev@example.com', 'RAHUL.SHARMA+DEV@EXAMPLE.COM', 'priya.nair@acme-corp.in',
    '4111 1111 1111 1111', '5555-5555-5555-4444', '3782 822463 10005',
    'ABCPE1234F', '+91 9876543210', '09876543210', '+91-98765-43210',
    '2345 6789 0124', '3456-7890-1238', '192.168.1.100', '10.24.8.14',
    'rahul.sharma@okicici', 'HDFC0001234', '00412988371234', '27ABCPE1234F1Z5'
  ];
  const untouchedNonPii = [
    '9910284756102938', '8842190037112204', '4111111111111112',
    '999.1.1.1', '1.2.3.4.5', '2345 6789 0125', 'ABCXE1234F'
  ];

  for (const mode of ['full', 'partial', 'pseudonym']) {
    const out = Engine.analyzeAndRedact(Engine.SAMPLES.server_log, { mode }).sanitizedText;
    for (const pii of rawPiiTokens) {
      assert.strictEqual(out.includes(pii), false, `Mode ${mode} leaked ${pii}`);
    }
    for (const safe of untouchedNonPii) {
      assert.strictEqual(out.includes(safe), true, `Mode ${mode} falsely altered ${safe}`);
    }
  }
});

// 19. Embedded browser self-tests pass
test('19. Built-in browser self-test runner reports 100% pass', () => {
  const selfRes = Engine.runSelfTests();
  assert.strictEqual(selfRes.passed, selfRes.total);
});

// 20. Malformed CSV (unclosed quote) & XSS strings handled safely without corruption
test('20. Malformed CSV and XSS strings do not crash or mutate surrounding text', () => {
  const malformedCsv = 'Name,Email\r\n"Unclosed,rahul@example.com';
  const csvOut = Engine.sanitizeCSV(malformedCsv, { mode: 'full' });
  assert.strictEqual(csvOut.rows.length, 2);
  assert.ok(!csvOut.sanitizedCSV.includes('rahul@example.com'));

  const xssInput = '<script>alert(1)</script> <img src=x onerror=alert(1)> rahul@example.com';
  const xssOut = Engine.analyzeAndRedact(xssInput, { mode: 'pseudonym' });
  assert.strictEqual(xssOut.sanitizedText, '<script>alert(1)</script> <img src=x onerror=alert(1)> USER_01');
});

// 21. Payment card full regression across modes, repetition, punctuation, CSV, and mode switching
test('21. Payment card redaction leaves zero exposed card digits in Full/Pseudonymize and only last 4 in Partial', () => {
  const validCards = ['4111111111111111', '4111 1111 1111 1111', '4111-1111-1111-1111', '4242 4242 4242 4242', '5555-5555-5555-4444'];
  for (const card of validCards) {
    const full = Engine.analyzeAndRedact('Card: ' + card, { mode: 'full' }).sanitizedText;
    assert.strictEqual(full, 'Card: [REDACTED]');

    const partial = Engine.analyzeAndRedact('Card: ' + card, { mode: 'partial' }).sanitizedText;
    const digitsOnly = card.replace(/\D/g, '');
    assert.ok(partial.endsWith(digitsOnly.slice(-4)), `Expected last 4 in ${partial}`);
    assert.ok(!partial.includes(digitsOnly.slice(0, 8)), `Leaked prefix in ${partial}`);

    const pseudo = Engine.analyzeAndRedact('Card: ' + card + ' and again ' + card, { mode: 'pseudonym' }).sanitizedText;
    assert.strictEqual(pseudo, 'Card: CARD_01 and again CARD_01');
  }

  // Repeated formatted vs unformatted same card -> same CARD_01
  const s = Engine.createPseudonymSession();
  const rep = Engine.analyzeAndRedact('a@b.com +91 9876543210 4111 1111 1111 1111 and 4111111111111111', { mode: 'pseudonym' }, s);
  assert.strictEqual(rep.sanitizedText, 'USER_01 PHONE_01 CARD_01 and CARD_01');

  // CSV cell with card
  const csvOut = Engine.sanitizeCSV('User,Card\nrahul@example.com,4242 4242 4242 4242', { mode: 'full' });
  assert.ok(!csvOut.sanitizedCSV.includes('4242'));
});

console.log(`\nSUMMARY: ${passed} passed, ${failed} failed out of ${passed + failed}`);
process.exit(failed > 0 ? 1 : 0);
