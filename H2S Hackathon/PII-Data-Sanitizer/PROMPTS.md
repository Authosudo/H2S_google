# Prompt & Engineering Log (`PROMPTS.md`)

Chronological record of how **PII SENTINEL** was designed, built, tested, and debugged.

---

## Step 1 — Initial Architecture & Verhoeff Test Data Generation
- **Prompt / Goal:** Inspect workspace, plan a 3-tier build (Tier 1 M1–M5 core, Tier 2 differentiators, Tier 3 polish), and generate mathematically valid Verhoeff Aadhaar test fixtures rather than guessing digits.
- **Output:** Ran a Node.js script implementing the Verhoeff `d`, `p`, and `inv` tables to generate valid 12-digit fictional Aadhaar numbers (`234567890124`, `345678901238`, `456789012341`, `567890123458`, `678901234560`) along with deliberate 1-digit checksum-failure variants (`234567890125`, etc.).

## Step 2 — Tier 1 Core Engine, UI, Diff View, Export & Tests
- **Prompt / Goal:** Build Tier 1 (`script.js`, `index.html`, `style.css`, `test-engine.js`, `tests.html`) covering M1–M5:
  - UMD pure engine (`detectPII`, `redactText`, `analyzeAndRedact`, `luhnCheck`, `verhoeffCheck`, `parseCSV`, `serializeCSV`, `sanitizeCSV`)
  - Mandatory detectors: Email, Indian Phone, IPv4, PAN, Aadhaar (Verhoeff), Credit Card (Luhn + brand prefix/length)
  - Overlap resolution priority (`EMAIL > CARD > AADHAAR > PAN > PHONE > IPV4`)
  - Three redaction modes: Full Mask, Partial Mask, Consistent Pseudonymization
  - Safe DOM-node side-by-side diff view (`createElement` + `textContent`, zero `innerHTML`)
  - 1-click export, RFC 4180 CSV + formula-injection neutralization, in-memory activity log, and strict CSP meta tag.
- **Status:** Implemented and verified in Tier 1 Node & browser runs.
- **Bugs Found & Fixed (Tier 1 Verification):**
  1. **Trailing punctuation on phones/IPv4:** Sentence-ending `.` after `91 8123456789.` and `10.0.0.1.` was initially rejected by overly broad `.` boundary checks. Refined to reject only decimal/version continuations (`\.\d` or `\d\.`).
  2. **PAN holder code fixture:** `ABCDE1234F` has invalid 4th holder character `D`; updated sample/test valid PAN to `ABCPE1234F` (`P` = Individual) and kept `ABCDE1234F` / `ABCXE1234F` as negative test cases.
  3. **1 MB overlap resolution bottleneck:** Replaced `O(N^2)` interval scan with 256-char spatial bucketing (`O(N)`), cutting 1 MB input processing well under 2 seconds.
  4. **Standalone `tests.html` UI bootstrap error:** Guarded `DOMContentLoaded` in `script.js` with `if (!$('inputEditor')) return;` so `tests.html` loads `PIIEngine` with zero console errors.

## Step 3 — Tier 2 Differentiators & Tier 3 Polish
- **Prompt / Goal:** Implement all Tier 2 (Section 9) and Tier 3 (Section 10) features:
  - Extended detectors (UPI, IFSC, GSTIN, Indian Passport, Voter ID, Vehicle Reg, context-gated Bank Account & DOB)
  - Policy Presets (`India DPDP Act 2023`, `PCI-DSS`, `GDPR-style`, `Developer logs / safe for AI`, `All Detectors`)
  - Risk Score 0–100 SVG Gauge + Before/After bars
  - CSV Column Intelligence table (header-name signals, per-column counts, include/exclude toggles)
  - Opt-in Reversible Pseudonymization (`Download Mapping JSON` + `Restore from Mapping JSON`)
  - Guided 5-step Demo Tour, Footer Self-Test badge + modal, Light/Dark theme toggle, Print-friendly Audit CSS, Keyboard Shortcuts modal (`?`).
- **Bugs Found & Fixed (Tier 2 Verification):**
  1. **Context-gated DOB false positive across adjacent fields:** In `DOB: 1994-08-15 LogDate: 2026-11-27`, a loose substring search in a 32-char window saw `DOB:` before `LogDate:`. Tightened both `DOB` and `BANK_ACCOUNT` context checks to anchor at the end of the immediate prefix (`$`), requiring the keyword right before the value (`LogDate:` is no longer misread as `DOB:`).
  2. **Tour banner `[hidden]` override & mobile toast stacking:** Visual inspection of screenshots revealed `.tour-banner { display: flex }` overrode the HTML `hidden` attribute on initial load, and rapid clicks stacked multiple toasts on 375px mobile. Added global `[hidden] { display: none !important; }` in `style.css` and capped visible toasts to 2 in `script.js`.

## Step 4 — Final Verification, Screenshots & Documentation
- **Verification Results:**
  - `node test-engine.js`: **19/19 passed**
  - `tests.html` (Chrome): **8/8 passed**
  - In-app self-test badge: **8/8 passed**
  - Chrome CDP Network verification: **3 initial local asset requests, 0 requests during interactions**, `0` console errors, verified over both `http://localhost:4173` and `file://`.
  - Captured desktop (`1440x900`), side-by-side diff, zero-outbound privacy proof, mobile (`375x812`), and browser self-test screenshots into `docs/screenshots/`.
- **Documentation:** Wrote judge-oriented `README.md` with requirements checklist, Mermaid architecture diagram, Luhn & Verhoeff explanations, limitations, and 3-minute demo script.

## Step 5 — Human-Centric UI/UX Clarity Redesign
- **User Feedback:** UI looked overly "AI-generated" (dense nested boxes, gradients, technical jargon, 15 checkboxes exposed upfront) and hard to understand at a glance.
- **Fixes Applied:**
  - Replaced gradient/glass card clutter with flat, crisp editorial surfaces and a plain-English 3-step guide strip at the top (`1. Paste text or load a sample -> 2. Pick how to hide data -> 3. Download cleaned file`).
  - Converted redaction modes into 3 self-explanatory cards with inline examples (`[REDACTED]`, `XXXX 1111`, `USER_01`) and placed the 15 individual detector toggles inside a collapsible drawer (`<details>`).
  - Surfaced the 1-click **Download Sanitized File** button right in the comparison header alongside the diff view, simplified technical labels into plain English, and used clean bottom-underline highlights in the diff panes.

## Step 6 — Soothing Beige Document-Tool Redesign
- **User Feedback:** Simplify for non-technical users using the soothing beige palette (`#F5F0E6`, `#FFFCF6`, `#E8DFCF`, `#D5C5AD`, `#8B7355`, `#4B463D`), remove dashboard cards, complicated navigation, gradients, and animations, and present a clear top-to-bottom 4-step workflow.
- **Changes Made:**
  - Applied the warm beige paper palette across `style.css` with zero gradients or animations.
  - Reorganized `index.html` into a plain-English 4-step document flow: Step 1 (Add text/file or load sample), Step 2 (Choose how to hide details with plain explanations), Step 3 (Success banner + side-by-side comparison), Step 4 (Large 1-click download), with Audit & Privacy details neatly tucked below.
  - Preserved all existing detection, Luhn/Verhoeff validation, overlap resolution, CSV intelligence, export, and self-test engine behavior in `script.js`, adding only a clear `#statusBanner` success/empty-state update.

## Step 7 — Complete UI/UX Redesign & Security Upgrade (8-Section Beige Commercial Layout)
- **Goal:** Organize the single page into the exact 8 commercial privacy sections (`Header`, `Introduction + Start Protecting`, `Input Area`, `Detection Results`, `Protection Settings`, `Comparison Area`, `Download Area`, `Activity History`), tighten the CSP, and run a full security/regression suite.
- **Security & UX Improvements:**
  - Tightened `index.html` CSP to `default-src 'none'; script-src 'self' blob:; style-src 'self'; img-src 'self' data:; worker-src blob:; connect-src 'none'; form-action 'none'; base-uri 'none'` by removing all inline `style=""` attributes and keeping zero inline `<script>` tags.
  - Added binary/null-byte file rejection, explicit inline export success confirmation (`#exportSuccessBanner`), full session/DOM cleanup on `Clear`, and individual counts for all 6 core PII categories (`Emails`, `Phone Numbers`, `PAN Patterns`, `Aadhaar-like`, `IP Addresses`, `Cards (Luhn Valid)`).
  - Added malformed CSV & XSS regression assertions (`test-engine.js` now 20 assertions) and verified 100 KB+ Blob Worker execution, `localStorage`/`sessionStorage` PII absence, and 0 CSP/console errors in Chrome.

## Step 8 — PRIVORA Branding & Logo Integration
- **Goal:** Apply the `PRIVORA — SMART DATA PRIVACY` brand name and shield+padlock+document logo.
- **Changes Made:** Saved original brand asset to `assets/privora-logo.jpg`, built a matching crisp inline SVG logo mark and SVG favicon in `index.html`, updated header typography (`PRIVORA` / `SMART DATA PRIVACY`), footer, `tests.html`, and `README.md`.

## Step 9 — PRIVORA Fintech-Inspired Redesign (Forest Green, Ivory & Champagne Gold)
- **Goal:** Upgrade PRIVORA into a modern, fintech-inspired website combining a dark forest-green (`#263D32` / `#34483D`) hero and security showcase with an ivory/cream (`#F5F1E8` / `#FFFEFA`) workspace, champagne-gold (`#C5A46D`) highlights, glassmorphism overview card, and banking-inspired Activity Overview.
- **Changes Made:**
  - Embedded the exact uploaded `assets/privora-logo.jpg` asset in both the header and footer alongside `PRIVORA / SMART DATA PRIVACY`.
  - Built the Hero section (`"Your Data Deserves Privacy."` + floating glassmorphism sample preview card), full interactive Workspace, 6 Feature cards, 4-step How It Works workflow, Security section (`"Privacy Is Not an Option. It's Our Foundation."`), and Activity Overview ledger (`#overviewRuns`, `#overviewProtected`, `#overviewMode`, `#overviewLastAction`).
  - Added mobile navigation toggle (`#btnMobileNav`) and verified all core detectors, Luhn checks, redaction modes, CSV/TXT exports, and 0 console errors.

## Step 10 — Dark & Light Mode Theme Switch
- **Goal:** Allow users to switch between Light and Dark modes according to preference (respecting `prefers-color-scheme` by default and persisting choice safely in `localStorage` without storing PII).
- **Changes Made:** Added `#btnThemeToggle` in the header of `index.html`, semantic light/dark CSS variables (`[data-theme="dark"]` in deep forest-slate & champagne gold) in `style.css`, and system-preference fallback + `aria-pressed` sync in `script.js`.

## Step 11 — Midnight Navy & Electric Blue Dual-Theme System
- **Goal:** Upgrade Light Mode (`#F4F7FC`, `#FFFFFF`, `#101B35`, `#2563EB`, `#0F172A`, `#64748B`, `#E2E8F0`) and Dark Mode (`#0B1120`, `#111C30`, `#162238`, `#60A5FA`, `#3B82F6`, `#F8FAFC`, `#A7B4C8`, `#26364F`) with Sun/Moon toggle, smooth transitions, and zero theme flashing (FOUC) on load.
- **Changes Made:**
  - Created synchronous pre-paint `theme-init.js` loaded in `<head>` of both `index.html` and `tests.html` (CSP `script-src 'self' blob:` compliant, zero `'unsafe-inline'`).
  - Added Sun/Moon SVG theme toggle (`#btnThemeToggle`) in `index.html` navbar and full CSS variable coverage across all cards, forms, modals, tables, diff highlights, and `tests.html` in `style.css`.

## Step 12 — Credit & Debit Card Detection Bug Fixes
- **Bug Reported:** Credit and Debit card numbers were missed in several real-world formats.
- **Root Causes Found & Fixed:**
  1. `cardRe` allowed `\s` (crossing newlines) and greedily swallowed trailing expiry/CVV digits (`4111 1111 1111 1111 12/28`, `4111 1111 1111 1111 123`), causing Luhn check to fail on 18/19 digits without falling back to the 16-digit card. Fixed with horizontal whitespace (`[ \t-]`), grouped patterns allowing multiple spaces (`4111  1111`), and automatic 16-digit prefix fallback.
  2. `detectCardBrand` lacked Maestro (`5018`/`5020`/`5038`/`6304`/`6761-6763`), expanded RuPay (`508`, `6521-6530`, `353`, `356`), Diners Club, JCB, and UnionPay BINs, and had no Luhn+context fallback for debit cards outside listed BIN ranges. Added full brand BINs plus Luhn+card-context fallback while still rejecting random ungrouped 16-digit numbers and Luhn failures.
  3. Unified category identifier to `PAYMENT_CARD` (with `localStorage` migration from legacy `CARD`), added `change` event listener alongside `input`, explicitly rejected unsupported separators (`4111/1111/1111/1111`, `4111.1111.1111.1111`, `4111_1111_1111_1111`), and added Test 21 covering all valid/invalid card examples across all 3 modes, CSV cells, punctuation, and repetition.
