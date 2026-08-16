# Auto True-VMP contract (Phase 0 — frozen)

Status: **Phase 0–3 done** + **0.6.25 industry app-scope** (packer + Desktop Advanced). Do not change names or default matrix without a changelog bump and Desktop sync.

Related: [`industry-profile.md`](industry-profile.md), [`IndustryVmpRules.java`](../packer/src/main/java/com/yqsh/protector/packer/IndustryVmpRules.java), [`PaymentVmpRules.java`](../packer/src/main/java/com/yqsh/protector/packer/PaymentVmpRules.java).

## Goals

1. Auto True-VMP is **explicitly configurable** (CLI + Desktop Advanced), not only implied by `--profile industry`.
2. **Profile = preset defaults**; explicit flags always win.
3. **Backward compatible**: omitting the new flags keeps today’s 0.6.23 behavior.
4. One semantic source of truth in packer; Desktop only forwards flags.

## Non-goals (this contract)

- Editable token word-lists in UI (tokens stay in code).
- Changing VMP compile / admission rules.
- Quota hollow, Frida binding, Flutter (roadmap elsewhere).

---

## CLI surface (canonical)

Paired flags (required in Phase 1):

| Flag | Effect |
|------|--------|
| `--payment-auto-vmp` | Force **on** payment markers (`PaymentVmpRules`) |
| `--no-payment-auto-vmp` | Force **off** payment markers |
| `--industry-auto-vmp` | Force **on** industry markers (`IndustryVmpRules`) |
| `--no-industry-auto-vmp` | Force **off** industry markers |

Manual targeting (unchanged):

| Flag | Effect |
|------|--------|
| `--true-vmp-prefix <desc>` | Repeatable; type descriptor prefix (e.g. `Lcom/foo/license/`) |

### Optional aggregate (Phase 1 may implement; not required for Desktop)

```text
--auto-true-vmp payment|industry|both|off
```

**Precedence if both appear:**

1. Paired fine-grained flags override the aggregate for the axes they set.
2. If fine-grained flags **conflict** with each other on the same axis (e.g. both `--payment-auto-vmp` and `--no-payment-auto-vmp`), **fail the run** with a non-zero exit (no silent last-wins).

Desktop MVP **must** emit only the paired flags (always explicit). Scripts may omit flags and rely on defaults below.

---

## Options model (`ProtectOptions`)

Use a three-state per axis (do **not** use a bare `boolean` default):

```text
enum AutoVmpMode { UNSET, OFF, ON }

paymentAutoVmp   // CLI unset → UNSET
industryAutoVmp  // CLI unset → UNSET
```

### Resolution (`effective`)

```text
paymentEffective =
  paymentAutoVmp == ON  → true
  paymentAutoVmp == OFF → false
  paymentAutoVmp == UNSET → true          // preserve historical “payment always on”

industryEffective =
  industryAutoVmp == ON  → true
  industryAutoVmp == OFF → false
  industryAutoVmp == UNSET → (profile == INDUSTRY)
```

`profile` **must not** be read inside the type-match helpers except via the resolved `industryEffective` / defaults above.

### Match predicate (`shouldTrueVmp`)

A type is True-VMP eligible iff **any**:

1. `paymentEffective && PaymentVmpRules.matches(type)`  
   (not app-package scoped — payment SDKs live under third-party packages)
2. `industryEffective && IndustryVmpRules.matches(type, appPackagePrefix)`  
   where `appPackagePrefix` is Manifest `package` as a Dalvik prefix
   (e.g. `com.foo.bar` → `Lcom/foo/bar/`). Empty/missing prefix → industry never matches.
3. any `--true-vmp-prefix` matches `type` (prefix startswith; **not** app-scoped)

Admission / compile skips remain unchanged after eligibility.

**Behavior change (0.6.25):** Industry auto True-VMP is narrower than 0.6.24 —
only types under the app Manifest package. Sibling modules outside that package
need `--true-vmp-prefix`.

---

## Default / compatibility matrix

| Invocation | paymentEffective | industryEffective | Notes |
|------------|------------------|-------------------|-------|
| `--profile industry` (no auto flags) | ON | ON | Same as 0.6.23 |
| `--profile balanced` (no auto flags) | ON | OFF | Same as 0.6.23 |
| `--profile industry --no-industry-auto-vmp` | ON | OFF | Keep industry SO defaults 48/24 unless budget flags set |
| `--profile balanced --industry-auto-vmp` | ON | ON | Advanced combo |
| `--no-payment-auto-vmp` (+ any profile) | OFF | (per rules above) | Manual prefixes still apply |
| Only `--true-vmp-prefix …` | ON (unset) | OFF unless industry | Prefixes additive |

SO budget remains orthogonal:

- Industry profile still applies **48 / 24 MB** when budget flags are absent (`protectSoBudgetExplicit` / `protectSoMaxFileExplicit` false).
- Turning industry auto-VMP off **does not** reset SO budget.

---

## Log contract

### Policy line (required once near protect start)

Exact key prefix (stable for grepping / Desktop):

```text
True-VMP policy: payment=<on|off> industry=<on|off> prefixes=<n> industry_scope=<Lcom/…/|none> (profile=<name>, payment_src=<default|cli>, industry_src=<default|cli>)
```

- `payment` / `industry`: **effective** values after resolution.
- `prefixes`: count of `--true-vmp-prefix` entries.
- `industry_scope`: Manifest package Dalvik prefix used to gate Industry auto-VMP, or `none`.
- `*_src`: `default` if that axis was `UNSET`; `cli` if a paired (or aggregate-resolved) flag set it.

### Count lines (unchanged meaning; gate industry line)

```text
Auto True-VMP (alipay|/wxapi/): types=<n> methods=<n>
Auto True-VMP (IndustryVmpRules): types=<n> methods=<n>
```

Emit the IndustryVmpRules count line **only when** `industryEffective` is true (or always with zeros — prefer **only when effective** to avoid noise). Payment line remains as today when payment path runs.

### Industry profile banner (keep)

```text
Industry defaults: IndustryVmpRules=<on|off> so_budget_mb=… so_max_file_mb=…
```

Update the banner so `IndustryVmpRules=` reflects **effective** industry auto-VMP (not “always on because profile”).

---

## Desktop forwarding (Phase 2; contract only)

| UI (Advanced) | CLI |
|---------------|-----|
| ☑ Payment auto True-VMP | Always pass `--payment-auto-vmp` or `--no-payment-auto-vmp` |
| ☑ Industry auto True-VMP | Always pass `--industry-auto-vmp` or `--no-industry-auto-vmp` |
| Manual prefixes box | Repeat `--true-vmp-prefix` (existing) |

**Preset linkage (UI only):**

- On Profile → `industry`: if user has not overridden industry checkbox, set industry ☑.
- On Profile → other: if not overridden, clear industry ☐.
- Payment default ☑; user override sticky until “reset advanced”.
- Do not clear manual prefixes on profile change.

Profile remains a **preset**; Advanced is the control surface for auto VMP.

---

## Phase gates

| Phase | Deliverable |
|-------|-------------|
| **0 (this doc)** | Names, defaults, logs, compat matrix frozen |
| **1** | Packer `ProtectOptions` + CLI + `shouldTrueVmp` + unit tests + CHANGELOG |
| **2** | Desktop Advanced: two checkboxes + move True-VMP prefixes; SO budget fields | **done** |
| **3+** | assets / res / channel / proxy / hollow / VMP1 in Advanced | **done** |

---

## Acceptance for Phase 1 (packer)

- [x] All six matrix rows behave as specified (log policy line matches).
- [x] `--profile industry` with no new flags ≡ 0.6.23 auto-VMP behavior.
- [x] Conflicting payment on+off flags → non-zero exit.
- [x] Unit tests cover resolution + representative `IndustryVmpRules` / `PaymentVmpRules` samples.
- [x] Docs: this file + [`industry-profile.md`](industry-profile.md) stay in sync.

**Implemented in packer 0.6.24** (`AutoVmpPolicy`, CLI flags, `True-VMP policy:` log).  
**0.6.25:** Industry match gated by Manifest `package` (`industry_scope=`).
