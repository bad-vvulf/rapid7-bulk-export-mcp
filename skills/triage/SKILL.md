---
name: triage
description: "Use when triaging Rapid7 vulnerabilities into active remediation, approved exception coverage, or new ticket creation. Applies a specific workflow: ensure current Rapid7 vulnerability data is available, rank findings by Rapid7 real risk score (`riskScoreV2_0`), break ties by affected asset count, exclude items expected to be handled by the scheduled Microsoft Patch Tuesday workflow, then perform a deterministic Jira coverage check in `TRESEC`, review linked PERAs, and decide whether the finding is already covered, requires manual review, or needs a new ticket."
---

# Rapid7 Vulnerability Triage

## Overview

Use this skill to decide which Rapid7 findings still need triage action. The goal is not to list the highest-risk findings in the abstract; it is to determine which findings still require remediation tracking after accounting for active Jira work, approved PERAs, and the separate Microsoft Patch Tuesday process.

This process is deterministic. Do not perform partial triage.

Valid triage requires both:

- current Rapid7 vulnerability data
- Atlassian Rovo Jira access to the `TRESEC` project

Stop if either is unavailable.

## Required Inputs

You need:

- current Rapid7 vulnerability data available for querying
- Atlassian Rovo Jira access to the `TRESEC` project

For first-pass triage, use the Rapid7 `vulnerabilities` table. Do not require policy or remediation data unless the user explicitly asks for lifecycle analysis or other deeper Rapid7 analysis.

## Workflow

### 1. Confirm current Rapid7 vulnerability data

Before triage:

- ensure Rapid7 vulnerability data is available
- ensure the vulnerability data is current enough for triage
- confirm the `vulnerabilities` table is usable
- if vulnerability data is missing or stale, run the Rapid7 MCP workflow needed to refresh or load current data before continuing
- if current vulnerability data cannot be made available, stop

### 2. Rank findings

Rank findings from the Rapid7 `vulnerabilities` table using:

1. `riskScoreV2_0` descending
2. affected asset count descending
3. stable tie-breaker such as `title` ascending

Treat `riskScoreV2_0` as the primary risk signal. Do not rank by severity first.

Recommended aggregation grain for first-pass triage:

Example query:

SELECT
  vulnId,
  title,
  MAX(riskScoreV2_0) AS risk_score,
  COUNT(DISTINCT assetId) AS affected_assets
FROM vulnerabilities
GROUP BY vulnId, title
ORDER BY risk_score DESC NULLS LAST, affected_assets DESC, title ASC

### 3. Exclude Patch Tuesday items

Do not include findings expected to be resolved by the scheduled Microsoft Patch Tuesday workflow.

Determine Patch Tuesday applicability from Rapid7-side data and Rapid7-visible finding characteristics, not from Jira naming, Jira descriptions, or other downstream external corroboration.

Do not assume every Microsoft vulnerability belongs to Patch Tuesday.

Exclude a finding only when Rapid7-side evidence indicates it belongs to the Microsoft Patch Tuesday remediation stream.

If Patch Tuesday applicability cannot be determined confidently from Rapid7-side data, keep the finding in scope and note that Patch Tuesday exclusion could not be confirmed.

### 4. Perform a deterministic Jira coverage check

For each ranked finding still in scope, perform a required Jira coverage check in `TRESEC` before concluding whether coverage exists.

Do not treat a narrow search miss as evidence that no Jira ticket exists.

Required process:

1. Normalize the Rapid7 finding title
2. Generate and search multiple naming variants
3. Collect all plausible Jira vulnerability remediation candidates
4. Classify each candidate by status
5. Use the best-supported vulnerability ticket or ticket set as the bridge record for PERA checks
6. Only after this process, decide whether there is active Jira coverage, historical-only Jira evidence, or no matching Jira evidence found

#### 4a. Normalize the Rapid7 finding title

Extract the core concepts from the Rapid7 title and any supporting context visible in Rapid7, such as:

- vendor or platform name
- product family
- abbreviation or acronym
- remediation verb or condition
- lifecycle wording such as obsolete, unsupported, end of life, legacy, outdated

Example:

`Obsolete VMware ESX Version` may require searching variants including:

- VMware
- ESX
- ESXi
- obsolete
- unsupported
- end of life
- upgrade
- latest version

#### 4b. Run required Jira search families

Before asserting absence, search `TRESEC` using multiple query families.

At minimum, search:

- exact or near-exact title phrasing
- vendor and product variants
- abbreviation and platform variants
- remediation-language variants such as `upgrade`, `update`, `unsupported`, `obsolete`, `end of life`
- Jira program wording variants such as `Obsolete Application Remediation` when relevant

Do not rely on a single literal-title search.

If the user mentions a specific Jira key, directly verify that ticket instead of relying only on search recall.

#### 4c. Candidate collection rule

Collect plausible candidate vulnerability remediation tickets even when the summary wording is broader or different from the Rapid7 title.

Examples of valid candidate evidence include:

- summary wording that refers to the same product family or platform
- remediation wording that clearly maps to the same finding
- linked asset, hostname, or system context that corroborates the match
- related remediation project naming that does not repeat the exact Rapid7 title

Do not reject a candidate solely because the summary does not exactly match the Rapid7 title.

#### 4d. Status classification

For each plausible candidate vulnerability remediation ticket, classify it as one of:

- `active_ticket_exists`
- `historical_ticket_only`
- `ambiguous_match`

Treat as active any non-terminal remediation status, such as:

- `Open`
- `In Progress`
- `Blocked`
- `In QA`
- any other status that is not clearly terminal

Treat these as terminal for triage purposes:

- `Done`
- `Closed`
- `Canceled` or `Cancelled`

If a matching ticket exists only in a terminal state, record that historical Jira evidence exists, but do not count it as active coverage.

Do not say `no ticket exists` when a terminal-state matching ticket exists.

#### 4e. Absence standard

Only state `no matching ticket found` after the required Jira search families have been completed and no plausible candidate vulnerability remediation ticket was found.

Until then, use conservative language such as:

- `no active ticket found in searches performed`
- `no matching ticket found yet`
- `historical ticket exists but no active ticket found`

#### 4f. Bridge rule for PERA checks

Use the best-supported matching vulnerability remediation ticket or ticket set as the bridge record for PERA checks.

If multiple plausible historical tickets exist for the same finding family over time, prefer the one with the strongest corroboration from asset, hostname, linked work items, or remediation context.

If the candidate set remains materially ambiguous after required searching, report `needs_manual_review` instead of overstating absence or coverage.

### 5. Check for approved PERAs

Only check PERAs when there is no active remediation ticket.

A historical matching remediation ticket in a terminal state is still useful as a bridge record for PERA discovery, but it does not count as active remediation coverage by itself.

Rules:

- Prefer PERAs linked to the relevant Jira vulnerability remediation ticket
- Use PERA summary naming and linked work items as corroboration, not as the sole match
- Respect scope: approved PERAs cannot be expanded retroactively

Count a PERA as valid coverage only when:

- it corresponds to the finding or allowed grouped scope
- and it is actually approved, not merely submitted or awaiting approval

Known non-approved statuses include:

- `In Review`
- `Waiting for approval`
- `Awaiting approval`
- `Rejected`
- `Re-Open`

If a matching PERA exists but is terminal, non-approved, unclear in approval state, or not reliably in scope for the current finding, do not count it as valid coverage.

If approval state is unclear from the visible ticket state, report `needs_manual_review` instead of overstating coverage.

PERA-specific guardrails:

- `Remediation` and `Acceptance` are different PERA types
- PERAs must be linked to the relevant vulnerability remediation ticket or tickets
- approved PERAs are immutable with respect to scope
- `Remediation` PERAs may link to only one vulnerability ticket
- `Acceptance` PERAs may link to multiple vulnerability tickets only when the constraint, business justification, and root cause are the same

### 6. Decide the triage outcome

For each finding, assign one outcome:

- `active_ticket_exists`
- `approved_pera_exists`
- `needs_ticket`
- `needs_manual_review`

Before assigning the final outcome, separately determine and report:

- whether any matching Jira remediation ticket exists
- whether any such ticket is active or terminal-only
- whether any matching PERA exists
- whether any such PERA is approved, terminal, non-approved, or ambiguous

Do not collapse `historical evidence exists` into `no evidence exists`.

Use `needs_manual_review` when matching or approval evidence is materially ambiguous.

## Matching Guidance

Use this confidence order:

1. Exact linked Jira vulnerability remediation ticket
2. Matching Jira vulnerability remediation ticket plus corroborating hostname, asset, or system context
3. Matching Jira vulnerability remediation ticket with strong product-family and remediation-language alignment
4. Matching PERA linked from that ticket
5. Loose title-only similarity

Do not conclude `no Jira ticket exists` from a failure at one search phrasing.

When Jira naming variants are common, prefer broader family matching across:

- vendor naming variants
- product naming variants
- abbreviations and aliases
- remediation-language variants
- standardized Jira program wording

Avoid claiming coverage based only on a similar PERA title when repeated findings exist over time.

Also avoid claiming absence based only on literal Rapid7 title similarity failure.

## Jira Matching Checklist

Before concluding that Jira coverage does or does not exist for a finding, complete this checklist:

- Normalize the Rapid7 finding title into core concepts
- Search exact or near-exact title wording
- Search vendor and product-family variants
- Search abbreviation and platform variants
- Search remediation-language variants
- Search relevant Jira program wording variants
- Directly verify any Jira key mentioned by the user
- Collect plausible candidate remediation tickets, even if wording is not identical
- Classify each candidate as active, terminal-only, or ambiguous
- Use the best-supported candidate ticket or ticket set as the bridge to PERA review
- Only after all required searches, decide whether the result is:
  - no matching ticket found
  - matching ticket exists but only in terminal state
  - active ticket exists
  - ambiguous and needs manual review

Do not treat a narrow search miss as sufficient evidence that no Jira ticket exists.

## Jira/PERA Rules

Use the Jira vulnerability remediation ticket as the authoritative remediation-tracking record.

Relevant Jira ticket standard:

- Asset/IVM ad-hoc pattern: `Vulnerability Remediation - <Vulnerability Title> - <mm/dd/yyyy>`
- Automated remediation projects may use broader standardized project titles rather than the exact Rapid7 finding title

Known non-approved PERA statuses include:

- `In Review`
- `Waiting for approval`
- `Awaiting approval`
- `Rejected`
- `Re-Open`

## Response Format

Return:

- the ranked findings inspected
- the Jira search evidence used
- the candidate Jira tickets found
- the status classification of each candidate
- the PERA evidence found
- the triage outcome for each

Preferred compact format:

1. <title>
   riskScoreV2_0: <score>
   affected_assets: <count>
   jira_search_terms: <short list of major variants searched>
   jira_candidates:
     - <ticket key> | <summary> | <status_classification>
     - <ticket key> | <summary> | <status_classification>
   pera_candidates:
     - <ticket key> | <summary> | <approval/state classification>
   outcome: <active_ticket_exists|approved_pera_exists|needs_ticket|needs_manual_review>
   rationale: <one short sentence>

Allowed Jira status classifications:

- `active`
- `terminal_only_match`
- `ambiguous_match`
- `none_found_after_required_search`

Allowed PERA classifications:

- `approved`
- `non_approved`
- `terminal_only`
- `ambiguous`
- `none_found`

## Guardrails

- Re-anchor to triage activity, not UI or widget errors
- Do not let historical closed tickets suppress current findings unless an active ticket or approved PERA exists
- Do not include Patch Tuesday-covered Microsoft findings in the triage result set
- If a finding cannot be matched reliably enough for enterprise-grade confidence, say so explicitly
- Do not conclude `no Jira ticket exists` from a narrow or literal-title search miss
- Do not collapse `matching ticket exists but only in terminal state` into `no ticket found`
- Directly verify any Jira key explicitly mentioned by the user
- Prefer `no active ticket found` over `no ticket found` unless required matching has been exhausted
- When historical Jira artifacts exist, report them explicitly even if the final outcome is still `needs_ticket`
- Do not invoke Jira UI widgets, embedded app views, or `ui://widget/...` resources during triage
- Use only non-UI Jira search, read, and action methods needed to evaluate remediation tickets and PERAs
- If a Jira UI widget error appears but Jira data retrieval still works, treat it as non-blocking, ignore the widget failure, and continue triage