<!--
  Deep code review prompt for react-native-ecc-csr library.
  
  This prompt orchestrates 5 specialized review agents in parallel.
  Edit via normal PRs to tune review dimensions and focus areas.
-->

You are running a deep code review in CI for react-native-ecc-csr.

PR NUMBER: {{PR_NUMBER}}

## Review Strategy

Spawn 5 specialized agents in parallel to review different dimensions:

1. **intent-reviewer** - Verify changes match PR intent/title
2. **clarity-reviewer** - Check code readability and maintainability
3. **robustness-reviewer** - Find edge cases, error handling gaps, memory leaks, crypto bugs
4. **consistency-reviewer** - Check keystore patterns, BouncyCastle usage, type consistency
5. **completeness-reviewer** - Verify tests, docs, security documentation updated

## Agent Definitions

### intent-reviewer
Verify the changes align with PR title and description. Check if commits match stated intent.
Focus: scope creep, unrelated changes, missing features from description
Model: sonnet (fast, intent is usually clear)

### clarity-reviewer
Assess code readability, naming, structure, comments.
Focus: confusing crypto logic, misleading names, missing comments for security patterns
Model: sonnet

### robustness-reviewer
Find bugs, edge cases, error handling gaps in cryptographic operations and keystore management.
Focus: null checks, memory leaks, resource cleanup, threading issues, ECC curve validation, CSR generation errors, key extraction vulnerabilities
Model: opus (deepest reasoning for correctness and security)

### consistency-reviewer
Check adherence to project patterns and conventions.
Focus: hardware vs software keystore decision logic, BouncyCastle provider management (remove system BC first), EncryptedFile usage for software keys, ProGuard rules, type safety (ECCurve unions)
Model: sonnet

### completeness-reviewer
Verify testing, documentation, and security documentation completeness.
Focus: missing tests for keystore scenarios, undocumented API changes, security considerations not updated, ProGuard rules not documented, backup exclusion warnings
Model: haiku (fast, checklist-style)

## Git Setup
The PR branch is checked out. Fetch main before running diff:
```bash
git fetch origin main:main
```

## Review Workflow

1. Fetch main branch
2. Get PR diff: `gh pr diff {{PR_NUMBER}}`
3. Spawn all 5 agents in parallel using Agent tool with appropriate model
4. Collect findings from each agent
5. Deduplicate and merge findings
6. Rate each finding 0-100 (confidence × impact)
7. Filter to keep only findings >75
8. Compile unified report grouped by severity:
   - Critical (91-100)
   - Important (76-90)
   - Consider (51-75) - optional tier for context
9. Post as SINGLE PR comment using `gh pr comment`

## Bedrock Model Mapping
When spawning agents via Agent tool, use:
- haiku → model: "haiku"
- sonnet → model: "sonnet"
- opus → model: "opus"

If opus fails with model access error, retry with sonnet and note downgrade in report.

## Library-Specific Patterns to Check

### Critical: Hardware vs Software Keystore (robustness + consistency reviewers)
- Hardware keystore: Android 12+ (API 31) only for TLS/ECDH (`PURPOSE_AGREE_KEY`)
- Software keystore fallback: Android 11 and below with warning
- TLS compatibility: Must accurately check device capabilities
Flag hardware keystore usage on Android <12 without fallback.

### Critical: Software Keystore Encryption (robustness + consistency reviewers)
- Must use `EncryptedFile` from AndroidX Security (v1.2.0+)
- AES256-GCM encryption with hardware-backed key
- File permissions set to mode 0600
- Excluded from backups via backup_rules.xml
Flag software keys without encryption or missing backup exclusion.

### Critical: BouncyCastle Provider (robustness + consistency reviewers)
- Remove system BC provider before registration
- Register full BC provider with EC support
- Use BC provider explicitly for operations
- ProGuard rules must keep EC classes: org.bouncycastle.jcajce.provider.asymmetric.ec.**
Flag missing BC provider removal or missing ProGuard rules.

### Type Safety (consistency reviewer)
- Must validate curve values: "secp256r1", "secp384r1", "secp521r1"
- Subject DN fields must be sanitized
- IP address format validation for SAN
Flag missing validation or type safety issues.

## Output Format

Post as SINGLE comment (no inline comments, no GitHub review):

gh pr comment {{PR_NUMBER}} --body "$(cat <<'REVIEW_REPORT'
_🤖 Deep code review. Five specialized agents analyzed this PR._

## Overview
[One-line summary of changes]

## Critical Issues (91-100)
[List critical findings with reasoning and specific line numbers]

## Important Issues (76-90)
[List important findings]

## Overall Assessment
[Summary: safe to merge, needs attention, or blocked by critical issues]
REVIEW_REPORT
)"

If report >60000 chars, truncate "Consider" tier with:
"_N additional findings omitted. Run locally for full report._"

## Context Files to Read
- README.md - Library overview and security considerations
- docs/ directory - Architecture and implementation details
- Any CHANGELOG.md - Recent changes
