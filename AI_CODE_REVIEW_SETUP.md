# AI Code Review Bot Setup

This document describes the AI code review infrastructure set up for the react-native-ecc-csr repository, based on the implementation from [react-native-mqtt-mtls PR #6](https://github.com/generacclean/react-native-mqtt-mtls/pull/6).

## Overview

Three automated review workflows have been configured:

1. **AI Code Review (Automatic)** - Runs automatically on PRs from allowlisted team members
2. **Claude Code Review (Manual)** - Triggered via `@claude` mentions or `claude-code` label
3. **Deep Code Review (Multi-Agent)** - Comprehensive review triggered via `/deep-review` command

## Files Created

### Configuration Files

- **`.github/ai-review/review-prompt.md`** - Tailored review instructions for ECC CSR library
  - Focus areas: cryptographic correctness, keystore security, BouncyCastle provider management
  - Critical patterns: hardware vs software keystore decision logic, encryption at rest, TLS compatibility
  - Security focus: key protection, backup exclusion, ProGuard rules

- **`.github/ai-review/reviewers.txt`** - Team allowlist for automatic reviews
  - Current members: castulo, benjaminkomen, evanbiskey, vedgenerac, jordanjkelly12, kuznetsov-sergei
  - Case-insensitive matching

### Workflow Files

- **`.github/workflows/ai-code-review.yml`** - Automatic review workflow
  - Triggers: PR opened/synchronize/ready_for_review on main branch
  - Only runs for allowlisted authors (non-draft PRs)
  - Model: Claude Sonnet 4.6
  - Timeout: 20 minutes
  - Max turns: 80

- **`.github/workflows/claude-code-review.yml`** - Manual review workflow
  - Triggers: `@claude` mentions in PR comments/reviews or `claude-code` label
  - Model: Claude Sonnet 4.6
  - Timeout: 25 minutes
  - Max turns: 40

- **`.github/workflows/deep-code-review.yml`** - Multi-agent review workflow
  - Trigger: `/deep-review` command in PR comments
  - Spawns 5 specialized agents in parallel:
    - **intent-reviewer** (sonnet) - Verify changes match PR intent
    - **clarity-reviewer** (sonnet) - Code readability and maintainability
    - **robustness-reviewer** (opus) - Bugs, edge cases, crypto vulnerabilities
    - **consistency-reviewer** (sonnet) - Pattern adherence, BouncyCastle usage
    - **completeness-reviewer** (haiku) - Tests, docs, security documentation
  - Model: Claude Sonnet 4.6 (coordinator), with model overrides for agents
  - Timeout: 30 minutes
  - Max turns: 80

## Review Focus Areas

The review prompts are tailored specifically for this ECC CSR library:

### Critical Security Patterns

1. **Hardware vs Software Keystore Decision**
   - Hardware keystore: Android 12+ (API 31) only for TLS/ECDH
   - Software keystore fallback: Android 11 and below with warning
   - TLS compatibility validation

2. **Software Keystore Encryption (v1.2.0+)**
   - Must use `EncryptedFile` from AndroidX Security
   - AES256-GCM encryption with hardware-backed encryption key
   - File permissions set to mode 0600
   - Backup exclusion via `backup_rules.xml`

3. **BouncyCastle Provider Management**
   - Remove system BC provider before registration (system BC lacks EC support)
   - Register full BC provider with EC algorithm support
   - ProGuard rules must keep EC classes

### Rating System

Issues are rated 0-100 for confidence × impact:
- **0-25**: Likely false positive
- **26-50**: Minor nitpick
- **51-75**: Valid but low-impact
- **76-90**: Important issue requiring attention
- **91-100**: Critical (key exposure, crypto failure, TLS incompatibility, memory leak)

Only issues rated **>75 with >80% confidence** are reported.

## AWS Configuration

All workflows use:
- **AWS Bedrock** via OIDC authentication
- **Role**: `arn:aws:iam::017820692424:role/GitHubClaudeBedrockRoleGeneracClean`
- **Region**: us-east-1

## Tool Allowlist

Restricted to safe, read-only tools plus GitHub comment operations:
- Read, Glob, Grep
- Git commands: `git diff`, `git log`, `git rev-parse`, `git fetch`
- GitHub CLI: `gh pr comment`, `gh pr diff`, `gh pr view`, `gh api`
- MCP GitHub tools: `mcp__github__create_inline_comment`, `mcp__github__create_comment`
- Agent tool (deep review only)

## Usage

### Automatic Review
- PRs from allowlisted authors automatically get reviewed
- No action needed

### Manual Review
- Comment `@claude` on any PR to trigger a review
- Or add the `claude-code` label to the PR

### Deep Review
- Comment `/deep-review` on any PR
- More comprehensive but higher cost (uses Opus for robustness reviewer)
- Best for security-critical changes or major refactors

## Customization

### Add/Remove Reviewers
Edit `.github/ai-review/reviewers.txt` - changes take effect on next PR

### Tune Review Behavior
Edit `.github/ai-review/review-prompt.md` - changes take effect on next review
- Adjust focus areas
- Add project-specific patterns
- Change severity thresholds
- No workflow changes needed

## Concurrency Controls

Each workflow includes concurrency controls to prevent duplicate runs:
- Automatic review: `ai-review-{pr_number}`
- Manual review: `claude-manual-review-{pr_number}`
- Deep review: `deep-review-{pr_number}`

Previous runs are cancelled when a new one starts for the same PR.

## Next Steps

1. ✅ Test the automatic review by creating a PR from an allowlisted author
2. ✅ Test manual review by commenting `@claude` on a PR
3. ✅ Test deep review by commenting `/deep-review` on a PR
4. ⚠️ Monitor first few reviews to tune the review prompt if needed
5. ⚠️ Adjust severity thresholds based on signal-to-noise ratio

## Differences from MQTT-mTLS Implementation

This setup is adapted for ECC CSR library specifics:

- **Focus shifted from MQTT/binary detection to cryptographic operations**
- **New critical patterns**: Hardware/software keystore decision, BouncyCastle provider management, encryption at rest
- **Security emphasis**: Key protection, backup exclusion, ProGuard rules for EC algorithms
- **Type safety**: ECC curve validation, subject DN field sanitization
- **Testing scenarios**: Hardware/software keystore test coverage, curve validation tests

All other infrastructure (AWS credentials, tool allowlist, concurrency controls) remains the same.
