# Publishing Guide

This package is published to **GitHub Packages** (not AWS CodeArtifact).

## Publishing a New Version

1. Go to the [Actions tab](https://github.com/generacclean/react-native-ecc-csr/actions/workflows/publish-github-packages.yml)
2. Click "Run workflow"
3. Optionally specify a version (e.g., `1.0.3`), or leave empty to use the current package.json version
4. The workflow will:
   - Update package.json version (if specified)
   - Publish to GitHub Packages
   - Create a git tag

## Consuming This Package

### Update your .npmrc

In your consuming app (e.g., installer-app), update `.npmrc` to point `@generacclean` packages to GitHub Packages:

```
# Change from AWS CodeArtifact:
# @generacclean:registry=https://generac-ces-381278101082.d.codeartifact.us-east-1.amazonaws.com/npm/generac-ces/

# To GitHub Packages:
@generacclean:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GH_NPM_TOKEN}
//npm.pkg.github.com/:always-auth=true
```

### Set up GH_NPM_TOKEN

Developers need a GitHub Personal Access Token with `read:packages` scope:

1. Go to https://github.com/settings/tokens
2. Generate a new token (classic) with `read:packages` scope
3. Add to your shell profile (~/.zshrc or ~/.bashrc):
   ```bash
   export GH_NPM_TOKEN=ghp_your_token_here
   ```

**No AWS CLI login required!** 🎉

## Benefits of GitHub Packages

- ✅ No AWS CLI `codeartifact login` needed
- ✅ Developers already have `GH_NPM_TOKEN` for other `@generac` packages
- ✅ Consistent with other internal packages like `@generacclean/error-catalog`
- ✅ Simple workflow using GitHub's built-in `GITHUB_TOKEN`
