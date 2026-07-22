# GitHub Actions Workflow Setup Guide

This document provides instructions for setting up GitHub Actions secrets and configuring automated builds.

## Prerequisites

Before setting up GitHub Actions, ensure you have:

1. A valid Android keystore file for signing release APKs
2. Keystore password and key password
3. Access to repository settings

## Step 1: Generate Keystore (if needed)

If you don't have a keystore, generate one:

```bash
keytool -genkey -v -keystore nexus.keystore \
  -keyalg RSA -keysize 2048 -validity 10000 \
  -alias nexus_key
```

You'll be prompted for:
- Keystore password
- Key password
- Personal information (name, organization, etc.)

## Step 2: Encode Keystore to Base64

The keystore needs to be base64 encoded to store as a GitHub secret.

### macOS:
```bash
cat nexus.keystore | base64 | pbcopy
```

### Linux:
```bash
cat nexus.keystore | base64 -w 0 > keystore.b64
cat keystore.b64
```

### Windows (PowerShell):
```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("nexus.keystore")) | Set-Clipboard
```

## Step 3: Add GitHub Secrets

1. Go to your repository: https://github.com/mohemmedalihasin-bot/nexus
2. Click **Settings** → **Secrets and variables** → **Actions**
3. Click **New repository secret** and add these secrets:

| Secret Name | Value |
|---|---|
| `KEYSTORE_FILE` | Base64 encoded keystore content |
| `KEYSTORE_PASSWORD` | Your keystore password |
| `KEY_ALIAS` | `nexus_key` (or your alias) |
| `KEY_PASSWORD` | Your key password |

## Step 4: Verify Setup

1. Go to **Actions** tab in your repository
2. You should see the **Build and Release APK** workflow
3. Test by triggering a manual workflow run

## Using the Workflow

### Automatic Builds

The workflow runs automatically on:
- **Push to main/develop branches**: Builds debug APK
- **Tag push (v*)**: Builds release APK and creates GitHub Release
- **Pull requests**: Builds and tests code

### Manual Workflow Dispatch

Trigger builds manually:

1. Go to **Actions** → **Build and Release APK**
2. Click **Run workflow**
3. Select build type (debug or release)

### Accessing Artifacts

After a successful build:

1. Go to **Actions** → Completed workflow run
2. Scroll to **Artifacts** section
3. Download the APK file

### Releases

For tag-based releases:

1. Create a tag: `git tag -a v1.0.0 -m "Release version 1.0.0"`
2. Push tag: `git push origin v1.0.0`
3. Workflow automatically:
   - Builds release APK
   - Creates GitHub Release
   - Attaches APK to release

View releases at: https://github.com/mohemmedalihasin-bot/nexus/releases

## Workflow Jobs Explanation

### Build Job
- Sets up JDK and Android SDK
- Builds debug or release APK
- Uploads artifacts
- Uploads to releases (for tags)

### Test Job
- Runs unit tests
- Uploads test reports

### Analyze Job
- Runs Lint analysis
- Uploads lint reports

### Performance Check
- Checks APK size
- Warns if APK exceeds 100MB

### Summary Job
- Generates build summary
- Posts results to GitHub

## Troubleshooting

### Build Fails: "Keystore not found"
- Verify secrets are added correctly
- Check that KEYSTORE_FILE is properly base64 encoded

### Build Fails: "Invalid keystore password"
- Verify KEYSTORE_PASSWORD is exactly correct
- Check for extra spaces or special characters

### APK Not Generated
- Check workflow logs for errors
- Ensure build.gradle is correctly configured
- Verify minSdk and targetSdk are valid

### Secrets Not Available
- Verify secrets are added to the correct repository
- Secrets are only available to the owner
- Wait for GitHub to propagate changes

## Security Best Practices

1. **Never commit keystore files** to version control
2. **Keep passwords secure** - use strong passwords
3. **Rotate signing keys** periodically (annual or as needed)
4. **Limit secret access** - only needed for release builds
5. **Review logs carefully** - secrets are masked in logs
6. **Use protected branches** - require reviews before release

## Environment Variables in Workflow

The workflow uses these environment variables during build:

```yaml
KEYSTORE_FILE: ${{ secrets.KEYSTORE_FILE }}
KEYSTORE_PASSWORD: ${{ secrets.KEYSTORE_PASSWORD }}
KEY_ALIAS: ${{ secrets.KEY_ALIAS }}
KEY_PASSWORD: ${{ secrets.KEY_PASSWORD }}
```

## Advanced Configuration

### Change Build Triggers

Edit `.github/workflows/build-apk.yml` to customize when builds trigger:

```yaml
on:
  push:
    branches:
      - main
      - develop
    tags:
      - 'v*'
```

### Add Additional Checks

Add custom validation or tests by modifying workflow steps.

### Notify on Build Status

Configure notifications:
- Slack integration
- Email notifications
- GitHub Status checks

## Reference Documentation

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Android Actions Setup](https://github.com/android-actions/setup-android)
- [Gradle Android Plugin](https://developer.android.com/studio/releases/gradle-plugin)
- [App Signing Guide](https://developer.android.com/studio/publish/app-signing)

## Support

For issues:
1. Check workflow logs for error messages
2. Review this setup guide
3. Open an issue on GitHub repository
4. Contact repository maintainers
