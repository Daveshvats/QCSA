# Building the STCA JetBrains Plugin

## Prerequisites

- JDK 17+ (Temurin recommended)
- Gradle 8.5+ (or use the wrapper)
- Internet access (for IntelliJ Platform dependencies)

## Quick build

```bash
cd editor/intellij-stca
./gradlew buildPlugin
```

The plugin zip will be at `build/distributions/stca-intellij-0.1.0.zip`.

## Install in IntelliJ

1. Build the plugin (see above)
2. Open IntelliJ > File > Settings > Plugins
3. Click the gear icon (⚙️) > Install Plugin from Disk
4. Select `build/distributions/stca-intellij-0.1.0.zip`
5. Restart IntelliJ

## CI build

The plugin is automatically built by GitHub Actions on every push to `editor/intellij-stca/`.
See `.github/workflows/build-jetbrains.yml`.

The built `.zip` is uploaded as an artifact that you can download from the Actions tab.

## Publish to JetBrains Marketplace

1. Build the plugin: `./gradlew buildPlugin`
2. Sign in to https://plugins.jetbrains.com/
3. Upload `build/distributions/stca-intellij-0.1.0.zip`
4. Wait for JetBrains review (1-3 days)

## Troubleshooting

### "Could not resolve org.jetbrains.intellij"
Make sure you have internet access. The `org.jetbrains.intellij` Gradle plugin
downloads IntelliJ Platform SDKs from JetBrains' servers.

### "Java 17 required"
The plugin targets IntelliJ 2023.1+ which requires JDK 17.
Install Temurin 17: https://adoptium.net/

### Build fails with Kotlin version mismatch
The `build.gradle.kts` pins Kotlin 1.9.0. If your IDE uses a different
version, update the `kotlinOptions.jvmTarget` in `build.gradle.kts`.

## Architecture

See [README.md](README.md) for the full architecture overview.
