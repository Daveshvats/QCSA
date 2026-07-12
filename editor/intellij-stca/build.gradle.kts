plugins {
    id 'org.jetbrains.intellij' version '1.16.0'
    id 'org.jetbrains.kotlin.jvm' version '1.9.0'
}

group 'com.stca.pipeline'
version '0.1.0'

repositories {
    mavenCentral()
}

dependencies {
    implementation 'org.jetbrains.kotlin:kotlin-stdlib:1.9.0'
    implementation 'com.google.code.gson:gson:2.10.1'
    testImplementation 'org.jetbrains.kotlin:kotlin-test:1.9.0'
}

// See https://github.com/JetBrains/gradle-intellij-plugin/
intellij {
    version = '2023.1'
    type = 'IC'  // IntelliJ IDEA Community Edition
    plugins = []  // no extra plugins required
}

patchPluginXml {
    sinceBuild = '231'
    untilBuild = '241.*'
}

// Configure the plugin's display name and description
tasks.named('buildSearchableOptions') {
    enabled = false  // speed up build
}

compileKotlin {
    kotlinOptions.jvmTarget = '17'
}

compileTestKotlin {
    kotlinOptions.jvmTarget = '17'
}

jar {
    archiveBaseName = 'stca-intellij'
}
