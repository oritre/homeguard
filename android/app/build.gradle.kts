plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.oritre.homeguard"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.oritre.homeguard"
        minSdk = 26
        targetSdk = 34
        versionCode = (System.getenv("GITHUB_RUN_NUMBER") ?: "1").toInt()
        versionName = "1.0.${System.getenv("GITHUB_RUN_NUMBER") ?: "0"}"
    }

    signingConfigs {
        create("home") {
            // A fixed key, so every new build installs as an update over the previous one.
            storeFile = file("homeguard.keystore")
            storePassword = "homeguard"
            keyAlias = "homeguard"
            keyPassword = "homeguard"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("home")
        }
        debug {
            signingConfig = signingConfigs.getByName("home")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}
