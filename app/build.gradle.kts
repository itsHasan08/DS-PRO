import com.google.gms.googleservices.GoogleServicesPlugin.MissingGoogleServicesStrategy

plugins {
  alias(libs.plugins.android.application)
  alias(libs.plugins.kotlin.compose)
  // alias(libs.plugins.kotlin.serialization)
  // alias(libs.plugins.google.devtools.ksp)
  alias(libs.plugins.secrets)
  alias(libs.plugins.google.services)
}

android {
  namespace = "com.example"
  compileSdk { version = release(36) { minorApiLevel = 1 } }

  defaultConfig {
    applicationId = "com.dspro.protection"
    minSdk = 26
    targetSdk = 36
    versionCode = 1
    versionName = "1.0"

    testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
  }

  // Do not remove or modify these signingConfigs. They are necessary for building, installing,
  // and updating Android apps in AI Studio.
  signingConfigs {
    create("release") {
      val keystorePath = System.getenv("KEYSTORE_PATH") ?: "${rootDir}/my-upload-key.jks"
      storeFile = file(keystorePath)
      storePassword = System.getenv("STORE_PASSWORD")
      keyAlias = "upload"
      keyPassword = System.getenv("KEY_PASSWORD")
    }
    create("debugConfig") {
      storeFile = file("${rootDir}/debug.keystore")
      storePassword = "android"
      keyAlias = "androiddebugkey"
      keyPassword = "android"
    }
  }

  buildTypes {
    release {
      isCrunchPngs = false
      isMinifyEnabled = false
      proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
      // Do not remove or modify this signingConfig assignment. It is necessary for Android apps in
      // AI Studio.
      signingConfig = signingConfigs.getByName("release")
    }
    debug {
      // Do not remove or modify this signingConfig assignment. It is necessary for Android apps in
      // AI Studio.
      signingConfig = signingConfigs.getByName("debugConfig")
    }
  }
  compileOptions {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
  }
  buildFeatures {
    compose = true
    buildConfig = true
  }
  testOptions { unitTests { isIncludeAndroidResources = true } }
  dependenciesInfo {
    includeInApk = false
    includeInBundle = true
  }
}

abstract class BuildGuardDexTask : DefaultTask() {
  @get:InputFile
  abstract val javaSource: RegularFileProperty

  @get:InputFiles
  abstract val dptSources: ConfigurableFileCollection

  @get:Internal
  abstract val sdkDirectory: DirectoryProperty

  @get:OutputDirectory
  abstract val outputAssetsDir: DirectoryProperty

  @get:Inject
  abstract val execOperations: ExecOperations

  @TaskAction
  fun buildGuardDex() {
    val sdkDir = sdkDirectory.get().asFile
    val platformJar = File(sdkDir, "platforms/android-36/android.jar").takeIf { it.exists() }
      ?: File(sdkDir, "platforms").listFiles()
        ?.sortedByDescending { it.name }
        ?.map { File(it, "android.jar") }
        ?.firstOrNull { it.exists() }
      ?: error("android.jar not found in ${sdkDir.absolutePath}")
    val d8Bin = File(sdkDir, "build-tools").listFiles()
      ?.sortedByDescending { it.name }
      ?.map { File(it, "d8") }
      ?.firstOrNull { it.exists() }
      ?: error("d8 executable not found in ${sdkDir.absolutePath}")

    val outDir = outputAssetsDir.get().asFile
    outDir.mkdirs()

    compileDexFromSources(
      name = "guard",
      sourceFiles = listOf(javaSource.get().asFile.absolutePath),
      outputDex = outDir.resolve("ds_pro_guard.dex"),
      platformJar = platformJar,
      d8Bin = d8Bin,
    )

    val dptList = dptSources.files
      .filter { it.isFile && it.extension == "java" }
      .map { it.absolutePath }
      .sorted()
    require(dptList.isNotEmpty()) { "No DPT shell Java sources found." }
    compileDexFromSources(
      name = "dpt",
      sourceFiles = dptList,
      outputDex = outDir.resolve("ds_pro_dpt_shell.dex"),
      platformJar = platformJar,
      d8Bin = d8Bin,
    )
  }

  private fun compileDexFromSources(
    name: String,
    sourceFiles: List<String>,
    outputDex: File,
    platformJar: File,
    d8Bin: File,
  ) {
    val classesDir = temporaryDir.resolve("${name}_classes").apply {
      deleteRecursively()
      mkdirs()
    }
    val javacBin = File(System.getProperty("java.home"), "bin/javac").absolutePath
    execOperations.exec {
      commandLine(
        listOf(
          javacBin,
          "-source", "1.8",
          "-target", "1.8",
          "-Xlint:-options",
          "-classpath", platformJar.absolutePath,
          "-d", classesDir.absolutePath,
        ) + sourceFiles,
      )
    }
    val classFiles = classesDir.walkTopDown()
      .filter { it.isFile && it.extension == "class" }
      .map { it.absolutePath }
      .toList()
    val dexTempDir = temporaryDir.resolve("${name}_dex").apply {
      deleteRecursively()
      mkdirs()
    }
    execOperations.exec {
      commandLine(
        listOf(
          d8Bin.absolutePath,
          "--min-api", "26",
          "--lib", platformJar.absolutePath,
          "--output", dexTempDir.absolutePath,
        ) + classFiles,
      )
    }
    val builtDex = dexTempDir.resolve("classes.dex")
    require(builtDex.exists() && builtDex.length() > 64) { "Failed to generate ${outputDex.name}" }
    builtDex.copyTo(outputDex, overwrite = true)
  }
}

androidComponents {
  onVariants { variant ->
    val capName = variant.name.replaceFirstChar { it.uppercase() }
    val buildGuardTask = tasks.register<BuildGuardDexTask>("build${capName}GuardDex") {
      javaSource.set(layout.projectDirectory.file("src/main/guard/com/dspro/guard/DsProGuardProvider.java"))
      dptSources.from(fileTree("src/main/dpt") { include("**/*.java") })
      sdkDirectory.set(androidComponents.sdkComponents.sdkDirectory)
      outputAssetsDir.set(layout.buildDirectory.dir("generated/dspro_guard_assets/${variant.name}"))
    }
    variant.sources.assets?.addGeneratedSourceDirectory(buildGuardTask, BuildGuardDexTask::outputAssetsDir)
  }
}

// Configure the Secrets Gradle Plugin to use .env and .env.example files
// to match the convention used in Web projects.
secrets {
  propertiesFileName = ".env"
  defaultPropertiesFileName = ".env.example"
  ignoreList.add("FIREBASE_APPCHECK_DEBUG_TOKEN")
}

googleServices { missingGoogleServicesStrategy = MissingGoogleServicesStrategy.WARN }

// Some unused dependencies are commented out below instead of being removed.
// This makes it easy to add them back in the future if needed.
dependencies {
  implementation(platform(libs.androidx.compose.bom))
  // implementation(platform(libs.firebase.bom))
  // implementation(libs.accompanist.permissions)
  implementation(libs.androidx.activity.compose)
  // implementation(libs.androidx.camera.camera2)
  // implementation(libs.androidx.camera.core)
  // implementation(libs.androidx.camera.lifecycle)
  // implementation(libs.androidx.camera.view)
  implementation(libs.androidx.compose.material.icons.core)
  implementation(libs.androidx.compose.material.icons.extended)
  implementation(libs.androidx.compose.material3)
  implementation(libs.androidx.compose.ui)
  implementation(libs.androidx.compose.ui.graphics)
  implementation(libs.androidx.compose.ui.tooling.preview)
  implementation(libs.androidx.core.ktx)
  // implementation(libs.androidx.datastore.preferences)
  implementation(libs.androidx.lifecycle.runtime.compose)
  implementation(libs.androidx.lifecycle.runtime.ktx)
  implementation(libs.androidx.lifecycle.viewmodel.compose)
  // implementation(libs.androidx.navigation.compose)
  // implementation(libs.androidx.room.ktx)
  // implementation(libs.androidx.room.runtime)
  // implementation(libs.coil.compose)
  // implementation(libs.converter.moshi)
  // implementation(libs.firebase.ai)
  // Uncomment to use Firestore:
  // implementation(libs.firebase.firestore)

  // Uncomment ALL FOUR of the following dependencies together to use Firebase Auth and Google
  // Sign-In via Credential Manager:
  // implementation(libs.firebase.auth)
  // implementation(libs.androidx.credentials)
  // implementation(libs.androidx.credentials.play.services)
  // implementation(libs.googleid)
  // implementation(libs.firebase.appcheck.recaptcha)
  // implementation(libs.firebase.appcheck.debug)
  implementation(libs.kotlinx.coroutines.android)
  implementation(libs.kotlinx.coroutines.core)
  // implementation(libs.kotlinx.serialization.json)
  // implementation(libs.logging.interceptor)
  // implementation(libs.moshi.kotlin)
  // implementation(libs.okhttp)
  // implementation(libs.play.services.location)
  // implementation(libs.retrofit)
  testImplementation(libs.androidx.compose.ui.test.junit4)
  testImplementation(libs.androidx.core)
  testImplementation(libs.androidx.junit)
  testImplementation(libs.junit)
  testImplementation(libs.kotlinx.coroutines.test)
  testImplementation(libs.robolectric)
  androidTestImplementation(platform(libs.androidx.compose.bom))
  androidTestImplementation(libs.androidx.compose.ui.test.junit4)
  androidTestImplementation(libs.androidx.espresso.core)
  androidTestImplementation(libs.androidx.junit)
  androidTestImplementation(libs.androidx.runner)
  debugImplementation(libs.androidx.compose.ui.test.manifest)
  debugImplementation(libs.androidx.compose.ui.tooling)
  // "ksp"(libs.androidx.room.compiler)
  // "ksp"(libs.moshi.kotlin.codegen)
}
