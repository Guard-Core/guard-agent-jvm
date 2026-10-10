plugins {
  alias(libs.plugins.kotlin.jvm)
  alias(libs.plugins.spotless)
  alias(libs.plugins.detekt)
  jacoco
}

group = "com.guardcore"

version = "3.2.2-SNAPSHOT"

kotlin {
  jvmToolchain(17)
}

repositories {
  mavenCentral()
}

dependencies {
  implementation(libs.kotlin.stdlib)
  implementation(libs.kotlinx.coroutines.core)

  testImplementation(kotlin("test"))
}

tasks.test {
  useJUnitPlatform()
}

spotless {
  kotlin {
    ktfmt()
  }
  kotlinGradle {
    ktfmt()
  }
}

detekt {
  buildUponDefaultConfig = true
}

// The JaCoCo coverage gate lands with real code in a later milestone. The
// plugin is applied now so reports exist from the first real classes on.
