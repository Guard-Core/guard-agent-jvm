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
  // Redis persistence (guard-agent-go pins go-redis v9; the JVM family pin
  // is the same major line the guard-core-jvm engine uses).
  implementation(libs.lettuce.core)

  // The facade sink contract (AgentHandlerProtocol): compile-only so the
  // published artifact stays transitive-free, mirroring the engine-free Go
  // agent library; tests link the real facade via the includeBuild.
  compileOnly(libs.guard.core)
  testImplementation(libs.guard.core)

  testImplementation(libs.kotlin.test)
  testImplementation(libs.kotlinx.coroutines.core)
  testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
  useJUnitPlatform()
  // Redis-backed persistence tests PING localhost:6379 (REDIS_HOST aware)
  // and skip when it is unreachable; CI runs a redis service container.
  testLogging {
    events("passed", "skipped", "failed")
  }
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
  config.setFrom(file("detekt.yml"))
}

// The JaCoCo coverage gate lands with the W8 quality-gate wave. The plugin
// is applied so reports exist from the first real classes on.
