import org.gradle.jvm.tasks.Jar

plugins {
  alias(libs.plugins.kotlin.jvm)
  alias(libs.plugins.spotless)
  alias(libs.plugins.detekt)
  jacoco
  `maven-publish`
  signing
}

// Maven coordinates: groupId com.guard-core (the Central Portal namespace;
// it reverses to guard-core.com). Kotlin packages stay com.guardcore.*:
// hyphens are illegal in JVM packages and the groupId/package mismatch is
// standard practice for hyphenated domains.
group = "com.guard-core"

version = "3.2.3"

// Section 14.3 lockfile analog: every configuration resolves against the
// committed gradle.lockfile. A dependency change without
// `./gradlew --write-locks` fails the build, and the lockfile is what the
// osv-scanner dependency-audit job reads.
dependencyLocking {
  lockAllConfigurations()
  // The family's own artifacts stay out of the lock state: CI substitutes the
  // composite engine build, the release publish job resolves the same version
  // from Maven Central, and the catalog pins it exactly either way.
  ignoredDependencies.add("com.guard-core:*")
}

kotlin {
  jvmToolchain(17)
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

// --- Publishing (Maven Central via the Central Portal; see docs/release.md) --
//
// The release workflow publishes the staging bundle to the Portal Publisher
// API with GUARD_CORE_USE_COMPOSITE=false. The published POM carries NO
// guard-core dependency (compileOnly above): the agent artifact stays
// engine-free at runtime, exactly like the Go agent library. Locally the
// rehearsal uses publishToMavenLocal; signing activates only when the GPG
// secrets are present so the local rehearsal needs no key material.

val sourcesJar by
    tasks.registering(Jar::class) {
      archiveClassifier = "sources"
      from(sourceSets["main"].allSource)
    }

// The standard javadoc task renders nothing for Kotlin-only sources; the jar
// carries the project README so it is never an empty javadoc jar (the Portal
// validator rejects those). Dokka HTML replaces this when the docs wave lands.
val javadocJar by
    tasks.registering(Jar::class) {
      archiveClassifier = "javadoc"
      from(tasks.named("javadoc"))
      from(rootProject.file("README.md"))
    }

publishing {
  publications {
    create<MavenPublication>("maven") {
      groupId = project.group.toString()
      artifactId = project.name
      version = project.version.toString()

      from(components["java"])
      artifact(sourcesJar)
      artifact(javadocJar)

      pom {
        name = "guard-agent-jvm"
        description =
            "Telemetry and monitoring agent for the Guard JVM family: buffering, transport " +
                "with HMAC signing and AES-256-GCM encryption, Redis persistence, circuit " +
                "breaker, and dynamic rules (true port of guard-agent-go v3.2.2)."
        url = "https://github.com/Guard-Core/guard-agent-jvm"

        licenses {
          license {
            name = "MIT License"
            url = "https://opensource.org/licenses/MIT"
          }
        }

        developers {
          developer {
            id = "rennf93"
            name = "Renzo Franceschini"
            email = "rennf93@guard-core.com"
            organization = "Guard-Core"
            organizationUrl = "https://github.com/Guard-Core"
          }
        }

        scm {
          connection = "scm:git:https://github.com/Guard-Core/guard-agent-jvm.git"
          developerConnection = "scm:git:ssh://github.com/Guard-Core/guard-agent-jvm.git"
          url = "https://github.com/Guard-Core/guard-agent-jvm"
        }
      }
    }
  }

  repositories {
    maven {
      name = "CentralStaging"
      url = uri(layout.buildDirectory.dir("central-staging"))
    }
  }
}

signing {
  val signingKey = System.getenv("GPG_PRIVATE_KEY")
  val signingPassphrase = System.getenv("GPG_PASSPHRASE")
  if (signingKey != null && signingPassphrase != null) {
    useInMemoryPgpKeys(signingKey, signingPassphrase)
    sign(publishing.publications)
  }
}
