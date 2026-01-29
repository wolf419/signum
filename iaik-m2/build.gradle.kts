plugins {
    `maven-publish`
}

publishing {
    publications {
        create<MavenPublication>("iaikJce") {
            groupId = "at.asitplus.thirdparty"
            artifactId = "iaik-jce"
            version = "1.0.0"

            artifact(rootProject.file("libs/iaik_jce.jar"))
        }

        create<MavenPublication>("iaikPq") {
            groupId = "at.asitplus.thirdparty"
            artifactId = "iaik-pq"
            version = "1.0.0"

            artifact(rootProject.file("libs/iaik_pq.jar"))
        }
    }

    repositories {
        mavenLocal()
    }
}
