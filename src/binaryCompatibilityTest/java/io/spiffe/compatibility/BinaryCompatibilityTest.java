package io.spiffe.compatibility;

import org.gradle.testkit.runner.BuildResult;
import org.gradle.testkit.runner.GradleRunner;
import org.gradle.testkit.runner.TaskOutcome;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.tools.ToolProvider;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class BinaryCompatibilityTest {
    @TempDir
    Path projectDir;

    private final List<String> versions = new ArrayList<>();

    @BeforeEach
    void setUp() throws IOException {
        write("settings.gradle", "rootProject.name = 'api'\n");
        Files.copy(Paths.get(System.getProperty("compatibilityScript")),
                projectDir.resolve("binary-compatibility.gradle"));
        write("build.gradle",
                "plugins {\n"
                        + "    id 'java-library'\n"
                        + "    id 'me.champeau.gradle.japicmp' version '0.4.6'\n"
                        + "}\n"
                        + "group = 'io.spiffe'\n"
                        + "version = '2.0.0'\n"
                        + "repositories {\n"
                        + "    maven { url = uri('repo'); content { includeGroup 'io.spiffe' } }\n"
                        + "    mavenCentral { content { excludeGroup 'io.spiffe' } }\n"
                        + "}\n"
                        + "tasks.register('japicmp', me.champeau.gradle.japicmp.JapicmpTask)\n"
                        + "apply from: 'binary-compatibility.gradle'\n");
        write("gradle.properties", "org.gradle.workers.max=2\norg.gradle.jvmargs=-Xmx256m\n");
    }

    @Test
    void checkRejectsRemovedPublicMethod() throws IOException {
        publish("1.0.0", "public void removed() {}");
        current("");

        BuildResult result = runner("check").buildAndFail();

        assertEquals(TaskOutcome.FAILED, result.task(":japicmp").getOutcome());
        assertTrue(report().contains("removed()"), report());
    }

    @Test
    void compatibleAdditionPassesAndIsUpToDateUntilApiChanges() throws IOException {
        publish("1.0.0", "public void retained() {}");
        current("public void retained() {} public void added() {}");
        assertEquals(TaskOutcome.SUCCESS, runner("check").build().task(":japicmp").getOutcome());
        assertEquals(TaskOutcome.UP_TO_DATE, runner("check").build().task(":japicmp").getOutcome());

        current("public void added() {}");
        assertEquals(TaskOutcome.FAILED, runner("check").buildAndFail().task(":japicmp").getOutcome());
        assertTrue(report().contains("retained()"), report());
    }

    @Test
    void selectsLatestStableReleaseAndAllowsPinnedBaseline() throws IOException {
        publish("1.0.0", "");
        publish("1.1.0", "public void stable() {}");
        publish("2.0.0-rc1", "public void prerelease() {}");
        current("");

        runner("check").buildAndFail();
        assertTrue(report().contains("stable()"), report());
        assertFalse(report().contains("prerelease()"), report());
        assertEquals(TaskOutcome.SUCCESS,
                runner("check", "-PbaselineVersion=1.0.0").build().task(":japicmp").getOutcome());
    }

    @Test
    void newlyPublishedBaselineInvalidatesPreviousResult() throws IOException {
        publish("1.0.0", "");
        current("");
        runner("check").build();

        publish("1.1.0", "public void newlyPublished() {}");

        assertEquals(TaskOutcome.FAILED, runner("check").buildAndFail().task(":japicmp").getOutcome());
        assertTrue(report().contains("newlyPublished()"), report());
    }

    @Test
    void missingBaselineFailsUnlessFirstReleaseIsExplicit() throws IOException {
        current("");
        assertTrue(runner("check").buildAndFail().getOutput().contains("io.spiffe:api"));
        assertTrue(runner("check", "-PbaselineVersion=1.2.3").buildAndFail()
                .getOutput().contains("io.spiffe:api:1.2.3"));

        BuildResult firstRelease = runner("check", "-PbaselineVersion=none").build();
        assertEquals(TaskOutcome.SKIPPED, firstRelease.task(":japicmp").getOutcome());
        assertTrue(firstRelease.getOutput().contains("No binary compatibility baseline"));
    }

    @Test
    void memberExclusionDoesNotHideOtherBreaksInTheClass() throws IOException {
        publish("1.0.0", "public void accepted() {} public void retained() {}");
        Files.writeString(projectDir.resolve("build.gradle"),
                "\ntasks.named('japicmp') { methodExcludes.add('io.spiffe.Api#accepted()') }\n",
                java.nio.file.StandardOpenOption.APPEND);
        current("public void retained() {}");
        runner("check").build();

        current("");
        runner("check").buildAndFail();
        assertTrue(report().contains("retained()"), report());
        assertFalse(report().contains("accepted()"), report());
    }

    @Test
    void detectsSourceCompatibleBuilderReturnTypeChange() throws IOException {
        publish("1.0.0", "public static OldBuilder builder() { return new OldBuilder(); } "
                + "public static class OldBuilder { public Api build() { return new Api(); } }");
        current("public static Builder builder() { return new Builder(); } "
                + "public static class Builder { public Api build() { return new Api(); } }");

        runner("check").buildAndFail();
        assertTrue(report().contains("builder()"), report());
        assertTrue(report().contains("io.spiffe.Api$OldBuilder"), report());
    }

    @Test
    void detectsPublishedBuilderRegressionFrom0814To0815() throws IOException {
        write("settings.gradle", "rootProject.name = 'java-spiffe-core'\n");
        Files.writeString(projectDir.resolve("build.gradle"),
                "\nrepositories { mavenCentral() }\n"
                        + "def released = configurations.detachedConfiguration("
                        + "dependencies.create('io.spiffe:java-spiffe-core:0.8.15'))\n"
                        + "released.resolutionStrategy.useGlobalDependencySubstitutionRules = false\n"
                        + "tasks.named('japicmp') {\n"
                        + "    newArchives.setFrom(released.incoming.artifactView {\n"
                        + "        componentFilter { id -> id instanceof org.gradle.api.artifacts.component.ModuleComponentIdentifier"
                        + " && id.group == 'io.spiffe' && id.module == 'java-spiffe-core' }\n"
                        + "    }.files)\n"
                        + "    newClasspath.setFrom(released)\n"
                        + "}\n",
                java.nio.file.StandardOpenOption.APPEND);

        BuildResult result = runner("check", "-PbaselineVersion=0.8.14").buildAndFail();

        assertEquals(TaskOutcome.FAILED, result.task(":japicmp").getOutcome());
        assertTrue(report().contains("DefaultX509Source$X509SourceOptions$X509SourceOptionsBuilder"), report());
        assertTrue(report().contains("builder()"), report());
    }

    @Test
    void checksProtectedMembersButExcludesInternalAndGeneratedPackages() throws IOException {
        publish("1.0.0", "protected void retained() {}",
                "io/spiffe/workloadapi/internal/Hidden.java", "package io.spiffe.workloadapi.internal; "
                        + "public class Hidden {}",
                "io/spiffe/workloadapi/grpc/Generated.java", "package io.spiffe.workloadapi.grpc; "
                        + "public class Generated {}");
        current("protected void retained() {}");
        runner("check").build();

        current("");
        runner("check").buildAndFail();
        assertTrue(report().contains("retained()"), report());
        assertFalse(report().contains("Hidden"), report());
        assertFalse(report().contains("Generated"), report());
    }

    private void current(String members) throws IOException {
        write("src/main/java/io/spiffe/Api.java", "package io.spiffe; public class Api { " + members + " }");
    }

    private void publish(String version, String members, String... extraSources) throws IOException {
        Path staging = projectDir.resolve("published-" + version);
        Path classes = staging.resolve("classes");
        Files.createDirectories(classes);
        List<String> compilerArgs = new ArrayList<>(Arrays.asList("--release", "8", "-d", classes.toString()));
        Path source = staging.resolve("io/spiffe/Api.java");
        Files.createDirectories(source.getParent());
        Files.writeString(source, "package io.spiffe; public class Api { " + members + " }");
        compilerArgs.add(source.toString());
        for (int i = 0; i < extraSources.length; i += 2) {
            Path extra = staging.resolve(extraSources[i]);
            Files.createDirectories(extra.getParent());
            Files.writeString(extra, extraSources[i + 1]);
            compilerArgs.add(extra.toString());
        }
        assertEquals(0, ToolProvider.getSystemJavaCompiler().run(null, null, null,
                compilerArgs.toArray(new String[0])));

        Path artifactDir = projectDir.resolve("repo/io/spiffe/api/" + version);
        Files.createDirectories(artifactDir);
        try (JarOutputStream jar = new JarOutputStream(
                Files.newOutputStream(artifactDir.resolve("api-" + version + ".jar")));
             Stream<Path> files = Files.walk(classes)) {
            for (Path file : (Iterable<Path>) files.filter(Files::isRegularFile)::iterator) {
                jar.putNextEntry(new JarEntry(classes.relativize(file).toString().replace('\\', '/')));
                Files.copy(file, jar);
                jar.closeEntry();
            }
        }
        Files.writeString(artifactDir.resolve("api-" + version + ".pom"),
                "<project><modelVersion>4.0.0</modelVersion><groupId>io.spiffe</groupId>"
                        + "<artifactId>api</artifactId><version>" + version + "</version></project>");
        versions.add(version);
        write("repo/io/spiffe/api/maven-metadata.xml",
                "<metadata><groupId>io.spiffe</groupId><artifactId>api</artifactId><versioning>"
                        + "<latest>" + version + "</latest><release>" + version + "</release><versions>"
                        + versions.stream().map(v -> "<version>" + v + "</version>")
                        .collect(java.util.stream.Collectors.joining())
                        + "</versions></versioning></metadata>");
    }

    private GradleRunner runner(String... arguments) {
        List<String> args = new ArrayList<>(Arrays.asList(arguments));
        args.add("--stacktrace");
        args.add("--console=plain");
        return GradleRunner.create().withProjectDir(projectDir.toFile()).withArguments(args);
    }

    private String report() throws IOException {
        return Files.readString(projectDir.resolve("build/reports/japicmp/japicmp.txt"));
    }

    private void write(String path, String contents) throws IOException {
        Path file = projectDir.resolve(path);
        Files.createDirectories(file.getParent());
        Files.writeString(file, contents);
    }
}
