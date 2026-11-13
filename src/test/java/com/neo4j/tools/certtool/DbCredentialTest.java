package com.neo4j.tools.certtool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.neo4j.tools.certtool.output.FilePermissions;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Pattern;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Covers {@code --db-credential-file}: a generated random password for the neo4j database user,
 * written to a locked-down file and never echoed to the run output.
 */
class DbCredentialTest {

    /** base64url without padding, 24 bytes of entropy. */
    private static final Pattern GENERATED_SHAPE = Pattern.compile("[A-Za-z0-9_-]{32}");

    @TempDir
    Path work;

    private int run(String... arguments) {
        return new Main(
                        new java.io.PrintStream(
                                new java.io.ByteArrayOutputStream(), true, StandardCharsets.UTF_8),
                        new java.io.PrintStream(
                                new java.io.ByteArrayOutputStream(), true, StandardCharsets.UTF_8))
                .run(arguments);
    }

    @Test
    @DisplayName("a credential-only run writes a 0600 file holding one strong password")
    void credentialOnlyRun() throws Exception {
        Path credential = work.resolve("db-credential");

        int exitCode = run(
                "--db-credential-file", credential.toString(),
                "--force");

        assertEquals(Main.EXIT_OK, exitCode);
        assertTrue(Files.isRegularFile(credential));
        if (FilePermissions.posixSupported()) {
            assertEquals("rw-------", java.nio.file.attribute.PosixFilePermissions.toString(
                    Files.getPosixFilePermissions(credential)),
                    "a credential file must be readable only by its owner");
        }
        List<String> lines = Files.readAllLines(credential, StandardCharsets.UTF_8);
        assertEquals(1, lines.size(), "exactly one line");
        assertTrue(
                GENERATED_SHAPE.matcher(lines.getFirst()).matches(),
                "192 bits of base64url: " + lines.getFirst());
    }

    @Test
    @DisplayName("the password is never echoed to the run output")
    void passwordIsNotPrinted() throws Exception {
        Path credential = work.resolve("db-credential");

        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        java.io.ByteArrayOutputStream err = new java.io.ByteArrayOutputStream();
        int exitCode;
        try (var outStream = new java.io.PrintStream(out, true, StandardCharsets.UTF_8);
                var errStream = new java.io.PrintStream(err, true, StandardCharsets.UTF_8)) {
            exitCode = new Main(outStream, errStream).run(new String[] {
                "--db-credential-file", credential.toString(),
            });
        }

        assertEquals(Main.EXIT_OK, exitCode);
        String printed = out.toString(StandardCharsets.UTF_8)
                + err.toString(StandardCharsets.UTF_8);
        for (String line : Files.readAllLines(credential, StandardCharsets.UTF_8)) {
            assertFalse(printed.contains(line), "the password must not appear in the output");
        }
    }

    @Test
    @DisplayName("two runs never generate the same password")
    void passwordsDiffer() throws Exception {
        Path first = work.resolve("first");
        Path second = work.resolve("second");
        assertEquals(Main.EXIT_OK, run("--db-credential-file", first.toString()));
        assertEquals(Main.EXIT_OK, run("--db-credential-file", second.toString()));

        assertNotEquals(
                Files.readString(first, StandardCharsets.UTF_8).strip(),
                Files.readString(second, StandardCharsets.UTF_8).strip());
    }

    @Test
    @DisplayName("an existing credential file is not overwritten unless --force is given")
    void existingFileIsProtected() throws Exception {
        Path credential = work.resolve("db-credential");
        assertEquals(Main.EXIT_OK, run("--db-credential-file", credential.toString()));
        String original = Files.readString(credential, StandardCharsets.UTF_8);

        int withoutForce = run("--db-credential-file", credential.toString());
        assertEquals(Main.EXIT_FAILURE, withoutForce, "an existing credential must not be clobbered");
        assertEquals(original, Files.readString(credential, StandardCharsets.UTF_8));

        int withForce = run("--db-credential-file", credential.toString(), "--force");
        assertEquals(Main.EXIT_OK, withForce);
        assertNotEquals(original, Files.readString(credential, StandardCharsets.UTF_8));
    }

    @Test
    @DisplayName("a cluster run writes the credential alongside the bundles")
    void alongsideAClusterRun() throws Exception {
        Path credential = work.resolve("db-credential");
        TestBundles.Run run = TestBundles.twoNodeCluster(
                work, "ca", "--db-credential-file", credential.toString());

        assertTrue(Files.isRegularFile(credential), "the credential file is written");
        assertTrue(Files.isRegularFile(run.caDirectory().resolve("ca.crt")), "so is the CA");
        assertTrue(run.output().contains("db credential"), "the summary names it: " + run.output());
        assertFalse(
                run.output().contains(Files.readString(credential, StandardCharsets.UTF_8).strip()),
                "but never the password itself");
    }

    @Test
    @DisplayName("a dry run alongside a cluster plans the credential and writes nothing")
    void dryRunPlansIt(@TempDir Path scopedWork) throws Exception {
        Path credential = scopedWork.resolve("db-credential");

        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        java.io.ByteArrayOutputStream err = new java.io.ByteArrayOutputStream();
        int exitCode;
        try (var outStream = new java.io.PrintStream(out, true, StandardCharsets.UTF_8);
                var errStream = new java.io.PrintStream(err, true, StandardCharsets.UTF_8)) {
            exitCode = new Main(outStream, errStream).run(new String[] {
                "--db-credential-file", credential.toString(),
                "--node", "core1:core1.example.com",
                "--out", scopedWork.resolve("out").toString(),
                "--password-file", TestBundles.passwordFile(scopedWork).toString(),
                "--pbkdf2-iterations", TestBundles.TEST_ITERATIONS,
                "--dry-run",
            });
        }

        assertEquals(Main.EXIT_OK, exitCode, err.toString());
        assertFalse(Files.exists(credential), "a dry run must not write the credential");
        assertFalse(Files.exists(scopedWork.resolve("out")), "nor any certificate material");
        assertTrue(out.toString().contains("Would create"), out.toString());
    }

    @Test
    @DisplayName("a standalone dry run plans only the credential file")
    void standaloneDryRunPlansOnlyTheCredential() throws Exception {
        Path credential = work.resolve("db-credential");

        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        java.io.ByteArrayOutputStream err = new java.io.ByteArrayOutputStream();
        int exitCode;
        try (var outStream = new java.io.PrintStream(out, true, StandardCharsets.UTF_8);
                var errStream = new java.io.PrintStream(err, true, StandardCharsets.UTF_8)) {
            exitCode = new Main(outStream, errStream).run(new String[] {
                "--db-credential-file", credential.toString(),
                "--dry-run",
            });
        }

        assertEquals(Main.EXIT_OK, exitCode, err.toString());
        assertFalse(Files.exists(credential), "a dry run must not write the credential");
        assertFalse(Files.exists(work.resolve("out")), "no output directory is created");
        assertTrue(out.toString().contains("1 files and 0 directories"), out.toString());
    }
}
