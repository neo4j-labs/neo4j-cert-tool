package com.neo4j.tools.certtool.output;

import com.neo4j.tools.certtool.PasswordProvider;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Generates a random password for a Neo4j database user and writes it to a credential file.
 *
 * <p>Deployments need a strong initial password as well as certificates, and inventing one by
 * hand — or generating it with whatever happens to be installed — is exactly the kind of step a
 * walkthrough gets wrong. The tool therefore generates one with the same strength as its key
 * passwords (192 bits, base64url, so every character is safe in configuration files and
 * connection strings) and writes it as a single line to a file of the caller's choosing.
 *
 * <p>The password is never echoed to the run output: the file is its only delivery. The file is
 * created {@code 0600}, and an existing file is never overwritten unless {@code --force} was
 * given — silently replacing a password a deployment depends on would be indistinguishable from
 * a bug.
 */
public final class DbCredential {

    private DbCredential() {}

    /** Writes a freshly generated password to {@code file} as one line, mode {@code 0600}. */
    public static void write(Path file, SecureRandom random, boolean force) throws IOException {
        if (Files.exists(file) && !force) {
            throw new IOException(
                    "The credential file " + file + " already exists. Move it aside, choose "
                            + "another path, or pass --force to overwrite.");
        }
        Path parent = file.getParent();
        if (parent != null && !Files.isDirectory(parent)) {
            Files.createDirectories(parent);
        }
        char[] password = PasswordProvider.generateOne(random);
        try {
            byte[] line = new byte[password.length + 1];
            try {
                for (int i = 0; i < password.length; i++) {
                    // base64url output is ASCII, so the character value is the byte value.
                    line[i] = (byte) password[i];
                }
                line[password.length] = '\n';
                FilePermissions.write(file, line, FilePermissions.OWNER_READ_WRITE);
            } finally {
                Arrays.fill(line, (byte) 0);
            }
        } finally {
            Arrays.fill(password, '\0');
        }
    }
}
