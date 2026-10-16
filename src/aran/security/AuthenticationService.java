package aran.security;

import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.logging.Logger;

/**
 * Handles user authentication with SHA-256 password hashing.
 * Credentials are stored as hashes — plaintext passwords are never stored.
 *
 * Default users (change in production via config):
 *   admin   / admin123
 *   analyst / analyst123
 */
public class AuthenticationService {
    private static final Logger LOG = Logger.getLogger(AuthenticationService.class.getName());
    private final Map<String, String> userHashes = new HashMap<>();

    public AuthenticationService() {
        // Load default users — in a real system these would come from DB
        userHashes.put("admin",   sha256("admin123"));
        userHashes.put("analyst", sha256("analyst123"));
    }

    /**
     * Authenticate a user with username + plaintext password.
     * @return true if credentials are valid
     */
    public boolean authenticate(String username, String password) {
        if (username == null || username.isBlank()) return false;
        if (password == null || password.isBlank()) return false;
        String stored = userHashes.get(username.trim().toLowerCase());
        if (stored == null) {
            LOG.warning("Login attempt for unknown user: " + username);
            return false;
        }
        return stored.equals(sha256(password));
    }

    /**
     * Returns true if the username exists in the system.
     */
    public boolean userExists(String username) {
        return username != null && userHashes.containsKey(username.trim().toLowerCase());
    }

    private static String sha256(String input) {
        try {
            byte[] bytes = MessageDigest.getInstance("SHA-256")
                .digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(bytes);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
