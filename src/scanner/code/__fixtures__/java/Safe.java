package fixtures;

import java.security.MessageDigest;

public class Safe {
    public void safePatterns() throws Exception {
        // SHA-256 (SAFE)
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

        // SHA-384 (SAFE)
        MessageDigest sha384 = MessageDigest.getInstance("SHA-384");
    }
}
