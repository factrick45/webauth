package ihm.webauth;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;

public class Hash {
    private static Argon2 argon = Argon2Factory.create();

    public static String hash(String password) {
        return argon.hash(10, 0xffff, 1, password);
    }

    public static boolean verify(String password, String hash) {
        return argon.verify(hash, password);
    }
}
