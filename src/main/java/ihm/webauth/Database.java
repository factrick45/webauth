package ihm.webauth;

import java.net.InetAddress;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.concurrent.locks.ReentrantLock;

public class Database {
    private static Connection connection = null;
    private static final ReentrantLock dblock = new ReentrantLock();

    public static void init() {
        try {
            // Ensure the sqlite driver class is loaded
            try {
                Class.forName("org.sqlite.JDBC");
            } catch (ClassNotFoundException e) {
                throw new RuntimeException("Failed to load SQLite");
            }
            connection = DriverManager.getConnection("jdbc:sqlite:plugins/WebAuth/users.db");

            Statement s = connection.createStatement();

            s.executeUpdate(
                "create table if not exists users (" +
                    "user text not null unique, " +
                    "pass text, " +
                    "time integer, " +
                    "lastip text" +
                ")"
            );
        } catch (SQLException e) {
            try {
                if (connection != null)
                    connection.close();
            } catch (SQLException e2) {
                throw new RuntimeException(e);
            }
            throw new RuntimeException(e);
        }
    }

    public static boolean exists(String user) {
        dblock.lock();
        try {
            String s = "select 1 from users where lower(user) = lower(?)";
            PreparedStatement ps = connection.prepareStatement(s);
            ps.setString(1, user);

            ResultSet rs = ps.executeQuery();
            if (!rs.next())
                return false;

            return true;
        } catch (SQLException e) {
            throw new RuntimeException(e);
        } finally {
            dblock.unlock();
        }
    }


    public static String getPass(String user) {
        dblock.lock();
        try {
            String s = "select pass from users where lower(user) = lower(?)";
            PreparedStatement ps = connection.prepareStatement(s);
            ps.setString(1, user);

            ResultSet rs = ps.executeQuery();
            if (!rs.next())
                return null;

            return rs.getString("pass");
        } catch (SQLException e) {
            throw new RuntimeException(e);
        } finally {
            dblock.unlock();
        }
    }

    public static void setPass(String user, String pass) {
        if (!exists(user))
            return;

        dblock.lock();
        try {
            String s = "update users set pass = ? where lower(user) = lower(?)";
            PreparedStatement ps = connection.prepareStatement(s);
            ps.setString(1, Hash.hash(pass));
            ps.setString(2, user);

            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        } finally {
            dblock.unlock();
        }
    }

    public static boolean verifyPass(String user, String pass) {
        if (!exists(user))
            return false;
        String hash = getPass(user);
        // No password has been set
        if (hash == null)
            return true;
        if (pass == null)
            return false;

        return Hash.verify(pass, hash);
    }

    public static void login(String user) {
        if (!exists(user))
            return;

        dblock.lock();
        try {
            String s = "update users set time = ? where lower(user) = lower(?)";
            PreparedStatement ps = connection.prepareStatement(s);
            ps.setLong(1, Instant.now().getEpochSecond());
            ps.setString(2, user);

            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        } finally {
            dblock.unlock();
        }
    }

    public static void login(String user, InetAddress ip) {
        if (!exists(user))
            return;

        dblock.lock();
        try {
            String s = "update users set time = ?, lastip = ? where lower(user) = lower(?)";
            PreparedStatement ps = connection.prepareStatement(s);
            ps.setLong(1, Instant.now().getEpochSecond());
            ps.setString(2, ip.getHostAddress());
            ps.setString(3, user);

            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        } finally {
            dblock.unlock();
        }
    }

    public static void logout(String user) {
        if (!exists(user))
            return;

        dblock.lock();
        try {
            String s = "update users set time = null, lastip = null where lower(user) = lower(?)";
            PreparedStatement ps = connection.prepareStatement(s);
            ps.setString(1, user);

            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        } finally {
            dblock.unlock();
        }
    }

    public static boolean isLoggedIn(String user, InetAddress ip) {
        if (!exists(user))
            return false;

        dblock.lock();
        try {
            String s = "select time, lastip from users where lower(user) = lower(?)";
            PreparedStatement ps = connection.prepareStatement(s);
            ps.setString(1, user);

            ResultSet rs = ps.executeQuery();
            if (!rs.next())
                return false;

            long time = rs.getLong("time");
            if (rs.wasNull())
                return false;
            int limit = WebAuth.INSTANCE.getConfig().getInt("session-expiry") * 60 * 60;
            if (Instant.now().getEpochSecond() > time + limit)
                return false;

            String lastip = rs.getString("lastip");
            if (lastip == null || !lastip.equals(ip.getHostAddress()))
                return false;

            return true;
        } catch (SQLException e) {
            throw new RuntimeException(e);
        } finally {
            dblock.unlock();
        }
    }

    public static boolean userAdd(String user) {
        if (exists(user))
            return false;

        dblock.lock();
        try {
            String s = "insert into users (user) values (?)";
            PreparedStatement ps = connection.prepareStatement(s);
            ps.setString(1, user);

            ps.executeUpdate();
            return true;
        } catch (SQLException e) {
            throw new RuntimeException(e);
        } finally {
            dblock.unlock();
        }
    }

    public static boolean userDel(String user) {
        if (!exists(user))
            return false;

        dblock.lock();
        try {
            String s = "delete from users where lower(user) = lower(?)";
            PreparedStatement ps = connection.prepareStatement(s);
            ps.setString(1, user);

            ps.executeUpdate();
            return true;
        } catch (SQLException e) {
            throw new RuntimeException(e);
        } finally {
            dblock.unlock();
        }
    }
}
