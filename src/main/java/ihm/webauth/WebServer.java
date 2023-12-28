package ihm.webauth;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.security.KeyStore;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;

public class WebServer {
    private static String loginPage;

    // Extracts a key and value from a POST request
    private static final Pattern postPattern = Pattern.compile("([^&=]+)=([^&]+)");

    private static Map<String, String> parsePost(String reqBody) {
        Map<String, String> ret = new HashMap<>();
        Matcher reg = postPattern.matcher(reqBody);
        while (reg.find()) {
            try {
                // Request body contains % escape codes
                ret.put(reg.group(1), URLDecoder.decode(reg.group(2), "UTF-8"));
            } catch (UnsupportedEncodingException e) {
                throw new AssertionError("UTF-8 doesn't exist.");
            }
        }
        return ret;
    }

    private static void processLogin(String user, String pass, InetAddress ip) throws Exception {
        if (user == null)
            throw new Exception("Invalid request.");
        try {
            if (!Database.verifyPass(user, pass))
                throw new Exception("Incorrect username or password.");
            Database.login(user, ip);
        } catch (SQLException e) {
            e.printStackTrace();
            throw new Exception("Internal error.");
        }
    }

    public static class LoginHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange t) throws IOException {
            String message = "";

            String lens = t.getRequestHeaders().getFirst("Content-length");
            if (t.getRequestMethod().equals("POST") && !lens.equals("null")) {
                int len = Integer.parseInt(lens);
                byte[] req = new byte[len];
                t.getRequestBody().read(req);
                t.getRequestBody().close();

                Map post = parsePost(new String(req));
                String user = (String) post.get("user");
                String pass = (String) post.get("pass");
                InetAddress ip = t.getRemoteAddress().getAddress();

                try {
                    processLogin(user, pass, ip);
                    message = "You are now logged in.";
                } catch (Exception e) {
                    message = e.getMessage();
                    WebAuth.INSTANCE.getLogger().info(
                        user + " failed to log in: " + message
                    );
                }
            }

            byte[] response = loginPage.replaceFirst("%message%", message).getBytes();

            t.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
            t.getResponseHeaders().add("Content-Type", "text/html; charset=utf-8");
            t.sendResponseHeaders(200, response.length);

            OutputStream os = t.getResponseBody();
            os.write(response);
            os.close();
        }
    }

    public static void init() {
        try {
            InputStream html = WebAuth.INSTANCE.getResource("login.html");
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            int b = 0;
            while ((b = html.read()) != -1)
                buf.write(b);
            html.close();
            loginPage = buf.toString();

            int port = WebAuth.INSTANCE.getConfig().getInt("port");
            HttpsServer https = HttpsServer.create(new InetSocketAddress(port), 0);
            SSLContext sslc = SSLContext.getInstance("TLS");

            char[] password = WebAuth.INSTANCE.getConfig().getString("pass").toCharArray();
            KeyStore ks = KeyStore.getInstance("PKCS12");
            try {
                FileInputStream kf = new FileInputStream("plugins/WebAuth/key.p12");
                ks.load(kf, password);
                kf.close();
            } catch (Exception e) {
                throw new RuntimeException("Failed to load key file", e);
            }

            KeyManagerFactory kmf =
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, password);

            TrustManagerFactory tmf =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);

            sslc.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            https.setHttpsConfigurator(
                new HttpsConfigurator(sslc) {
                    public void configure(HttpsParameters param) {
                        try {
                            SSLContext ctx = getSSLContext();
                            SSLEngine eng = ctx.createSSLEngine();

                            param.setNeedClientAuth(false);
                            param.setCipherSuites(eng.getEnabledCipherSuites());
                            param.setProtocols(eng.getEnabledProtocols());

                            SSLParameters sslp = ctx.getSupportedSSLParameters();
                            param.setSSLParameters(sslp);
                        } catch (Exception e) {
                            throw new RuntimeException(e);
                        }
                    }
                }
            );

            https.createContext("/", new LoginHandler());
            // Single thread
            https.setExecutor(null);
            https.start();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
