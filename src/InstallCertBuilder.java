import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Scanner;

/**
 * Class used to add the server's certificate to the KeyStore with your trusted
 * certificates.
 */

public class InstallCertBuilder {

    public static void main(String[] args) throws Exception {

        Scanner scanner = new Scanner(System.in);
        System.out.println("-------SSL Certificate Installer---------");

        System.out.println("Enter HOST (e.g self-signed.badssl.com) :: ");
        String host = scanner.nextLine();

        System.out.println("Enter File Name (e.g badssl.jks) :: ");
        String fileName = scanner.nextLine();

        System.out.println("Enter PORT (e.g 443) :: ");
        int port = scanner.nextInt();

        System.out.println("Enter Password (e.g changeit) :: ");
        String password = scanner.nextLine();

        scanner.nextLine();

        scanner.close();

        installCert(host, fileName, port, password);

    }

    public static void installCert(String host, String fileName, int port, String password) throws Exception {

        char[] passphrase = password.toCharArray();

        File file = new File(fileName);
        file.createNewFile();

        System.out.println("Loading KeyStore " + file + "...");
        InputStream in = new FileInputStream(file);
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());

        try {
            ks.load(in, passphrase);
            in.close();
        } catch (Exception e) {
            ks.load(null, passphrase);
        }

        SSLContext context = SSLContext.getInstance("TLS");
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        X509TrustManager defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];
        SavingTrustManager tm = new SavingTrustManager(defaultTrustManager);
        context.init(null, new TrustManager[] { tm }, null);
        SSLSocketFactory factory = context.getSocketFactory();

        System.out.println("Opening connection to " + host + ":" + port + " ...");
        SSLSocket socket;

        socket = (SSLSocket) factory.createSocket(host, port);
        socket.setSoTimeout(10000);

        try {
            System.out.println("Starting SSL handshake...");
            socket.startHandshake();
            socket.close();
            System.out.println();
            System.out.println("Certificate is already trusted.");
        } catch (SSLException e) {
            X509Certificate[] chain = tm.chain;
            if (chain == null) {
                System.out.println("Could not obtain server certificate chain.");
                return;
            }
            System.out.println();
            System.out.println("Server sent " + chain.length + " certificate(s):");
            System.out.println();
            MessageDigest sha1 = MessageDigest.getInstance("SHA1");
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            for (int i = 0; i < chain.length; i++) {
                X509Certificate cert = chain[i];
                System.out.println(" " + (i + 1) + " Subject " + cert.getSubjectDN());
                System.out.println("   Issuer  " + cert.getIssuerDN());
                sha1.update(cert.getEncoded());
                System.out.println("   sha1    " + toHexString(sha1.digest()));
                md5.update(cert.getEncoded());
                System.out.println("   md5     " + toHexString(md5.digest()));
                System.out.println();
            }
            int k = 0;
            X509Certificate cert = chain[k];
            String alias = host + "-" + (k + 1);
            ks.setCertificateEntry(alias, cert);
            OutputStream out = new FileOutputStream(file);
            ks.store(out, passphrase);
            out.close();
            System.out.println();
            System.out.println(cert);
        }

    }

    private static final char[] HEXDIGITS = "0123456789abcdef".toCharArray();

    private static String toHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 3);
        for (int b : bytes) {
            b &= 0xff;
            sb.append(HEXDIGITS[b >> 4]);
            sb.append(HEXDIGITS[b & 15]);
            sb.append(' ');
        }
        return sb.toString();
    }

    private static class SavingTrustManager implements X509TrustManager {

        private final X509TrustManager tm;
        private X509Certificate[] chain;

        SavingTrustManager(X509TrustManager tm) {
            this.tm = tm;
        }

        public X509Certificate[] getAcceptedIssuers() {

            return new X509Certificate[0];
        }

        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            throw new UnsupportedOperationException();
        }

        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            this.chain = chain;
            tm.checkServerTrusted(chain, authType);
        }
    }

}
