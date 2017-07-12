import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.UnknownHostException;
import java.security.KeyStore;
import javax.net.SocketFactory;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import org.apache.commons.httpclient.params.HttpConnectionParams;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;

public class SocketFactoryHttps implements ProtocolSocketFactory {

    private SSLContext ssl = null;
    private static SocketFactoryHttps instancia;

    public static void iniciar() throws Exception {
        if (instancia == null) {
            KeyStore trustore = KeyStore.getInstance(KeyStore.getDefaultType());
            FileInputStream fis = new FileInputStream("cacerts.jks");
            trustore.load(fis, "12345678".toCharArray());
            fis.close();
            instancia = new SocketFactoryHttps(trustore);
            Protocol protocol = new Protocol("https", instancia, 443);
            Protocol.registerProtocol("https", protocol);
        }
    }

    private SocketFactoryHttps(KeyStore truststore) throws Exception {

        TrustManager[] trustManagers = new TrustManager[] { new TrustManagerImpl(truststore) };
        SSLContext sslContext = SSLContext.getInstance("SSL");
        sslContext.init(null, trustManagers, null);
        ssl = sslContext;
        HttpsURLConnection.setDefaultSSLSocketFactory(ssl.getSocketFactory());
        HostnameVerifier hv = new HostnameVerifier() {

            @Override
            public boolean verify(String hostname, SSLSession arg1) {
                return true;
            }
        };
        HttpsURLConnection.setDefaultHostnameVerifier(hv);
        HttpsURLConnection.setFollowRedirects(true);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localAddress, int localPort, HttpConnectionParams params) throws IOException {
        if (params == null) {
            throw new IllegalArgumentException("Parameters may not be null");
        }
        System.out.println("Criando socket HTTPS...");
        int timeout = params.getConnectionTimeout();
        SocketFactory socketfactory = ssl.getSocketFactory();
        Socket socket;
        if (timeout == 0) {
            socket = socketfactory.createSocket(host, port, localAddress, localPort);
        }
        else {
            socket = socketfactory.createSocket();
            SocketAddress localaddr = new InetSocketAddress(localAddress, localPort);
            SocketAddress remoteaddr = new InetSocketAddress(host, port);
            socket.bind(localaddr);
            socket.connect(remoteaddr, timeout);
        }
        SSLSocket sslSocket = (SSLSocket) socket;
        System.out.println("CipherSuites Habilitadas: ");
        for (String s : sslSocket.getEnabledCipherSuites())
            System.out.println("\t" + s);
        System.out.println("CipherSuite Utilizada: " + sslSocket.getSession().getCipherSuite());
        System.out.println("Protocolo Utilizado: " + sslSocket.getSession().getProtocol());
        try {
            System.out.println("Certificado do Servidor: " + sslSocket.getSession().getPeerPrincipal().getName());
        } catch (SSLPeerUnverifiedException e) {
            System.out.println("Certificado do Servidor: FALHA NO HANDSHAKE");
        }
        System.out.println("Socket HTTPS criado com sucesso.");
        return socket;
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress clientHost, int clientPort) throws IOException, UnknownHostException {
        System.out.println("Criando socket HTTPS...");
        Socket socket = ssl.getSocketFactory().createSocket(host, port, clientHost, clientPort);
        System.out.println("Socket HTTPS criado com sucesso.");
        return socket;
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
        System.out.println("Criando socket HTTPS...");
        Socket socket = ssl.getSocketFactory().createSocket(host, port);
        System.out.println("Socket HTTPS criado com sucesso.");
        return socket;
    }

}