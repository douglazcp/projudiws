import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.net.ssl.X509TrustManager;

public class TrustManagerImpl implements X509TrustManager {

    private final CertPathValidator CERTIFICATE_VALIDATOR;
    private final X509Certificate[] CERTIFICADOS_CONFIAVEIS;
    private final CertificateFactory CERTIFICATE_FACTORY;

    public TrustManagerImpl(KeyStore truststore) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        CERTIFICATE_VALIDATOR = CertPathValidator.getInstance("PKIX");
        CERTIFICATE_FACTORY = CertificateFactory.getInstance("X.509");
        List<X509Certificate> confiaveis = new ArrayList<X509Certificate>();
        Enumeration<String> enumeration = truststore.aliases();
        while (enumeration.hasMoreElements()) {
            String alias = enumeration.nextElement();
            if (truststore.isCertificateEntry(alias)) {
                X509Certificate certificado = (X509Certificate) truststore.getCertificate(alias);
                confiaveis.add(certificado);
            }
        }
        System.out.println(confiaveis.size() + " certificados confiáveis carregados.");
        CERTIFICADOS_CONFIAVEIS = confiaveis.toArray(new X509Certificate[confiaveis.size()]);
    }

    public X509Certificate[] getAcceptedIssuers() {
        return CERTIFICADOS_CONFIAVEIS;
    }

    public void checkClientTrusted(X509Certificate[] certs, String authType) throws CertificateException {
        System.out.println("Validando certificado do usuário...");
        verifica(certs);
    }

    public void checkServerTrusted(X509Certificate[] certs, String authType) throws CertificateException {
        System.out.println("Validando certificado do servidor...");
        verifica(certs);
    }

    private void verifica(X509Certificate[] cadeia) throws CertificateException {

        System.out.println("Validando certificado " + cadeia[0].getSubjectDN().getName() + " ...");
        List<X509Certificate> emissores = new ArrayList<X509Certificate>();
        int qtd_emissores = cadeia.length - 1;
        for (int i = qtd_emissores; i > 0; i--)
            for (X509Certificate c : CERTIFICADOS_CONFIAVEIS)
                if (Arrays.equals(cadeia[i].getSubjectX500Principal().getEncoded(), c.getSubjectX500Principal().getEncoded())) {
                    emissores.add(c);
                    break;
                }
        if (emissores.size() != qtd_emissores)
            throw new CertificateException("Cadeia de certificados não confiável.");
        Set<TrustAnchor> ancoras = new HashSet<TrustAnchor>();
        for (X509Certificate c : emissores) {
            ancoras.add(new TrustAnchor(c, null));
        }
        try {
            PKIXParameters parametros = new PKIXParameters(ancoras);
            parametros.setRevocationEnabled(false);
            List<X509Certificate> certificado = new ArrayList<X509Certificate>();
            certificado.add(cadeia[0]);
            CERTIFICATE_VALIDATOR.validate(CERTIFICATE_FACTORY.generateCertPath(certificado), parametros);
            for (X509Certificate c : cadeia) {
                c.checkValidity();
            }
        } catch (CertificateExpiredException e) {
            throw new CertificateException("Período de validade expirou");
        } catch (CertificateNotYetValidException e) {
            throw new CertificateException("Período de validade ainda não começou");
        } catch (InvalidAlgorithmParameterException e) {
            throw new CertificateException("Erro na integridade do certificado", e);
        } catch (CertPathValidatorException e) {
            throw new CertificateException("Erro na integridade do certificado", e);
        }
        System.out.println("Certificado válido.");
    }
}