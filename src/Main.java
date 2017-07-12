import java.io.IOException;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.cookie.CookiePolicy;
import org.apache.commons.httpclient.methods.GetMethod;

public class Main {

    public static void main(String args[]) throws Exception {
        System.out.println("##################################################");
        System.out.println("SO = " + System.getProperty("os.name") + " (" + System.getProperty("os.arch") + ")");
        System.out.println("JAVA = " + System.getProperty("java.version"));
        System.out.println("##################################################");
        System.out.println("Configurando conexão HTTPS...");
        SocketFactoryHttps.iniciar();
        System.out.println("##################################################");
        String resposta = logarProjudi(new HttpClient(), "1", "testeana", "123456");
        System.out.println("##################################################");
        System.out.println("Resposta do serviço Web:");
        System.out.println(resposta);
    }

    public static String logarProjudi(HttpClient httpClient, String operacao, String login, String senha) throws Exception {
        GetMethod httpMethod = null;
        try {
            String url = "https://projudi.tjgo.jus.br/servico01?a=" + operacao + "&b=" + login + "&c=" + senha;
            httpMethod = new GetMethod(url);
            httpMethod.getParams().setCookiePolicy(CookiePolicy.RFC_2109);
            httpMethod.addRequestHeader("Accept", "application/xml");
            httpClient.executeMethod(httpMethod);
            if (httpMethod.getStatusCode() == HttpStatus.SC_NOT_FOUND || httpMethod.getStatusCode() == HttpStatus.SC_SERVICE_UNAVAILABLE) {
                throw new IOException("Serviço indisponível no momento.");
            }
            return httpMethod.getResponseBodyAsString();
        } catch (IOException e) {
            throw new IOException("Não foi possível conectar ao Projudi.", e);
        } catch (Exception e) {
            throw new IOException("Erro ao Logar no Projudi.", e);
        } finally {
            if (httpMethod != null) {
                httpMethod.releaseConnection();
            }
        }
    }
}
