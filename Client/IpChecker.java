package Client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.URI;
import java.net.URL;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Paths;

public class IpChecker {

    public static void main(String[] args) {
        try {
            String externalIP = getExternalIP();
            System.out.println("Your external IP address is: " + externalIP);
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }

    public static String getExternalIP() throws IOException, InterruptedException {
        // // Define the URL as a URI
        // URI uri = URI.create("http://checkip.amazonaws.com");

        // // Create an HttpClient
        // HttpClient httpClient = HttpClient.newHttpClient();

        // // Create an HttpRequest
        // HttpRequest request = HttpRequest.newBuilder(uri).build();

        // // Send the request and receive a response
        // HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        // // Extract and return the external IP address from the response
        // return "172.22.64.1";//response.body().trim();


        try {
            InetAddress localHost = InetAddress.getLocalHost();
            return localHost.getHostAddress();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        return "";

    }
}
