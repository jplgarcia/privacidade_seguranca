package Client;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;

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

        try {
            InetAddress localHost = InetAddress.getLocalHost();
            return localHost.getHostAddress();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        return "";
    }
}
