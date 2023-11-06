package Common;

import java.io.Serializable;

public class UserData implements Serializable {
    private String publicKey;
    private String ipAddress;
    private int port;
    private long lastPingTime;

    public UserData(String publicKey, String ipAddress) {
        this.publicKey = publicKey;
        this.ipAddress = ipAddress;
        this.lastPingTime = System.currentTimeMillis();
    }

    public String getPublicKey() {
        return publicKey;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ip) {
        this.ipAddress = ip;
    }

    public long getLastPingTime() {
        return lastPingTime;
    }

    public void setLastPingTime(long lastPingTime) {
        this.lastPingTime = lastPingTime;
    }
}