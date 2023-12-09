package Server;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import Common.UserData;

public class P2PServer {
    private static final int PORT = 12345;
    private static final Map<String, UserData> onlineUsers = new HashMap<>();
    private static final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("Server started on port " + PORT);

            // Start a thread to periodically check for inactive users
            scheduler.scheduleAtFixedRate(() -> checkInactiveUsers(), 1, 10, TimeUnit.SECONDS);

            while (true) {
                Socket clientSocket = serverSocket.accept();
                new Thread(new ClientHandler(clientSocket)).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void checkInactiveUsers() {
        long currentTime = System.currentTimeMillis();
        List<String> usersToRemove = new ArrayList<>();

        for (Map.Entry<String, UserData> entry : onlineUsers.entrySet()) {
            long lastPingTime = entry.getValue().getLastPingTime();
            if (currentTime - lastPingTime > TimeUnit.SECONDS.toMillis(10)) {
                usersToRemove.add(entry.getKey());
            }
        }

        for (String publicKey : usersToRemove) {
            onlineUsers.remove(publicKey);
            System.out.println("User with public key '" + publicKey + "' has been removed due to inactivity.");
        }
    }

    static class ClientHandler implements Runnable {
        private Socket socket;

        public ClientHandler(Socket socket) {
            this.socket = socket;
        }

        @Override
        public void run() {
            try (ObjectInputStream inputStream = new ObjectInputStream(socket.getInputStream());
                 ObjectOutputStream outputStream = new ObjectOutputStream(socket.getOutputStream())) {

                // Receive user information as serialized object
                UserData userData = (UserData) inputStream.readObject();
                onlineUsers.put(userData.getPublicKey(), userData);

                System.out.println("User with public key '" + userData.getPublicKey() + "' is online.");

                while (true) {
                    // Receive ping as serialized object
                    UserData pingData = (UserData) inputStream.readObject();
                    onlineUsers.get(pingData.getPublicKey()).setLastPingTime(System.currentTimeMillis());
                    List<UserData> onlineUserList = new ArrayList<>(onlineUsers.values());
                    outputStream.writeObject(onlineUserList);
                }
            } catch (IOException | ClassNotFoundException e) {
                e.printStackTrace();
            }
        }
    }
}
