package Client;

import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import javax.crypto.Cipher;

import Common.UserData;


public class P2PClient {
    private static final String SERVER_HOST = "localhost"; // Change this to the server's IP address or hostname
    private static final int SERVER_PORT = 12345;

    private static final int MESSAGE_PORT = 54325;

    public static void main(String[] args) throws InvalidKeySpecException, IOException, InterruptedException {
        try {
            KeyPair keyPair = loadOrGenerateKeys();
            String publicKeyString = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());

            // Create a separate thread to listen for messages
            Thread messageListener = new Thread(new MessageListener());
            messageListener.start();

            // Start a thread to read and send messages from the command line
            Thread messageSender = new Thread(new MessageSender());
            messageSender.start();

            Socket socket = new Socket(SERVER_HOST, SERVER_PORT);
            ObjectOutputStream outputStream = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream inputStream = new ObjectInputStream(socket.getInputStream());

            // Send user information as serialized object
            UserData userData = new UserData(publicKeyString, IpChecker.getExternalIP() + ":" + String.valueOf(MESSAGE_PORT)); // Change port as needed
            outputStream.writeObject(userData);

            System.out.println("Connected to the server.");

            // Start a thread to periodically ping the server
            ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
            scheduler.scheduleAtFixedRate(() -> sendPing(outputStream, inputStream, publicKeyString), 0, 45, TimeUnit.SECONDS);

        } catch (IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    private static KeyPair loadOrGenerateKeys() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        File publicKeyFile = new File("./publicKey.txt");
        File privateKeyFile = new File("./privateKey.txt");

        KeyPair keyPair;
        if (publicKeyFile.exists() && privateKeyFile.exists()) {
            // Keys already exist, load them from files
            PublicKey publicKey = loadPublicKey(publicKeyFile);
            PrivateKey privateKey = loadPrivateKey(privateKeyFile);
            keyPair = new KeyPair(publicKey, privateKey);
        } else {
            // Keys do not exist, generate and save them
            keyPair = generateAndSaveKeys(publicKeyFile, privateKeyFile);
        }
        return keyPair;
    }

    private static PublicKey loadPublicKey(File file) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] encodedKey = Files.readAllBytes(file.toPath());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
        return keyFactory.generatePublic(keySpec);
    }

    private static PrivateKey loadPrivateKey(File file) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] encodedKey = Files.readAllBytes(file.toPath());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);
        return keyFactory.generatePrivate(keySpec);
    }

    private static KeyPair generateAndSaveKeys(File publicKeyFile, File privateKeyFile) throws NoSuchAlgorithmException, IOException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Save the keys to files
        saveKeyToFile(publicKey, publicKeyFile);
        saveKeyToFile(privateKey, privateKeyFile);

        return keyPair;
    }

    private static void saveKeyToFile(Key key, File file) throws IOException {
        byte[] encodedKey = key.getEncoded();
        Files.write(file.toPath(), encodedKey);
    }

    private static void sendPing(ObjectOutputStream outputStream, ObjectInputStream inputStream, String publicKeyString) {
        try {
            String address;
            try {
                address = IpChecker.getExternalIP() + ":" + String.valueOf(MESSAGE_PORT);                
            } catch (Exception e) {
                System.out.println("Error getting external address");
                return;
            }
            UserData pingData = new UserData(publicKeyString, address);
            outputStream.writeObject(pingData);

            // Receive and print the list of online users
            Object response = inputStream.readObject();
            if (response instanceof java.util.List) {
                List<UserData> onlineUsersList = (List<UserData>) response;
                Map<String, UserData> registeredUsers = loadRegisteredUsersFromCSV();
                                
                for (UserData user : onlineUsersList) {
                    if (registeredUsers.containsKey(user.getPublicKey())) {
                        registeredUsers.get(user.getPublicKey()).setIpAddress(user.getIpAddress());
                    } else {
                        registeredUsers.put(user.getPublicKey(), user);
                    }
                }

                saveRegisteredUsersToCSV(registeredUsers);
            }
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    private static Map<String, UserData> loadRegisteredUsersFromCSV() {
        Map<String, UserData> onlineUsers = new HashMap<>();
        String csvFile = "registered_users.csv"; // Replace with the actual CSV file path
        try {
            BufferedReader reader = new BufferedReader(new FileReader(csvFile));
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(",");
                if (parts.length >= 1) {
                    String publicKey = parts[0];
                    String ipAddress = parts[1];
                    //String username = parts[2];
                    UserData ud = new UserData(publicKey, ipAddress);
                    onlineUsers.put(publicKey, ud);
                }
            }
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return onlineUsers;
    }

    private static void saveRegisteredUsersToCSV(Map<String, UserData> onlineUsers) {
        String csvFile = "registered_users.csv"; // Replace with the actual CSV file path

        try { 
            BufferedWriter writer = new BufferedWriter(new FileWriter(csvFile));
            for (UserData user : onlineUsers.values()) {
                String line = String.join(",", user.getPublicKey(), user.getIpAddress());
                writer.write(line);
                writer.newLine();
            }
            writer.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static class MessageListener implements Runnable {
        @Override
        public void run() {
            try (ServerSocket messageServerSocket = new ServerSocket(MESSAGE_PORT)) {
                System.out.println("Message listener started on port " + String.valueOf(MESSAGE_PORT));

                while (true) {
                    Socket messageSocket = messageServerSocket.accept();
                    new Thread(new MessageHandler(messageSocket)).start();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private static class MessageHandler implements Runnable {
        private Socket messageSocket;

        public MessageHandler(Socket messageSocket) {
            this.messageSocket = messageSocket;
        }

        @Override
        public void run() {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(messageSocket.getInputStream()))) {
                String message;                
                String decMessage;
                while ((message = reader.readLine()) != null) {
                    String[] parts = message.split("###");
                    if (parts.length != 3) {
                        System.out.println("received wrong formatted message");
                        continue;
                    }
                    PublicKey pbKey;
                    try {
                        byte[] encodedKey = Base64.getDecoder().decode(parts[2]);
                        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
                        pbKey = keyFactory.generatePublic(keySpec);
                        if (!verifySignature(parts[0], parts[1], pbKey)){
                            System.out.println("invalid signature");
                            continue;
                        }
                    } catch (Exception e) {
                        System.out.println("error check signature");
                    }
                    try {
                        decMessage = decryptMessage(parts[0]);
                    } catch (Exception e) {
                        System.out.println("error decrypting message");
                        continue;
                    }
                    System.out.println("Received message: " + message);
                    System.out.println("The message is: " + decMessage);
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        public static String decryptMessage(String encryptedMessage) throws Exception {
            File privateKeyFile = new File("./privateKey.txt");
            byte[] privateKeyBytes = loadPrivateKey(privateKeyFile).getEncoded();
    
            // Create a PrivateKey object from the decoded bytes
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
    
            // Initialize the Cipher for decryption with PKCS#1 v1.5 padding
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
    
            // Decode the Base64 encoded encrypted message
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMessage);
    
            // Decrypt the message
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
    
            // Convert the decrypted bytes to a string and return it
            return new String(decryptedBytes);
        }

        public static boolean verifySignature(String message, String digitalSignature, PublicKey publicKey) throws Exception {
            // Create a Signature object and initialize it with the sender's public key
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);
    
            // Update the Signature object with the received message
            signature.update(message.getBytes());
    
            // Decode the received digital signature from Base64
            byte[] signatureBytes = Base64.getDecoder().decode(digitalSignature);
    
            // Verify the digital signature
            return signature.verify(signatureBytes);
        }
    }

    private static class MessageSender implements Runnable {
        
        @Override
        public void run() {
            Scanner scanner = new Scanner(System.in);
            while (true) {
                // Read input from the command line
                System.out.print("Enter recipient's public key and message (e.g., publicKey message): ");
                String input = scanner.nextLine();
                String[] parts = input.split(" ");
                
                if (parts.length != 2) {
                    System.out.println("Invalid input. Usage: publicKey message");
                    continue;
                }
                
                String recipientPublicKey = parts[0];
                String message = parts[1];
                
                // Check if the recipient is a contact
                Map<String, UserData> registeredUsers = loadRegisteredUsersFromCSV();
                if (registeredUsers.containsKey(recipientPublicKey)) {
                    UserData recipient = registeredUsers.get(recipientPublicKey);
                    sendMessageToRecipient(recipient, message);
                } else {
                    System.out.println("Recipient is not online.");
                }
            }
        }

        private void sendMessageToRecipient(UserData recipient, String message) {
            File publicKeyFile = new File("./publicKey.txt");
            String senderPublicKey;
            try {
                senderPublicKey = Base64.getEncoder().encodeToString(loadPublicKey(publicKeyFile).getEncoded());            
            } catch (Exception e) {
                System.out.println("error loading public key");
                return;
            }

            String address = recipient.getIpAddress();
            String[] comm = address.split(":");
            String encMessage;
            try {
                encMessage = encryptMessage(message, recipient.getPublicKey());                
            } catch (Exception e) {
                System.out.println("Failed to encyrpt message");
                return;
            }
            String signedMessage;
            try {
                signedMessage = signMessage(encMessage);
            } catch (Exception e) {
                System.out.println("Failed to sign message");
                return;
            }
            try (Socket messageSocket = new Socket(comm[0], Integer.parseInt(comm[1]));
                 PrintWriter writer = new PrintWriter(messageSocket.getOutputStream(), true)) {
                // Send the message to the recipient
                writer.println(encMessage + "###" + signedMessage + "###" + senderPublicKey);
                System.out.println("Message sent to recipient.");
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        public static String encryptMessage(String message, String publicKeyString) throws Exception {
            // Decode the Base64 encoded public key
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString);

            // Create a PublicKey object from the decoded bytes
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            // Initialize the Cipher for encryption with PKCS#1 v1.5 padding
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            // Encrypt the message
            byte[] encryptedBytes = cipher.doFinal(message.getBytes());

            // Encode the encrypted bytes as Base64 and return the result as a string
            return Base64.getEncoder().encodeToString(encryptedBytes);
        }

        public static String signMessage(String message) throws Exception {
            File privateKeyFile = new File("./privateKey.txt");
            PrivateKey privateKey = loadPrivateKey(privateKeyFile);
    
            // Create a Signature object and initialize it with the private key
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            // Update the Signature object with the data to be signed
            signature.update(message.getBytes());
            // Generate the digital signature
            byte[] digitalSignature = signature.sign();
            // Encode the digital signature as Base64 and return it
            return Base64.getEncoder().encodeToString(digitalSignature);
        }

        
    }
}
