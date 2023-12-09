package Common;

import Client.P2PClient;

import javax.crypto.Cipher;
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class App_Visual {
	static JFrame frame;
	static JPanel chatPanel;
	static JList<String> userList = null;
	static JTextArea chatArea;
	static JTextField chatField;
	static JTextField usernameField;
	static String username;

	static P2PClient client;
	static Map<String, String> chatHistories = new HashMap<>();

	static DefaultListModel<String> listModel = new DefaultListModel<>();

	public static void main(String[] args) {

		frame();
		registerNewUser();
		panelAfterRegistration();
		loadConversations();
		loadChatArea();

		ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
		scheduler.scheduleAtFixedRate(() -> redraw(), 0, 3, TimeUnit.SECONDS);

		// Create a separate thread to listen for messages
        Thread messageListener = new Thread(new MessageListener());
        messageListener.start();
	}

	public static void redraw() {
		updateListModel();
	}

	public static void frame() {
		//request username
		frame = new JFrame();//creating instance of JFrame
		frame.setSize(600, 600);//400 width and 500 height
		frame.setLayout(new BorderLayout());//using no layout managers
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		//usernameField = new JTextField();
		//usernameField.setPreferredSize(new Dimension(200, 30));
		// Initialize UserData
		// Username selecti
		 // Set preferred size

	}

	public static void registerNewUser() {
		//if (Objects.equals(username, "unknown")) {
			JPanel usernamePanel = new JPanel();
			usernamePanel.setLayout(new FlowLayout());
			usernameField = new JTextField();
			usernameField.setPreferredSize(new Dimension(200, 30)); // Set preferred size
			usernamePanel.add(usernameField);
			JButton b = new JButton("Select Username");
			b.setPreferredSize(new Dimension(150, 30));
			b.addActionListener(new ActionListener() {

				public void actionPerformed(ActionEvent e) {
					username = usernameField.getText();
					usernamePanel.add(usernameField);
					System.out.println("Username: " + username);// Set username in UserData
					client = new P2PClient(username);
					frame.remove(usernamePanel);
					frame.add(chatPanel, BorderLayout.CENTER);
					chatPanel.setVisible(true); // Make chatPanel visible
					// try {
					// 	client.forcePing();						
					// } catch (Exception er) {
					// 	System.out.println("failed to ping after user registration");
					// 	return;
					// }
					
					frame.revalidate();
					frame.repaint();
				}
			});
			usernamePanel.add(b);
			frame.add(usernamePanel, BorderLayout.NORTH);
	}
	//}
	public static void panelAfterRegistration(){
		// Chat panel (initially not visible)
		chatPanel = new JPanel();
		chatPanel.setLayout(new BorderLayout());
		chatPanel.setVisible(false);
	}
		// User list
	public static void loadConversations() {
		
		Map<String, UserData> users = client.loadRegisteredUsersFromCSV(); //put all users into hashMap

		ArrayList<String> usernames = new ArrayList<String>();
		for (Map.Entry<String, UserData> entry : users.entrySet()) {
			UserData userData = entry.getValue();
			String ipAddress = userData.getIpAddress();
			String publicKey = userData.getPublicKey();
			String username = userData.getUsername();
			usernames.add(username);
		}

		// listModel.clear();
		for (String item : usernames) {
			if (!listModel.contains(item))
				listModel.addElement(item);
		}
		
		userList = new JList<>(listModel);
		userList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		userList.addListSelectionListener(e -> {
			if (!e.getValueIsAdjusting()) {
			String selectedUser = userList.getSelectedValue();
				// Load chat for selected user
			chatArea.setText(chatHistories.getOrDefault(selectedUser, ""));
			}
		});
		chatPanel.add(new JScrollPane(userList), BorderLayout.WEST);

		
	}


	public static void updateListModel() {
		Map<String, UserData> users = client.loadRegisteredUsersFromCSV();
		
		int listSizeIterate = listModel.getSize();
		ArrayList<Integer> removables = new ArrayList<Integer>();
		for (int i = 0; i < listSizeIterate; i++) {
			String element = listModel.elementAt(i);
			boolean exists = false;
			for (UserData user : users.values()) {
				if (user.getUsername().equals(element)){
					exists = true;
				}
			}
			if (!exists) {
				removables.add(i);
			}
		}

		var removablesReversed = removables.reversed();
		for (int i = 0; i < removablesReversed.size(); i++) {
			listModel.remove(removablesReversed.get(i));
		}

		for(UserData user : users.values()) {
			int listSize = listModel.getSize();
			boolean exists = false;
			for (int i = 0; i < listSize; i++) {
				if (listModel.elementAt(i).equals(user.getUsername())) {
					exists = true;
				}
			}
			if (!exists){
				listModel.addElement(user.getUsername());
			}
		}
	}

	

	public static void loadChatArea() {	
		// Chat area
		chatArea = new JTextArea();
		chatArea.setEditable(false);
		chatPanel.add(new JScrollPane(chatArea), BorderLayout.CENTER);

		// Chat input field
		JPanel inputPanel = new JPanel();
		inputPanel.setLayout(new BorderLayout());

		chatField = new JTextField();
		inputPanel.add(chatField, BorderLayout.CENTER);

		JButton sendButton = new JButton("Send");
		sendButton.addActionListener(e -> {
			// Send message
			String message = username + ": " + chatField.getText();
			chatArea.append("\n" + message);
			chatField.setText("");

			// Save message to chat history
			String selectedUser = userList.getSelectedValue();
			Map<String, UserData> users = client.loadRegisteredUsersFromCSV(); //put all users into hashMap
			UserData selectedUserData = null;
			ArrayList<String> usernames = new ArrayList<String>();
			for (Map.Entry<String, UserData> entry : users.entrySet()) {
				if (entry.getValue().getUsername().equals(selectedUser)) {
					selectedUserData = entry.getValue();
				}
			}
			if (selectedUserData == null) {
				return;
			}

			client.sendMessageToRecipient(selectedUserData, message);

			String history = chatHistories.getOrDefault(selectedUser, "");
			history += "\n" + message;
			chatHistories.put(selectedUser, history);

			// Save message to file
			// try (PrintWriter out = new PrintWriter(new FileWriter("chat.txt", true))) {
			// 	out.println(message);
			// } catch (IOException ex) {
			// 	ex.printStackTrace();
			// }
		});
		inputPanel.add(sendButton, BorderLayout.EAST);
		chatPanel.add(inputPanel, BorderLayout.SOUTH);
		frame.setVisible(true);//making th

	}

	private static class MessageListener implements Runnable {
        @Override
        public void run() {
            try (ServerSocket messageServerSocket = new ServerSocket(client.MESSAGE_PORT)) {
                System.out.println("Message listener started on port " + String.valueOf(client.MESSAGE_PORT));

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

					Map<String, UserData> users = client.loadRegisteredUsersFromCSV(); //put all users into hashMap
					String user = "";
					for (Map.Entry<String, UserData> entry : users.entrySet()) {
						if (entry.getKey().equals(parts[2])) { // get username from public keys
							user = entry.getValue().getUsername();
						}
					}

					String history = chatHistories.getOrDefault(user, "");
					history += "\n" + decMessage;
					chatHistories.put(user, history);

					if (user.equals(userList.getSelectedValue())) {
						String usermessage = user + ": " + decMessage;
						chatArea.append("\n" + usermessage);
					}

					// Save message to file
					// try (PrintWriter out = new PrintWriter(new FileWriter("chat.txt", true))) {
					// 	out.println(message);
					// } catch (IOException ex) {
					// 	ex.printStackTrace();
					// }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        public static String decryptMessage(String encryptedMessage) throws Exception {
            File privateKeyFile = new File("./privateKey.txt");
            byte[] privateKeyBytes = client.loadPrivateKey(privateKeyFile).getEncoded();
    
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
}
