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
		frame = new JFrame();
		frame.setSize(600, 600);
		frame.setLayout(new BorderLayout());
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.setTitle("White Shuttle");
	}

	public static void registerNewUser() {
		JPanel usernamePanel = new JPanel();
		usernamePanel.setLayout(new FlowLayout());
		usernameField = new JTextField();
		usernameField.setPreferredSize(new Dimension(200, 30));
		usernamePanel.add(usernameField);
		JButton b = new JButton("Select Username");
		b.setPreferredSize(new Dimension(150, 30));
		b.addActionListener(new ActionListener() {

			public void actionPerformed(ActionEvent e) {
				username = usernameField.getText();
				System.out.println("Username: " + username);
				client = new P2PClient(username);
				frame.remove(usernamePanel);
				frame.add(chatPanel, BorderLayout.CENTER);
				chatPanel.setVisible(true);
			
				frame.revalidate();
				frame.repaint();
			}
		});

		usernamePanel.add(b);
		frame.add(usernamePanel, BorderLayout.NORTH);
	}

	public static void panelAfterRegistration(){
		// Chat panel (initially not visible)
		chatPanel = new JPanel();
		chatPanel.setLayout(new BorderLayout());
		chatPanel.setVisible(false);
	}

	public static void loadConversations() {
		
		Map<String, UserData> users = P2PClient.loadRegisteredUsersFromCSV(); //put all users into hashMap

		ArrayList<String> usernames = new ArrayList<String>();
		for (Map.Entry<String, UserData> entry : users.entrySet()) {
			UserData userData = entry.getValue();
			String username = userData.getUsername();
			usernames.add(username);
		}

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
		Map<String, UserData> users = P2PClient.loadRegisteredUsersFromCSV();
		
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
			Map<String, UserData> users = P2PClient.loadRegisteredUsersFromCSV(); //put all users into hashMap
			UserData selectedUserData = null;

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
		});

		inputPanel.add(sendButton, BorderLayout.EAST);
		chatPanel.add(inputPanel, BorderLayout.SOUTH);
		frame.setVisible(true);

	}

	private static class MessageListener implements Runnable {
        @Override
        public void run() {
            try (ServerSocket messageServerSocket = new ServerSocket(P2PClient.MESSAGE_PORT)) {
                System.out.println("Message listener started on port " + String.valueOf(P2PClient.MESSAGE_PORT));

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

					//TODO:
					/// Caso grupo
					/*
					 * Criar opcao na interface pra criar grupo e selecionar usuario q estao online
					 * 
					 * na hora de receber, recebe tb a chave publica de todos os membro no grupo
					 * num csv de grupos cria um arquivo dizendo quais chaves publicas tao em cada grupo
					 * 
					 * na hora de enviar mensagem (isso acontece no p2p client) - botaria um 4 campo separado por ### com onome do grupo
					 * na hora de enviar mensagem tem que enviar separadamente pra todos os membros (são varios send message) e todos no final tem o ###nome_do_grupo
					 * tambem adicionaria no final um ###usuario1,usuario2,usuario3,usuario4
					 * sendo usuario1= chave publica do usuario 1
					 * isso é usado para caso voce nao esteja no grupo poder regidtrar o grupo
					 * 
					 * se nao tiver ria
					 * 
					 * ou seja:
					 * 
					 * recebimento de mensagem:
					 * verifica se o comprimento do split (lnha 273) é == 5 ou 3
					 * se for 5 é mensagem em grupo
					 * se for 3 é mensagem normal
					 * 
					 * mensagem normal ta funcionando, pra fazer em gurpo funcionar é algo do tipo:
					 * 
					 * verifica se ja faz parte do grupo com esse nome
					 * se fizer decripta a mensagem e salva no historico e escreve no chat
					 * se nao fizer, tem que criar a entrada daquele grupo na lista
					 * 
					 * 
					 * a funcao Update list model tem que escrever e verificar e salvar nao apenas os nomes de usuario, mas tambem os de grupos
					 * 
					 * 
					 * 
					 */
					
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

					Map<String, UserData> users = P2PClient.loadRegisteredUsersFromCSV(); //put all users into hashMap
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
						//String usermessage = user + ": " + decMessage;
						chatArea.append("\n" + decMessage);
					}
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        public static String decryptMessage(String encryptedMessage) throws Exception {
            File privateKeyFile = new File("./privateKey.txt");
            byte[] privateKeyBytes = P2PClient.loadPrivateKey(privateKeyFile).getEncoded();
    
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
