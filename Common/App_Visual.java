package Common;

import Client.P2PClient;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ArrayList;
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
			try (PrintWriter out = new PrintWriter(new FileWriter("chat.txt", true))) {
				out.println(message);
			} catch (IOException ex) {
				ex.printStackTrace();
			}
		});
		inputPanel.add(sendButton, BorderLayout.EAST);
		chatPanel.add(inputPanel, BorderLayout.SOUTH);
		frame.setVisible(true);//making th

		}
	}

