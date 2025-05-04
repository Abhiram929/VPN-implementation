import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Base64;
import java.util.Scanner;

public class JavaVPN {
    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static SecretKey secretKey;
    private static IvParameterSpec ivParameterSpec;
    private static boolean isServer;

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Java VPN Implementation");
        System.out.println("1. Start VPN Server");
        System.out.println("2. Connect to VPN Server");
        System.out.print("Choose option (1/2): ");
        int choice = scanner.nextInt();
        scanner.nextLine();
        
        try {
            generateKey();
            if (choice == 1) {
                isServer = true;
                startServer();
            } else if (choice == 2) {
                isServer = false;
                startClient();
            } else {
                System.out.println("Invalid choice");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void startServer() throws Exception {
        System.out.print("Enter server port (default 8888): ");
        String portInput = new Scanner(System.in).nextLine();
        int port = portInput.isEmpty() ? 8888 : Integer.parseInt(portInput);

        try (ServerSocket serverSocket = new ServerSocket(port);
             Socket socket = serverSocket.accept();
             ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {
                
            oos.writeObject(secretKey);
            oos.writeObject(ivParameterSpec);
            oos.flush();
            System.out.println("Client connected. Secure channel established.");
            System.out.println("Type messages below (type 'exit' to quit):");
            new Thread(new MessageReceiver(ois)).start();
            new Thread(new MessageSender(oos)).start();
            while (true) Thread.sleep(1000);
        }
    }

    private static void startClient() throws Exception {
        System.out.print("Enter server IP (default localhost): ");
        String ip = new Scanner(System.in).nextLine();
        if (ip.isEmpty()) ip = "localhost";
        System.out.print("Enter server port (default 8888): ");
        String portInput = new Scanner(System.in).nextLine();
        int port = portInput.isEmpty() ? 8888 : Integer.parseInt(portInput);

        try (Socket socket = new Socket(ip, port);
             ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {
            
            secretKey = (SecretKey) ois.readObject();
            ivParameterSpec = (IvParameterSpec) ois.readObject();
            System.out.println("Connected to VPN server. Secure channel established.");
            System.out.println("Type messages below (type 'exit' to quit):");
            new Thread(new MessageReceiver(ois)).start();
            new Thread(new MessageSender(oos)).start();
            while (true) Thread.sleep(1000);
        }
    }

    private static void generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        secretKey = keyGenerator.generateKey();
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        ivParameterSpec = new IvParameterSpec(iv);
    }

    private static String encrypt(String input) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        return Base64.getEncoder().encodeToString(cipher.doFinal(input.getBytes()));
    }

    private static String decrypt(String cipherText) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        return new String(cipher.doFinal(Base64.getDecoder().decode(cipherText)));
    }

    static class MessageReceiver implements Runnable {
        private final ObjectInputStream ois;
        public MessageReceiver(ObjectInputStream ois) { this.ois = ois; }
        public void run() {
            try {
                while (true) {
                    String decryptedMessage = decrypt((String) ois.readObject());
                    System.out.println((isServer ? "Client" : "Server") + ": " + decryptedMessage);
                }
            } catch (Exception e) {
                System.out.println((isServer ? "Client" : "Server") + " disconnected");
                System.exit(0);
            }
        }
    }

    static class MessageSender implements Runnable {
        private final ObjectOutputStream oos;
        private final Scanner scanner = new Scanner(System.in);
        public MessageSender(ObjectOutputStream oos) { this.oos = oos; }
        public void run() {
            try {
                while (true) {
                    String message = scanner.nextLine();
                    if ("exit".equalsIgnoreCase(message)) System.exit(0);
                    oos.writeObject(encrypt(message));
                    oos.flush();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}