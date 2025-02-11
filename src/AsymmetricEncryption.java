import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
//import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;

public class AsymmetricEncryption {
    public static void main(String[] args) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            String choice;

            do {
                System.out.println("Please choose an option: [encrypt, decrypt, exit]");
                choice = reader.readLine().trim();

                if (choice.equalsIgnoreCase("encrypt")) {
                    System.out.println("Enter the file path to encrypt:");
                    String filePath = reader.readLine().trim();

                    byte[] encryptedData = encrypt(filePath, keyPair.getPublic());
                    Files.write(Paths.get("encrypted_file"), encryptedData);
                    System.out.println("Encrypted file created as 'encrypted_file'.");

                    byte[] privateKeyBytes = keyPair.getPrivate().getEncoded();
                    Files.write(Paths.get("private_key"), privateKeyBytes);
                    System.out.println("Decryption key created as 'private_key'.");
                } else if (choice.equalsIgnoreCase("decrypt")) {
                    System.out.println("Enter the encrypted file path:");
                    String encryptedFilePath = reader.readLine().trim();

                    System.out.println("Enter the decryption key file path:");
                    String decryptionKeyFilePath = reader.readLine().trim();

                    byte[] decryptedData = decrypt(encryptedFilePath, decryptionKeyFilePath);
                    Files.write(Paths.get("decrypted_file"), decryptedData);
                    System.out.println("Decrypted file created as 'decrypted_file'.");
                }
            } while (!choice.equalsIgnoreCase("exit"));

            System.out.println("Exiting...");
            reader.close();
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static byte[] encrypt(String filePath, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] fileBytes = Files.readAllBytes(Paths.get(filePath));
        return cipher.doFinal(fileBytes);
    }

    private static byte[] decrypt(String encryptedFilePath, String privateKeyFilePath) throws Exception {
        byte[] privateKeyBytes = Files.readAllBytes(Paths.get(privateKeyFilePath));
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] encryptedData = Files.readAllBytes(Paths.get(encryptedFilePath));
        return cipher.doFinal(encryptedData);
    }
}