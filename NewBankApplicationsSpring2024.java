import java.util.Scanner;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Base64;
import java.util.Date;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Arrays;
import java.io.FileOutputStream;
import java.io.OutputStream;

public class NewBankApplicationsSpring2024 {
    private int balance;
    private int previousTransaction;
    private byte[] encryptedName;
    private byte[] encryptedID;
    private SecretKey secretKey;
    private String customerName;
    private String customerID;

    public NewBankApplicationsSpring2024(String customerName, String customerID) {
        this.customerName = customerName;
        this.customerID = customerID;
        try {
            // Generate a random initialization vector (IV)
            byte[] iv = generateIV();

            // Generate a secret key (16 bytes)
            String secretKeyString = "ThisIsASecretKey12"; // 16 bytes
            byte[] keyBytes = Arrays.copyOf(secretKeyString.getBytes(), 16);
            secretKey = new SecretKeySpec(keyBytes, "AES");

            // Encrypt customer name and ID
            encryptedName = encrypt(customerName, iv);
            encryptedID = encrypt(customerID, iv);
            
            // Write encoded secret key and encrypted data to files
            String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
            writeToFile("secret_key.txt", encodedKey.getBytes());
            String encodedEncryptedName = Base64.getEncoder().encodeToString(encryptedName);
            writeToFile("encrypted_name.txt", encodedEncryptedName.getBytes());
            String encodedEncryptedID = Base64.getEncoder().encodeToString(encryptedID);
            writeToFile("encrypted_id.txt", encodedEncryptedID.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private byte[] generateIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    public void deposit(int amount) throws DailyLimitException {
        if (amount <= 0) {
            System.out.println("Invalid deposit amount. Please reenter a value.");
            return;
        }
        try {
            if (amount > 500) {
                throw new DailyLimitException("Daily deposit limit exceeded. Maximum deposit amount is 500.");
            }
            balance += amount;
            previousTransaction = amount;
            auditTransaction("Deposit", amount);
        } catch (DailyLimitException e) {
            System.out.println("Error: " + e.getMessage());
        }
    }

    public void withdraw(int amount) {
        if (amount <= 0) {
            System.out.println("Error, invalid withdrawal amount. Please enter a valid amount.");
            return;
        }
        if (amount > balance) {
            System.out.println("Error, insufficient funds. Cannot withdraw more than available balance.");
            return;
        }
        balance -= amount;
        previousTransaction = -amount;
        balance -= 1; // Charge a small fee
        auditTransaction("Withdrawal", amount);
    }

    public void getPreviousTransaction() {
        if (previousTransaction > 0) {
            System.out.println("Deposited: " + previousTransaction);
        } else if (previousTransaction < 0) {
            System.out.println("Withdrawn: " + Math.abs(previousTransaction));
        } else {
            System.out.println("No transaction history.");
        }
    }

    public void showMenu() throws Exception {
        Scanner scanner = new Scanner(System.in);
        char option;

        System.out.println("Welcome, " + decode(decrypt(encryptedName)));
        System.out.println("Your ID: " + decode(decrypt(encryptedID)));
        System.out.println();

        do {
            System.out.println("A - Check Balance");
            System.out.println("B - Deposit");
            System.out.println("C - Withdraw");
            System.out.println("D - Transaction History");
            System.out.println("E - Exit");
            System.out.println("Enter an option:");

            option = scanner.next().charAt(0);
            System.out.println();

            switch (option) {
                case 'A':
                    System.out.println("Balance: " + balance);
                    break;
                case 'B':
                    System.out.println("Enter amount to deposit:");
                    int depositAmount = scanner.nextInt();
                    deposit(depositAmount);
                    break;
                case 'C':
                    System.out.println("Enter amount to withdraw:");
                    int withdrawAmount = scanner.nextInt();
                    withdraw(withdrawAmount);
                    break;
                case 'D':
                    getPreviousTransaction();
                    break;
                case 'E':
                    System.out.println("Exiting the application...");
                    break;
                default:
                    System.out.println("Invalid option. Only A, B, C, D, or E is available");
                    break;
            }
        } while (option != 'E');

        // Print URL encoding before and after
        String queryBeforeEncoding = "<#BankersULT.gif>";
        System.out.println("Here is our URL before encoding: https://Group1bank.com?query=" + queryBeforeEncoding);
        System.out.println("Here is our URL after encoding: " + buildEncodedUrl(queryBeforeEncoding));

        // Close scanner after the menu loop
        scanner.close();

        System.out.println("Thank you. Have a nice day!");
    }

    private byte[] encrypt(String input, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
        return cipher.doFinal(input.getBytes());
    }

    private String decrypt(byte[] input) throws Exception {
        // Extract the IV from the input
        byte[] iv = new byte[16];
        System.arraycopy(input, 0, iv, 0, 16);

        // Decrypt the ciphertext (excluding the IV)
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        byte[] decryptedData = cipher.doFinal(input, 16, input.length - 16);

        return new String(decryptedData);
    }

    private String decode(String input) {
        // For basic decoding, you can reverse the encoding process
        return input.replaceAll("/n", "<");
    }

    private void auditTransaction(String transactionType, int amount) {
        try (FileWriter writer = new FileWriter("transaction_log.txt", true)) {
            Date date = new Date();
            writer.write("Date: " + date.toString() + ", Customer ID: " + customerID + ", Transaction Type: " + transactionType + ", Amount: " + amount + "\n");
        } catch (IOException e) {
            System.out.println("Error writing to transaction log: " + e.getMessage());
        }
    }

    static String buildEncodedUrl(String q) {
        String encodedUrl = "https://Group1bank.com?query==" + Base64.getUrlEncoder().encodeToString(q.getBytes());
        return encodedUrl;
    }

    static class DailyLimitException extends Exception {
        private static final long serialVersionUID = 1L;
        public DailyLimitException(String message) {
            super(message);
        }
    }

    public static void main(String[] args) throws Exception {
    	NewBankApplicationsSpring2024 combinedFiles = new NewBankApplicationsSpring2024("User", "08312000");
        combinedFiles.showMenu();
    }

    private void writeToFile(String fileName, byte[] data) throws IOException {
        try (OutputStream outputStream = new FileOutputStream(fileName)) {
            outputStream.write(data);
        }
    }
}
