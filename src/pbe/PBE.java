package pbe;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.file.Files;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;

/**
 *
 * @author ttkoch
 */
public class PBE {

    private static int ITERATIONS = 1000;

    public static void main(String[] args)
            throws Exception {
// Find out if encrypting or decrypting
        String input = (String) JOptionPane.
                showInputDialog(null, "Select Encryption or Decryption",
                "PBE Encryption Example", JOptionPane.INFORMATION_MESSAGE,
                null,
                new String[]{"Encrypt", "Decrypt"},
                "Encrypt");
// Select an input file
        JFileChooser chooser = new JFileChooser();
        int result = chooser.showOpenDialog(null);
        if (result != JFileChooser.APPROVE_OPTION) {
            System.out.println("No input file, so program will terminate");
        }
        File inFile = chooser.getSelectedFile();
// Select an output file
        chooser = new JFileChooser();
        result = chooser.showSaveDialog(null);
        if (result != JFileChooser.APPROVE_OPTION) {
            System.out.println("No output file, so program will terminate");
        }
        File outFile = chooser.getSelectedFile();
// Get the password to use for password-based encryption
        char[] password = PasswordDialog.getThePassword();
// Copy the contents of the file to a ByteOutput stram
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        Files.copy(inFile.toPath(), bOut);
        byte[] text = bOut.toByteArray();
        byte[] output = null;
        switch (input) {
            case "Encrypt":
                output = encrypt(password, text);
                break;
            case "Decrypt":
                output = decrypt(password, text);
                break;
        }
// Copy the results of the operation to the output file
        ByteArrayInputStream bIn = new ByteArrayInputStream(output);
        Files.copy(bIn, outFile.toPath());
        System.exit(0);
    }

    private static byte[] encrypt(char[] password, byte[] plaintext)
            throws Exception {
// Begin by creating a random salt of 64 bits (8 bytes)
        byte[] salt = new byte[8];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);
// Create the PBEKeySpec with the given password
        PBEKeySpec keySpec = new PBEKeySpec(password);
// Get a SecretKeyFactory for PBEWithSHA1AndDESede
        SecretKeyFactory keyFactory =
                SecretKeyFactory.getInstance("PBEWithSHA1AndDESede");
// Create our key
        SecretKey key = keyFactory.generateSecret(keySpec);
// Now create a parameter spec for our salt and iterations
        PBEParameterSpec paramSpec =
                new PBEParameterSpec(salt, ITERATIONS);
// Create a cipher and initialize it for encrypting
        Cipher cipher = Cipher.getInstance("PBEWithSHA1AndDESede");
        cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);
        byte[] ciphertext = cipher.doFinal(plaintext);
// Store both the salt and the cipher text in a
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        bOut.write(salt);
        bOut.write(ciphertext);
        return bOut.toByteArray();
    }

    private static byte[] decrypt(char[] password, byte[] text)
            throws Exception {
// Begin by splitting the text into salt and ciphertext
// salt is first 8 bytes,
        byte[] salt = new byte[8];
        byte[] ciphertext = new byte[text.length - 8];
        ByteArrayInputStream bIn = new ByteArrayInputStream(text);
        bIn.read(salt);
        bIn.read(ciphertext);
// Create the PBEKeySpec with the given password
        PBEKeySpec keySpec = new PBEKeySpec(password);
// Get a SecretKeyFactory for PBEWithSHA1AndDESede
        SecretKeyFactory keyFactory =
                SecretKeyFactory.getInstance("PBEWithSHA1AndDESede");
// Create our key
        SecretKey key = keyFactory.generateSecret(keySpec);
// Now create a parameter spec for our salt and iterations
        PBEParameterSpec paramSpec =
                new PBEParameterSpec(salt, ITERATIONS);
// Create a cipher and initialize it for encrypting
        Cipher cipher = Cipher.getInstance("PBEWithSHA1AndDESede");
        cipher.init(Cipher.DECRYPT_MODE, key, paramSpec);
// Perform the actual decryption
        return cipher.doFinal(ciphertext);
    }
}
// Dialog for password gathering
class PasswordDialog extends JDialog {

    private JPasswordField passwordField;
    JButton okButton;

    PasswordDialog() {
        this.setTitle("Enter Your Password");
        this.setModal(true);
        passwordField = new JPasswordField(20);
        passwordField.setEchoChar('*');
        JPanel bPanel = new JPanel();
        okButton = new JButton("Done");
        bPanel.add(okButton);
        add(passwordField, BorderLayout.NORTH);
        add(bPanel, BorderLayout.SOUTH);
        this.pack();
        okButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent ae) {
                setVisible(false);
            }
        });
    }

    static char[] getThePassword() {
        PasswordDialog d = new PasswordDialog();
        d.setVisible(true);
        return d.passwordField.getPassword();
    }
}
