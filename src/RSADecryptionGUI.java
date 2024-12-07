import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.util.Scanner;

/**
 * A GUI-based program for RSA decryption.
 * Reads the private key and ciphertext from files, decrypts the ciphertext using modular arithmetic,
 * and displays the resulting plaintext in the GUI.
 */
public class RSADecryptionGUI extends JFrame 
{
    private JTextArea decryptedTextArea; // Area to display decrypted text
    private JLabel feedbackLabel; // Label for feedback messages

    /**
     * Constructs the RSA Decryption GUI, setting up the layout and components.
     */
    public RSADecryptionGUI() 
    {
        setTitle("RSA Decryptor"); // Window title
        setSize(600, 400); // Window dimensions
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new GridLayout(3, 1)); // 3 rows in the layout

        // Section 1: Output field for decrypted text
        JPanel textOutputPanel = new JPanel(new BorderLayout());
        textOutputPanel.add(new JLabel("Decrypted Text:"), BorderLayout.NORTH);
        decryptedTextArea = new JTextArea();
        decryptedTextArea.setEditable(false); // Make the area read-only
        textOutputPanel.add(new JScrollPane(decryptedTextArea), BorderLayout.CENTER);
        add(textOutputPanel);

        // Section 2: Feedback label for user messages
        feedbackLabel = new JLabel("Status: Ready to decrypt ciphertext.");
        add(feedbackLabel);

        // Section 3: Decrypt button to start the decryption process
        JButton decryptButton = new JButton("Decrypt Now");
        decryptButton.addActionListener(new DecryptAction());
        add(decryptButton);
    }

    /**
     * Main method to launch the RSA Decryption GUI.
     *
     * @param args Command-line arguments (not used).
     */
    public static void main(String[] args) 
    {
        SwingUtilities.invokeLater(() -> 
        {
            RSADecryptionGUI app = new RSADecryptionGUI();
            app.setVisible(true); // Show the GUI
        });
    }

    /**
     * Action Listener for the Decrypt button. Handles decryption logic.
     */
    private class DecryptAction implements ActionListener 
    {
        @Override
        public void actionPerformed(ActionEvent e) 
        {
            try 
            {
                long modulus, privateKey;

                // Step 1: Read the private key from a file
                try (Scanner keyReader = new Scanner(new File("private_key.txt"))) 
                {
                    modulus = keyReader.nextLong(); // Read modulus (n)
                    privateKey = keyReader.nextLong(); // Read private key (d)
                } 
                catch (FileNotFoundException ex) 
                {
                    feedbackLabel.setText("Status: Private key file not found.");
                    return;
                }

                // Step 2: Read the ciphertext from a file
                String ciphertext;
                try (BufferedReader cipherReader = new BufferedReader(new FileReader("ciphertext.txt"))) 
                {
                    ciphertext = cipherReader.readLine(); // Read the entire ciphertext as a single line
                } 
                catch (FileNotFoundException ex) 
                {
                    feedbackLabel.setText("Status: Ciphertext file not found.");
                    return;
                }

                // Step 3: Split the ciphertext into individual encrypted values
                String[] encryptedValues = ciphertext.split(" ");
                StringBuilder decryptedTextBuilder = new StringBuilder();

                // Step 4: Decrypt each encrypted value
                for (String value : encryptedValues) 
                {
                    if (!value.isEmpty()) 
                    { // Ensure the value is not empty
                        try 
                        {
                            long encryptedValue = Long.parseLong(value); // Parse the encrypted value
                            long decryptedChar = modPower(encryptedValue, privateKey, modulus); // Decrypt using modular exponentiation
                            decryptedTextBuilder.append((char) decryptedChar); // Convert to character
                        } 
                        catch (NumberFormatException ex) 
                        {
                            feedbackLabel.setText("Status: Error parsing ciphertext values.");
                            return;
                        }
                    }
                }

                // Step 5: Display the decrypted text in the GUI
                decryptedTextArea.setText(decryptedTextBuilder.toString());
                feedbackLabel.setText("Status: Decryption successful.");
            } 
            catch (Exception ex) 
            {
                feedbackLabel.setText("Status: Decryption failed due to an unexpected error.");
            }
        }
    }

    /**
     * Performs modular exponentiation using repeated squaring.
     * Computes (base^exponent) % mod without overflow.
     *
     * @param base     The base value to be raised to the power.
     * @param exponent The exponent value.
     * @param mod      The modulus value.
     * @return The result of (base^exponent) % mod.
     */
    private long modPower(long base, long exponent, long mod) 
    {
        long result = 1; // Initialize the result
        base %= mod; // Reduce base modulo mod to ensure it's within range

        while (exponent > 0) 
        {
            // If the current bit of the exponent is 1, multiply the result by the base
            if ((exponent & 1) == 1) 
            {
                result = (result * base) % mod;
            }
            exponent >>= 1; // Right shift the exponent (equivalent to dividing it by 2)
            base = (base * base) % mod; // Square the base and reduce modulo mod
        }

        return result;
    }
}
