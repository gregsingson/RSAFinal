

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.util.Random;

/**
 * A GUI-based program for RSA encryption. 
 * Allows users to input prime numbers manually or generate them randomly, 
 * computes RSA keys, encrypts plaintext, and saves the results to files.
 */
public class RSAEncryptionGUI extends JFrame 
{
    private JTextField primeField1;// Input fields for prime numbers
    private JTextField primeField2; 
    private JTextArea plainTextArea; // Input area for plaintext
    private JLabel feedbackLabel; // Label to show user feedback
    private JCheckBox randomPrimesCheckBox; // Checkbox for random prime generation

    /**
     * Constructs the RSA Encryption GUI, setting up the layout and components.
     */
    public RSAEncryptionGUI() 
    {
        setTitle("RSA Encryptor"); // Window title
        setSize(600, 400); // Window dimensions
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new GridLayout(6, 1)); // 6 rows in the layout

        // Section 1: Option to use random primes
        JPanel randomPrimesPanel = new JPanel();
        randomPrimesCheckBox = new JCheckBox("Generate random primes");
        randomPrimesCheckBox.addActionListener(e -> togglePrimeFields(!randomPrimesCheckBox.isSelected()));
        randomPrimesPanel.add(randomPrimesCheckBox);
        add(randomPrimesPanel);

        // Section 2: Input fields for prime numbers
        JPanel primePanel = new JPanel(new GridLayout(1, 4));
        primePanel.add(new JLabel("Prime 1: "));
        primeField1 = new JTextField();
        primePanel.add(primeField1);

        primePanel.add(new JLabel("Prime 2: "));
        primeField2 = new JTextField();
        primePanel.add(primeField2);
        add(primePanel);

        // Section 3: Input field for plaintext
        JPanel textInputPanel = new JPanel(new BorderLayout());
        textInputPanel.add(new JLabel("Text to Encrypt:"), BorderLayout.NORTH);
        plainTextArea = new JTextArea();
        textInputPanel.add(new JScrollPane(plainTextArea), BorderLayout.CENTER);
        add(textInputPanel);

        // Section 4: Feedback label
        feedbackLabel = new JLabel("Status: Enter primes and text to encrypt.");
        add(feedbackLabel);

        // Section 5: Encrypt button
        JButton encryptButton = new JButton("Encrypt Now");
        encryptButton.addActionListener(new EncryptAction());
        add(encryptButton);
    }

    /**
     * Main method to launch the RSA Encryption GUI.
     *
     * @param args Command-line arguments (not used).
     */
    public static void main(String[] args) 
    {
        SwingUtilities.invokeLater(() -> 
        {
            RSAEncryptionGUI app = new RSAEncryptionGUI();
            app.setVisible(true); // Show the GUI
        });
    }

    /**
     * Toggles the input fields for primes based on the random prime generation option.
     *
     * @param enable Whether the input fields should be enabled.
     */
    private void togglePrimeFields(boolean enable) 
    {
        primeField1.setEnabled(enable);
        primeField2.setEnabled(enable);
    }

    /**
     * Action Listener for the Encrypt button. Handles RSA encryption logic.
     */
    private class EncryptAction implements ActionListener 
    {
        @Override
        public void actionPerformed(ActionEvent e) 
        {
            try 
            {
                long prime1;
                long prime2;

                // If random primes option is selected
                if (randomPrimesCheckBox.isSelected()) 
                {
                    prime1 = generateRandomPrime(100, 1000);
                    do 
                    {
                        prime2 = generateRandomPrime(100, 1000);
                    } 
                    while (prime2 == prime1);

                    feedbackLabel.setText("Generated Primes: Prime 1 = " + prime1 + ", Prime 2 = " + prime2);
                } 
                else 
                {
                    // Validate manual prime input
                    prime1 = Long.parseLong(primeField1.getText());
                    prime2 = Long.parseLong(primeField2.getText());

                    if (!isPrime(prime1) || !isPrime(prime2) || prime1 == prime2) 
                    {
                        feedbackLabel.setText("Status: Invalid primes. Ensure they are distinct and prime.");
                        return;
                    }
                }

                // Compute RSA values
                long modulus = prime1 * prime2;
                if (modulus <= 255) 
                {
                    feedbackLabel.setText("Status: Modulus too small. Use larger primes.");
                    return;
                }

                long totient = (prime1 - 1) * (prime2 - 1);
                long publicKey = findPublicKey(totient);
                long privateKey = calculateModInverse(publicKey, totient);

                // Save keys to files
                try (PrintWriter publicWriter = new PrintWriter("public_key.txt")) 
                {
                    publicWriter.println(modulus);
                    publicWriter.println(publicKey);
                }
                try (PrintWriter privateWriter = new PrintWriter("private_key.txt")) 
                {
                    privateWriter.println(modulus);
                    privateWriter.println(privateKey);
                }

                // Encrypt plaintext
                String plainText = plainTextArea.getText();
                StringBuilder cipherBuilder = new StringBuilder();
                for (char character : plainText.toCharArray()) 
                {
                    if (character < 32 || character > 126) 
                    {
                        feedbackLabel.setText("Status: Unsupported character '" + character + "'. Only ASCII is supported.");
                        return;
                    }
                    long cipherValue = modPower(character, publicKey, modulus);
                    cipherBuilder.append(cipherValue).append(" ");
                }

                // Save ciphertext
                try (PrintWriter cipherWriter = new PrintWriter("ciphertext.txt")) 
                {
                    cipherWriter.println(cipherBuilder.toString().trim());
                }

                feedbackLabel.setText("Status: Encryption successful. Files saved.");
            } 
            catch (NumberFormatException ex) 
            {
                feedbackLabel.setText("Status: Invalid input. Enter numeric primes.");
            } 
            catch (IOException ex) 
            {
                feedbackLabel.setText("Status: Error saving files.");
            }
        }
    }

    /**
     * Checks whether a number is prime.
     *
     * @param number The number to check.
     * @return True if the number is prime, false otherwise.
     */
    private boolean isPrime(long number) 
    {
        if (number <= 1) 
        	return false;
        if (number <= 3) 
        	return true;
        if (number % 2 == 0 || number % 3 == 0) 
        	return false;
        for (long i = 5; i * i <= number; i += 6) 
        {
            if (number % i == 0 || number % (i + 2) == 0) 
            	return false;
        }
        return true;
    }

    /**
     * Generates a random prime number within a range.
     *
     * @param min The minimum value for the prime.
     * @param max The maximum value for the prime.
     * @return A randomly generated prime number.
     */
    private long generateRandomPrime(int min, int max) 
    {
        Random random = new Random();
        long option;
        do 
        {
            option = random.nextInt(max - min + 1) + min;
        } 
        while (!isPrime(option));
        return option;
    }

    /**
     * Finds a public key that is coprime with the totient.
     *
     * @param phi The totient value.
     * @return A valid public key.
     */
    private long findPublicKey(long phi) 
    {
        for (long holder = 3; holder < phi; holder++) 
        {
            if (gcd(holder, phi) == 1) return holder;
        }
        return 3;
    }

    /**
     * Calculates the modular inverse using the Extended Euclidean Algorithm.
     *
     * @param e   The public key.
     * @param phi The totient value.
     * @return The modular inverse of e modulo phi.
     */
    private long calculateModInverse(long e, long phi) 
    {
        long originalPhi = phi; 
        long a = 0;
        long b = 1;
        while (e > 1) 
        {
            long quotient = e / phi;
            long temp = phi;
            phi = e % phi;
            e = temp;

            temp = a;
            a = b - quotient * a;
            b = temp;
        }
        return b < 0 ? b + originalPhi : b;
    }

    /**
     * Computes the greatest common divisor (GCD) of two numbers.
     *
     * @param a The first number.
     * @param b The second number.
     * @return The GCD of the two numbers.
     */
    private long gcd(long a, long b) 
    {
        while (b != 0) 
        {
            long temp = b;
            b = a % b;
            a = temp;
        }
        return a;
    }

    /**
     * Performs modular exponentiation.
     *
     * @param base     The base value.
     * @param exponent The exponent value.
     * @param mod      The modulus value.
     * @return The result of (base^exponent) % mod.
     */
    private long modPower(long base, long exponent, long mod) 
    {
        long result = 1;
        base %= mod;
        while (exponent > 0) 
        {
            if ((exponent & 1) == 1) result = (result * base) % mod;
            exponent >>= 1;
            base = (base * base) % mod;
        }
        return result;
    }
}
