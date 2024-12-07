import java.io.*;
import java.util.Scanner;

/**
 * A program for RSA decryption. Reads the private key and ciphertext from files,
 * decrypts the ciphertext using modular arithmetic, and outputs the plaintext.
 */
public class Decryption 
{

    public static void main(String[] args) 
    {
        long modulus;
        long privateKey;

        // Step 1: Read the private key from the file
        try (Scanner privateKeyReader = new Scanner(new File("private_key.txt"))) 
        {
            modulus = privateKeyReader.nextLong(); // Read modulus (n)
            privateKey = privateKeyReader.nextLong(); // Read private key (d)
        } 
        catch (FileNotFoundException e) 
        {
            System.out.println("Private key file not found. Ensure 'private_key.txt' exists.");
            return;
        } 
        catch (IOException e) 
        {
            System.out.println("Error reading private key file: " + e.getMessage());
            return;
        }

        // Step 2: Read the ciphertext from the file
        String[] encryptedValues;
        try (BufferedReader ciphertextReader = new BufferedReader(new FileReader("ciphertext.txt"))) 
        {
            String ciphertext = ciphertextReader.readLine(); // Read the entire ciphertext as a single line
            encryptedValues = ciphertext.split(" "); // Split the ciphertext into individual encrypted values using spaces
        } 
        catch (FileNotFoundException e) 
        {
            System.out.println("Ciphertext file not found. Ensure 'ciphertext.txt' exists.");
            return;
        } 
        catch (IOException e) 
        {
            System.out.println("Error reading ciphertext file: " + e.getMessage());
            return;
        }

        // Step 3: Decrypt the ciphertext
        StringBuilder decryptedText = new StringBuilder(); // Store the decrypted text
        for (String value : encryptedValues) 
        {
            if (!value.isEmpty()) 
            { // Ensure value is not empty
                try 
                {
                    long encryptedValue = Long.parseLong(value); // Parse the encrypted value from the string
                    long decryptedCharacter = computeModularPower(encryptedValue, privateKey, modulus); // Decrypt using modular exponentiation
                    decryptedText.append((char) decryptedCharacter); // Convert the decrypted value to a character and append to the result
                } 
                catch (NumberFormatException e) 
                {
                    System.out.println("Error parsing encrypted value: " + e.getMessage());
                    return;
                }
            }
        }

        // Step 4: Output the decrypted text
        System.out.println("Decrypted text: " + decryptedText.toString());
    }

    /**
     * Performs modular exponentiation using repeated squaring.
     * Computes (base^exponent) % mod without overflow.
     *
     * @param base     The base value to be raised to the power.
     * @param exponent The exponent value to raise the base to.
     * @param mod      The modulus value for the operation.
     * @return The result of (base^exponent) % mod.
     */
    public static long computeModularPower(long base, long exponent, long mod) 
    {
        long result = 1; // Initialize the result
        base %= mod; // Reduce base to ensure it's within the modulus range

        while (exponent > 0) 
        {
            // If the current bit of the exponent is 1, multiply the result by the current base
            if ((exponent & 1) == 1) 
            {
                result = (result * base) % mod;
            }
            exponent >>= 1; // Right shift the exponent (equivalent to dividing it by 2)
            base = (base * base) % mod; // Square the base and reduce it modulo mod
        }

        return result;
    }
}
