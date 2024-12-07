import java.io.*;
import java.util.Random;
import java.util.Scanner;

/**
 * A program for RSA encryption. Allows users to input prime numbers or generate them randomly,
 * computes RSA keys, encrypts plaintext, and saves the results to files.
 */
public class Encryption 
{

    public static void main(String[] args) 
    {
        Scanner scanner = new Scanner(System.in);
        long primaryPrime = 0;
        long secondaryPrime = 0;

        // Prompt user to choose between inputting primes or generating them randomly
        System.out.print("Would you like to (1) input prime numbers or (2) generate them randomly? Enter 1 or 2: ");
        int choice = scanner.nextInt();

        if (choice == 1) 
        {
            // Manual input: Validate the first prime number
            do 
            {
                System.out.print("Enter the first prime number: ");
                while (!scanner.hasNextLong()) 
                {
                    System.out.println("Invalid input. Please enter a valid integer value.");
                    scanner.next();
                }
                primaryPrime = scanner.nextLong();
                if (!checkPrime(primaryPrime)) 
                {
                    System.out.println("The number " + primaryPrime + " is not prime. Try a different value.");
                }
            } 
            while (!checkPrime(primaryPrime));

            // Manual input: Validate the second prime number
            do 
            {
                System.out.print("Enter the second prime number (must be different from the first): ");
                while (!scanner.hasNextLong()) 
                {
                    System.out.println("Invalid input. Please enter a valid integer value.");
                    scanner.next();
                }
                secondaryPrime = scanner.nextLong();
                if (!checkPrime(secondaryPrime)) 
                {
                    System.out.println("The number " + secondaryPrime + " is not prime. Try a different value.");
                }
                else if (secondaryPrime == primaryPrime) 
                {
                    System.out.println("The second prime cannot be the same as the first prime (" + primaryPrime + ").");
                }
            } 
            while (!checkPrime(secondaryPrime) || secondaryPrime == primaryPrime);

        } 
        else if (choice == 2) 
        {
            // Random prime generation
            primaryPrime = generateRandomPrime(100, 1000);
            do 
            {
                secondaryPrime = generateRandomPrime(100, 1000);
            } 
            while (secondaryPrime == primaryPrime);

            System.out.println("Generated Prime 1: " + primaryPrime);
            System.out.println("Generated Prime 2: " + secondaryPrime);
        } 
        else 
        {
            // Handle invalid choice
            System.out.println("Invalid choice. Please restart the program and enter 1 or 2.");
            return;
        }

        // Compute modulus and validate its size
        long modulus = primaryPrime * secondaryPrime;
        if (modulus <= 255) {
            System.out.println("The modulus (n = " + modulus + ") is too small for encryption. Please use larger primes.");
            return;
        }

        // Calculate the totient, public key, and private key
        long totient = (primaryPrime - 1) * (secondaryPrime - 1);
        long publicKey = findPublicKey(totient);
        long privateKey = calculateModInverse(publicKey, totient);

        // Save public key to a file
        try (PrintWriter pubKeyFile = new PrintWriter("public_key.txt")) 
        {
            pubKeyFile.println(modulus);
            pubKeyFile.println(publicKey);
        } 
        catch (IOException e) 
        {
            System.out.println("Error writing public key to file: " + e.getMessage());
            return;
        }

        // Save private key to a file
        try (PrintWriter privKeyFile = new PrintWriter("private_key.txt")) 
        {
            privKeyFile.println(modulus);
            privKeyFile.println(privateKey);
        } 
        catch (IOException e) 
        {
            System.out.println("Error writing private key to file: " + e.getMessage());
            return;
        }

        System.out.println("Public Key: (" + modulus + ", " + publicKey + ")");
        System.out.println("Private Key: (" + modulus + ", " + privateKey + ")");

        // Prompt user for plaintext input
        scanner.nextLine(); 
        System.out.print("Enter the text to encrypt: ");
        String plaintext = scanner.nextLine();

        // Encrypt the plaintext
        StringBuilder encryptedData = new StringBuilder();
        for (char ch : plaintext.toCharArray()) 
        {
            if (ch < 32 || ch > 126) 
            { // Ensure character is valid ASCII
                System.out.println("Unsupported character '" + ch + "' detected. Only ASCII characters are supported.");
                return;
            }
            int asciiValue = ch; // Convert character to ASCII
            long encryptedValue = fastExponentiation(asciiValue, publicKey, modulus);
            encryptedData.append(encryptedValue).append(" "); // Append encrypted value with space delimiter
        }

        // Save the ciphertext to a file
        try (PrintWriter cipherFile = new PrintWriter("ciphertext.txt")) 
        {
            cipherFile.println(encryptedData.toString().trim());
        } 
        catch (IOException e) 
        {
            System.out.println("Error saving ciphertext: " + e.getMessage());
            return;
        }

        System.out.println("Encryption completed. Ciphertext saved to 'ciphertext.txt'.");
    }

    /**
     * Checks if a number is prime.
     *
     * @param num The number to check.
     * @return True if the number is prime, false otherwise.
     */
    public static boolean checkPrime(long num) 
    {
        if (num <= 1) 
        	return false; // Numbers ≤ 1 are not prime
        if (num <= 3) 
        	return true; // 2 and 3 are prime
        if (num % 2 == 0 || num % 3 == 0) 
        	return false; // Exclude multiples of 2 and 3

        // Check divisors up to the square root of the number
        for (long i = 5; i * i <= num; i += 6) 
        {
            if (num % i == 0 || num % (i + 2) == 0) 
            	return false;
        }
        return true;
    }

    /**
     * Generates a random prime number within a specified range.
     *
     * @param min The minimum value for the prime number.
     * @param max The maximum value for the prime number.
     * @return A randomly generated prime number.
     */
    public static long generateRandomPrime(int min, int max) 
    {
        Random random = new Random();
        long option;
        do 
        {
            option = random.nextInt(max - min + 1) + min; // Generate a random number in range
        } 
        while (!checkPrime(option));
        return option;
    }

    /**
     * Computes the greatest common divisor (GCD) of two numbers.
     *
     * @param a The first number.
     * @param b The second number.
     * @return The GCD of the two numbers.
     */
    public static long findGCD(long a, long b) 
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
     * Finds a public key that is coprime with the totient.
     *
     * @param phi The totient value (phi(n)).
     * @return A public key that is coprime with phi.
     */
    public static long findPublicKey(long phi) 
    {
        for (long holder = 3; holder < phi; holder++) 
        {
            if (findGCD(holder, phi) == 1) return holder;
        }
        return 3;
    }

    /**
     * Calculates the modular multiplicative inverse using the Extended Euclidean Algorithm.
     *
     * @param e   The public key.
     * @param phi The totient value (phi(n)).
     * @return The modular inverse of e modulo phi.
     */
    public static long calculateModInverse(long e, long phi) 
    {
        long originalPhi = phi;
        long a = 0;
        long b = 1; 
        long temp;

        while (e > 1) 
        {
            long quotient = e / phi;
            temp = phi;
            phi = e % phi;
            e = temp;

            temp = a;
            a = b - quotient * a;
            b = temp;
        }
        return (b < 0) ? b + originalPhi : b;
    }

    /**
     * Performs modular exponentiation efficiently using repeated squaring.
     *
     * @param base     The base value.
     * @param exponent The exponent value.
     * @param mod      The modulus value.
     * @return The result of (base^exponent) % mod.
     */
    public static long fastExponentiation(long base, long exponent, long mod) 
    {
        long result = 1;
        base %= mod;
        while (exponent > 0) 
        {
            if ((exponent & 1) == 1) result = (result * base) % mod; // Multiply when exponent is odd
            exponent >>= 1; // Divide exponent by 2
            base = (base * base) % mod; // Square the base
        }
        return result;
    }
}
