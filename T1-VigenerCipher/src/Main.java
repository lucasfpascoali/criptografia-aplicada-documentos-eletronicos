import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        String plainText = scanner.nextLine();
        String key = scanner.nextLine();
        char operation = scanner.next().charAt(0);

        String result = vigenereCipher(plainText, key, operation);
        System.out.println(result);
    }

    public static String vigenereCipher(String plainText, String key, char operation) {
        if (operation == 'd') {
            return encrypt(plainText, key, true);
        }

        return encrypt(plainText, key, false);
    }

    private static String encrypt(String plainText, String key, Boolean negativeShift) {
        StringBuilder cypherText = new StringBuilder();

        int charCounter = 0;
        for (char c : plainText.toCharArray()) {
            if (!Character.isLetter(c)) {
                cypherText.append(c);
                continue;
            }

            int defaultValue = 'a';
            if (Character.isUpperCase(c)) {
                defaultValue = 'A';
            }

            int shift = key.charAt(charCounter % key.length()) - defaultValue;
            if (negativeShift) {
                shift = -shift;
            }
            int newPosition = (c - defaultValue + shift) % 26;
            if (newPosition < 0) {
                newPosition += 26;
            }

            charCounter++;
            cypherText.append((char) (defaultValue + newPosition));
        }

        return cypherText.toString();
    }
}