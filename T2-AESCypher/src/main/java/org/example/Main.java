package org.example;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.util.Arrays;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        String operationMode = scanner.nextLine();
        Integer keySize = scanner.nextInt();
        scanner.nextLine();
        Character operationType = scanner.nextLine().charAt(0);
        String plainText = scanner.nextLine();
        scanner.close();

        if (operationType == 'D') {
            System.out.println(
                    new String(
                            removeTrailingZeros(
                                    runOperationMode(hexStringToByteArray(plainText), keySize, operationType, operationMode)
                            )
                    )
            );
        } else if (operationType == 'E') {
            System.out.println(
                    DatatypeConverter.printHexBinary(
                            runOperationMode(plainText.getBytes(), keySize, operationType, operationMode)
                    )
            );
        } else {
            System.out.println("Wrong operation type!");
        }
    }

    private static byte[] runOperationMode(byte[] plainText, Integer keySize, Character operationType, String operationMode) {
        try {
            SecretKey key = new SecretKeySpec(getKey(keySize), "AES");

            switch (operationMode) {
                case "ECB":
                    return ECB(getPaddedInput(plainText), key, operationType == 'E' ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE);
                case "CBC":
                    return CBC(getPaddedInput(plainText), key, operationType == 'E' ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE);
                case "CFB":
                    return CFB(plainText, key, operationType == 'E' ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE);
                case "OFB":
                    return OFB(plainText, key, operationType == 'E' ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE);
                case "CTR":
                    return CTR(plainText, key, operationType == 'E' ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE);
                default:
                    throw new IllegalArgumentException("Unsupported operation mode: " + operationMode);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] ECB(byte[] input, SecretKey key, int mode) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(mode, key);
        return cipher.doFinal(input);
    }

    private static byte[] CBC(byte[] input, SecretKey key, int mode) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(mode, key, new IvParameterSpec(getIV()));
        return cipher.doFinal(input);
    }

    private static byte[] CFB(byte[] input, SecretKey key, int mode) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
        cipher.init(mode, key, new IvParameterSpec(getIV()));
        return cipher.doFinal(input);
    }

    private static byte[] OFB(byte[] input, SecretKey key, int mode) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/OFB/NoPadding");
        cipher.init(mode, key, new IvParameterSpec(getIV()));
        return cipher.doFinal(input);
    }

    private static byte[] CTR(byte[] input, SecretKey key, int mode) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(mode, key, new IvParameterSpec(getIV()));
        return cipher.doFinal(input);
    }

    private static byte[] getIV() {
        return new byte[16]; // Required to pass the VPL tests, this value should be unpredictable
    }

    private static byte[] getKey(Integer keySize) {
        switch (keySize) {
            case 128: {
                return hexStringToByteArray("637572736F63727970746F6772616679");
            }
            case 192: {
                return hexStringToByteArray("637572736F63727970746F6772616679637572736F637279");
            }
            case 256: {
                return hexStringToByteArray("637572736F63727970746F6772616679637572736F63727970746F6772616679");
            }
            default:
                throw new IllegalArgumentException("Wrong key size!");
        }
    }

    private static byte[] getPaddedInput(byte[] input) {
        return Arrays.copyOf(input, (input.length / 16 + ((input.length % 16 == 0) ? 0 : 1)) * 16);
    }

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    private static byte[] removeTrailingZeros(byte[] input) {
        int lastNonZeroIndex = input.length - 1;
        while (lastNonZeroIndex >= 0 && input[lastNonZeroIndex] == 0) {
            lastNonZeroIndex--;
        }

        return Arrays.copyOfRange(input, 0, lastNonZeroIndex + 1);
    }
}