package org.example;

import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        Integer rawN = scanner.nextInt();
        Integer n = Math.abs(rawN);

        if (n != 1 && isPrime(n)) {
            System.out.printf("Resultado final: %d é provavelmente primo", rawN);
        } else {
            System.out.printf("Resultado final: %d é composto", rawN);
        }
    }

    private static Integer getValueOfK(Integer n) {
        Integer k = 1;
        while (((n - 1) / ((int) Math.pow(2, k))) % 2 == 0) {
            k++;
        }

        return k;
    }

    private static Integer getValueOfM(Integer n, Integer k) {
        return n / (int) Math.pow(2, k);
    }

    private static Boolean isPrime(Integer p) {
        if (p == 2) return true;

        Integer k = getValueOfK(p);
        Integer m = getValueOfM(p, k);

        // a between 2 and 5 is required by the exercise, but upper limit cannot be greater than p
        Integer upperLimit = 5;
        if (p < upperLimit) {
            upperLimit = p - 1;
        }

        for (int a = 2; a <= upperLimit; a++) {
            if (verifyFirstCondition(a, m, p) || verifySecondCondition(a, m, k, p)) {
                System.out.printf("Teste a=%d -> Provavelmente primo\n\n", a);
            } else {
                System.out.printf("Teste a=%d -> Composto\n\n", a);
                return false;
            }
        }

        return true;
    }

    private static Boolean verifyFirstCondition(Integer a, Integer m, Integer p) {
        return Math.pow(a, m) % p == 1;
    }

    private static Boolean verifySecondCondition(Integer a, Integer m, Integer k, Integer p) {
        Integer previousPower = (int) Math.pow(a, m);
        if (previousPower % p == p - 1) {
            return true;
        }

        for (int i = 1; i < k; i++) {
            previousPower *= previousPower;
            if (previousPower % p == p - 1) {
                return true;
            }
        }

        return false;
    }
}