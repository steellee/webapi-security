package com.steellee.util.security.rsaAes;

import java.security.SecureRandom;

/**
 * 随机数生成
 */
public class SecureRandomUtil {

    // 使用SecureRandom替换Random，提高随机数的安全性
    public static SecureRandom random = new SecureRandom();

    public static String getRandom(int length) {
        StringBuilder ret = new StringBuilder();
        for (int i = 0; i < length; i++) {
            boolean isChar = (random.nextInt(2) % 2 == 0);// 输出字母还是数字
            if (isChar) { // 字符串
                int choice = random.nextInt(2) % 2 == 0 ? 65 : 97; // 取得大写字母还是小写字母
                ret.append((char)(choice + random.nextInt(26)));
            } else { // 数字
                ret.append(Integer.toString(random.nextInt(10)));
            }
        }
        return ret.toString();
    }

    public static String getRandomNum(int length) {
        StringBuilder ret = new StringBuilder();
        for (int i = 0; i < length; i++) {
            ret.append(Integer.toString(random.nextInt(10)));
        }
        return ret.toString();
    }

    public static void main(String[] args) {
        System.out.println(getRandom(16));
    }

}
