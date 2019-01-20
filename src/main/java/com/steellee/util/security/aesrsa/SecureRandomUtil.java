package com.steellee.util.security.aesrsa;

import java.security.SecureRandom;

/**
 * 随机数生成
 *
 * @author steellee
 * @date 2019/1/13
 */
public class SecureRandomUtil {

    /** 使用SecureRandom替换Random，提高随机数的安全性 */
    public static SecureRandom random = new SecureRandom();

    /**
     * 输出指定长度的随机数
     *
     * @param length 输出长度
     * @return 字母+数字组合
     */
    public static String getRandom(int length) {
        StringBuilder ret = new StringBuilder();
        for (int i = 0; i < length; i++) {
            // 输出字母还是数字
            boolean isChar = (random.nextInt(2) % 2 == 0);
            // 字符串
            if (isChar) {
                // 取得大写字母还是小写字母
                int choice = random.nextInt(2) % 2 == 0 ? 65 : 97;
                ret.append((char)(choice + random.nextInt(26)));
            } else {
                // 数字
                ret.append(Integer.toString(random.nextInt(10)));
            }
        }
        return ret.toString();
    }

    /**
     * 输出指定长度的随机数
     *
     * @param length 输出长度
     * @return 纯数字
     */
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
