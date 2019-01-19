package com.steellee.util.security;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * @author steellee
 * @version V2.0.0
 * @date 2019/01/19
 */
public class AESCoderTest {

    @Test
    public void test() throws Exception {
        String inputStr = "I am AES";
        String key = "9999999999999999";
        System.err.println("原文:\t" + inputStr);
        System.err.println("密钥:\t" + key);

        String inputData = AESCoder.encryptToBase64(inputStr, key);

        System.err.println("加密后:\t" + inputData);

        String outputData = AESCoder.decryptFromBase64(inputData, key);

        System.err.println("解密后:\t" + outputData);

        assertEquals(inputStr, outputData);
    }
}
