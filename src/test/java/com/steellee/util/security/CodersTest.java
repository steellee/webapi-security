package com.steellee.util.security;

import com.sun.org.apache.xerces.internal.impl.dv.util.HexBin;
import org.junit.Test;

import java.math.BigInteger;
import java.util.Arrays;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

/**
 * @author steellee
 * @version V1.0.0
 * @Description TODO
 * @date 2019/01/19
 */
public class CodersTest {

    @Test
    public void test() throws Exception {
        String inputStr = "简单加密";
        System.err.println("原文:" + inputStr);

        byte[] inputData = inputStr.getBytes();
        String code = Coders.encryptBASE64(inputData);

        System.err.println("BASE64加密后:\n" + code);

        byte[] output = Coders.decryptBASE64(code);

        String outputStr = new String(output);

        System.err.println("BASE64解密后:\n" + outputStr);

        // 验证BASE64加密解密一致性  
        assertEquals(inputStr, outputStr);

        // 验证MD5对于同一内容加密是否一致  
        assertArrayEquals(Coders.encryptMD5(inputData), Coders
            .encryptMD5(inputData));

        // 验证SHA对于同一内容加密是否一致  
        assertArrayEquals(Coders.encryptSHA(inputData), Coders
            .encryptSHA(inputData));

        String key = Coders.initMacKey();
        System.err.println("Mac密钥:\n" + key);

        // 验证HMAC对于同一内容，同一密钥加密是否一致  
        assertArrayEquals(Coders.encryptHMAC(inputData, key), Coders.encryptHMAC(
            inputData, key));

        BigInteger md5 = new BigInteger(Coders.encryptMD5(inputData));
        System.err.println("MD5:\n" + md5.toString(16));

        BigInteger sha = new BigInteger(Coders.encryptSHA(inputData));
        System.err.println("SHA:\n" + sha.toString(32));

        BigInteger mac = new BigInteger(Coders.encryptHMAC(inputData, key));
        System.err.println("HMAC:\n" + mac.toString(16));
    }
}
