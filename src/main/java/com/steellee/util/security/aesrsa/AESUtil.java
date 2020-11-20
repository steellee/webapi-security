package com.steellee.util.security.aesrsa;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.misc.BASE64Decoder;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Security;

/**
 * AES算法实现Java和JS（请查看resource下的3DES目录demo）互通加解密
 * crypto-js
 * https://www.jianshu.com/p/34c15b8d025a
 * https://blog.csdn.net/gulang03/article/details/82230408
 */
public class AESUtil {

    /** 算法/模式/补码方式 */
    public static final String AES_TYPE = "AES/CBC/NOPadding";
//    public static final String AES_TYPE = "AES/CBC/PKCS5Padding";
//    public static final String AES_TYPE = "AES/CBC/PKCS7Padding";
    static String data = "测试一下abac1232%…";
    static String key = "abcdef0123456789";  //16位
    static String iv = "0123456789abcdef";  //16位

    public static void main(String args[]) throws Exception {
        System.out.println(encryptAES(data));
        System.out.println(decryptAES(encryptAES(data)));
    }

    public static String encryptAES(String data) throws Exception {

        try {
            //如果是PKCS7Padding填充方式，则必须加上下面这行
            Security.addProvider(new BouncyCastleProvider());

            Cipher cipher = Cipher.getInstance(AES_TYPE);   //参数分别代表 算法名称/加密模式/数据填充方式
            int blockSize = cipher.getBlockSize();

            byte[] dataBytes = data.getBytes();
            int plaintextLength = dataBytes.length;
            if (plaintextLength % blockSize != 0) {
                plaintextLength = plaintextLength + (blockSize - (plaintextLength % blockSize));
            }

            byte[] plaintext = new byte[plaintextLength];
            System.arraycopy(dataBytes, 0, plaintext, 0, dataBytes.length);

            SecretKeySpec keyspec = new SecretKeySpec(key.getBytes(), "AES");
            IvParameterSpec ivspec = new IvParameterSpec(iv.getBytes());

            cipher.init(Cipher.ENCRYPT_MODE, keyspec, ivspec);
            byte[] encrypted = cipher.doFinal(plaintext);

            return new sun.misc.BASE64Encoder().encode(encrypted);

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String decryptAES(String data) throws Exception {
        try {
//            //如果是PKCS7Padding填充方式，则必须加上下面这行
//            Security.addProvider(new BouncyCastleProvider());

            byte[] encrypted1 = new BASE64Decoder().decodeBuffer(data);

            Cipher cipher = Cipher.getInstance(AES_TYPE);
            SecretKeySpec keyspec = new SecretKeySpec(key.getBytes(), "AES");
            IvParameterSpec ivspec = new IvParameterSpec(iv.getBytes());

            cipher.init(Cipher.DECRYPT_MODE, keyspec, ivspec);

            byte[] original = cipher.doFinal(encrypted1);
            String originalString = new String(original);
            return originalString;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}