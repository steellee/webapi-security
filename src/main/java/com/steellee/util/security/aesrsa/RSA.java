package com.steellee.util.security.aesrsa;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * RSA算法
 *
 * @author steellee
 * @date 2019/1/13
 */
public class RSA {

    /**
     * CBC模式要求加密字符串长度为16倍数
     */
    public static final String RSA_ALGORITHM = "RSA/ECB/PKCS1Padding";
    /**
     * 字符编码
     */
    public static final String CHAR_ENCODING = "UTF-8";

    /**
     * RSA生成密钥长度
     */
    private static int KEYSIZE = 2048;

    /**
     * RSA 签名算法
     */
    private static String SIGNATURE_ALGORITHM__SHA1RSA = "SHA1WithRSA";
    /**
     * RSA2 签名算法（推荐）
     */
//    private static String SIGNATURE_ALGORITHM_SHA256RSA = "SHA1WithRSA";
    private static String SIGNATURE_ALGORITHM_SHA256RSA = "SHA256WithRSA";

    /**
     * 生成密钥对
     */
    public static Map<String, String> generateKeyPair() throws Exception {
        /** RSA算法要求有一个可信任的随机数源 */
        SecureRandom sr = new SecureRandom();
        /** 为RSA算法创建一个KeyPairGenerator对象 */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        /** 利用上面的随机数据源初始化这个KeyPairGenerator对象 */
        kpg.initialize(KEYSIZE, sr);
        /** 生成密匙对 */
        KeyPair kp = kpg.generateKeyPair();
        /** 得到公钥 */
        Key publicKey = kp.getPublic();
        byte[] publicKeyBytes = publicKey.getEncoded();
        String pub = new String(Base64.getEncoder().encode(publicKeyBytes), CHAR_ENCODING);
        /** 得到私钥 */
        Key privateKey = kp.getPrivate();
        byte[] privateKeyBytes = privateKey.getEncoded();
        String pri = new String(Base64.getEncoder().encode(privateKeyBytes), CHAR_ENCODING);

        Map<String, String> map = new HashMap<String, String>();
        map.put("publicKey", pub);
        map.put("privateKey", pri);
        RSAPublicKey rsp = (RSAPublicKey)kp.getPublic();
        BigInteger bint = rsp.getModulus();
        byte[] b = bint.toByteArray();
        byte[] deBase64Value = Base64.getEncoder().encode(b);
        String retValue = new String(deBase64Value);
        map.put("modulus", retValue);
        return map;
    }

    /**
     *  RSA加密
     *
     * @param source 源数据
     * @param publicKey server公钥
     * @return 加密数据
     * @throws Exception 异常
     */
    public static String encrypt(String source, String publicKey) throws Exception {
        Key key = getPublicKey(publicKey);
        /** 得到Cipher对象来实现对源数据的RSA加密 */
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] b = source.getBytes();
        /** 执行加密操作 */
        byte[] b1 = cipher.doFinal(b);
        return new String(Base64.getEncoder().encode(b1), CHAR_ENCODING);
    }

    /**
     * RSA解密算法
     *
     * @param cryptograph 密文
     * @param privateKey server私钥
     * @return 明文
     * @throws Exception 异常
     */
    public static String decrypt(String cryptograph, String privateKey) throws Exception {
        Key key = getPrivateKey(privateKey);
        /** 得到Cipher对象对已用公钥加密的数据进行RSA解密 */
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] b1 = Base64.getDecoder().decode(cryptograph.getBytes());
        /** 执行解密操作 */
        byte[] b = cipher.doFinal(b1);
        return new String(b);
    }

    /**
     * 得到公钥
     *
     * @param key 密钥字符串（经过base64编码）
     * @throws Exception 异常
     */
    public static PublicKey getPublicKey(String key) throws Exception {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(key.getBytes()));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return publicKey;
    }

    /**
     * 得到私钥
     *
     * @param key 密钥字符串（经过base64编码）
     * @throws Exception 异常
     */
    public static PrivateKey getPrivateKey(String key) throws Exception {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(key.getBytes()));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
    }

    /**
     * RSA 签名
     * @param content 传递内容
     * @param privateKey client私钥
     * @return 数字签名
     */
    public static String sign(String content, String privateKey) {
        String charset = CHAR_ENCODING;
        try {
            PKCS8EncodedKeySpec priPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey.getBytes()));
            KeyFactory keyf = KeyFactory.getInstance("RSA");
            PrivateKey priKey = keyf.generatePrivate(priPKCS8);

            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM_SHA256RSA);

            signature.initSign(priKey);
            signature.update(content.getBytes(charset));

            byte[] signed = signature.sign();

            return new String(Base64.getEncoder().encode(signed));
        } catch (Exception e) {

        }
        return null;
    }

    /**
     *  验证签名
     *
     * @param content client传递的签名数据
     * @param sign client传递的数字签名
     * @param publicKey server公钥
     * @return
     */
    public static boolean checkSign(String content, String sign, String publicKey) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            byte[] encodedKey = Base64.getDecoder().decode(publicKey);
            PublicKey pubKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));

            java.security.Signature signature = java.security.Signature.getInstance(SIGNATURE_ALGORITHM_SHA256RSA);

            signature.initVerify(pubKey);
            signature.update(content.getBytes("utf-8"));

            boolean bverify = signature.verify(Base64.getDecoder().decode(sign));
            return bverify;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    public static void main(String[] args) throws Exception {
        /*Map map = generateKeyPair();
        System.out.println("publicKey: " + map.get("publicKey"));
        System.out.println("privateKey: " + map.get("privateKey"));*/

        String pri = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCBsdlc28P9Su8a1cY6V2LTT1ADDeCD/wyQFijH66vhd724eTLYeesNO74O56HP0JHM1X07J8GSv+Xhyo0b7WbQzICYb1pUlPMY7VbBRpbIVTQic57x+ErRMocGNl5Hnnr9Od++PnfFkysqCzyiQi8j6UH83TJXqS1gIHKGbg44XdVLQwphzOmf8pul6TaBldCXBQRFIiTZMkhvW3a8sJZwb2FY4u+0B36x3l+zYVltcVVIqaQn17POzNeNHuvH1k0AiwL2TbUFvVUjrAxllIsqgl/J+Xr0C8Pt+wnKfFS3rM7OztUiNOQPF70lQQXKNSnBg/fVrxupEdCHqGQ/90IBAgMBAAECggEAM62sUQX4yHsNX4IDJMghRtX5qd3jsnT0io1p3o+Xw5W08UbJ7dxWvsUpbEL8BRS0pAwFhIbI6TKx5RCSvagRKe3y58qnEcDwROR9hzIbbuQUjA3KLdyj40vg5abQVnVdyH1BHEtD6mRD9NLZbEY3BnYxpxJ0tt1giUckm1BLNkYLrhcV5g4Wkhhc/71MkIiTl/imH91VinOpPgcslGhk4fXEUbkQBpVR/Vf9DKzbPmAcHCvA+V1Ga/1p2GYXtJgFJFJYvoKwQNwDdafd3477GQiK8OsVlto7FZHaiN/HWkC8uOnGZyNDhMXWMmFO1EvMGnCytPbKvUDW+tx3o6QIiQKBgQDGy1J/v0lvHr7I4R85wXjfA05xx5miAsAfC7ivvbgrX3aYb4eiTKcLVaIUDx/xjBeQPLqiWbV70Ix0FxFktzCk0P2pxdJIQS11jQyL9pqbu5IE/m7Od4oCr9ZVr0Z+MPYApLljzbGHA3P9TyI9rb17Z6rnDYikGYxxydXpMbUFVwKBgQCnBCM+X+Qww3FvcSU7dAJ5TmwHKaSc4IMGsGP96t1FOPtjxHas3t09R40R2vBBhKiBB4sK7kkeq0Jt37tMLjJQwfoxPixEPvY3Ikke6s008AzXynGIkXK8rSo2Pv0iXP2sNaqOPZO1bjUA1E08orS7NdzHjjLmfixp8IyZSaFEZwKBgQC3Ychw39y2DP6iAEn11WvTDhHHFAG9Whwwh3ePZswF9sJITFoqdduCsTQanPkysbDq9ZqVOXwZA4ENdlotNnBBGill+37H+Jge4Ea6tnpZPuashKli/RLq95oY4N9+eVv1q/74+j7R9XWCLwW/MA6jUDZvfiSWfJr6PN5/h8MdcQKBgQCKRHKpANn5RNR0XkdkoPYrVzE3/NG6zmOq9fzSCc6FsFbukYduNlMSmFnBnm+ozhpyN7x0oDEIot+r9r0opFYjZXOrsL0VAsrzef7vCZQ5b0Iyo/a6CS/j47g+kIcgG7wnBYbdmzzdxw86UIhg2pKlKkJNMvwQtgQu8GZ1wO8xoQKBgGpFxhhZoqKDfu12LPQjxW+ga8SS0ZcTcIxN+a/TXlsdoCT+w+Uwjmn0JcX8gSL4W9RdDcyfTnKOUKa8CZe2DhISs7LeKS/PUlrLjqPF/O0GJPRpeBc7GbhPF4PhmzSafV9VIQj88CrvD7S0VJl+Atxu1MzbIHeuFpWjpu744ARc";
        String pub = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgbHZXNvD/UrvGtXGOldi009QAw3gg/8MkBYox+ur4Xe9uHky2HnrDTu+Duehz9CRzNV9OyfBkr/l4cqNG+1m0MyAmG9aVJTzGO1WwUaWyFU0InOe8fhK0TKHBjZeR556/Tnfvj53xZMrKgs8okIvI+lB/N0yV6ktYCByhm4OOF3VS0MKYczpn/Kbpek2gZXQlwUERSIk2TJIb1t2vLCWcG9hWOLvtAd+sd5fs2FZbXFVSKmkJ9ezzszXjR7rx9ZNAIsC9k21Bb1VI6wMZZSLKoJfyfl69AvD7fsJynxUt6zOzs7VIjTkDxe9JUEFyjUpwYP31a8bqRHQh6hkP/dCAQIDAQAB";

        String test = "RSA2 测试一下";
        // 公钥加密
        String decryptStr = encrypt(test, pub);
        // 私钥解密
        System.out.println(decrypt(decryptStr, pri));

    }
}