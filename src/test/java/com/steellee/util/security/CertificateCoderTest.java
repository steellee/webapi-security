package com.steellee.util.security;

import java.util.Base64;

/**
 * @Description 公私钥证书加解密演示
 *
 * @author steellee
 * @version V1.0.0
 * @date 2019/01/19
 */
public class CertificateCoderTest {

    public static final String SERVER_CERT_LOCATION  = "D:\\work\\ideaworkspace\\test\\sao\\github\\webapi-security\\src\\main\\resources\\cert\\server.cer";
    public static final String SERVER_PCERT_LOCATION = "D:\\work\\ideaworkspace\\test\\sao\\github\\webapi-security\\src\\main\\resources\\cert\\server.p12";

    public static void main(String[] args) throws Exception {
        CertificateCoder coder = new CertificateCoder();
        String context = "context:1234567890@abcdef";
        System.out.println("原文:" + context);
        byte[] bytes = coder.encryptByPublicKey(context.getBytes("UTF-8"),
            SERVER_CERT_LOCATION);
        String encryptBase64 = new String(Base64.getEncoder().encode(bytes), "UTF-8");
        System.out.println("公钥加密后：" + encryptBase64);
        //String str="BOcK4HQyuiRr8uf752nbPZKuebgA1uQlv3lvxqdjuZiogSCPh9jQJTW9n4RKaOnK7hpYmjr9MNm2QkT2jO7Vyj4/B+qvkXTQnqEfYwHxtvDrSAdcl5kM8ghFipbO3l88Wi9/cfCpgCY73Y5okCt2VDcMceeltozgSEz43f3Rktc=";
        byte[] bytes1 = Base64.getDecoder().decode(encryptBase64);
        byte[] src = coder.decryptByPrivateKey(bytes1, SERVER_PCERT_LOCATION, "000000");
        //
        System.out.println("私钥解密后：" + new String(src));
    }
}
