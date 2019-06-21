package com.steellee.util.security;

import org.apache.commons.lang.CharEncoding;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Enumeration;

/**
 * 证书加解密模块
 *
 * @author steellee
 * @version V1.0.0
 * @date 2019/06/19
 */
public class CertificateCoder {

    /**
     * 证书类型X509
     */
    private static final String CERT_TYPE         = "X.509";

    /**
     * 密钥库类型PCKS12
     */
    private static final String STORE_TYPE        = "PKCS12";

    /**
     * 服务器私钥
     */
    private PrivateKey          privateKey;

    /**
     * RSA最大加密明文大小
     */
    private static final int    MAX_ENCRYPT_BLOCK = 117;

    /**
     * RSA最大解密密文大小
     */
    private static final int    MAX_DECRYPT_BLOCK = 128;

    /**
     * 由certPath获得私钥
     * 
     * @param certPath 密钥库路径
     * @param password 密码
     * @return PrivateKey 私钥
     * @throws Exception
     */
    @SuppressWarnings("rawtypes")
    public PrivateKey getPrivateKeyByKeyStore(String certPath, String password) throws Exception {

        // 获得密钥库
        KeyStore ks = getKeyStore(certPath, password);
        Enumeration keyenum = ks.aliases();
        String keyAlias = null;
        // 获得私钥
        if (keyenum.hasMoreElements()) {
            keyAlias = (String) keyenum.nextElement();
        }
        privateKey = (PrivateKey) ks.getKey(keyAlias, password.toCharArray());
        return privateKey;

    }

    /**
     * 由KeyStore获得私钥
     * 
     * @param keyStorePath 密钥库路径
     * @param alias 别名
     * @param password 密码
     * @return PrivateKey 私钥
     * @throws Exception
     */
    public PublicKey getPublicKeyByKeyStore(String keyStorePath, String alias, String password)
                                                                                               throws Exception {

        // 获得密钥库
        KeyStore ks = getCertKeyStore(keyStorePath, password);
        // 获得私钥
        Certificate certificate = ks.getCertificate(alias);
        return certificate.getPublicKey();

    }

    /**
     * 由Certificate获得公钥
     * 
     * @param certificatePath 证书路径
     * @return PublicKey 公钥
     * @throws Exception
     */
    public PublicKey getPublicKeyByCertificate(String certificatePath) throws Exception {

        // 获得证书
        Certificate certificate = getCertificate(certificatePath);
        // 获得公钥
        return certificate.getPublicKey();

    }

    /**
     * 获得Certificate
     * 
     * @param certificatePath 证书路径
     * @return Certificate 证书
     * @throws Exception
     */
    private X509Certificate getCertificate(String certificatePath) throws Exception {

        // 实例化证书工厂
        CertificateFactory certificateFactory = CertificateFactory.getInstance(CERT_TYPE);
        // 取得证书文件流
        FileInputStream in = new FileInputStream(certificatePath);
        // 生成证书
        Certificate certificate = certificateFactory.generateCertificate(in);
        // 关闭证书文件流
        in.close();
        return (X509Certificate) certificate;
    }

    /**
     * 获得KeyStore
     * 
     * @param keyStorePath 密钥库路径
     * @param password 密码
     * @return KeyStore 密钥库
     * @throws Exception
     */
    private KeyStore getKeyStore(String keyStorePath, String password) throws Exception {

        // 实例化密钥库
        KeyStore ks = KeyStore.getInstance(STORE_TYPE);
        // 获得密钥库文件流
        FileInputStream in = new FileInputStream(keyStorePath);
        // 加载密钥库
        ks.load(in, password.toCharArray());
        // 关闭密钥库文件流
        in.close();
        return ks;
    }

    /**
     * 获得KeyStore
     * 
     * @param keyStorePath 密钥库路径
     * @param password 密码
     * @return KeyStore 密钥库
     * @throws Exception
     */
    private KeyStore getCertKeyStore(String keyStorePath, String password) throws Exception {

        // 实例化密钥库
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        // 获得密钥库文件流
        FileInputStream in = new FileInputStream(keyStorePath);
        // 加载密钥库
        ks.load(in, password.toCharArray());
        // 关闭密钥库文件流
        in.close();
        return ks;
    }

    /**
     * 公钥加密
     * 
     * @param data 待加密数据
     * @param serverCertPath 证书路径
     * @return byte[] 加密数据
     * @throws Exception
     */
    public byte[] encryptByPublicKey(byte[] data, String serverCertPath) throws Exception {
        // 取得公钥
        PublicKey publicKey = getPublicKeyByCertificate(serverCertPath);

        if (publicKey == null) {
            return null;
        }
        // 对数据加密
        Cipher cipher = Cipher.getInstance(publicKey.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段加密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_ENCRYPT_BLOCK;
        }
        byte[] encryptedData = out.toByteArray();
        out.close();
        return encryptedData;

    }

    /**
     * 公钥加密
     * 
     * @param data 待加密数据
     * @param keyStorePath 证书路径
     * @param alias 别名
     * @param password 密码
     * @return byte[] 加密数据
     * @throws Exception
     */
    public byte[] encryptByPublicKey(byte[] data, String keyStorePath, String alias, String password)
                                                                                                     throws Exception {

        // 取得公钥
        PublicKey publicKey = getPublicKeyByKeyStore(keyStorePath, alias, password);
        // 对数据加密
        Cipher cipher = Cipher.getInstance(publicKey.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段加密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_ENCRYPT_BLOCK;
        }
        byte[] encryptedData = out.toByteArray();
        out.close();
        return encryptedData;

    }

    /**
     * 私钥解密
     * 
     * @param data 待解密数据
     * @param certificatePath 密钥库路径
     * @param password 密码
     * @return byte[] 解密数据
     * @throws Exception
     */
    public byte[] decryptByPrivateKey(byte[] data, String certificatePath, String password)
                                                                                           throws Exception {

        // 取得私钥
        privateKey = getPrivateKeyByKeyStore(certificatePath, password);
        // 对数据加密
        Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段解密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
                cache = cipher.doFinal(data, offSet, MAX_DECRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_DECRYPT_BLOCK;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();
        return decryptedData;

    }

    /**
     * 签名
     *
     * @param data 待签名数据
     * @param certificatePath 密钥库路径
     * @param password 密码
     * @return byte[] 签名
     * @throws Exception
     */
    public byte[] sign(byte[] data, String certificatePath, String password) throws Exception {

        // 构建签名，由证书指定签名算法
        Signature signature = Signature.getInstance("SHA1withRSA");
        // 获取私钥
        privateKey = getPrivateKeyByKeyStore(certificatePath, password);
        // 初始化签名，由私钥构建
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    /**
     * 验证签名
     * 
     * @param data 数据
     * @param signdata 签名
     * @param certificate 证书路径
     * @return boolean 验证通过为真
     * @throws Exception
     */
    public boolean verify(byte[] data, byte[] signdata, X509Certificate certificate, String alias)
                                                                                                  throws Exception {

        // 获得得到密钥库
        //KeyStore ks = getCertKeyStore(keyStorePath, password);

        // 获取证书
        //X509Certificate x509Certificate = (X509Certificate) ks.getCertificate(alias);

        // 由证书构建签名
        Signature signature = Signature.getInstance("SHA1withRSA");

        // 由证书初始化签名，实际上是使用了证书中的公钥
        signature.initVerify(certificate);

        signature.update(data);

        return signature.verify(signdata);

    }

    public static void main(String[] args) throws Exception {
        CertificateCoder coder = new CertificateCoder();
        String deskey = "E6D137BC70D9A15B";
        String pubkeyLocation = "D:/padposserver.cer";
        byte[] ecode = coder
            .encryptByPublicKey(deskey.getBytes(CharEncoding.UTF_8), pubkeyLocation);
        String base64 = new String(Base64.getEncoder().encode(ecode));
        System.out.println(base64);
        //        String keyloaction = "D:\\home\\lklsecurity\\ssl\\padpos\\certs\\20170222\\822290054110676-91027522.p12";
        //        String raw = "822290054110676&91027522&867707027723198";
        //        byte[] endata = coder.sign(raw.getBytes(), keyloaction, "123456");
        //        System.out.println(StringUtils.newStringUtf8(Base64.encodeBase64(endata, false)));

        String p12Key = "D:/padposserver.p12";
        byte[] raw = coder.decryptByPrivateKey(Base64.getDecoder().decode("fA4uyrmb1iAmQD2WvXrYUNa1Ulw6LZDHqB8+x6T3CUR0ZPyKcZPFzMVw2dduAszQXJ6rHZE2Ukd2Nq7DK/cGs9IQ7KA7dvuEEVZmepURFxVOzHG4N3GDlGTp3d+liDnm29io3LQ6Cl5dY+T3axpsgHmknPZ+CVZAN2vcnB7NaAA="), p12Key, "000000");
        System.out.println(new String(raw));
    }
}