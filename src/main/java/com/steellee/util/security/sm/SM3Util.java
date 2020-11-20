package com.steellee.util.security.sm;

import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

import java.net.URLEncoder;
import java.util.Base64;

/**
 * SM3 消息摘要。
 * js（请查看resource下的SM3目录demo）与java通用
 *
 * SM3算法，已公开，可以用MD5作为对比理解。输出长度为256Bit（32Byte），因此SM3算法的安全性要高于MD5算法和SHA-1算法。
 * <p>
 * 场景应用： 数字签名和验证消息认证码的生成与验证以及随机数的生成
 *
 * @author steellee
 * @date 2019/1/17
 */
public class SM3Util {

    /**
     * 获取数字签名
     *
     * @param srcData 源数据
     * @return
     */
    public static String hash(byte[] srcData) {
        SM3Digest digest = new SM3Digest();
        digest.update(srcData, 0, srcData.length);
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);
        return Base64.getEncoder().encodeToString(hash);
    }

    /**
     * 签名（SM3算法 + Base64）, 编码采用：UTF-8
     *
     * @param srcData   源数据
     * @param secretKey 密钥
     * @return 数字签名
     */
    public static String hmac(String srcData, String secretKey) throws Exception {
        KeyParameter keyParameter = new KeyParameter(secretKey.getBytes("UTF-8"));
        SM3Digest digest = new SM3Digest();
        HMac mac = new HMac(digest);
        mac.init(keyParameter);
        byte[] hsrcData = srcData.getBytes("UTF-8");
        mac.update(hsrcData, 0, hsrcData.length);
        byte[] signData = new byte[mac.getMacSize()];
        mac.doFinal(signData, 0);
        return Base64.getEncoder().encodeToString(signData);
    }

    /**
     * 验证消息/签名
     *
     * @param srcData 源数据
     * @param sm3Hash 数字签名
     * @return 是否匹配
     */
    public static boolean verify(String srcData, String sm3Hash) throws Exception {
        String newHash = hash(srcData.getBytes("UTF-8"));
        if (newHash.equals(sm3Hash)) {
//        if (Arrays.equals(newHash, sm3Hash)) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * 验证消息/签名
     *
     * @param srcData   源数据
     * @param secretKey 密钥key
     * @param sm3Hash   数字签名
     * @return 是否匹配
     */
    public static boolean verify2(String srcData, String sm3Hash, String secretKey) throws Exception {
        String newHash = hmac(secretKey, srcData);
        if (newHash.equals(sm3Hash)) {
            return true;
        } else {
            return false;
        }
    }

    public static void main(String[] args) throws Exception {
        String source = "abc124567我们";
        String encodeSource = Base64.getEncoder().encodeToString(source.getBytes("UTF-8"));
        String urlEncodeSource = URLEncoder.encode(source,"UTF-8");
//        System.out.println(encodeSource);
        String key = "12345678";
        System.out.println("获取数字签名(无key): "+ hash(encodeSource.getBytes("UTF-8")));
        System.out.println("获取数字签名(有key): "+ hmac(urlEncodeSource, key));
    }
}
