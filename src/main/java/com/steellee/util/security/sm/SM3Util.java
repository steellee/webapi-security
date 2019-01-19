package com.steellee.util.security.sm;

import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

import java.util.Arrays;

/**
 * SM3 消息摘要。
 *
 * SM3算法，已公开，可以用MD5作为对比理解。输出长度为256Bit（32Byte），因此SM3算法的安全性要高于MD5算法和SHA-1算法。
 * <p>
 * 场景应用： 数字签名和验证消息认证码的生成与验证以及随机数的生成
 *
 * @author steellee
 * @date 2019/1/17
 */
public class SM3Util extends GMBaseUtil {

    /**
     * 获取数字签名
     *
     * @param srcData 源数据
     * @return
     */
    public static byte[] hash(byte[] srcData) {
        SM3Digest digest = new SM3Digest();
        digest.update(srcData, 0, srcData.length);
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);
        return hash;
    }

    /**
     * 签名（SM3算法 + Base64）, 编码采用：UTF-8
     *
     * @param secretKey 密钥
     * @param srcData   源数据
     * @return 数字签名
     */
    public static String hmac(String secretKey, String srcData) throws Exception {
        KeyParameter keyParameter = new KeyParameter(secretKey.getBytes("UTF-8"));
        SM3Digest digest = new SM3Digest();
        HMac mac = new HMac(digest);
        mac.init(keyParameter);
        byte[] hsrcData = srcData.getBytes("UTF-8");
        mac.update(hsrcData, 0, hsrcData.length);
        byte[] signData = new byte[mac.getMacSize()];
        mac.doFinal(signData, 0);
        return new sun.misc.BASE64Encoder().encode(signData);
    }

    /**
     * 验证消息/签名
     *
     * @param srcData 源数据
     * @param sm3Hash 数字签名
     * @return 是否匹配
     */
    public static boolean verify(byte[] srcData, byte[] sm3Hash) {
        byte[] newHash = hash(srcData);
        if (Arrays.equals(newHash, sm3Hash)) {
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
}
