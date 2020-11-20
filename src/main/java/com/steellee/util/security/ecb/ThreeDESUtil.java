package com.steellee.util.security.ecb;

import java.io.UnsupportedEncodingException;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * js（请查看resource下的3DES目录demo）与java通用的3DES(ECB,CBC)+Base64加密编码,解码解密
 * 3DES加密解密和BASE64编码解码混合使用
 * https://blog.csdn.net/bob_Xing_Yang/article/details/80417383
 */
public class ThreeDESUtil {

    //key必须在16位/24位/32位,下面使用的是24位,不足24位则后面余数补0填充满24位
//    public static final String key="12345677654321";
    //定义加密算法，有DES、DESede(即3DES)、Blowfish
    private static final String Algorithm = "DESede";
    //如果使用DESede,默认则使用"DESede/ECB/PKCS5Padding"  ECB:电子密码本形式加密,
    // BCB:密码块链接加密
//    private static final String DES_TYPE = "DESede/ECB/PKCS5Padding";
    private static final String DES_TYPE = "DESede/CBC/PKCS5Padding";
//    private static final String DES_TYPE = "DESede/ECB/NoPadding";


    /**
     * 3DES加密方法
     * @param src 源数据的字节数组
     * @return
     */
    public static byte[] encryptMode(byte[] src,String key) {
        try {
            SecretKey deskey = new SecretKeySpec(build3DesKey(key), Algorithm);    //生成密钥
            Cipher c1 = Cipher.getInstance(DES_TYPE);    //实例化负责加密/解密的Cipher工具类
            c1.init(Cipher.ENCRYPT_MODE, deskey);    //初始化为加密模式
            return c1.doFinal(src);
        } catch (java.security.NoSuchAlgorithmException e1) {
            e1.printStackTrace();
        } catch (javax.crypto.NoSuchPaddingException e2) {
            e2.printStackTrace();
        } catch (Exception e3) {
            e3.printStackTrace();
        }
        return null;
    }
    //3DES解密
    public static byte[] decrypt(byte[] data,String key){
        try {
            SecretKey deskey = new SecretKeySpec(build3DesKey(key), Algorithm);    //生成密钥
            Cipher cipher = Cipher.getInstance(DES_TYPE);
            cipher.init(Cipher.DECRYPT_MODE,deskey);
            return cipher.doFinal(data);
        } catch (Exception ex) {
            //解密失败，打日志
            ex.printStackTrace();
        }
        return null;
    }

    /**
     *  3DES加密Base64编码处理方法
     * @param sourceData 字符串
     * @param key 用于3DES加密解密的密钥
     * @return  经过3DES+Base64加密后的字符串
     */
    public static String encode3DesBase64(String sourceData, String key){
        byte [] base = encryptMode(sourceData.getBytes(), key);
        return  Base64.getEncoder().encodeToString(base);
    }

    /**
     * 将3DES+Base64加密后的byte数组进行解密
     * @param encryptData 先3DES+Base64加密后的 byte数组
     * @param key  用于3DES加密解密的密钥
     * @return 未加密前的字符串
     */
    public static String decode3DesBase64(String encryptData, String key){
        byte[] b = null;
        String result = null;
        try {
            b = decrypt(Base64.getDecoder().decode(encryptData.getBytes()), key);
            result = new String(b, "utf-8");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }
    //构建3DES密钥
    public static byte[] build3DesKey(String keyStr) throws UnsupportedEncodingException {
        byte[] key = new byte[24];    //声明一个24位的字节数组，默认里面都是0
        byte[] temp = keyStr.getBytes("UTF-8");    //将字符串转成字节数组
        /*
         * 执行数组拷贝
         * System.arraycopy(源数组，从源数组哪里开始拷贝，目标数组，拷贝多少位)
         */
        if(key.length > temp.length){
            //如果temp不够24位，则拷贝temp数组整个长度的内容到key数组中
            System.arraycopy(temp, 0, key, 0, temp.length);
        }else{
            //如果temp大于24位，则拷贝temp数组24个长度的内容到key数组中
            System.arraycopy(temp, 0, key, 0, key.length);
        }
        return key;
    }

    public static void main(String[] args) throws Exception{
        String source= "987123876345dfsdfadfsadfs撒旦飞洒地方！@#";
        String securityKey = "1234567";
//        String securityKey = "5865a298396e765babe959db30f493c52dfb7f494721813a416e5a61a38a386c";
//        String newKey = Base64.getEncoder().encodeToString(build3DesKey(securityKey));
//        System.out.println("newKey: " + newKey);

        String encrySource = encode3DesBase64(source, securityKey);
        System.out.println(source + "加密后：" + encrySource);
        System.out.println("解密后： " + decode3DesBase64(encrySource, securityKey));
    }
}