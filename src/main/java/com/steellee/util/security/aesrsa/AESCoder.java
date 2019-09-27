package com.steellee.util.security.aesrsa;

import java.io.UnsupportedEncodingException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/**
 * 对称加密算法: 适用DES,AES...
 *
 * @author steellee
 * @date 2019/1/17
 */
public class AESCoder {

    /** 算法/模式/补码方式 */
    public static final String AES_TYPE = "AES/CBC/PKCS5Padding";
    public static final String CODE_TYPE = "UTF-8";
    public static final String AES_KEY = "a98fdfd1f87631a2a98fdfabf87631a2";
    public static final String IVPARA = "0000000000000000";
    //字符补全
    private static final String[] consult = new String[]{"0","1","2","3","4","5","6","7","8","9","A","B","C","D","E","F","G"};

    private static Logger logger = Logger.getLogger(AESCoder.class);
    /**
     * 加密
     * <pre>
     * TODO 此处添加方法描述
     * </pre>
     * @date 2019年2月13日 上午8:42:59
     * @param cleartext 待加密串
     * @param aeskey 加密因子
     * @return
     * @throws Exception
     */
    public static String encrypt(String cleartext, String aeskey) throws Exception{
        try {
            byte[] encodeFormat = Hex.decodeHex(aeskey.toCharArray());
            IvParameterSpec zeroIv = new IvParameterSpec(IVPARA.getBytes());
            //两个参数，第一个为私钥字节数组， 第二个为加密方式 AES或者DES
            SecretKeySpec key = new SecretKeySpec(encodeFormat, "AES");
            //实例化加密类，参数为加密方式，要写全
            Cipher cipher = Cipher.getInstance(AES_TYPE); //PKCS5Padding比PKCS7Padding效率高，PKCS7Padding可支持IOS加解密
            //初始化，此方法可以采用三种方式，按加密算法要求来添加。（1）无第三个参数（2）第三个参数为SecureRandom random = new SecureRandom();中random对象，随机数。(AES不可采用这种方法)（3）采用此代码中的IVParameterSpec
            //加密时使用:ENCRYPT_MODE;  解密时使用:DECRYPT_MODE;
            cipher.init(Cipher.ENCRYPT_MODE, key, zeroIv); //CBC类型的可以在第三个参数传递偏移量zeroIv,ECB没有偏移量
            //加密操作,返回加密后的字节数组，然后需要编码。主要编解码方式有Base64, HEX, UUE,7bit等等。此处看服务器需要什么编码方式
            if(AES_TYPE.equals("AES/ECB/NoPadding")){
                cleartext = completionCodeFor16Bytes(cleartext);
            }
            byte[] encryptedData = cipher.doFinal(cleartext.getBytes(CODE_TYPE));

            return new BASE64Encoder().encode(encryptedData);
        } catch (Exception e) {
            logger.error("加密出现异常", e);
            throw e;
        }
    }

    /**
     * 解密
     * <pre>
     * TODO 此处添加方法描述
     * </pre>
     * @date 2019年2月13日 上午8:43:43
     * @param encrypted 待解密串
     * @param aeskey 解密因子
     * @return
     * @throws Exception
     */
    public static String decrypt(String encrypted, String aeskey) throws Exception{
        try {
            byte[] encodeFormat = Hex.decodeHex(aeskey.toCharArray());
            IvParameterSpec zeroIv = new IvParameterSpec(IVPARA.getBytes());
            byte[] byteMi = new BASE64Decoder().decodeBuffer(encrypted);
            SecretKeySpec key = new SecretKeySpec(encodeFormat, "AES");
            Cipher cipher = Cipher.getInstance(AES_TYPE);
            cipher.init(Cipher.DECRYPT_MODE, key, zeroIv);
            byte[] decryptedData = cipher.doFinal(byteMi);
            String content = new String(decryptedData);
            //还原
            if(AES_TYPE.equals("AES/ECB/NoPadding")){
                System.out.println("解密内容还原前: "+content);
                content = resumeCodeOf16Bytes(content);
            }
            return content;
        } catch (Exception e) {
            logger.error("解密出现异常", e);
            throw e;
        }
    }

    public static String completionCodeFor16Bytes(String str) throws UnsupportedEncodingException{
        int num = str.getBytes(CODE_TYPE).length;
        int index = num%16;
        //进行加密内容补全操作, 加密内容应该为 16字节的倍数, 当不足16*n字节是进行补全, 差一位时 补全16+1位
        //补全字符 以 $ 开始,$后一位代表$后补全字符位数,之后全部以0进行补全;
        if(index != 0){
            StringBuffer sbBuffer = new StringBuffer(str);
            if(16-index == 1){
                sbBuffer.append("$" + consult[16-1] + addStr(16-1-1));
            }else{
                sbBuffer.append("$" + consult[16-index-1] + addStr(16-index-1-1));
            }
            str = sbBuffer.toString();
        }
        return str;
    }

    //追加字符
    public static String addStr(int num){
        StringBuffer sbBuffer = new StringBuffer("");
        for (int i = 0; i < num; i++) {
            sbBuffer.append("0");
        }
        return sbBuffer.toString();
    }

    public static String resumeCodeOf16Bytes(String str){
        int indexOf = str.lastIndexOf("$");
        if(indexOf == -1){
            return str;
        }
        String trim = str.substring(indexOf+1,indexOf+2).trim();
        int num = 0;
        for (int i = 0; i < consult.length; i++) {
            if(trim.equals(consult[i])){
                num = i;
            }
        }
        if(num == 0){
            return str;
        }
        return str.substring(0,indexOf).trim();
    }


    public static void main(String[] args) throws Exception {
        String content = "我们来测试一下";
        String key = "a98fdfd1f87631a2a98fdfabf87631a2";
        test(content, key);
    }

    public static void test(String content, String key) throws Exception{
        logger.info("加密内容：" + content);
        // 加密
        String encryptResult = encrypt(content,AES_KEY);
        logger.info("加密后：" + encryptResult);

        // 解密
        String decryptResult = decrypt(encryptResult,AES_KEY);
        logger.info("解密完成后：" + decryptResult);
    }
}
