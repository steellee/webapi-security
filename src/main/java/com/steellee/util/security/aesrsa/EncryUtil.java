package com.steellee.util.security.aesrsa;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.TypeReference;
import org.apache.commons.lang.StringUtils;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;

/**
 * 验签加密工具
 *
 * @author steellee
 * @date 2019/1/13
 */
public class EncryUtil {

    /**
     * 生成RSA签名(客户端)
     */
    public static String handleRSA(HashMap<String, Object> map, String privateKey) {
        StringBuffer sbuffer = new StringBuffer();
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            sbuffer.append(entry.getValue());
        }
        String signTemp = sbuffer.toString();

        String sign = "";
        if (StringUtils.isNotEmpty(privateKey)) {
            sign = RSA.sign(signTemp, privateKey);
        }
        return sign;
    }

    /**
     * 返回的结果进行验签(服务端)
     *
     * @param data             业务数据密文
     * @param encrypt_key      对ybAesKey加密后的密文
     * @param clientPublicKey  客户端公钥
     * @param serverPrivateKey 服务器私钥
     * @return 验签是否通过
     */
    public static boolean checkDecryptAndSign(String data, String encrypt_key, String clientPublicKey,
        String serverPrivateKey) throws Exception{

        /** 1.使用server的私钥解开aesEncrypt。 */
        String AESKey = "";
        try {
            AESKey = RSA.decrypt(encrypt_key, serverPrivateKey);
        } catch (Exception e) {
            /** AES密钥解密失败 */
            e.printStackTrace();
            return false;
        }

        /** 2.用aeskey解开data。取得data明文 */
        String realData = AESCoder.decrypt(data, AESKey);

        HashMap<String, String> map = JSON.parseObject(realData, new TypeReference<HashMap<String, String>>() {});

        /** 3.取得data明文sign。 */
        String sign = StringUtils.trimToEmpty(map.get("sign"));

        /** 4.对map中的值进行验证 */
        StringBuffer signData = new StringBuffer();
        Iterator<Entry<String, String>> iter = map.entrySet().iterator();
        while (iter.hasNext()) {
            Entry<String, String> entry = iter.next();

            /** 把sign参数隔过去 */
            if (StringUtils.equals((String)entry.getKey(), "sign")) {
                continue;
            }
            signData.append(entry.getValue() == null ? "" : entry.getValue());
        }

        /** 5. result为true时表明验签通过 */
        boolean result = RSA.checkSign(signData.toString(), sign, clientPublicKey);

        return result;
    }
}
