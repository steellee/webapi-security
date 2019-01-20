package com.steellee.util.security.aesrsa;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.junit.Assert;
import org.junit.Test;

import java.util.HashMap;

/**
 * 开放接口方案：AES加解密数据 + RSA验签 应用示例
 *
 * @author steellee
 * @version V1.0.0
 * @date 2019/01/13
 */
public class AesRsaCoderTest {

    /**
     * 1. 服务器端(server)和客户端(client)分别生成自己的密钥对
     * 2. server和client分别交换自己的公钥
     */
    public final String clientPrivateKey = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCToobfDGJT/Ek8OwkYCmlv647dcrC+t+jhH0lFij7vOoVvzI8UBtDluRdV+1X3cYaEogVsFz5u+CeIN2PEc9hIus+LnvrALkuFW53l3HQgUil5FmNoIbgdXk25vGR97fsmLI99utDj+kAcfK42ZQ/TpihzM4m8wUk/UuRdOMPYtrtJhMEYcOqtWVYh4VF4R8DpqA9PjnTrpkseWReu4gVULHw7Ep55A8AqZ/Y0DVOEBn9UHCzCgs8mw8LXII68yUmWgOVSrws0/WxYLQJaaqW8guJW+4vxvK4J+Su85BOJGXkUkyPKATPwInFTb+1QKxMJWkfFJC0Xa+NN2esDUj3vAgMBAAECggEAeCnLGPTde3pWqX1rk3O2CfByoe/dx/2swL9URhOV0eWSAkM/GY/Kq5ARXFxrxjFSydWOEEKDAJNeqdJbk+SuX9QdZYkKky2bLno5dIQQyNXXB8WfN3xqfQzquoiKSq1Ow+11BWLu7wAa+pTIv2FWlnAhcFK8gzPXSIFRekbfsR0drGVY+vVyR4YPzwcReUtx57jowWAzJl6hYpJKw4OGw+5Tp0aK8671rvavtH1uyzpu0+APOmILmTNEDYlyb/kHBNWHLDYYFtZLFWc2lQzOxYRXwZ5tyFhpyXuAsWecZBJSBWfqyIzl7c0R0fOHEfe+irN+N7+OmWBC2Ya1/lTlQQKBgQDD69Nv0YVAe1ff6vinB3MfPPQ4lAN2Ehxv6jeHygbf09LQkGTMHxeob1ELCviCf1JfiO5WU6mTdZawuYpDICnj4yKg7xjN/jCNpqv6+Un6jKc6Ya4FLuxvQysprrwAH8+KfMn4zFGfKPEP7n3yZxb0ATeiAsNvPaRaQhbRDS4yUQKBgQDA6CK53qkGyW3XSbLJjqEcZ35r0uQw+FdIg7acH5F8maf3kEDoNyXDXtjD9uK3T4IKDT2pAF++7PN0dRRLUSmK+NlFaF7TbNjlqc39O4sFMKFR/DQGts4L6jnzhNb9OxaNFWuLOQF5BpEMx3d9UTo0lADu8QIZbMj25DpueIMcPwKBgQCzJCqMj7ObpixPXfZGI5Wr9nwIT65qg1zlJ+/mhV+LwY99jMndqoBjToV352wbRnf3SqlC3fSsFFTY+o3lmr8y1DiRlo3DrKyQmNmf/dka8wjlZPNNYf5mLbCFyHO2WV/XbQrwJ0JqmXDx9EvNHV3rdkF8LbKtQFvK+6sJM1gOQQKBgClw9RzW/5rMpQMt+vGf6W6PsTH6sTjv8NhMK2uowHlzDQl6/OamCj/JXWnj3Nqigv4j0A5BXVBH2Rk4ma6Adhs70Hk/rbdf18ymyPDQ3NG1m8JgGtEibmtS2zY8YG8wRWzzoBHdojpctcZ4B2xticKH1Rd/wQKzQwz/BKp8yzXDAoGBALNGi/k2IZFdWNh7tA+j/EZ1O96c21AQEZViREPq/0gdJ7ZulUNHXQWVpQo4ZQA5gwHhIAvSf0QTe/mE99uQnDnBjYUXuTgAxYazbLoYKx110Rmdy14E6CTYCu3QmqTaG2CtBeDP1bZ8PQrvKgN68oFty4tX2uumrBf6aGH0X2um";

    public final String clientPublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAk6KG3wxiU/xJPDsJGAppb+uO3XKwvrfo4R9JRYo+7zqFb8yPFAbQ5bkXVftV93GGhKIFbBc+bvgniDdjxHPYSLrPi576wC5LhVud5dx0IFIpeRZjaCG4HV5Nubxkfe37JiyPfbrQ4/pAHHyuNmUP06YoczOJvMFJP1LkXTjD2La7SYTBGHDqrVlWIeFReEfA6agPT45066ZLHlkXruIFVCx8OxKeeQPAKmf2NA1ThAZ/VBwswoLPJsPC1yCOvMlJloDlUq8LNP1sWC0CWmqlvILiVvuL8byuCfkrvOQTiRl5FJMjygEz8CJxU2/tUCsTCVpHxSQtF2vjTdnrA1I97wIDAQAB";


    public final String serverPrivateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALIZ98KqgLW8IMt4" +
        "G+N+4d3DiOiEa+5s6lCMSGE/NbU9stJEqw0EuCP54MY6JkT0HCYTCrLXqww6rSQy" +
        "WF7BNCVGssk2XDcvSKiCz1ZMgabd6XVK5kvIycySydXQ0Ky6rnfxw8w2mllHABFv" +
        "s1eamaHQozv18n/XGqemjW2BFy/jAgMBAAECgYAxT3FCi3SBXKnzy7hk/z9H6Bhi" +
        "0C8V3z/stzpe+mJDYOa+wtZdD15wT4HFQFpSIwgcHo+Kvp2UEDbZ27qN2Y43AZbF" +
        "9LOalWTRUzYtr8wL8MIbgtew/QQ9YFNWdkTZ6MxCItjD/mSz3Lrkcphvbsx4VoCV" +
        "YIJ04r+Loi0t9g0guQJBANvkpfrq0bLVRYWfaigjkx47mr0trJkB7mjADe69Iqts" +
        "M/2x5dHPpClDK78yzAWxU2BrYzOd31QIOm32iMIvRxUCQQDPWJPMOzcq8Jqs1PAM" +
        "7D0hxnvF3tSJB0CJCQWdGFkJiuIYSbrWnCVF78jJyU2AK1H3RDi9BzGPL2Z3i2Si" +
        "+9kXAkAPnKtAJl3fEY9PDmNuGCCA3AB/f/eqIV345/HVSm5kt1j1oSTNAa4JE/DO" +
        "MWAU42MlDFrNtl69y5vCZOeOyeaFAkBOJieGmWcAozDZJWTYqg2cdk/eU08t2nLj" +
        "c2gPPscIRrVSzC9EhhOyWV8HVv0D6s/471inPlfajNYFBp/Goj+/AkEAiejHX/58" +
        "Vv8+ccW22RMZmyxiHcZpTw9hz7vHUCWv03+fyVGtGMhJ4xuPt8UaZm91yHSPWWar" +
        "M8Xa7errKaXN9A==";
    public final String serverPublicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCyGffCqoC1vCDLeBvjfuHdw4jo" +
        "hGvubOpQjEhhPzW1PbLSRKsNBLgj+eDGOiZE9BwmEwqy16sMOq0kMlhewTQlRrLJ" +
        "Nlw3L0iogs9WTIGm3el1SuZLyMnMksnV0NCsuq538cPMNppZRwARb7NXmpmh0KM7" +
        "9fJ/1xqnpo1tgRcv4wIDAQAB";

    /** 固定AES密钥*/
    public final String ACCESS_KEY = "kl0QkB7NB98qmSSB";

    @Test
    public void testSignAndVerify() {
        HashMap<String, Object> params = new HashMap<String, Object>();
        params.put("sid", "QRwgw5xVKY+GkcPKD0FIWnUiTyKsQsAB");
        params.put("orderId", "0300201901000222");
        params.put("dfMercId", "822290063000044");
        params.put("amt", "10000");

        try {
            client(params);
            server();
        } catch (Exception ex){
            ex.printStackTrace();
            Assert.fail();
        }
    }

    /**
     * 客户端逻辑
     * @param params 请求明文数据
     * @throws Exception
     */
    public void client(HashMap<String, Object> params) throws Exception {

        // 3. client生成AES密钥(aesKey)
//        String aesKey = ACCESS_KEY;
        String aesKey = SecureRandomUtil.getRandom(16);
        System.out.println("3. client生成AES密钥(aesKey) - 随机生成AES密钥: " + aesKey);

        // 4. client使用sever的RSA公钥对aesKey进行加密(encryptkey)
        String encryptkey = RSA.encrypt(aesKey, serverPublicKey);
        System.out.println("4. client使用sever的RSA公钥对aesKey进行加密(encryptkey): "+encryptkey );

        // 5. client使用自己的RSA私钥对请求明文数据(params)进行数字签名
        String sign = EncryUtil.handleRSA(params, clientPrivateKey);
        System.out.println("5. client使用自己的RSA私钥对请求明文数据(params)进行数字签名: " + sign);

        params.put("sign", sign);
        // 6. 将签名加入到请求参数中，然后转换为json格式
        String jsonParams = JSON.toJSONString(params);
        System.out.println("6. 将签名加入到请求参数中，然后转换为json格式--加密前的请求数据:\n" +  jsonParams);

        // 7. client使用aesKey对请求数据(jsonParams)进行加密得到密文(data)
        String data = AESCoder.encryptToBase64(jsonParams, aesKey);
        System.out.println("7. client使用aesKey对json数据进行加密得到密文(data): "+ data);


        // 8. 分别将data和encryptkey作为参数传输给服务器端
        RequestInfo.data = data;
        RequestInfo.encryptkey = encryptkey;
        System.out.println("加密后的请求数据:\n" +  new RequestInfo().toString());
    }

    /**
     * 服务端逻辑
     * @throws Exception
     */
    public void server() throws Exception {

        // 1. 对客户端请求的数据，进行验签
        boolean passSign = EncryUtil.checkDecryptAndSign(RequestInfo.data, RequestInfo.encryptkey, clientPublicKey, serverPrivateKey);
        System.out.println("1. 对客户端请求的数据，进行验签: "+ passSign);

        // 是否验签通过。
        if (passSign) {
            // 2, 使用sever私钥对encryptkey进行解密，得到aeskey
            String aeskey = RSA.decrypt(RequestInfo.encryptkey, serverPrivateKey);
            System.out.println("2, 验签通过。使用sever私钥对encryptkey进行解密，得到aeskey: "+ aeskey);

            // 3，使用aesKey对json数据进行解密得到明文(data)
            String data = AESCoder.decryptFromBase64(RequestInfo.data, aeskey);
            System.out.println("3，使用aesKey对json数据进行解密得到明文(data) : "+ data);

            JSONObject jsonObj = JSONObject.parseObject(data);
            String sid = jsonObj.getString("sid");
            String orderId = jsonObj.getString("orderId");
            String dfMercId = jsonObj.getString("dfMercId");
            String amt = jsonObj.getString("amt");
            System.out.println("-----------得到最终解密后的明文:"
                + "sid: " + sid
                + " orderId: " + orderId
                + " dfMercId: " + dfMercId
                + " amt: " + amt
            );

        } else {
            System.out.println("验签失败");
        }
    }

    public static class RequestInfo {
        public static String data;
        public static String encryptkey;

        @Override
        public String toString() {
            return "data:" + data + "\nencryptkey:" + encryptkey;
        }
    }
}
