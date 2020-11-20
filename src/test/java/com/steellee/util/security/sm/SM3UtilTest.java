package com.steellee.util.security.sm;

import org.junit.Assert;
import org.junit.Test;

public class SM3UtilTest {

    // 源数据
    public static final byte[] SRC_DATA = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
    public static final String SRC_DATA_S = "abc123您好";

    public static void main(String[] args) {

    }
    /**
     * 验签1
     * 类似于md5（参数），得到唯一值
     */
    @Test
    public void testHashAndVerify() {
        try {
            String hash = SM3Util.hash(SRC_DATA);
            System.out.println("SM3 hash result:\n" + hash);
            boolean flag = SM3Util.verify(SRC_DATA_S, hash);
            if (!flag) {
                Assert.fail();
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    /**
     * 验签2
     * 类似于md5（参数 + mackey），得到唯一值验签
     *  mackey 对双方透明
     */
    @Test
    public void testHmacSM3() {
        try {
            String srcData = "SM3验签SM3验签SM3验签SM3验签SM3验签SM3验签SM3验签SM3验签SM3验签SM3验签SM3验签SM3验签SM3验签SM3验签SM3验签SM3验签SM3验签SM3验签SM3验签SM3验签SM3验签SM3验签SM3验签";
            String secretKey = "a90834e7e62d047eeda90834e7e62d047eeda90834e7e62d047eeda90834e7e62d047eeda90834e7e62d047eeda90834e7e62d047eeda90834e7e62d047eeda90834e7e62d047eeda90834e7e62d047eeda90834e7e62d047eeda90834e7e62d047eeda90834e7e62d047eeda90834e7e62d047eed";
            String signData = SM3Util.hmac(secretKey, srcData);
            System.out.println("hmac(base64 string):\n" + signData);
            boolean flag = SM3Util.verify2(srcData, signData, secretKey);
            if (!flag) {
                Assert.fail();
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }
}
