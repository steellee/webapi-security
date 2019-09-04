package com.steellee.util.security;

import com.alibaba.fastjson.JSON;
import org.junit.Test;

/**
 * Description: 签名工具算法测试
 *
 * @author steellee
 * @version 1.0.0
 * Create Time: 2019/9/4 16:43
 */
public class SignRuleTest {

    @Test
    public void sign1Test() throws Exception{
        ApiDto apiDto = new ApiDto();
        apiDto.setInscode("1234");
        apiDto.setPayeridcard("aaaa");
        apiDto.setTasknumbers("bbbb");
        apiDto.setTotalamount("9999");
        String json = JSON.toJSONString(apiDto);
        long start = System.currentTimeMillis();
        // 性能测试
        for(int i= 1; i< 100; i++){
            SignRule.sign1(json);
        }
        System.out.println("100个并发时间（毫秒）:" + (System.currentTimeMillis() - start));
    }
}
