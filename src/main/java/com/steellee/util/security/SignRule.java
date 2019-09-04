package com.steellee.util.security;

import com.alibaba.fastjson.JSON;
import org.apache.commons.codec.binary.Hex;

import java.util.*;

/**
 * Description: 签名工具算法
 *
 * @author steellee
 * @version 1.0.0
 * Create Time: 2019/9/4 11:19
 */
public class SignRule {

    private static String MAC_KEY = "192006250b4c09247ec02edce69f6a2d";
    private static String SIGN_SPLIT = "&";
    /**
     * 参照腾讯： https://pay.weixin.qq.com/wiki/doc/api/jsapi.php?chapter=4_3
     *      第一步：对参数按照key=value的格式，并按照参数名ASCII字典序排序如下：
     *      stringA="appid=wxd930ea5d5a258f4f&body=test&device_info=1000&mch_id=10000100&nonce_str=ibuaiVcKdpRxkhJA
     *      第二步：拼接API密钥：
     *      stringSignTemp=stringA+"&key=192006250b4c09247ec02edce69f6a2d" //注：key为商户平台设置的密钥key
     *      sign=MD5(stringSignTemp).toUpperCase()="9A0A8659F005D6984697E2CA0A9CF3B7" //注：MD5签名方式
     *      sign=hash_hmac("sha256",stringSignTemp,key).toUpperCase()="6A9AE1657590FD6257D693A078E1C3E4BB6BA4DC30B23E0EE2496E54170DACD6" //注：HMAC-SHA256签名方式
     */
    public static String sign1(String json) throws Exception{
        // 拼接排序验证字符串
        String stringA = getSortedString(json);
        // 拼接API密钥
        String stringSignTemp = stringA+"&key=" + MAC_KEY;
        System.out.println("拼接排序后字符串:" + stringSignTemp);
        // MD5签名方式
        String sign = Hex.encodeHexString(Coders.encryptMD5(stringSignTemp.getBytes("utf-8")),false);
//         HMAC-SHA256签名方式
//        String sign = Hex.encodeHexString(Coders.encryptHMAC(stringSignTemp.getBytes("utf-8"), MAC_KEY),true);
        return sign;
    }

    private static String getSortedString(String json){
        StringBuffer content = new StringBuffer("");
        // 反序列化
        Map map = JSON.parseObject(json, SortedMap.class);
        Set keys = map.keySet();
        Iterator it = keys.iterator();
        while (it.hasNext()){
            String key = (String)it.next();
            String value = Objects.toString(map.get(key),"");
            content.append(key).append("=").append(value).append(SIGN_SPLIT);
        }
        return content.toString();
    }

    /*private static String getSortedStringBak(Object params){
        Map<String, String> map = new HashMap(16);
        Map<String, String> treeMap = new TreeMap();
        map.putAll(getFiledToMap(params));
        // 只排序一次
        treeMap.putAll(map);
        StringBuffer sorted = new StringBuffer();
        for(Map.Entry<String, String> entry: treeMap.entrySet()) {
            sorted.append(entry.getKey()).append("=").append(entry.getValue()).append(SIGN_SPLIT);
        }
        return sorted.toString();
    }
    private static Map<String, String> getFiledToMap(Object params) {
        Field[] fields = params.getClass().getDeclaredFields();
        Map<String, String> map = new HashMap(16);
        for (int i = 0; i < fields.length; i++) {
            // 忽略UID
            if ("serialVersionUID".equals(fields[i].getName())) {
                continue;
            }
            // 如果是复合字段就跳出
            if (fields[i].isSynthetic() && "$jacocoData".equals(fields[i].getName())) {
                continue;
            }
            map.put(fields[i].getName(), getFieldValueByName(fields[i].getName(), params));
        }
        return map;
    }
    *//**
     * 根据属性名获取属性值
     *//*
    private static String getFieldValueByName(String fieldName, Object params) {
        try {
            String firstLetter = fieldName.substring(0, 1).toUpperCase();
            String getter = "get" + firstLetter + fieldName.substring(1);
            Method method = params.getClass().getMethod(getter, new Class[]{});
            Object value = method.invoke(params, new Object[]{});
            return value == null?"": value.toString();
        } catch (Exception e) {
            return null;
        }
    }*/
}
