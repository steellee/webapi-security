package com.steellee.config.multiapi;

import org.springframework.web.bind.annotation.Mapping;

import java.lang.annotation.*;

/**
 *  接口版本标识注解
 *
 * @author steellee
 * @version V1.0.0
 * @date 2019/01/20
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Mapping
public @interface ApiVersion {
    /**
     * 版本号
     * @return
     */
    int value();
}
