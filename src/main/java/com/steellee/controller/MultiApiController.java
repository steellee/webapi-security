package com.steellee.controller;

import com.steellee.config.multiapi.ApiVersion;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;

/**
 * 多版本接口测试（向下兼容）
 *
 * @author steellee
 * @version V1.0.0
 * @date 2019/01/20
 */
@Controller
@RequestMapping("/{version}/")
public class MultiApiController {

    @RequestMapping("hello/")
    @ApiVersion(1)
    @ResponseBody
    public String hello(HttpServletRequest request){
        System.out.println("test1..........");
        return "hello";
    }

    @RequestMapping("hello/")
    @ApiVersion(2)
    @ResponseBody
    public String hello2(HttpServletRequest request){
        System.out.println("test2.........");
        return "hello";
    }

    @RequestMapping("hello/")
    @ApiVersion(5)
    @ResponseBody
    public String hello5(HttpServletRequest request){
        System.out.println("test5.........");
        return "hello";
    }
}
