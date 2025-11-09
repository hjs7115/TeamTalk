package com.example.chat_server.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
//@Component 한마디로 스프링빈으로 등록하기 위한 라벨링 작업
public class PageController {

    @GetMapping("/")
    public String home(){
        return "index";
    }
    //페이지를 조회 및 이동할때 위와같이 @GetMapping()을 써서 이동.
}