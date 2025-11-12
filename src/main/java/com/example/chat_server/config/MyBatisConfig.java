package com.example.chat_server.config;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@MapperScan("com.example.chat_server.mapper")
public class MyBatisConfig {}
