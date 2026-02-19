package com.example.chat_server.mapper;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

@Mapper
public interface ServerUserMapper {

    int exists(@Param("serverId") Long serverId,
               @Param("memberId") Long memberId);
}