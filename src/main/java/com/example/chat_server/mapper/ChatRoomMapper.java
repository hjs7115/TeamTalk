package com.example.chat_server.mapper;

import com.example.chat_server.entity.ChatRoom;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.Map;

@Mapper
public interface ChatRoomMapper {
    int insertRoom(@Param("serverId") Long serverId,
                   @Param("roomName") String roomName);

    Long selectLastInsertId(); // 방 생성 직후 room_id 얻기
    Map<String, Object> selectRoomById(@Param("roomId") Long roomId);
}

