package com.example.chat_server.service;

import com.example.chat_server.dto.ChatRoomCreateRequest;
import com.example.chat_server.mapper.ChatRoomMapper;
import org.springframework.stereotype.Service;

@Service
public class ChatRoomService {

    private final ChatRoomMapper chatRoomMapper;

    public ChatRoomService(ChatRoomMapper chatRoomMapper) {
        this.chatRoomMapper = chatRoomMapper;
    }

    public Long create(ChatRoomCreateRequest req) {
        if (req.getServerId() == null) {
            throw new IllegalArgumentException("serverId는 필수입니다.");
        }
        if (req.getRoomName() == null || req.getRoomName().isBlank()) {
            throw new IllegalArgumentException("roomName은 필수입니다.");
        }

        chatRoomMapper.insertRoom(req.getServerId(), req.getRoomName().trim());
        return chatRoomMapper.selectLastInsertId();
    }
}