package com.example.chat_server.dto;

public class ChatRoomCreateResponse {
    private Long roomId;

    public ChatRoomCreateResponse(Long roomId) {
        this.roomId = roomId;
    }

    public Long getRoomId() { return roomId; }
}