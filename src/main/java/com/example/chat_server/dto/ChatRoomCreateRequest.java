package com.example.chat_server.dto;

public class ChatRoomCreateRequest {
    private String roomName;
    private Long serverId;

    public String getRoomName() { return roomName; }
    public void setRoomName(String roomName) { this.roomName = roomName; }

    public Long getServerId() { return serverId; }
    public void setServerId(Long serverId) { this.serverId = serverId; }
}