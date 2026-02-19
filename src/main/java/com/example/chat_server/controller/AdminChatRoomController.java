package com.example.chat_server.controller;

import com.example.chat_server.dto.ChatRoomCreateRequest;
import com.example.chat_server.dto.ChatRoomCreateResponse;
import com.example.chat_server.service.ChatRoomService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin")
public class AdminChatRoomController {

    private final ChatRoomService chatRoomService;

    public AdminChatRoomController(ChatRoomService chatRoomService) {
        this.chatRoomService = chatRoomService;
    }

    @PostMapping("/chat-rooms")
    public ChatRoomCreateResponse create(@RequestBody ChatRoomCreateRequest req) {
        Long roomId = chatRoomService.create(req);
        return new ChatRoomCreateResponse(roomId);
    }
}