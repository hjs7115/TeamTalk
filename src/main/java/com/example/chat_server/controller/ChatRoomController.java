package com.example.chat_server.controller;

import com.example.chat_server.service.ChatJoinService;
import com.example.chat_server.service.CustomUserDetails;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/chat-rooms")
public class ChatRoomController {

    private final ChatJoinService chatJoinService;

    public ChatRoomController(ChatJoinService chatJoinService) {
        this.chatJoinService = chatJoinService;
    }

    @PostMapping("/{roomId}/join")
    public Map<String, Object> join(@PathVariable Long roomId,
                                    @AuthenticationPrincipal CustomUserDetails user) {

        Long memberId = user.getMemberId();
        Long deptId = user.getDeptId();

        chatJoinService.join(roomId, memberId, deptId);
        return Map.of("ok", true);
    }
}
