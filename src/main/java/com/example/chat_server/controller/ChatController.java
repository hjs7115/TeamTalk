package com.example.chat_server.controller;

import com.example.chat_server.dto.CreateRoomRequest;
import com.example.chat_server.dto.SendMessageRequest;
import com.example.chat_server.service.ChatJoinService;
import com.example.chat_server.service.ChatService;
import com.example.chat_server.service.CustomUserDetails;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/chat")
public class ChatController {

    private final ChatService chatService;
    private final ChatJoinService chatJoinService;

    public ChatController(ChatService chatService, ChatJoinService chatJoinService) {
        this.chatService = chatService;
        this.chatJoinService = chatJoinService;
    }

    @PostMapping("/rooms")
    public Map<String, Object> createRoom(@AuthenticationPrincipal CustomUserDetails user,
                                          @RequestBody CreateRoomRequest req) {
        Long memberId = user.getMemberId();
        Long deptId = user.getDeptId();

        Long roomId = chatService.createRoom(memberId, deptId, req.getServerId(), req.getRoomName());
        return Map.of("roomId", roomId);
    }

    @PostMapping("/rooms/{roomId}/join")
    public Map<String, Object> join(@AuthenticationPrincipal CustomUserDetails user,
                                    @PathVariable Long roomId) {
        Long memberId = user.getMemberId();
        Long deptId = user.getDeptId();

        // 안전한 참여 규칙(서버 소속 여부 + 중복 join 방지)을 ChatJoinService로 일원화
        chatJoinService.join(roomId, memberId, deptId);
        return Map.of("ok", true);
    }

    @PostMapping("/rooms/{roomId}/leave")
    public Map<String, Object> leave(@AuthenticationPrincipal CustomUserDetails user,
                                     @PathVariable Long roomId) {
        Long memberId = user.getMemberId();

        chatService.leaveRoom(memberId, roomId);
        return Map.of("ok", true);
    }

    @PostMapping("/rooms/{roomId}/messages")
    public Map<String, Object> send(@AuthenticationPrincipal CustomUserDetails user,
                                    @PathVariable Long roomId,
                                    @RequestBody SendMessageRequest req) {
        Long memberId = user.getMemberId();
        Long deptId = user.getDeptId();

        chatService.sendMessage(memberId, deptId, roomId, req.getMessageDetail());
        return Map.of("ok", true);
    }

    @GetMapping("/rooms/{roomId}/messages")
    public List<Map<String, Object>> messages(@AuthenticationPrincipal CustomUserDetails user,
                                              @PathVariable Long roomId) {
        Long memberId = user.getMemberId();

        return chatService.getMessages(memberId, roomId);
    }
}