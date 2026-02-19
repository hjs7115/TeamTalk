package com.example.chat_server.service;

import com.example.chat_server.entity.ChatRoom;
import com.example.chat_server.mapper.ChatJoinMapper;
import com.example.chat_server.mapper.ChatRoomMapper;
import com.example.chat_server.mapper.ServerUserMapper;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Service;

@Service
public class ChatJoinService {

    private final ChatRoomMapper chatRoomMapper;
    private final ServerUserMapper serverUserMapper;
    private final ChatJoinMapper chatJoinMapper;

    public ChatJoinService(ChatRoomMapper chatRoomMapper,
                           ServerUserMapper serverUserMapper,
                           ChatJoinMapper chatJoinMapper) {
        this.chatRoomMapper = chatRoomMapper;
        this.serverUserMapper = serverUserMapper;
        this.chatJoinMapper = chatJoinMapper;
    }

    public void join(Long roomId, Long memberId, Long deptId) {
        if (roomId == null) throw new IllegalArgumentException("roomId는 필수입니다.");

        ChatRoom room = chatRoomMapper.findById(roomId);
        if (room == null) {
            throw new IllegalArgumentException("존재하지 않는 채팅방입니다.");
        }

        // ✅ 서버 멤버인지 확인 (server_user 기반)
        if (serverUserMapper.exists(room.getServerId(), memberId) <= 0) {
            throw new IllegalArgumentException("해당 서버에 소속된 사용자만 참여할 수 있습니다.");
        }

        // 중복 join 방지
        if (chatJoinMapper.exists(roomId, memberId) > 0) {
            return; // 이미 참여중이면 무시(정책)
        }

        try {
            chatJoinMapper.insert(roomId, memberId, deptId);
        } catch (DuplicateKeyException e) {
            // UNIQUE 없더라도 혹시 정책에 맞게 안전 처리
        }
    }
}