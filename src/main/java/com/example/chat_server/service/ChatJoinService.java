package com.example.chat_server.service;

import com.example.chat_server.mapper.ChatJoinMapper;
import com.example.chat_server.mapper.ChatRoomMapper;
import com.example.chat_server.mapper.ServerUserMapper;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Service;

import java.util.Map;

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

        Map<String, Object> room = chatRoomMapper.selectRoomById(roomId);
        if (room == null) {
            throw new IllegalArgumentException("존재하지 않는 채팅방입니다.");
        }

        Object serverIdObj = room.get("server_id");
        if (serverIdObj == null) {
            throw new IllegalArgumentException("채팅방의 server_id가 없습니다.");
        }
        Long serverId = ((Number) serverIdObj).longValue();

        if (serverUserMapper.exists(serverId, memberId) <= 0) {
            throw new IllegalArgumentException("해당 서버에 소속된 사용자만 참여할 수 있습니다.");
        }

        if (chatJoinMapper.existsJoin(roomId, memberId) > 0) {
            return;
        }

        try {
            chatJoinMapper.insertJoin(roomId, memberId, deptId);
        } catch (DuplicateKeyException e) {
            // DB에 UNIQUE/PK가 있으면 중복 join 시 여기로 올 수 있음 (안전 처리)
        }
    }
}