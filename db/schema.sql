-- 1. 부서
CREATE TABLE department (
                            dept_id   BIGINT AUTO_INCREMENT PRIMARY KEY,
                            dept_nm   VARCHAR(20) NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 2. 상태
CREATE TABLE state (
                       state_id   BIGINT AUTO_INCREMENT PRIMARY KEY,
                       state_name VARCHAR(20) NOT NULL,
                       state_text VARCHAR(50) NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 3. 회원 (원래 user 테이블)
CREATE TABLE member (
                        member_id BIGINT AUTO_INCREMENT PRIMARY KEY,
                        dept_id   BIGINT       NOT NULL,
                        name      VARCHAR(20)  NOT NULL,
                        email     VARCHAR(100) NOT NULL,
                        position  VARCHAR(50)  NOT NULL,
                        join_date TIMESTAMP    NULL,
                        birth     DATE         NOT NULL,
                        state_id  BIGINT       NOT NULL,
                        phone_num VARCHAR(20)  NOT NULL,

                        CONSTRAINT fk_member_department
                            FOREIGN KEY (dept_id) REFERENCES department (dept_id),
                        CONSTRAINT fk_member_state
                            FOREIGN KEY (state_id) REFERENCES state (state_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 4. 서버
CREATE TABLE server (
                        server_id BIGINT AUTO_INCREMENT PRIMARY KEY,
                        title     VARCHAR(50) NULL,
                        member_id BIGINT      NOT NULL,
                        dept_id   BIGINT      NOT NULL,

                        CONSTRAINT fk_server_member
                            FOREIGN KEY (member_id) REFERENCES member (member_id),
                        CONSTRAINT fk_server_department
                            FOREIGN KEY (dept_id) REFERENCES department (dept_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 5. 채팅방
CREATE TABLE chat_room (
                           room_id    BIGINT AUTO_INCREMENT PRIMARY KEY,
                           room_name  VARCHAR(50) NULL,
                           updated_at DATETIME     NULL,
                           server_id  BIGINT       NOT NULL,

                           CONSTRAINT fk_chat_room_server
                               FOREIGN KEY (server_id) REFERENCES server (server_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 6. 채팅방 참여 (팀채팅방 참여)
CREATE TABLE chat_join (
                           chat_join_id BIGINT AUTO_INCREMENT PRIMARY KEY,
                           member_id    BIGINT NOT NULL,
                           dept_id      BIGINT NOT NULL,
                           room_id      BIGINT NOT NULL,

                           CONSTRAINT fk_chat_join_member
                               FOREIGN KEY (member_id) REFERENCES member (member_id),
                           CONSTRAINT fk_chat_join_department
                               FOREIGN KEY (dept_id) REFERENCES department (dept_id),
                           CONSTRAINT fk_chat_join_room
                               FOREIGN KEY (room_id) REFERENCES chat_room (room_id),

                           CONSTRAINT uq_chat_join_member_room
                               UNIQUE (member_id, room_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 7. 메시지
CREATE TABLE message (
                         message_id     BIGINT AUTO_INCREMENT PRIMARY KEY,
                         message_detail VARCHAR(500) NULL,
                         member_id      BIGINT       NOT NULL,
                         dept_id        BIGINT       NOT NULL,
                         room_id        BIGINT       NOT NULL,

                         CONSTRAINT fk_message_member
                             FOREIGN KEY (member_id) REFERENCES member (member_id),
                         CONSTRAINT fk_message_department
                             FOREIGN KEY (dept_id) REFERENCES department (dept_id),
                         CONSTRAINT fk_message_room
                             FOREIGN KEY (room_id) REFERENCES chat_room (room_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 8. 첨부파일
CREATE TABLE attachment (
                            attachment_id BIGINT AUTO_INCREMENT PRIMARY KEY,
                            message_id    BIGINT NOT NULL,

                            CONSTRAINT fk_attachment_message
                                FOREIGN KEY (message_id) REFERENCES message (message_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 9. 이미지 (프로필 이미지 등)
CREATE TABLE image (
                       member_img_id BIGINT AUTO_INCREMENT PRIMARY KEY,
                       member_id     BIGINT      NOT NULL,
                       dept_id       BIGINT      NOT NULL,
                       original      VARCHAR(50) NULL,
                       path          VARCHAR(50) NULL,

                       CONSTRAINT fk_image_member
                           FOREIGN KEY (member_id) REFERENCES member (member_id),
                       CONSTRAINT fk_image_department
                           FOREIGN KEY (dept_id) REFERENCES department (dept_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 10. 서버 유저
CREATE TABLE server_user (
                             server_member_id BIGINT AUTO_INCREMENT PRIMARY KEY,
                             member_id        BIGINT NOT NULL,
                             dept_id          BIGINT NOT NULL,
                             server_id        BIGINT NOT NULL,

                             CONSTRAINT fk_server_user_member
                                 FOREIGN KEY (member_id) REFERENCES member (member_id),
                             CONSTRAINT fk_server_user_department
                                 FOREIGN KEY (dept_id) REFERENCES department (dept_id),
                             CONSTRAINT fk_server_user_server
                                 FOREIGN KEY (server_id) REFERENCES server (server_id),

                             CONSTRAINT uq_server_user_member_server
                                 UNIQUE (member_id, server_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 11. 채팅 알림 (읽음/안읽음 등)
CREATE TABLE chat_alarm (
                            chat_alarm_id BIGINT AUTO_INCREMENT PRIMARY KEY,
                            message_id    BIGINT NOT NULL,
                            chat_state    INT    NOT NULL,
                            member_id     BIGINT NOT NULL,
                            dept_id       BIGINT NOT NULL,

                            CONSTRAINT fk_chat_alarm_message
                                FOREIGN KEY (message_id) REFERENCES message (message_id),
                            CONSTRAINT fk_chat_alarm_member
                                FOREIGN KEY (member_id) REFERENCES member (member_id),
                            CONSTRAINT fk_chat_alarm_department
                                FOREIGN KEY (dept_id) REFERENCES department (dept_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 12. 직장동료
CREATE TABLE colleague (
                           co_id      BIGINT AUTO_INCREMENT PRIMARY KEY,
                           member_id2 BIGINT NOT NULL,
                           dept_id2   BIGINT NOT NULL,

                           CONSTRAINT fk_colleague_member
                               FOREIGN KEY (member_id2) REFERENCES member (member_id),
                           CONSTRAINT fk_colleague_department
                               FOREIGN KEY (dept_id2) REFERENCES department (dept_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE auth_user (
                           user_id BIGINT AUTO_INCREMENT PRIMARY KEY,
                           member_id BIGINT NOT NULL,
                           dept_id BIGINT NOT NULL,
                           username VARCHAR(50) NOT NULL UNIQUE,
                           password_hash VARCHAR(255) NOT NULL,
                           role VARCHAR(50) NOT NULL,

                           CONSTRAINT fk_auth_user_member
                               FOREIGN KEY (member_id) REFERENCES member(member_id),
                           CONSTRAINT fk_auth_user_department
                               FOREIGN KEY (dept_id) REFERENCES department(dept_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 가입요청(승인 전) 테이블
CREATE TABLE signup_request (
                                req_id BIGINT AUTO_INCREMENT PRIMARY KEY,

                                name VARCHAR(20) NOT NULL,
                                email VARCHAR(100) NOT NULL,
                                phone_num VARCHAR(20) NOT NULL,

                                username VARCHAR(50) NOT NULL,
                                password_hash VARCHAR(255) NOT NULL,

                                status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
                                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

                                assigned_dept_id BIGINT NULL,
                                reviewed_by BIGINT NULL,
                                reviewed_at DATETIME NULL,
                                reject_reason VARCHAR(255) NULL,

                                CONSTRAINT uq_signup_request_username UNIQUE (username),
                                CONSTRAINT uq_signup_request_email UNIQUE (email),

                                CONSTRAINT fk_signup_request_dept
                                    FOREIGN KEY (assigned_dept_id) REFERENCES department(dept_id),
                                CONSTRAINT fk_signup_request_reviewed_by
                                    FOREIGN KEY (reviewed_by) REFERENCES member(member_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- chat_join PK 추가 (중복 join 방지)
ALTER TABLE chat_join
    ADD CONSTRAINT pk_chat_join
        PRIMARY KEY (member_id, room_id);
