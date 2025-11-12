package com.example.chat_server.controller;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.*;
import com.example.chat_server.service.UserService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class AuthController {

    private final AuthenticationManager authManager;
    private final UserService userService; // 🔽 추가

    public AuthController(AuthenticationManager authManager, UserService userService) {
        this.authManager = authManager;
        this.userService = userService;
    }

    // ✅ 회원가입 (username, password 받음)
    @PostMapping("/auth/register")
    public Map<String, Object> register(@RequestBody RegisterRequest req) {
        if (req.username() == null || req.username().isBlank() ||
                req.password() == null || req.password().isBlank()) {
            return Map.of("ok", false, "message", "username/password는 필수입니다.");
        }
        try {
            userService.register(req.username(), req.password());
            return Map.of("ok", true);
        } catch (IllegalArgumentException e) {
            return Map.of("ok", false, "message", e.getMessage());
        }
    }

    // ✅ 로그인 (기존 그대로)
    @PostMapping("/auth/login")
    public Map<String, Object> login(@RequestBody LoginRequest req, HttpServletRequest request) {
        UsernamePasswordAuthenticationToken token =
                new UsernamePasswordAuthenticationToken(req.username(), req.password());

        Authentication authentication = authManager.authenticate(token); // 실패 시 401

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        HttpSession session = request.getSession(true);
        session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, context);

        return Map.of("ok", true, "username", authentication.getName());
    }

    // ✅ 로그아웃 (기존 그대로)
    @PostMapping("/auth/logout")
    public Map<String, Object> logout(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) session.invalidate();
        SecurityContextHolder.clearContext();
        return Map.of("ok", true);
    }

    // ✅ 로그인 여부 (기존 그대로)
    @GetMapping("/me")
    public Map<String, Object> me(Authentication auth) {
        if (auth == null) return Map.of("authenticated", false);
        return Map.of(
                "authenticated", true,
                "username", auth.getName(),
                "roles", auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList()
        );
    }

    // DTO
    public record LoginRequest(String username, String password) {}
    public record RegisterRequest(String username, String password) {} // 🔽 추가
}