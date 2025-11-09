package com.example.chat_server.config;

import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SecurityConfigUnitTest {

    SecurityConfig config = new SecurityConfig();

    @Test
    void authenticationSuccessHandler_setsSessionAndRedirect() throws Exception {
        // given
        var handler = config.authenticationSuccessHandler();
        var request = new MockHttpServletRequest();
        var response = new MockHttpServletResponse();
        var auth = new UsernamePasswordAuthenticationToken(
                "managerUser", "pw",
                List.of(new SimpleGrantedAuthority("MANAGER"))
        );

        // when
        handler.onAuthenticationSuccess(request, response, auth);

        // then
        HttpSession session = request.getSession(false);
        assertNotNull(session);
        assertEquals(true, session.getAttribute("Manager"));
        assertEquals("managerUser", session.getAttribute("username"));
        assertEquals(true, session.getAttribute("isAuthenticated"));
        assertEquals("/", response.getRedirectedUrl());
    }

    @Test
    void corsConfigurationSource_hasExpectedValues() {
        var source = config.corsConfigurationSource();
        var conf = source.getCorsConfiguration(null);

        assertNotNull(conf);
        assertEquals(List.of("http://localhost:3000", "http://localhost:8080", "https://localhost:8080"),
                conf.getAllowedOrigins());
        assertEquals(List.of("GET","POST","PUT","DELETE"), conf.getAllowedMethods());
        assertEquals(List.of("Authorization","Content-Type"), conf.getAllowedHeaders());
    }
}
