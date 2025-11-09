package com.example.chat_server.config;


import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.io.IOException;
import java.util.Arrays;

@Configuration
@EnableWebSecurity
//SpringSecurity기능을 사용하려면 이 어노테이션을 사용
public class SecurityConfig {

    @Bean
public SecurityFilterChain springSecurityFilterChain(HttpSecurity http, CorsConfigurationSource corsConfigurationSource) throws Exception {
    //스프링 세큐리티 기능을 사용하고자 할때 이 메소드안에 작성한다.
        http.csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
                //csrf 해킹기법으로부터 보 하기 위한 일종의 코드 방법 => 나중에 따로 자바스크립트에다가 csrf기능도 넣어놓을 것
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                //cors는 특정서버로만 데이터를 넘길 수 있도록 설정할 수 있음
                        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
//세션설정
        .authorizeHttpRequests(authz -> authz.requestMatchers("/","/loginPage","/logout","/noticeCheckPage","/register","/menu/all")
                .permitAll()
                .requestMatchers(HttpMethod.POST,"/login").permitAll()
                .requestMatchers("/resources/**","/WEB-INF/**").permitAll()
                .requestMatchers("/noticeAdd","/noticeModifyPage").hasAnyAuthority("ADMIN","MANAGER")
                .requestMatchers(HttpMethod.POST,"/menu/add").hasAnyAuthority("ADMIN","MANAGER")
                .requestMatchers(HttpMethod.POST,"/menu/update").hasAnyAuthority("ADMIN","MANAGER")
                .requestMatchers(HttpMethod.POST,"/menu/delete").hasAnyAuthority("ADMIN","MANAGER")
                .anyRequest().authenticated()
        );

        http.formLogin(
         login->login.loginPage("/loginPage")//url을 작성해서 로그인 페이지로 이동할때
                 .loginProcessingUrl("/login")
                 .failureUrl("/loginPage?error=true")
                 .usernameParameter("username")
                 .passwordParameter("password")
                 .successHandler(authenticationSuccessHandler())
                 .permitAll()
        )
                .logout(logout -> logout.logoutRequestMatcher(new AntPathRequestMatcher("/logout"))//logout URL을 통해서 로그아웃이 됨
                        .logoutSuccessUrl("/")//로그아웃 성공후 이 url로 리다이렉팅
                        .invalidateHttpSession(true)//세션무효화
                        .deleteCookies("JSESSIONID")//쿠키삭제
                        .permitAll()
                );

        return http.build();
}

@Bean
public AuthenticationSuccessHandler authenticationSuccessHandler(){
    return new SimpleUrlAuthenticationSuccessHandler(){

        @Override
        public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
            //로그인이 성공했을 때 특별기능을 넣고싶을 때(세션,권한기능)
            HttpSession session = request.getSession();//세션 기능을 가지고 온것
            boolean isManager = authentication.getAuthorities().stream().anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals("ADMIN") ||
                    grantedAuthority.getAuthority().equals("MANAGER"));
            if(isManager){
                session.setAttribute("Manager",true);
            }
            session.setAttribute("username",authentication.getName());
            session.setAttribute("isAuthenticated",true);
            //request.getContextPath()=>localhost:8080
            response.sendRedirect(request.getContextPath()+"/");
            super.onAuthenticationSuccess(request, response, authentication);
        }
    };
}
@Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:3000", "http://localhost:8080", "https://localhost:8080"));
        //localhost:8080서버에서는 프론트에서 백엔드단 혹은 백엔드단에서 프론트단으로 데이터를 주고 받을 수 있게 하는 것
        //프론트단 localhost:3000, 백엔드단 localhost:8080
        configuration.setAllowedMethods(Arrays.asList("GET","POST","PUT","DELETE"));
        configuration.setAllowedHeaders(Arrays.asList("Authorization","Content-Type"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}