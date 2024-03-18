package com.example.springjwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity //이 컨피큐레이션 클래스는 시큐리티를 위한 컨피그 클래스이기 때문에 선언.
public class SecurityConfig {



    //시큐리티를 통해서 회원정보를 저장하고, 검증할 때는 항상 비밀번호를 해쉬로 암호화 하여 검증하게 되는데 그럴 경우 사용하는 bean을 등록
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        //csrf disable  --> jwt 방식은 csrf 공격에 대한 방어를 하지 않아도 됨.
        http.csrf((auth) -> auth.disable());

        //Form 로그인 방식 disable
        http.formLogin((auth) -> auth.disable());

        //http basic 인증 방식 disable
        http.httpBasic((auth) -> auth.disable());

        //경로별 인가 작업
        http.authorizeHttpRequests((auth) -> auth
                .requestMatchers("/login", "/", "/join").permitAll() //"/login", "/", "/join" 해당 경로로 들어오는 것들에 대해서는 무조건 인가 처리 해줌.
                .requestMatchers("/admin").hasRole("ADMIN") // /admin 으로 들어오는 리퀘스트에 대해서는 롤이 ADMIN값을 가지고 있는 것에 대해서만 인가 처리 해주도록.
                .anyRequest().authenticated());  // 그렇지 않은 것 들에 대해서는 인가된 것들만.

        //jwt 통신 방식에서는 가장 중요한 것이, 세션이 무상태여야 됨.
        http.sessionManagement((session) -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }
}
