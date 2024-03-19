package com.example.springjwt.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


public class LoginFilter extends UsernamePasswordAuthenticationFilter {
    // UsernamePasswordAuthenticationFilter 이 필터는 시큐리티에서 form 로그인을 disable 시키지 않았다면 사용하지 상속받지 않아도 되지만, 
    // 시큐리티 컨피그에서 이미 폼로그인을 disable 처리를 해놨기 때문에, 이 부분에 대해서 처리를 해줘야한다.

    private final AuthenticationManager authenticationManager;

    public LoginFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username = obtainUsername(request);
        String password = obtainPassword(request);

        System.out.println("username = " + username);
        System.out.println("password = " + password);

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, null);
        //토큰에 유저이름과 패스워드를 담아서, 이제 authenticationManager한테 인가를 시킴
        return authenticationManager.authenticate(authToken);
    }


    //authenticationManager 얘를 통해서 인가가 되었다. 그러면 아래 successfulAuthentication 이 작동
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) {
        System.out.println("success");
    }

    //실패 하면 하위 작업이 실행
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {
        System.out.println("fail");
    }
}
