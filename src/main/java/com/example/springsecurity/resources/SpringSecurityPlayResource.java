package com.example.springsecurity.resources;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SpringSecurityPlayResource {
    @GetMapping("/csrf")
    public CsrfToken retrieveCsrf(HttpServletRequest request){
        System.out.println("request = " + request);
        return (CsrfToken) request.getAttribute("_csrf");
    }
}
