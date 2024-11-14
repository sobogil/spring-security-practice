package com.example.springsecurity;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class HelloWorldResource {
    @GetMapping("hello")
    public String helloWorld(){
        return "hello";
    }
}
