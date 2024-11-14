package com.example.springsecurity;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

import java.util.List;
@RestController
public class TodoResource {
    private Logger logger = LoggerFactory.getLogger(getClass());

    private static final List<Todo> TODO_LIST =
            List.of(
                    new Todo("bogil", "hello"),
                    new Todo("david", "bye")
            );
    @GetMapping("/todos")
    public List<Todo> retrieveAllTodos(){
        return TODO_LIST;
    }

    @GetMapping("/users/{username}/todos")
    public Todo retrieveTodos(@PathVariable String username){
        return TODO_LIST.get(0);
    }
    @PostMapping("/users/{username}/todos")
    public void createTodos(@PathVariable String username, @RequestBody Todo todo){
        logger.info("Create {} for {}", todo, username);
    }


}

record Todo (String username, String decription) {}
