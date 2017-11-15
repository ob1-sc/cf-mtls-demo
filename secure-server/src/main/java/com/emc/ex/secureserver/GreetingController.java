package com.emc.ex.secureserver;

import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class GreetingController {

    @RequestMapping(value = "/user")
    public String user(Principal principal) {
        UserDetails currentUser = (UserDetails) ((Authentication) principal).getPrincipal();
        return "Hello " + currentUser.getUsername();
    }

    @RequestMapping(value = "/headers")
    public String header(@RequestHeader HttpHeaders headers) {
        return "Headers: " + headers.toString();
    }
}
