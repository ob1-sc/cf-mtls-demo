package com.emc.ex.insecureserver;

import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GreetingController {

    @RequestMapping(value = "/headers")
    public String header(@RequestHeader HttpHeaders headers) {
        return "Headers: " + headers.toString();
    }
}
