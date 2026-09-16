package com.apitest.web;

import com.apitest.filter.JwtAuthFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * FR-3: the one protected business endpoint. Authentication itself already
 * happened in {@link JwtAuthFilter}, which rejects unauthenticated/invalid
 * requests with 401 before this controller ever runs and stashes the
 * authenticated username as a request attribute.
 */
@RestController
public class HelloController {

    @GetMapping("/api/v1/hello")
    public Map<String, Object> hello(HttpServletRequest request) {
        String username = (String) request.getAttribute(JwtAuthFilter.AUTHENTICATED_USERNAME_ATTR);
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("message", "Hello, " + username + "!");
        resp.put("server_time_utc", Instant.now().toString());
        return resp;
    }
}
