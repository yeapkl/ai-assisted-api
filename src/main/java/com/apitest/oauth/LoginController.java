package com.apitest.oauth;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * NFR-14: the OAuth 2.1 Authorization Server's HTML login form - the one
 * intentional exception to this API otherwise being JSON-only. Plain
 * hand-written HTML (no templating engine dependency) since this is a
 * single static form; the actual authentication decision is made by Spring
 * Security's {@code UsernamePasswordAuthenticationFilter} (wired to
 * {@link UserStoreUserDetailsService} - see {@code AuthorizationServerConfig}),
 * not by this controller.
 */
@Controller
public class LoginController {

    @GetMapping("/login")
    public ResponseEntity<String> login(HttpServletRequest request,
            @RequestParam(value = "error", required = false) String error) {
        return ResponseEntity.ok()
                .contentType(MediaType.TEXT_HTML)
                .body(renderLoginPage(request, error != null));
    }

    /**
     * Shared with {@link LoginFailureHandler} so an invalid-credentials
     * submission re-renders this same form (with an error) directly in the
     * failed POST's response, rather than issuing a redirect back to a
     * fresh GET (NFR-14: "re-render... and do not redirect").
     */
    static String renderLoginPage(HttpServletRequest request, boolean showError) {
        CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        String csrfInput = csrfToken != null
                ? "<input type=\"hidden\" name=\"%s\" value=\"%s\"/>"
                        .formatted(escape(csrfToken.getParameterName()), escape(csrfToken.getToken()))
                : "";
        // NFR-4's intent extended to this form: a single generic message,
        // never revealing whether the username or the password was wrong.
        String errorBlock = showError
                ? "<p role=\"alert\" style=\"color:#b00020\">Invalid username or password.</p>"
                : "";

        return """
                <!doctype html>
                <html lang="en">
                <head>
                  <meta charset="utf-8"/>
                  <title>Sign in</title>
                </head>
                <body>
                  <h1>Sign in</h1>
                  %s
                  <form method="post" action="/login">
                    %s
                    <div>
                      <label for="username">Username</label>
                      <input type="text" id="username" name="username" autocomplete="username" required/>
                    </div>
                    <div>
                      <label for="password">Password</label>
                      <input type="password" id="password" name="password" autocomplete="current-password" required/>
                    </div>
                    <button type="submit">Sign in</button>
                  </form>
                </body>
                </html>
                """.formatted(errorBlock, csrfInput);
    }

    private static String escape(String value) {
        return value == null ? "" : value.replace("&", "&amp;").replace("\"", "&quot;").replace("<", "&lt;");
    }
}
