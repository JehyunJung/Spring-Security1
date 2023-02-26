package io.security.basicsecurity;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

//@RestController
@Slf4j
public class SecurityController2 {
    @GetMapping("/")
    public String index(HttpSession session) {
        Authentication threadLocalAuthentication = SecurityContextHolder.getContext().getAuthentication();
        SecurityContext context = (SecurityContext) session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication sessionAuthentication = context.getAuthentication();


        log.info("ThreadLocal Authentication: {}", threadLocalAuthentication);
        log.info("Session Authentication: {}", sessionAuthentication);

        return "home";

    }
    
    @GetMapping("/thread")
    public String thread() {
        //새로운 쓰레드의 실행
        new Thread(
                ()->{
                    Authentication authenciation = SecurityContextHolder.getContext().getAuthentication();
                    log.info("Sub Thread Authentication: {}", authenciation);
                }
        ).start();
        return "thread";
    }
}
