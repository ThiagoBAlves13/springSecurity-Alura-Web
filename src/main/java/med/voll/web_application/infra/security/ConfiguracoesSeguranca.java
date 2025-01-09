package med.voll.web_application.infra.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;

@Configuration
@EnableWebSecurity
public class ConfiguracoesSeguranca {


        // código omitido

        @Bean
        public SecurityFilterChain filtrosSeguranca(HttpSecurity http) throws Exception {
                return http
                                .authorizeHttpRequests(req -> {
                                        req.requestMatchers("/css/**", "/js/**", "/assets/**", "/h2-console/**", "/", "/index", "/home")
                                                        .permitAll();
                                        req.anyRequest().authenticated();
                                })
                                .formLogin(form -> form.loginPage("/login")
                                                .defaultSuccessUrl("/")
                                                .permitAll())
                                .logout(logout -> logout.addLogoutHandler(new SecurityContextLogoutHandler())
                                                .logoutSuccessUrl("/login?logout")
                                                .permitAll())
                                .rememberMe(rememberMe -> rememberMe.key("lembrarDeMim")
                                                .alwaysRemember(true))
                                .csrf(Customizer.withDefaults())
                                .build();
        }

        @Bean    
        public WebSecurityCustomizer webSecurityCustomizer() {
                return (web) -> web.ignoring().requestMatchers("/h2-console/**");
        }

        @Bean
        public PasswordEncoder codificadorDeSenha(){
                return new BCryptPasswordEncoder();
        }

}
