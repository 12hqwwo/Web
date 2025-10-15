package com.project.DuAnTotNghiep.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Configuration
    public static class AppConfiguration {
        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
            http.csrf().disable().authorizeRequests()
                    // Tài nguyên tĩnh, public pages
                    .antMatchers("/css/**", "/js/**", "/images/**", "/vendor/**", "/plugins/**", "/webjars/**", "/favicon.ico", "/error").permitAll()
                    .antMatchers("/", "/home/**", "/product/**", "/about/**", "/contact/**").permitAll()
                    .antMatchers("/admin/vendors/**", "/admin/assets/**", "/vendors/**", "/assets/**", "/css/**", "/js/**", "/images/**", "/webjars/**").permitAll()
					
					
					
                    // Quyền của User và Vendor (User chức năng cơ bản, Vendor có thêm các chức năng shop)
                    .antMatchers("/profile/**", "/orders/**", "/checkout/**", "/comment/**", "/discount/**",
                        "/favorite/**", "/cart/**", "/payment/**", "/history/**")
                    .hasAnyRole("USER", "VENDOR", "ADMIN")

                    // Chức năng admin & vendor dùng chung (shop, sản phẩm, đơn hàng, hóa đơn, doanh thu, size, brand, bill-return, discount)
                    .antMatchers(
                        "/admin/thong-ke-doanh-thu",
                        "/admin/bill-list",
                        "/admin/chi-tiet-san-pham/**",
                        "/admin/product/**",
                        "/admin/product-all",
                        "/admin/product-create",
                        "/admin/brand-all", "/admin/brand-create", "/admin/brand-detail/**",
                        "/admin/size-all", "/admin/size-create", "/admin/size-detail/**",
                        "/admin/color-list", "/admin/color-create", "/admin/edit-color/**",
                        "/admin/pos",
                        "/admin-only/bill-return",
                        "/admin-only/bill-return-create",
                        "/admin-only/bill-return-detail/**",
                        "/admin-only/product-discount",
                        "/admin-only/product-discount-create"
                    ).hasAnyRole("VENDOR", "ADMIN")

                    // Các chức năng chỉ dành cho ADMIN (quản lý user, danh mục, vận chuyển, chiết khấu app, giảm phí vận chuyển,...)
                    .antMatchers("/admin/**", "/management/**", "/system/**").hasRole("ADMIN")

                    // Các request khác thì cho phép (để login form không bị chặn)
                    .anyRequest().permitAll()

                    .and().formLogin().loginPage("/user-login") // trang login
                    .loginProcessingUrl("/user_login") // action form login
                    .usernameParameter("email") // dùng email làm username
                    .defaultSuccessUrl("/", true) // chuyển về trang chủ sau khi login
                    .permitAll().and().logout().logoutUrl("/user_logout").logoutSuccessUrl("/").permitAll().and()
                    .rememberMe().key("AbcDefgHijklmnOp_123456789").rememberMeParameter("remember-me")
                    .tokenValiditySeconds(7 * 24 * 60 * 60);

            http.headers().frameOptions().disable();
            return http.build();
        }

        @Bean
        public AuthenticationSuccessHandler successHandler() {
            SavedRequestAwareAuthenticationSuccessHandler handler = new SavedRequestAwareAuthenticationSuccessHandler();
            handler.setDefaultTargetUrl("/");
            return handler;
        }

        @Bean
        public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
            return authConfig.getAuthenticationManager();
        }

        @Bean
        public WebSecurityCustomizer webSecurityCustomizer() {
            return (web) -> web.ignoring().antMatchers("/img/**", "/js/**", "/css/**", "/fonts/**", "/plugins/**",
                    "/vendor/**", "/static/**", "/webjars/**", "/images/**", "/favicon.ico", "/error");
        }
    }
}