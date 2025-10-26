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
                    // ========== PUBLIC RESOURCES ==========
                    .antMatchers("/css/**", "/js/**", "/images/**", "/vendor/**", "/plugins/**", 
                                 "/webjars/**", "/favicon.ico", "/error").permitAll()
                    .antMatchers("/", "/home/**", "/product/**", "/about/**", "/contact/**").permitAll()
                    .antMatchers("/admin/vendors/**", "/admin/assets/**", "/vendors/**", "/assets/**").permitAll()
                    .antMatchers("/user-login", "/register", "/register-save", "/forgot-pass", 
                                 "/reset-pass", "/reset-password", "/verify-otp", "/resend-otp", "/reset-page").permitAll()
                    
                    // ========== USER AREA (Khách hàng) ==========
                    .antMatchers("/profile/**", "/orders/**", "/checkout/**", "/comment/**", 
                                 "/discount/**", "/favorite/**", "/cart/**", "/payment/**", "/history/**")
                    .hasAnyRole("USER", "VENDOR", "ADMIN")

                    // ========== ƯU TIÊN CAO NHẤT - RULES CỤ THỂ ==========
                    
                    // ✅ THỐNG KÊ - CHỈ ADMIN (KHÔNG CHO VENDOR VÀ USER)
                    .antMatchers("/admin/thong-ke-doanh-thu/**", "/admin/thong-ke-san-pham/**")
                    .hasRole("ADMIN")  // ← CHỈ ADMIN

                    // ✅ BÁN TẠI QUẦY (POS) - ADMIN VÀ VENDOR
                    .antMatchers("/admin/pos/**")
                    .hasAnyRole("VENDOR", "ADMIN")

                    // ✅ QUẢN LÝ HÓA ĐƠN - ADMIN VÀ VENDOR
                    .antMatchers("/admin/bill-list/**", "/admin/generate-pdf/**")
                    .hasAnyRole("VENDOR", "ADMIN")

                    // ✅ QUẢN LÝ SẢN PHẨM - ADMIN VÀ VENDOR
                    .antMatchers("/admin/chi-tiet-san-pham/**", "/admin/product/**", 
                                 "/admin/product-all/**", "/admin/product-create/**")
                    .hasAnyRole("VENDOR", "ADMIN")

                    // ✅ QUẢN LÝ THUỘC TÍNH SẢN PHẨM - ADMIN VÀ VENDOR
                    .antMatchers("/admin/brand-all/**", "/admin/brand-create/**", "/admin/brand-detail/**",
                                 "/admin/size-all/**", "/admin/size-create/**", "/admin/size-detail/**",
                                 "/admin/color-list/**", "/admin/color-create/**", "/admin/edit-color/**",
                                 "/admin/material-all/**", "/admin/material-create/**", "/admin/material-detail/**",
                                 "/admin/category-all/**", "/admin/category-create/**", "/admin/category-detail/**")
                    .hasAnyRole("VENDOR", "ADMIN")

                    // ✅ TRẢ HÀNG VÀ GIẢM GIÁ - ADMIN VÀ VENDOR
                    .antMatchers("/admin-only/bill-return/**", "/admin-only/bill-return-create/**", 
                                 "/admin-only/bill-return-detail/**",
                                 "/admin-only/product-discount/**", "/admin-only/product-discount-create/**")
                    .hasAnyRole("VENDOR", "ADMIN")

                    // ========== QUẢN LÝ HỆ THỐNG - CHỈ ADMIN ==========
                    .antMatchers("/admin/account/**", "/admin/customer/**", "/admin/role/**",
                                 "/admin/discount-code/**", "/admin/shipping/**", 
                                 "/management/**", "/system/**")
                    .hasRole("ADMIN")

                    // ========== CATCH ALL /admin/** - ĐẶT CUỐI CÙNG ==========
                    .antMatchers("/admin/**")
                    .hasAnyRole("ADMIN", "VENDOR")  // USER KHÔNG VÀO ĐƯỢC

                    // ========== DEFAULT ==========
                    .anyRequest().authenticated()  // ← SỬA: YÊU CẦU ĐĂNG NHẬP cho các request còn lại

                    // ========== LOGIN & LOGOUT ==========
                    .and().formLogin()
                        .loginPage("/user-login")
                        .loginProcessingUrl("/user_login")
                        .usernameParameter("email")
                        .defaultSuccessUrl("/", true)
                        .permitAll()
                    .and().logout()
                        .logoutUrl("/user_logout")
                        .logoutSuccessUrl("/")
                        .permitAll()
                    .and().rememberMe()
                        .key("AbcDefgHijklmnOp_123456789")
                        .rememberMeParameter("remember-me")
                        .tokenValiditySeconds(7 * 24 * 60 * 60)
                    
                    // ========== XỬ LÝ LỖI 403 ==========
                    .and().exceptionHandling()
                        .accessDeniedPage("/403");  // Tạo trang 403.html

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