package com.project.DuAnTotNghiep.controller.user;

import com.project.DuAnTotNghiep.dto.Account.AccountDto;
import com.project.DuAnTotNghiep.entity.Account;
import com.project.DuAnTotNghiep.entity.Customer;
import com.project.DuAnTotNghiep.entity.Role;
import com.project.DuAnTotNghiep.exception.ShopApiException;
import com.project.DuAnTotNghiep.repository.AccountRepository;
import com.project.DuAnTotNghiep.repository.CustomerRepository;
import com.project.DuAnTotNghiep.service.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.mail.MessagingException;
import java.time.LocalDateTime;

@Controller
public class AuthController {

    private final AccountService accountService;
    private final AccountRepository accountRepository;
    private final PasswordEncoder passwordEncoder;
    private final VerificationCodeService verificationCodeService;

    private final CustomerRepository customerRepository;


    public AuthController(AccountService accountService, AccountRepository accountRepository, PasswordEncoder passwordEncoder, SessionService sessionService, CookieService cookieService, VerificationCodeService verificationCodeService, CustomerRepository customerRepository) {
        this.accountService = accountService;
        this.accountRepository = accountRepository;
        this.passwordEncoder = passwordEncoder;
        this.verificationCodeService = verificationCodeService;
        this.customerRepository = customerRepository;
    }

    @GetMapping("/user-login")
    public String viewLogin(Model model) {
        return "user/login";
    }

    @GetMapping("/forgot-pass")
    public String forgotPass(Model model){
        return "user/forgot-pass";
    }
    
    // ✅ THÊM MỚI: Xử lý POST từ trang forgot-pass (gửi email)
    @PostMapping("/reset-page")
    public String sendResetPasswordEmail(@RequestParam String email, 
                                         RedirectAttributes redirectAttributes) {
        try {
            // Kiểm tra email có tồn tại không
            Account account = accountService.findByEmail(email);
            
            if (account == null) {
                redirectAttributes.addFlashAttribute("errorMessage", 
                    "Email không tồn tại trong hệ thống!");
                return "redirect:/forgot-pass";
            }
            
            // Gửi mã OTP đến email
            verificationCodeService.createVerificationCode(email);
            
            redirectAttributes.addFlashAttribute("success", 
                "Mã xác thực đã được gửi đến email " + email);
            redirectAttributes.addFlashAttribute("email", email);
            
            return "redirect:/reset-pass";
            
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("errorMessage", 
                "Có lỗi xảy ra: " + e.getMessage());
            return "redirect:/forgot-pass";
        }
    }

    // ✅ THÊM MỚI: Hiển thị trang nhập mã OTP và mật khẩu mới
    @GetMapping("/reset-pass")
    public String showResetPasswordPage(Model model) {
        return "user/reset-pass";
    }

    @GetMapping("/register")
    public String register(Model model,@ModelAttribute("Account") Account account){
        return "user/register";
    }

    @PostMapping("/register-save")
    public String saveRegister(Model model, 
                               @Validated @ModelAttribute AccountDto accountDto, 
                               RedirectAttributes redirectAttributes) throws MessagingException {

        Account accountByEmail = accountService.findByEmail(accountDto.getEmail());
        Account accountByPhone = accountRepository.findByCustomer_PhoneNumber(accountDto.getPhoneNumber());

        if (accountByEmail != null) {
            redirectAttributes.addFlashAttribute("errorMessage", "Email đã tồn tại !");
            return "redirect:/register";
        }
        if (accountByPhone != null) {
            redirectAttributes.addFlashAttribute("errorMessage", "Số điện thoại " + accountDto.getPhoneNumber() + " đã được đăng ký!");
            return "redirect:/register";
        }

        // ✅ Tạo tài khoản mới
        Account account = new Account();
        account.setEmail(accountDto.getEmail());

        Account lastAccount = accountRepository.findTopByOrderByIdDesc();
        Long nextCode = (lastAccount == null) ? 1 : lastAccount.getId() + 1;
        String accCode = "TK" + String.format("%04d", nextCode);
        account.setCode(accCode);

        String encoded = passwordEncoder.encode(accountDto.getPassword());
        account.setPassword(encoded);
        account.setNonLocked(true);

        // Mặc định role USER
        Role role = new Role();
        role.setId(3L);
        account.setRole(role);

        // ✅ Xử lý Customer
        Customer customer;
        if (customerRepository.existsByPhoneNumber(accountDto.getPhoneNumber())) {
            customer = customerRepository.findByPhoneNumber(accountDto.getPhoneNumber());
            customer.setName(accountDto.getName());
        } else {
            customer = new Customer();
            customer.setName(accountDto.getName());
            customer.setPhoneNumber(accountDto.getPhoneNumber());

            Customer lastCustomer = customerRepository.findTopByOrderByIdDesc();
            Long nextCustomerCode = (lastCustomer == null) ? 1 : lastCustomer.getId() + 1;
            String cusCode = "KH" + String.format("%04d", nextCustomerCode);
            customer.setCode(cusCode);
        }

        account.setCustomer(customer);
        account.setCreateDate(LocalDateTime.now());
        customerRepository.save(customer);
        accountService.save(account);

        // ✅ Gửi OTP xác thực email
        verificationCodeService.createVerificationCode(account.getEmail());
        redirectAttributes.addFlashAttribute("email", account.getEmail());

        redirectAttributes.addFlashAttribute("success", "Đăng ký thành công! Vui lòng kiểm tra email để xác thực tài khoản.");
        return "redirect:/verify-otp";
    }


    @PostMapping("/reset-password")
    public String resetPassword(@RequestParam String verificationCode,
                                @RequestParam String newPassword,
                                RedirectAttributes model) {
        // Kiểm tra mã xác nhận và lấy người dùng liên kết
        Account account = verificationCodeService.verifyCode(verificationCode);

        if (account != null) {
            // Đặt lại mật khẩu và xóa mã xác nhận
            accountService.resetPassword(account, newPassword);
            model.addFlashAttribute("success", "Đặt lại mật khẩu thành công");
            return "redirect:/user-login";
        } else {
            // Mã xác nhận không hợp lệ
            model.addFlashAttribute("errorMessage", "Mã xác thực không hợp lệ");
            return "redirect:/reset-pass";
        }
    }
    
    @GetMapping("/verify-otp")
    public String verifyOtpPage() {
        return "user/verify-otp"; // Trang HTML để người dùng nhập mã OTP
    }

    @PostMapping("/verify-otp")
    public String verifyOtp(@RequestParam String code, RedirectAttributes redirectAttributes) {
        Account account = verificationCodeService.verifyCode(code);

        if (account != null) {
            redirectAttributes.addFlashAttribute("success", "Xác thực thành công! Bạn có thể đăng nhập ngay.");
            return "redirect:/user-login";
        } else {
            redirectAttributes.addFlashAttribute("errorMessage", "Mã OTP không hợp lệ hoặc đã hết hạn!");
            return "redirect:/verify-otp";
        }
    }
    
    @PostMapping("/resend-otp")
    public String resendOtp(@RequestParam String email, RedirectAttributes redirectAttributes) {
        try {
            verificationCodeService.createVerificationCode(email);
            redirectAttributes.addFlashAttribute("success", "Mã OTP mới đã được gửi đến " + email);
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("errorMessage", "Không thể gửi lại OTP: " + e.getMessage());
        }
        redirectAttributes.addFlashAttribute("email", email);
        return "redirect:/verify-otp";
    }
}