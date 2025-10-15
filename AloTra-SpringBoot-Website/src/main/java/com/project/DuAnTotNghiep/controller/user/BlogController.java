package com.project.DuAnTotNghiep.controller.user;


import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class BlogController {

    @GetMapping("/getblog")
    public String getBlog(Model model) {
        model.addAttribute("layoutUser", "user/blog");
        return "user/blog";    }


    @GetMapping("/getblogdetail")
    public String getBlogDetail(Model model) {
        model.addAttribute("layoutUser", "user/blog-detail");
        return "user/blog-detail";
    }
}
