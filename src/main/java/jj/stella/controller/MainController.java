package jj.stella.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;

import jakarta.servlet.http.HttpServletRequest;

@Controller
public class MainController {
	
	/** 로그인 메인페이지 */
	@GetMapping(value={"/"})
	public ModelAndView main(HttpServletRequest req) throws Exception {
		
		ModelAndView page = new ModelAndView();
		page.setViewName("index");
		
		return page;
		
	};
	
}