package com.Security.Secureapp.exception;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.ModelAndView;

@ControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(CsrfValidationException.class)
    public ModelAndView handleCsrfValidationException(HttpServletRequest request, CsrfValidationException ex) {
        logger.warn("CSRF Validation Error: {} for URL: {}", ex.getMessage(), request.getRequestURL());
        ModelAndView mav = new ModelAndView("error"); // Renders error.html
        mav.addObject("status", HttpStatus.BAD_REQUEST.value());
        mav.addObject("error", "Bad Request");
        mav.addObject("message", ex.getMessage());
        mav.addObject("timestamp", new java.util.Date());
        mav.addObject("path", request.getRequestURI());
        return mav;
    }

    @ExceptionHandler(Exception.class)
    public ModelAndView handleAllExceptions(HttpServletRequest request, Exception ex) {
        logger.error("Global Error: {} for URL: {}", ex.getMessage(), request.getRequestURL(), ex);
        ModelAndView mav = new ModelAndView("error"); // Renders error.html
        mav.addObject("status", HttpStatus.INTERNAL_SERVER_ERROR.value());
        mav.addObject("error", "Internal Server Error");
        mav.addObject("message", "An unexpected error occurred. Please try again later.");
        mav.addObject("timestamp", new java.util.Date());
        mav.addObject("path", request.getRequestURI());
        return mav;
    }
}