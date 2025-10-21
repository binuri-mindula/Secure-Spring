package com.Security.Secureapp.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
public class GlobalAppException extends RuntimeException {
    public GlobalAppException(String message, Throwable cause) {
        super(message, cause);
    }

    public GlobalAppException(String message) {
        super(message);
    }
}