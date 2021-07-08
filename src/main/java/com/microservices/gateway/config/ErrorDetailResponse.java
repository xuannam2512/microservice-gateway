package com.microservices.gateway.config;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class ErrorDetailResponse {
    private String key;
    private String value;
}
