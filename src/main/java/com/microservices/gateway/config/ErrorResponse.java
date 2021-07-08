package com.microservices.gateway.config;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
public class ErrorResponse {
    @Builder.Default
    private String timestamp = LocalDateTime.now().toString();
    private String type;
    private String path;
    private String message;
    private Integer status;
    @JsonProperty("errorList")
    private List<ErrorDetailResponse> errorDetailResponseList;
}
