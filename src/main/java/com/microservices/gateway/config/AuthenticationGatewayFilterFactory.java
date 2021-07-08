package com.microservices.gateway.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@Component
public class AuthenticationGatewayFilterFactory extends AbstractGatewayFilterFactory<AuthenticationGatewayFilterFactory.Config> {

    private final Logger logger = LoggerFactory.getLogger(AuthenticationGatewayFilterFactory.class);
    private final ObjectWriter objectMapper = new ObjectMapper().writer().withDefaultPrettyPrinter();

    @Autowired
    private RestTemplate restTemplate;

    public AuthenticationGatewayFilterFactory() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            var request = exchange.getRequest();
            var headers = request.getHeaders();
            var data = headers.get("Authorization");
            if (data != null) {
                var authorization = data.get(0);
                if (authorization != null && authorization.toLowerCase().startsWith("bearer")) {
                    var jwtToken = authorization.substring(7);

                    try {
                        // build request and send
                        var httpHeaders = new HttpHeaders();
                        httpHeaders.setBasicAuth(config.getClientId(), config.getClientSecret());
                        var builder = UriComponentsBuilder.fromHttpUrl(config.getUrl())
                                .queryParam("token", jwtToken)
                                .queryParam("path", Objects.requireNonNull(request.getPath()))
                                .queryParam("method", Objects.requireNonNull(request.getMethod()).name());

                        var result = restTemplate.exchange(builder.toUriString(), HttpMethod.GET, new HttpEntity<>(httpHeaders), Map.class);
                        if (Objects.requireNonNull(result.getBody()).containsKey("accessToken")) {
                            exchange.getRequest().mutate()
                                    .headers(h -> h.setBearerAuth(result.getBody().get("accessToken").toString()));
                        }
                    } catch (Exception e) {
                        var statusCode = ((HttpClientErrorException.BadRequest) e).getRawStatusCode();
                        if (Objects.requireNonNull(HttpStatus.resolve(statusCode)).is4xxClientError())
                            return this.handleInvalidToken(exchange, e.getMessage());

                        if (Objects.requireNonNull(HttpStatus.resolve(statusCode)).is5xxServerError()) {
                            var response = exchange.getResponse();
                            response.setRawStatusCode(statusCode);
                            return response.setComplete();
                        }
                    }
                    logger.info("Complete to call request");
                } else {
                    return this.handleInvalidToken(exchange, "Token invalid");
                }
            } else {
                return this.handleNoToken(exchange, "No token");
            }

            return chain.filter(exchange);
        });
    }

    private Mono<Void> handleNoToken(ServerWebExchange exchange, String message) {
        final var errorKey = "token";
        final var errorValue = "no.token";
        var errorDetailResponseList = Collections.singletonList(new ErrorDetailResponse(errorKey, errorValue));
        return handleError(exchange, message, errorDetailResponseList, HttpStatus.FORBIDDEN);
    }

    private Mono<Void> handleInvalidToken(ServerWebExchange exchange, String message) {
        final var errorKey = "token";
        final var errorValue = "invalid.token";
        var errorDetailResponseList = Collections.singletonList(new ErrorDetailResponse(errorKey, errorValue));
        return handleError(exchange, message, errorDetailResponseList, HttpStatus.UNAUTHORIZED);
    }

    private Mono<Void> handleError(ServerWebExchange exchange, String message, List<ErrorDetailResponse> errorDetailResponseList, HttpStatus httpStatus) {
        var error = ErrorResponse.builder()
                .status(httpStatus.value())
                .message(message)
                .type(exchange.getRequest().getURI().toString())
                .path(exchange.getRequest().getPath().toString())
                .errorDetailResponseList(errorDetailResponseList)
                .build();

        var response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        var bytes = new byte[0];
        try {
            bytes = objectMapper.writeValueAsString(error).getBytes(StandardCharsets.UTF_8);
        } catch (JsonProcessingException e) {
            logger.info("Error parser object", e.getMessage());
        }

        return response.writeWith(Mono.just(response.bufferFactory().wrap(bytes)));
    }

    public static class Config {
        private String clientId;
        private String clientSecret;
        private String url;

        public String getUrl() {
            return url;
        }

        public void setUrl(String url) {
            this.url = url;
        }

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getClientSecret() {
            return clientSecret;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }
    }
}
