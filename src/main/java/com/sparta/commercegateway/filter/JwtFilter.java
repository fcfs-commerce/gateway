package com.sparta.commercegateway.filter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sparta.commercegateway.util.JwtUtil;
import io.jsonwebtoken.Claims;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class JwtFilter implements WebFilter {

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {

    ServerHttpRequest request = exchange.getRequest();
    ServerHttpResponse response = exchange.getResponse();

    if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
      return chain.filter(exchange);
    }

    String token = JwtUtil.getJwtFromHeader(request);

    if (token != null && JwtUtil.validateToken(token)) {
      Claims userInfo = JwtUtil.getUserInfoFromToken(token);
      String userId = userInfo.getSubject();

      ServerHttpRequest.Builder mutatedRequest = request.mutate();
      String claimKey = "X-Claim-UserId";
      String claimValue = userId.toString();
      mutatedRequest.header(claimKey, claimValue);

      request = mutatedRequest.build();
      exchange = exchange.mutate().request(request).build();
    } else if (token == null) {
      return handlerUnauthorized(response, "No Authorization Header.");
    } else {
      return handlerUnauthorized(response, "JWT is not valid.");
    }

    return chain.filter(exchange);
  }

  private Mono<Void> handlerUnauthorized(ServerHttpResponse response, String message) {
    response.setStatusCode(HttpStatus.UNAUTHORIZED);
    response.getHeaders().add("Content-Type", "application/json");

    ObjectMapper mapper = new ObjectMapper();
    Map<String, String> map = new HashMap<>();
    map.put("message", message);
    map.put("code", "401");
    map.put("status", "Unauthorized");
    String body = null;
    try {
      body = mapper.writeValueAsString(map);
    } catch (JsonProcessingException e) {
      throw new RuntimeException(e);
    }

    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
    DataBuffer buffer = response.bufferFactory().wrap(bytes);
    return response.writeWith(Mono.just(buffer));
  }
}
