package net.cyforkk.common.security.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import net.cyforkk.common.security.config.JwtProperties;
import org.springframework.util.Assert;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

/**
 * JWT通用工具类 (Production Version)
 * <p>
 * 提供JWT令牌的生成、解析、验证和声明提取功能。
 * 核心特性：
 * 1. 支持双Token机制 (Access + Refresh)
 * 2. 适配 Duration 配置类型，支持直观的时间配置
 * 3. 强制使用 UTF-8 编码，防止跨平台乱码
 * 4. 完善的日志记录，拒绝异常吞没
 * </p>
 *
 * @author Cyforkk
 * @version 2.4
 */
@Slf4j
public class JwtUtil {

    private final JwtProperties jwtProperties;

    // 常量定义
    public static final String CLAIM_KEY_USERNAME = "username";
    public static final String CLAIM_KEY_USER_ID = "id";

    /**
     * 构造器注入
     * @param jwtProperties 配置属性
     */
    public JwtUtil(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;

        // 启动时防御性检查 (Fail Fast)
        String secret = jwtProperties.getSecret();
        if (secret == null || secret.isBlank()) {
            throw new IllegalArgumentException("❌ [Common-Security] 启动失败：未配置 jwt.secret！");
        }
        // HS256 要求密钥至少 32 字节
        if (secret.getBytes(StandardCharsets.UTF_8).length < 32) {
            throw new IllegalArgumentException("❌ [Common-Security] 启动失败：jwt.secret 长度不足32字节 (HS256要求)！");
        }
    }

    // ============================ 1. Token 生成区 ============================

    /**
     * 生成 Access Token
     */
    public String createAccessToken(Object userId, String username) {
        Assert.notNull(userId, "userId cannot be null");
        Map<String, Object> claims = new HashMap<>();
        claims.put(CLAIM_KEY_USERNAME, username);
        claims.put(CLAIM_KEY_USER_ID, userId);
        return createToken(userId.toString(), claims, jwtProperties.getExpiration().toMillis());
    }

    /**
     * 生成 Refresh Token
     */
    public String createRefreshToken(String subject) {
        // Refresh Token 使用独立的过期时间
        return createToken(subject, new HashMap<>(), jwtProperties.getRefreshExpiration().toMillis());
    }

    private String createToken(String subject, Map<String, Object> claims, long expire) {
        return Jwts.builder()
                .setId(UUID.randomUUID().toString()) // JTI: 唯一标识，用于黑名单机制
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expire))
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // ============================ 2. Token 解析与校验区 ============================

    /**
     * 解析Token
     */
    public Claims parseToken(String token) {
        if (token == null) {
            throw new IllegalArgumentException("Token cannot be null");
        }
        if (token.startsWith(jwtProperties.getTokenHead())) {
            token = token.substring(jwtProperties.getTokenHead().length());
        }
        return Jwts.parserBuilder()
                .setSigningKey(getSignKey())
                .setAllowedClockSkewSeconds(60) // 允许 60秒 时钟偏差
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * 验证 Token 是否有效
     */
    public boolean validateToken(String token, String expectedId) {
        try {
            String subject = extractSubject(token);
            return subject.equals(expectedId) && !isTokenExpired(token);
        } catch (ExpiredJwtException e) {
            log.debug("Token已过期: {}", e.getMessage());
            return false;
        } catch (Exception e) {
            log.warn("Token验证异常: {}", e.getMessage());
            return false;
        }
    }

    private boolean isTokenExpired(String token) {
        try {
            return extractExpiration(token).before(new Date());
        } catch (Exception e) {
            return true;
        }
    }

    // ============================ 3. 数据提取区 ============================

    public String extractSubject(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = parseToken(token);
        return claimsResolver.apply(claims);
    }

    private Key getSignKey() {
        return Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8));
    }
}