package net.cyforkk.common.security.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import net.cyforkk.common.security.config.JwtProperties;
import org.springframework.util.Assert;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * JWT通用工具类 (Final Version 2.3)
 * <p>
 * 提供JWT令牌的生成、解析、验证和声明提取功能。
 * 核心特性：
 * 1. 支持双Token机制 (Access + Refresh)，修复了有效期引用错误的问题
 * 2. 适配 Duration 配置类型，支持直观的时间配置
 * 3. 强制使用 UTF-8 编码，防止跨平台乱码
 * </p>
 *
 * @author Cyforkk
 * @version 2.3
 */
public class JwtUtil {

    private final JwtProperties jwtProperties;

    // 常量定义：避免魔法值
    public static final String CLAIM_KEY_USERNAME = "username";
    public static final String CLAIM_KEY_USER_ID = "id";

    /**
     * 构造器注入JWT配置属性
     *
     * @param jwtProperties JWT配置属性
     */
    public JwtUtil(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
    }

    // ============================ 1. Token 生成区 ============================

    /**
     * 【推荐】便捷方法：生成 Access Token
     * 专门为最常用的场景设计，隐藏 Map 的创建细节
     *
     * @param userId   用户ID (支持 Long 或 String)
     * @param username 用户名 (或手机号)
     * @return Token 字符串
     * @throws IllegalArgumentException if userId is null
     */
    public String createAccessToken(Object userId, String username) {
        // 生产级代码习惯：入口参数校验，Fail Fast
        Assert.notNull(userId, "userId cannot be null");

        Map<String, Object> claims = new HashMap<>();
        claims.put(CLAIM_KEY_USERNAME, username);
        // 把 ID 也放入 Claims，方便前端解析 payload 直接获取，不用解密 subject
        claims.put(CLAIM_KEY_USER_ID, userId);

        // 调用底层的通用方法
        return createToken(userId.toString(), claims, jwtProperties.getExpiration().toMillis());
    }

    /**
     * 【重载方法】仅根据 UserID 生成 Access Token
     * <p>
     * 适用场景：
     * 1. 当前上下文只有 ID，没有用户名信息（如内部服务调用、异步任务）。
     * 2. 不需要前端显示用户名的简单场景。
     * </p>
     *
     * @param userId 用户ID
     * @return Access Token 字符串
     */
    public String createAccessToken(Object userId) {
        Assert.notNull(userId, "userId cannot be null");

        Map<String, Object> claims = new HashMap<>();
        claims.put(CLAIM_KEY_USER_ID, userId);

        // 注意：这里没有 put CLAIM_KEY_USERNAME
        return createToken(userId.toString(), claims, jwtProperties.getExpiration().toMillis());
    }

    /**
     * 生成 Access Token (自定义 Claims)
     *
     * @param subject 通常是 userId
     * @param claims  额外载荷
     */
    public String createAccessToken(String subject, Map<String, Object> claims) {
        return createToken(subject, claims, jwtProperties.getExpiration().toMillis());
    }

    /**
     * 生成 Refresh Token
     *
     * @param subject 用户标识，通常是用户ID
     * @return Refresh Token字符串
     */
    public String createRefreshToken(String subject) {
        // Refresh Token 只需要 ID 即可
        // 修复 Bug：必须使用 RefreshExpiration (如7天)，而不是 AccessExpiration (如30分钟)
        return createToken(subject, new HashMap<>(), jwtProperties.getRefreshExpiration().toMillis());
    }

    /**
     * 底层Token生成方法
     */
    private String createToken(String subject, Map<String, Object> claims, long expire) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expire))
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // ============================ 2. Token 解析区 ============================

    /**
     * 解析Token并获取声明(Claims)
     *
     * @param token JWT令牌字符串
     * @return 声明(Claims)对象
     * @throws io.jsonwebtoken.JwtException 如果令牌无效(过期/签名错误)
     */
    public Claims parseToken(String token) {
        if (token == null) {
            throw new IllegalArgumentException("Token cannot be null");
        }
        // 自动处理前缀
        if (token.startsWith(jwtProperties.getTokenHead())) {
            token = token.substring(jwtProperties.getTokenHead().length());
        }
        return Jwts.parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // ============================ 3. Token 校验区 ============================

    /**
     * 【严谨校验】验证 Token 是否有效，且属于指定用户
     *
     * @param token      Token字符串
     * @param expectedId 期望的用户ID
     * @return boolean
     */
    public boolean validateToken(String token, String expectedId) {
        try {
            String subject = extractSubject(token);
            return subject.equals(expectedId) && !isTokenExpired(token);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 【基础校验】仅验证 Token 是否格式正确且未过期
     */
    public boolean validateToken(String token) {
        try {
            parseToken(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 判断 Token 是否过期
     */
    private boolean isTokenExpired(String token) {
        try {
            return extractExpiration(token).before(new Date());
        } catch (Exception e) {
            return true;
        }
    }

    // ============================ 4. 数据提取区 ============================

    public String extractSubject(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public String extractUsername(String token) {
        return extractClaim(token, claims -> claims.get(CLAIM_KEY_USERNAME, String.class));
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = parseToken(token);
        return claimsResolver.apply(claims);
    }

    /**
     * 获取签名密钥
     * 优化：强制使用 UTF-8，防止跨平台乱码
     */
    private Key getSignKey() {
        return Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8));
    }
}