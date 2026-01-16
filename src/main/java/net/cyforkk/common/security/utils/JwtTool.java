package net.cyforkk.common.security.utils;

/**
 * ClassName: JwtTool
 * Package: net.cyforkk.common.security.utils
 * Description:
 *
 * @Author Cyforkk
 * @Create 2026/1/15 下午4:06
 * @Version 1.0
 */

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import net.cyforkk.common.security.config.JwtProperties;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * JWT 通用工具类
 */
public class JwtTool {

    private final JwtProperties jwtProperties;

    // 构造器注入配置
    public JwtTool(JwtProperties jwtProperties){
        this.jwtProperties = jwtProperties;
    }

    /**
     * 生成 Access Token
     * @param subject 通常是 userId
     * @param claims  额外载荷
     */
    public String createAccessToken(String subject, Map<String, Object> claims){
        return createToken(subject, claims, jwtProperties.getExpiration());
    }

    /**
     * 生成 Refresh Token
     */
    public String createRefreshToken(String subject){
        return createToken(subject, new HashMap<>(), jwtProperties.getRefreshExpiration());
    }

    /**
     * 底层生成方法
     */
    public String createToken(String subject, Map<String,Object> claims, long expire){
        return Jwts.builder()
                // 1. 设置载荷 (Payload)：比如 {"role": "admin"}
                .setClaims(claims)
                // 2. 设置核心标识 (Subject)：比如 userId "1001"
                .setSubject(subject)
                // 3. 设置签发时间 (IssuedAt)：现在
                .setIssuedAt(new Date())
                // 4. 设置过期时间 (Expiration)：现在 + 有效期
                .setExpiration(new Date(System.currentTimeMillis() + expire))
                // 5. 盖章 (Signature)：用你的 Secret 加密
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                // 6. 压缩成字符串
                .compact();
    }

    /**
     * 解析 Token 获取 Claims
     */
    public Claims parseToken(String token){
        // 如果带了前缀，自动去掉
        if(token.startsWith(jwtProperties.getTokenHead()))
        {
            token = token.substring(jwtProperties.getTokenHead().length());
        }
        // 然后再进行解密
        return Jwts.parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)  // <--- 关键：如果签名不对或过期，这里直接抛异常
                .getBody();
    }

    /**
     * 校验 Token 是否合法 (验签 + 验过期)
     */
    public boolean validateToken(String token)  {
        try{
            parseToken(token);
            return true;
        }catch(Exception e){
            return false;
        }
    }

    /**
     * 提取 Subject (UserId)
     */
    public String extractSubject(String token){
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * 通用提取方法
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
        final Claims claims = parseToken(token);
        return claimsResolver.apply(claims);
    }

    public Key getSignKey(){
        return Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes());
    }




}
