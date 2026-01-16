package net.cyforkk.common.security.utils;



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
 * JWT通用工具类
 * <p>
 * 提供JWT令牌的生成、解析、验证和声明提取功能。
 * 依赖于{@link JwtProperties}配置。
 * </p>
 *
 * @author Cyforkk
 * @version 1.0
 */
public class JwtTool {

    private final JwtProperties jwtProperties;

    /**
     * 构造器注入JWT配置属性
     *
     * @param jwtProperties JWT配置属性
     */
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
     * 生成Refresh Token
     * <p>
     * Refresh Token用于获取新的Access Token，通常具有较长的过期时间。
     * 不包含额外声明信息。
     * </p>
     *
     * @param subject 用户标识，通常是用户ID
     * @return Refresh Token字符串
     */
    public String createRefreshToken(String subject){
        return createToken(subject, new HashMap<>(), jwtProperties.getRefreshExpiration());
    }

    /**
     * 底层Token生成方法
     * <p>
     * 根据提供的主题、声明和过期时间生成JWT令牌。
     * 使用HS256算法签名。
     * </p>
     *
     * @param subject 主题，通常是用户标识
     * @param claims  额外声明信息
     * @param expire  过期时间（毫秒）
     * @return JWT令牌字符串
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
     * 解析Token并获取声明(Claims)
     * <p>
     * 自动处理Token前缀（如"Bearer "），验证签名和过期时间。
     * 如果令牌无效（签名错误、过期等），将抛出异常。
     * </p>
     *
     * @param token JWT令牌字符串（可包含前缀）
     * @return 声明(Claims)对象
     * @throws io.jsonwebtoken.JwtException 如果令牌无效
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
     * 校验Token是否合法（验签 + 验过期）
     * <p>
     * 通过解析令牌来验证其签名和过期时间，不抛出异常。
     * </p>
     *
     * @param token JWT令牌字符串
     * @return true 如果令牌有效，否则返回false
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
     * 提取Subject（用户ID）
     * <p>
     * 从令牌中提取主题(subject)声明，通常是用户标识。
     * </p>
     *
     * @param token JWT令牌字符串
     * @return 主题字符串
     * @throws io.jsonwebtoken.JwtException 如果令牌无效
     */
    public String extractSubject(String token){
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * 通用声明提取方法
     * <p>
     * 使用提供的函数从令牌声明中提取特定值。
     * </p>
     *
     * @param token JWT令牌字符串
     * @param claimsResolver 声明解析函数，例如{@link Claims::getSubject}
     * @param <T> 返回值类型
     * @return 从声明中提取的值
     * @throws io.jsonwebtoken.JwtException 如果令牌无效
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
        final Claims claims = parseToken(token);
        return claimsResolver.apply(claims);
    }

    /**
     * 获取签名密钥
     * <p>
     * 根据配置的密钥字符串生成HMAC-SHA密钥。
     * </p>
     *
     * @return 签名密钥
     */
    public Key getSignKey(){
        return Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes());
    }




}
