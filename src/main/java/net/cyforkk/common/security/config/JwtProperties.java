package net.cyforkk.common.security.config;

/**
 * ClassName: JwtProperties
 * Package: net.cyforkk.common.security.config
 * Description:
 *
 * @Author Cyforkk
 * @Create 2026/1/15 下午4:05
 * @Version 1.0
 */

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * JWT 配置属性类
 * 自动读取 application.yml 中以 jwt 开头的配置
 */
@Data
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {
    /**
     * 密钥 (必须大于32位)
     */
    private String secret;

    /**
     * Access Token 过期时间 (默认30分钟)
     */
    private Long expiration = 1800000L;

    /**
     * Refresh Token 过期时间 (默认7天)
     */
    private Long refreshExpiration =  604800000L;

    /**
     * 请求头名称 (默认 Authorization)
     */
    private String header = "Authorization";

    /**
     * Token 前缀 (默认 "Bearer ")
     */
    private String tokenHead = "Bearer ";
}
