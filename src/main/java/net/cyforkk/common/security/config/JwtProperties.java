package net.cyforkk.common.security.config;



import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * JWT配置属性类
 * <p>
 * 自动读取application.yml中以jwt为前缀的配置项。
 * 使用{@link ConfigurationProperties}绑定属性值。
 * </p>
 *
 * @author Cyforkk
 * @version 1.0
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
