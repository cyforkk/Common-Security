package net.cyforkk.common.security.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * JWT配置属性类 (Production Version)
 * <p>
 * 自动读取application.yml中以jwt为前缀的配置项。
 * 核心优化：
 * 1. 使用 {@link Duration} 替代 Long，支持 "30m", "7d" 等直观配置。
 * 2. 将 Token 刷新接口路径配置化，提升模块通用性。
 * </p>
 *
 * @author Cyforkk
 * @version 2.4
 */
@Data
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {

    /**
     * 密钥 (必须复杂且保密，生产环境建议从环境变量或 Vault 读取)
     * <p>注意：HS256算法要求密钥长度至少32个字符</p>
     */
    private String secret;

    /**
     * Access Token 过期时间
     * <p>配置示例：30m (30分钟), 1h (1小时)</p>
     * 默认：30分钟
     */
    private Duration expiration = Duration.ofMinutes(30);

    /**
     * Refresh Token 过期时间
     * <p>配置示例：7d (7天)</p>
     * 默认：7天
     */
    private Duration refreshExpiration = Duration.ofDays(7);

    /**
     * 请求头名称
     * 默认：Authorization
     */
    private String header = "Authorization";

    /**
     * Token 前缀
     * 默认："Bearer "
     */
    private String tokenHead = "Bearer ";

    /**
     * Token 刷新接口的路径 (白名单)
     * <p>
     * 在 Filter 中遇到此路径时，将跳过 AccessToken 的校验，
     * 而是去检查 RefreshToken。
     * </p>
     * 默认：/user/refresh
     */
    private String refreshUrl = "/user/refresh";
}