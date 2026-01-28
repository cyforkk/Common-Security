package net.cyforkk.common.security.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Collections;
import java.util.List;

/**
 * CORS 跨域配置属性
 * <p>
 * 对应 application.yml 中的 security.cors 前缀
 * </p>
 *
 * @author Cyforkk
 * @version 1.0
 */
@Data
@ConfigurationProperties(prefix = "security.cors")
public class CorsProperties {

    /**
     * 是否开启 CORS 配置 (默认 false)
     */
    private boolean enabled = false;

    /**
     * 允许跨域的路径
     * 默认：/** (所有路径)
     */
    private String pathPattern = "/**";

    /**
     * 允许跨域的源 (Allowed Origins)
     * <p>示例：http://localhost:8080, https://www.example.com</p>
     * <p>注意：如果要允许所有，请使用 "*"</p>
     */
    private List<String> allowedOrigins = Collections.emptyList();

    /**
     * 允许的 HTTP 方法
     * <p>默认：GET, POST, PUT, DELETE, OPTIONS, PATCH</p>
     */
    private List<String> allowedMethods = List.of("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH");

    /**
     * 允许的请求头
     * 默认：* (所有)
     */
    private List<String> allowedHeaders = List.of("*");

    /**
     * 是否允许携带凭证 (Cookie/Token)
     * 默认：true (通常前后端分离都需要)
     */
    private boolean allowCredentials = true;

    /**
     * 预检请求(OPTIONS)的缓存时间 (秒)
     * 默认：3600 (1小时)
     */
    private Long maxAge = 3600L;
}