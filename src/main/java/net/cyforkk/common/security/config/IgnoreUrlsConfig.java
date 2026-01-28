package net.cyforkk.common.security.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * URL白名单配置属性类 (Production Ready)
 * <p>
 * 用于接收 application.yml 中 `security.ignored.urls` 下的配置项。
 * 定义不需要经过 Spring Security 认证过滤器的接口路径（PermitAll）。
 * </p>
 *
 * <h3>配置示例：</h3>
 * <pre>
 * security:
 * ignored:
 * urls:
 * - /auth/login
 * - /doc.html
 * - /webjars/**
 * </pre>
 *
 * @author Cyforkk
 * @version 2.4
 */
@Data // 提供 Getter, Setter, ToString, Equals, HashCode
@ConfigurationProperties(prefix = "security.ignored")
public class IgnoreUrlsConfig {

    /**
     * 免鉴权 URL 列表
     * <p>
     * 1. 支持 Ant-Path 风格通配符 (如 /user/**). <br>
     * 2. 默认初始化为空列表，防止空指针异常 (NPE).
     * </p>
     */
    private List<String> urls = new ArrayList<>();
}