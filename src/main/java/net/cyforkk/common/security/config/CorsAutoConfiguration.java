package net.cyforkk.common.security.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * CORS 跨域自动配置类
 * <p>
 * 当 security.cors.enabled=true 时生效。
 * 解决了 allowCredentials 与 通配符 '*' 的冲突问题。
 * </p>
 *
 * @author Cyforkk
 * @version 2.4
 */
@Slf4j
@AutoConfiguration
@EnableConfigurationProperties(CorsProperties.class)
@ConditionalOnProperty(prefix = "security.cors", name = "enabled", havingValue = "true")
public class CorsAutoConfiguration {

    @Bean("corsConfigurationSource") // ✅ 显式指定 Bean 名称，防止重命名导致 Security 无法识别
    public CorsConfigurationSource corsConfigurationSource(CorsProperties properties) {
        log.info("启用 CORS 跨域配置 | 路径: {} | 允许源: {}",
                properties.getPathPattern(), properties.getAllowedOrigins());

        CorsConfiguration configuration = new CorsConfiguration();

        // 1. 智能处理源 (Origin)
        if (properties.getAllowedOrigins().contains("*")) {
            // 使用 Pattern 模式以支持 allowCredentials
            configuration.addAllowedOriginPattern("*");
        } else {
            configuration.setAllowedOrigins(properties.getAllowedOrigins());
        }

        // 2. 设置其他属性
        configuration.setAllowedMethods(properties.getAllowedMethods());
        configuration.setAllowedHeaders(properties.getAllowedHeaders());
        configuration.setAllowCredentials(properties.isAllowCredentials()); // ✅ 使用 isXxx()
        configuration.setMaxAge(properties.getMaxAge());

        // 3. 注册路径
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration(properties.getPathPattern(), configuration);

        return source;
    }
}