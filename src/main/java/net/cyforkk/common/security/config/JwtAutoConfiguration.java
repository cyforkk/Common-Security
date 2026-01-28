package net.cyforkk.common.security.config;

import lombok.extern.slf4j.Slf4j;
import net.cyforkk.common.security.utils.JwtUtil;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * JWT 模块自动配置入口
 * <p>
 * 负责加载配置属性并初始化 JwtUtil 工具类。
 * </p>
 *
 * @author Cyforkk
 * @version 1.0
 */
@Slf4j
@AutoConfiguration
// ✅ 核心：统一激活本模块所有的配置属性类
@EnableConfigurationProperties({JwtProperties.class, IgnoreUrlsConfig.class})
public class JwtAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean // 允许业务方覆盖
    public JwtUtil jwtUtil(JwtProperties properties) {
        log.info("初始化 JWT 安全模块 | Token前缀: {} | Access过期: {} | Refresh过期: {}",
                properties.getTokenHead(),
                properties.getExpiration(),
                properties.getRefreshExpiration());

        return new JwtUtil(properties);
    }
}