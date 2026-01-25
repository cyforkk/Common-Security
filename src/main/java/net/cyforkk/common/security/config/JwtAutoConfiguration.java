package net.cyforkk.common.security.config;

import net.cyforkk.common.security.utils.JwtUtil;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * JWT自动配置类
 * <p>
 * 通过Spring Boot自动配置机制自动创建{@link JwtUtil} Bean。
 * 当容器中不存在JwtTool Bean时自动配置生效。
 * </p>
 *
 * @author Cyforkk
 * @version 1.0
 * @see JwtProperties
 * @see JwtUtil
 */

@AutoConfiguration
@EnableConfigurationProperties(JwtProperties.class)
public class JwtAutoConfiguration {

    /**
     * 创建JWT工具Bean
     *
     * @param properties JWT配置属性
     * @return 配置好的JWT工具实例
     */
    @Bean
    @ConditionalOnMissingBean
    public JwtUtil JwtUtil(JwtProperties properties){
        return new JwtUtil(properties);
    }
}
