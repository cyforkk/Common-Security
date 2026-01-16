package net.cyforkk.common.security.config;

import net.cyforkk.common.security.utils.JwtTool;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * ClassName: JwtAutoConfiguration
 * Package: net.cyforkk.common.security.config
 * Description:
 *
 * @Author Cyforkk
 * @Create 2026/1/15 下午4:06
 * @Version 1.0
 */

@AutoConfiguration
@EnableConfigurationProperties(JwtProperties.class)
public class JwtAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public JwtTool jwtTool(JwtProperties properties){
        return new JwtTool(properties);
    }
}
