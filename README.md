# Common Security Starter 🛡️

**Common Security** 是一个基于 **Spring Boot 3** 和 **JWT** 的通用安全认证模块。它旨在为微服务架构提供开箱即用的、生产级的安全基础设施，解决了鉴权、跨域 (CORS)、URL 白名单管理等核心问题。

## ✨ 核心特性

- **🔐 生产级 JWT 实现**
  - 支持 **双令牌机制** (Access Token + Refresh Token)。
  - 内置 **JTI (Token ID)**，支持后续扩展黑名单/强退功能。
  - **防御性编程**：启动时强制校验密钥长度（HS256 至少 32 字节），拒绝弱密码隐患。
  - **分布式适配**：内置 60 秒时钟偏差容错，解决分布式服务器时间不同步导致的验签失败问题。
  - **日志可观测**：全链路日志记录，拒绝异常吞没，快速定位 Token 过期、篡改或格式错误。
- **🌐 智能 CORS 管理**
  - **按需开启**：通过 `security.cors.enabled` 开关控制，零侵入性。
  - **安全兼容**：完美解决 `AllowCredentials=true` 与通配符 `*` 的冲突问题（自动降级为 `OriginPattern`）。
  - **环境隔离**：支持通过配置区分开发环境（localhost）与生产环境域名。
- **⚡ 极简配置体验**
  - **语义化配置**：支持 `30m`、`7d` 等 `Duration` 格式，告别毫秒换算烦恼。
  - **自动装配 (SPI)**：基于 Spring Boot 3 `AutoConfiguration` 机制，引入依赖即生效，无需手动扫描包。
  - **高内聚设计**：JWT 刷新路径自动加入白名单，无需重复配置。

## 📦 快速开始

### 1. 引入依赖

在你的 Spring Boot 应用的 `pom.xml` 中引入本模块：

```XML
<dependency>
    <groupId>net.cyforkk</groupId>
    <artifactId>common-security</artifactId>
    <version>2.4</version>
</dependency>

<dependency>
    <groupId>org.springframework</groupId>
    <artifactId>spring-web</artifactId>
    <scope>provided</scope>
</dependency>
```

### 2. 添加配置 (application.yml)

所有配置均开箱即用，以下为完整配置示例：

```YAML
jwt:
  # [必填] 密钥：HS256算法要求至少32个字符，否则启动报错
  secret: "Make_Sure_This_Secret_Key_Is_Long_Enough_For_Security_12345"
  # [可选] Token前缀，默认 "Bearer "
  token-head: "Bearer "
  # [可选] AccessToken 过期时间，默认 30m
  expiration: 30m
  # [可选] RefreshToken 过期时间，默认 7d
  refresh-expiration: 7d
  # [可选] 刷新接口路径，会自动加入白名单
  refresh-url: "/auth/refresh"

security:
  # URL 白名单配置
  ignored:
    urls:
      - "/doc.html"
      - "/webjars/**"
      - "/swagger-resources/**"
      - "/auth/login"
      - "/auth/register"
      
  # CORS 跨域配置
  cors:
    enabled: true # 开启跨域支持
    path-pattern: "/**"
    # 允许的域名，开发环境可用 "*"
    allowed-origins:
      - "http://localhost:5173"
      - "https://www.your-production-domain.com"
    allowed-methods:
      - "GET"
      - "POST"
      - "PUT"
      - "DELETE"
      - "OPTIONS"
    allow-credentials: true
    max-age: 3600
```

### 3. 代码中使用

#### 生成 Token (登录场景)

```Java
@RestController
@RequestMapping("/auth")
public class AuthController {

    @Resource
    private JwtUtil jwtUtil;

    @PostMapping("/login")
    public LoginVO login(@RequestBody LoginDTO loginDTO) {
        // ... 校验账号密码 ...
        Long userId = user.getId();
        String username = user.getUsername();

        // 生成双 Token
        String accessToken = jwtUtil.createAccessToken(userId, username);
        String refreshToken = jwtUtil.createRefreshToken(userId.toString());

        return new LoginVO(accessToken, refreshToken);
    }
}
```

#### 校验 Token (过滤器场景)

在你的 `JwtAuthenticationTokenFilter` 中：

```Java
@Component
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {

    @Resource
    private JwtUtil jwtUtil;
    @Resource
    private JwtProperties jwtProperties;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) {
        String authHeader = request.getHeader(jwtProperties.getHeader());
        
        if (authHeader != null && authHeader.startsWith(jwtProperties.getTokenHead())) {
            String authToken = authHeader.substring(jwtProperties.getTokenHead().length());
            
            // 校验 Token 有效性
            if (jwtUtil.validateToken(authToken)) {
                String username = jwtUtil.extractUsername(authToken);
                // ... 执行 SecurityContextHolder 授权逻辑 ...
            }
        }
        chain.doFilter(request, response);
    }
}
```

## 🏗️ 架构设计

本模块严格遵循 Spring Boot Starter 规范：

- **配置层**：`JwtProperties`, `CorsProperties`, `IgnoreUrlsConfig` 负责承载 YAML 数据。
- **装配层**：`JwtAutoConfiguration`, `CorsAutoConfiguration` 利用 `@AutoConfiguration` 和 `@Conditional` 实现按需加载。
- **工具层**：`JwtUtil` 封装底层 JJWT 逻辑，提供简洁 API。

## ⚠️ 注意事项

1. **JDK 版本**：本项目基于 Java 17+ 构建。
2. **Spring Boot 版本**：适配 Spring Boot 3.x (Jakarta EE)。
3. **密钥安全**：在生产环境中，**严禁**将 `jwt.secret` 硬编码在代码仓库中。建议通过环境变量 (`export JWT_SECRET=...`) 或 K8s Secret 注入。

## 📝 版本历史

- **v2.4 (Current)**: 生产级版本。修复日志吞没问题，增强密钥长度校验，优化 CORS 自动配置。
- **v2.3**: 引入 `Duration` 配置类型，支持直观时间配置。
- **v1.0**: 初始版本，基础 JWT 生成与解析。

------

*Built with ❤️ by Cyforkk*