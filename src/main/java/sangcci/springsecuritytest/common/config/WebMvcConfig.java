package sangcci.springsecuritytest.common.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        // /api/v1/oauth2/** 경로를 정적 리소스 처리에서 제외
        registry.addResourceHandler("/static/**")
                .addResourceLocations("classpath:/static/");
    }
}