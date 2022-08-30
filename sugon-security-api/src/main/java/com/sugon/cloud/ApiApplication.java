package com.sugon.cloud;

import com.baomidou.mybatisplus.extension.spring.MybatisSqlSessionFactoryBean;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.apache.ibatis.session.SqlSessionFactory;
import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.core.env.Environment;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

import javax.activation.DataSource;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * @Author: yangdingshan
 * @Date: 2022/7/7 9:48
 * @Description:
 */
@Slf4j
@EnableSwagger2
@EnableGlobalMethodSecurity(
        prePostEnabled = true,
        securedEnabled = true,
        jsr250Enabled = true)
@SpringBootApplication
@MapperScan(basePackages = {"com.sugon.cloud.mapper"})
public class ApiApplication {

    public static void main(String[] args) throws UnknownHostException {
        ConfigurableApplicationContext context = SpringApplication.run(ApiApplication.class, args);
        Environment env = context.getEnvironment();
        String appName = env.getProperty("spring.application.name");
        String hosts = InetAddress.getLocalHost().getHostAddress();
        String port = env.getProperty("server.port");
        String contextPath = env.getProperty("server.servlet.context-path", "");
        String path = env.getProperty("spring.mvc.servlet.path", "");
        log.info("\n----------------------------------------------------------\n\t" +
                        "应用 '{}' 运行成功! 访问连接:\n\t" +
                        "Swagger文档-旧: \t\thttp://{}:{}{}{}/swagger-ui.html\n\t" +
                        "Swagger文档-新: \t\thttp://{}:{}{}{}/doc.html#/home\n\t" +
                        "----------------------------------------------------------",
                appName, hosts, port, contextPath, path, hosts, port, contextPath, path
        );
    }





}
