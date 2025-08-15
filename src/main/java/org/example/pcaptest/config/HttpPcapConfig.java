package org.example.pcaptest.config;


import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;


@Data
@Component
@ConfigurationProperties("http.pacp")
public class HttpPcapConfig {

    /**
     * 是否开启http监听
     */
    private Boolean enable = false;

    private Integer interfaceIndex;

}
