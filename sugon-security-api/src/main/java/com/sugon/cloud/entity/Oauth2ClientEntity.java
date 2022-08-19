package com.sugon.cloud.entity;


import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableName;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.sugon.cloud.enums.AuthorizationGrantTypeEnum;
import com.sugon.cloud.enums.ClientAuthenticationMethodEnum;
import com.sugon.cloud.enums.ClientTypeEnum;
import com.sugon.cloud.utils.JsonInstantDeserializer;
import com.sugon.cloud.utils.JsonInstantSerializer;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;

import javax.validation.constraints.NotNull;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

@Data
@AllArgsConstructor
@NoArgsConstructor
@ApiModel("客户端")
@TableName("oauth2_registered_client")
public class Oauth2ClientEntity {

    @ApiModelProperty(hidden = true)
    @TableField(exist = false)
    private String id;
    @ApiModelProperty("客户端id")
    @NotNull(message = "客户端id不能位空")
    private String clientId;

    @ApiModelProperty(value = "分发时间", hidden = true)
    private Instant clientIdIssuedAt;

    @ApiModelProperty("客户端密码")
    @NotNull(message = "客户端密码不能位空")
    private String clientSecret;

    @ApiModelProperty("过期时间，时间戳13位（）")
    @JsonDeserialize(using = JsonInstantDeserializer.class)
    @JsonSerialize(using = JsonInstantSerializer.class)
    private Instant clientSecretExpiresAt;

    @ApiModelProperty("客户端名称")
    private String clientName;
    private  Set<ClientAuthenticationMethodEnum> clientAuthenticationMethods = new HashSet();
    private  Set<AuthorizationGrantTypeEnum> authorizationGrantTypes = new HashSet();
    private  Set<String> redirectUris = new HashSet();

    @ApiModelProperty("范围 eg: message:read,message:write")
    private  Set<String> scopes = new HashSet();

    @ApiModelProperty("类型")
    private ClientTypeEnum typeEnum;

    //we will user client settings  or token settings
}
