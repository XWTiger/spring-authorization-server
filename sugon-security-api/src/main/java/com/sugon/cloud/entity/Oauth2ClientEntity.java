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

    private String id;
    @ApiModelProperty("客户端id")
    @NotNull(message = "客户端id不能位空")
    private String clientId;

    @ApiModelProperty(value = "分发时间", hidden = true)

    @JsonDeserialize(using = JsonInstantDeserializer.class)
    @JsonSerialize(using = JsonInstantSerializer.class)
    private Instant clientIdIssuedAt;

    @ApiModelProperty("客户端密码")
    @NotNull(message = "客户端密码不能位空")
    private String clientSecret;

    @ApiModelProperty("过期时间，时间戳13位（）")
    private Instant clientSecretExpiresAt;

    @ApiModelProperty("客户端名称")
    private String clientName;
    @TableField(exist = false)
    private  Set<ClientAuthenticationMethodEnum> clientAuthenticationMethod = new HashSet<ClientAuthenticationMethodEnum>();
    @TableField(exist = false)
    private  Set<AuthorizationGrantTypeEnum> authorizationGrantType = new HashSet<AuthorizationGrantTypeEnum>();
    @TableField(exist = false)
    private  Set<String> redirectUri = new HashSet();

    @ApiModelProperty(hidden = true)
    private String clientAuthenticationMethods;

    @ApiModelProperty(hidden = true)
    private String authorizationGrantTypes;

    @ApiModelProperty(hidden = true)
    private String redirectUris;

    @TableField(exist = false)
    @ApiModelProperty("范围 eg: message:read,message:write")
    private  Set<String> scope = new HashSet();

    private String scopes;


    @ApiModelProperty("类型")
    private ClientTypeEnum type;

    //we will user client settings  or token settings
}
