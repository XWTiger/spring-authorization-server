package com.sugon.cloud.enums;

public enum AuthorizationGrantTypeEnum {

    /**
     * 简单模式
     */
    IMPLICIT("implicit"),
    /**
     * 刷新token
     */
    REFRESH_TOKEN("refresh_token"),

    CLIENT_CREDENTIALS("client_credentials"),
    PASSWORD("password"),
    JWT_BEARER("urn:ietf:params:oauth:grant-type:jwt-bearer");

    public String value;

    AuthorizationGrantTypeEnum(String value) {
        this.value = value;
    }
}
