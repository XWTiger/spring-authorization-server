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

    private AuthorizationGrantTypeEnum(String value) {
        this.value = value;
    }

    public static AuthorizationGrantTypeEnum getByValue(String value) {
        if (IMPLICIT.value.equals(value)) {
            return IMPLICIT;
        }
        if (REFRESH_TOKEN.value.equals(value)) {
            return REFRESH_TOKEN;
        }
        if (CLIENT_CREDENTIALS.value.equals(value)) {
            return CLIENT_CREDENTIALS;
        }
        if (PASSWORD.value.equals(value)) {
            return PASSWORD;
        }
        if (JWT_BEARER.value.equals(value)) {
            return JWT_BEARER;
        }
        return null;
    }
}
