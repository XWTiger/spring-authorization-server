package com.sugon.cloud.enums;

public enum ClientAuthenticationMethodEnum {
    CLIENT_SECRET_BASIC("client_secret_basic"),
    CLIENT_SECRET_POST("client_secret_post"),
    CLIENT_SECRET_JWT("client_secret_jwt"),
    PRIVATE_KEY_JWT("private_key_jwt"),
    NONE("none");
    public String value;

    ClientAuthenticationMethodEnum(String value) {
        this.value = value;
    }

    public static ClientAuthenticationMethodEnum getByValue(String value) {

        if (CLIENT_SECRET_BASIC.value.equals(value)) {
            return CLIENT_SECRET_BASIC;
        }
        if (CLIENT_SECRET_POST.value.equals(value)) {
            return CLIENT_SECRET_POST;
        }
        if (CLIENT_SECRET_JWT.value.equals(value)) {
            return CLIENT_SECRET_JWT;
        }
        if (PRIVATE_KEY_JWT.value.equals(value)) {
            return PRIVATE_KEY_JWT;
        }
        if (NONE.value.equals(value)) {
            return NONE;
        }
        return null;

    }
}
