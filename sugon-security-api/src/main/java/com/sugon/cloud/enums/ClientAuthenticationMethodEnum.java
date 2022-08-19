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
}
