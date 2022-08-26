package com.sugon.cloud.entity;

import com.baomidou.mybatisplus.annotation.TableField;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@ApiModel
public class PasswordEntity {

    @JsonProperty("new_password")
    @ApiModelProperty(value = "新密码",required = true)
    @Size(min = 6, max = 32)
    @NotNull
    private String newPassword;
    @NotNull
    @ApiModelProperty(value = "旧密码", required = true)
    @JsonProperty("old_password")
    private String oldPassword;
    @NotNull
    @ApiModelProperty(value = "用户Id", required = true)
    private String userId;
    @NotNull
    @ApiModelProperty(value = "publicKey", required = true)
    @JsonProperty("public_key")
    @TableField(exist = false)
    private String publicKey;

    public String getNewPassword() {
        return newPassword;
    }

    public void setNewPassword(String newPassword) {
        this.newPassword = newPassword;
    }

    public String getOldPassword() {
        return oldPassword;
    }

    public void setOldPassword(String oldPassword) {
        this.oldPassword = oldPassword;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }
}
