package com.sugon.cloud.entity;

import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;
import org.springframework.format.annotation.DateTimeFormat;

import java.util.Date;

@Data
@TableName("ram_user")
public class RamUserEntity {
    @TableId
    @ApiModelProperty(value = "用户ID")
    private String id;
    @ApiModelProperty(value = "用户名")
    @JsonProperty("user_name")
    private String userName;
    @ApiModelProperty(value = "显示名")
    @JsonProperty("display_name")
    private String displayName;

    @ApiModelProperty(value = "描述")
    private String comments;

    @ApiModelProperty(value = "邮件")
    private String email;

    @ApiModelProperty(value = "手机")
    private String mobile;
    //@JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @ApiModelProperty(value = "密码")
    private String password;

    @ApiModelProperty(value = "盐")
    private String salt;

    @ApiModelProperty(value = "用户类型")
    private String type;
    @JsonProperty("owner_id")
    @ApiModelProperty(value = "主账号ID")
    private String ownerId;

    @ApiModelProperty(value = "过期时间")
    @JsonFormat(timezone = "GMT+8", pattern = "yyyy-MM-dd HH:mm:ss")
    @DateTimeFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    @JsonProperty("time_limit")
    private Date timeLimit;

    @ApiModelProperty(value = "状态")
    private Boolean status;
    @ApiModelProperty(value = "上次登陆")
    @JsonProperty("last_login")
    @JsonFormat(timezone = "GMT+8", pattern = "yyyy-MM-dd")
    @DateTimeFormat(pattern = "yyyy-MM-dd")
    private Date lastLogin;
    @ApiModelProperty(value = "上次改密")
    @JsonProperty("last_password_time")
    @JsonFormat(timezone = "GMT+8", pattern = "yyyy-MM-dd")
    @DateTimeFormat(pattern = "yyyy-MM-dd")
    private Date lastPasswordTime;
    @ApiModelProperty(value = "创建人")
    @JsonProperty("create_by")
    private String createBy;
    @ApiModelProperty(value = "允许登录IP")
    @JsonProperty("allow_ip")
    private String allowIp;
    @ApiModelProperty(value = "创建时间")
    @JsonProperty("create_at")
    @JsonFormat(timezone = "GMT+8", pattern = "yyyy-MM-dd HH:mm:ss")
    @DateTimeFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private Date createAt;
    @ApiModelProperty(value = "授权时间")
    @JsonProperty("join_at")
    @JsonFormat(timezone = "GMT+8", pattern = "yyyy-MM-dd HH:mm:ss")
    @DateTimeFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    @TableField(exist = false)
    private Date joinAt;
   /* @ApiModelProperty(value = "拥有策略列表")
    @TableField(exist = false)*/
    /*private List<RamPolicyEntity> ramPolicyEntities;*/
    @ApiModelProperty(value = "用户来源")
    //用户来源
    private String origin;
    @ApiModelProperty(value = "来源用户Id")
    //来源用户Id
    @JsonProperty("origin_user_id")
    @TableField("origin_user_id")
    private String originUserId;
    @ApiModelProperty(value = "来源用户名")
    //来源用户名
    @JsonProperty("origin_user_name")
    @TableField("origin_user_name")
    private String originUsername;
    @ApiModelProperty(value = "公钥")
    @JsonProperty("public_key")
    @TableField(exist = false)
    private String publicKey;
    @ApiModelProperty(value = "主账号信息")
    @JsonProperty("master_user")
    @TableField(exist = false)
    private RamUserEntity masterUser;

    @ApiModelProperty(value = "项目id")
    @JsonProperty("project_id")
    @TableField(exist = false)
    private String projectId;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public String getComments() {
        return comments;
    }

    public void setComments(String comments) {
        this.comments = comments;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getMobile() {
        return mobile;
    }

    public void setMobile(String mobile) {
        this.mobile = mobile;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getAllowIp() {
        return allowIp;
    }

    public void setAllowIp(String allowIp) {
        this.allowIp = allowIp;
    }

    public String getOwnerId() {
        return ownerId;
    }

    public void setOwnerId(String ownerId) {
        this.ownerId = ownerId;
    }

    public Boolean getStatus() {
        return status;
    }

    public void setStatus(Boolean status) {
        this.status = status;
    }

    public Date getLastLogin() {
        return lastLogin;
    }

    public void setLastLogin(Date lastLogin) {
        this.lastLogin = lastLogin;
    }

    public Date getLastPasswordTime() {
        return lastPasswordTime;
    }

    public void setLastPasswordTime(Date lastPasswordTime) {
        this.lastPasswordTime = lastPasswordTime;
    }

    public String getCreateBy() {
        return createBy;
    }

    public void setCreateBy(String createBy) {
        this.createBy = createBy;
    }

    public Date getCreateAt() {
        return createAt;
    }

    public void setCreateAt(Date createAt) {
        this.createAt = createAt;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }



    public Date getTimeLimit() {
        return timeLimit;
    }

    public void setTimeLimit(Date timeLimit) {
        this.timeLimit = timeLimit;
    }

    public String getOrigin() {
        return origin;
    }

    public void setOrigin(String origin) {
        this.origin = origin;
    }

    public String getOriginUserId() {
        return originUserId;
    }

    public void setOriginUserId(String originUserId) {
        this.originUserId = originUserId;
    }

    public String getOriginUsername() {
        return originUsername;
    }

    public void setOriginUsername(String originUsername) {
        this.originUsername = originUsername;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public RamUserEntity getMasterUser() {
        return masterUser;
    }

    public void setMasterUser(RamUserEntity masterUser) {
        this.masterUser = masterUser;
    }

    public String getProjectId() {
        return projectId;
    }

    public void setProjectId(String projectId) {
        this.projectId = projectId;
    }
}
