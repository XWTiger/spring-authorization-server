package com.sugon.cloud.common;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.sugon.cloud.enums.ResultStatus;
import io.swagger.annotations.ApiModelProperty;

public class ResultModel<T> {
    @ApiModelProperty("状态码")
    @JsonProperty("status_code")
    private Integer statusCode = 1;
    @ApiModelProperty("执行结果消息")
    @JsonProperty("status_mes")
    private String statusMes = "执行成功";
    @ApiModelProperty("返回内容")
    private T content;
    @ApiModelProperty("资源")
    private String resource;

    public Integer getStatusCode() {
        return this.statusCode;
    }

    public void setStatusCode(Integer statusCode) {
        this.statusCode = statusCode;
        if (0 == statusCode) {
            this.statusMes = "执行失败";
        }

    }

    public String getStatusMes() {
        return this.statusMes;
    }

    public void setStatusMes(String statusMes) {
        this.statusMes = statusMes;
    }

    public T getContent() {
        return this.content;
    }

    public void setContent(T content) {
        this.content = content;
    }

    public ResultModel() {
    }

    public ResultModel(ResultStatus status) {
        this.statusCode = status.getCode();
        this.statusMes = status.getMessage();
    }

    public ResultModel(ResultStatus status, T content) {
        this.statusCode = status.getCode();
        this.statusMes = status.getMessage();
        this.content = content;
    }

    public ResultModel(Integer statusCode, String statusMes, T content) {
        this.statusCode = statusCode;
        this.statusMes = statusMes;
        this.content = content;
    }

    public ResultModel(String resource, Integer statusCode, String statusMes, T content) {
        this.resource = resource;
        this.statusCode = statusCode;
        this.statusMes = statusMes;
        this.content = content;
    }

    public ResultModel(Boolean statusCode, String statusMes, T content) {
        if (statusCode == null) {
            this.statusCode = null;
        } else if (statusCode) {
            this.statusCode = 1;
        } else {
            this.statusCode = 0;
        }

        this.statusMes = statusMes;
        this.content = content;
    }

    public static <T> ResultModel success(String msg, T content) {
        ResultModel resultModel = new ResultModel(1, msg, content);
        return resultModel;
    }

    public static <T> ResultModel success(String msg, String resource, T content) {
        ResultModel resultModel = new ResultModel(resource, 1, msg, content);
        return resultModel;
    }

    public static <T> ResultModel success(String resource) {
        ResultModel resultModel = new ResultModel(resource, 1, "执行成功", (Object)null);
        return resultModel;
    }

    public static <T> ResultModel success(T content) {
        ResultModel resultModel = new ResultModel(1, "执行成功", content);
        return resultModel;
    }

    public static ResultModel error() {
        ResultModel resultModel = new ResultModel(0, "执行失败", (Object)null);
        return resultModel;
    }

    public static ResultModel error(String msg) {
        ResultModel resultModel = new ResultModel(0, msg, (Object)null);
        return resultModel;
    }

    public static <T> ResultModel error(String msg, T content) {
        ResultModel resultModel = new ResultModel(0, msg, content);
        return resultModel;
    }

    public String getResource() {
        return this.resource;
    }

    public void setResource(String resource) {
        this.resource = resource;
    }
}
