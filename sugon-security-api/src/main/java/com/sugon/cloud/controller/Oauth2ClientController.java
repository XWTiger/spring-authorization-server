package com.sugon.cloud.controller;

import com.sugon.cloud.common.ResultModel;
import com.sugon.cloud.entity.Oauth2ClientEntity;
import com.sugon.cloud.service.impl.Oauth2ClientService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RestController
@Api("oauth2 客户端接口")
@RequestMapping("/api/oauth2/client")
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class Oauth2ClientController {

    private final Oauth2ClientService oauth2ClientService;

    @ApiOperation("新增")
    @PostMapping
    public ResultModel<Oauth2ClientEntity> create(@Valid @RequestBody Oauth2ClientEntity oauth2ClientEntity) throws Exception {
        Oauth2ClientEntity result = oauth2ClientService.create(oauth2ClientEntity);
        return ResultModel.success(result);
    }
}
