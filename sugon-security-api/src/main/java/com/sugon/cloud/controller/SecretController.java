package com.sugon.cloud.controller;

import com.sugon.cloud.common.ResultModel;
import com.sugon.cloud.utils.RSAUtil;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.concurrent.TimeUnit;

@Api("密文相关接口")
@RestController
@Slf4j
//@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class SecretController {

    @Autowired
    private  RedisTemplate redisTemplate;

    @GetMapping("api/salt")
    @ApiOperation("获取salt")
    public ResultModel initSalt() {
        ResultModel resultModel = new ResultModel();
        try {
            Map<String, Object> keyPairMap = RSAUtil.genKeyPair();
            String publicKey = RSAUtil.getPublicKey(keyPairMap);
            String privateKey = RSAUtil.getPrivateKey(keyPairMap);
            System.out.println(publicKey);
            System.out.println(privateKey);
            resultModel.setContent(publicKey);
            redisTemplate.opsForValue().set(publicKey,privateKey, 12, TimeUnit.HOURS);

            return resultModel;
        } catch (Exception e) {
            resultModel.setStatusCode(0);
            resultModel.setStatusMes("获取信息失败");
            log.error("init public key error", e);
        }
        return resultModel;
    }


    @PostMapping("api/encrypt")
    @ApiOperation("加密")
    public ResultModel encrypt (@RequestParam("key") String publicKey, @RequestParam("password") String password) {
        ResultModel resultModel = new ResultModel();
        try {
            String encrypted = Base64.encodeBase64String(RSAUtil.encryptByPublicKey(password.getBytes(), publicKey));
            resultModel.setContent(encrypted);
        } catch (Exception e) {
            resultModel.setStatusCode(0);
            resultModel.setStatusMes("加密失败");
            log.error("encrypt By publicKey error", e);
        }
        return resultModel;
    }

    @PostMapping("api/decrypt")
    @ApiOperation("解密")
    public ResultModel decrypt (@RequestParam("key") String key, @RequestParam("password") String password) {
        ResultModel resultModel = new ResultModel();
        String privateKey = (String) redisTemplate.opsForValue().get(key);
        try {
            String decrypt = new String(RSAUtil.decryptByPrivateKey(Base64.decodeBase64(password), privateKey));
            resultModel.setContent(decrypt);
        } catch (Exception e) {
            resultModel.setStatusCode(0);
            resultModel.setStatusMes("解密失败");
            log.error("decrypt By PrivateKey error", e);
        }
        return resultModel;
    }
}
