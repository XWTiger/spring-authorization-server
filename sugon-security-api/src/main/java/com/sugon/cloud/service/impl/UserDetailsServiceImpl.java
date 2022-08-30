package com.sugon.cloud.service.impl;


import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.sugon.cloud.entity.RamUserEntity;
import com.sugon.cloud.mapper.RamUserMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Objects;
import java.util.Set;

@Service
@Slf4j
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private  RamUserMapper ramUserMapper;

    @Autowired
    private  RedisTemplate redisTemplate;

    public static final String LOCKED_HEADER = "LOCKED:";
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        //check if is cached in redis
        RamUserEntity userEntity = loadUserByUserName(username);
        UserDetails user = User.builder()
                .username(username)
                .password(userEntity.getPassword())
                .roles(userEntity.getType())
                .accountExpired(Objects.isNull(userEntity.getTimeLimit())? false : userEntity.getTimeLimit().before(new Date()))
                .build();

        return user;
    }

    public RamUserEntity loadUserByUserName(String userName) {

        RamUserEntity userEntity = (RamUserEntity) redisTemplate.opsForValue().get(userName);
        if (Objects.isNull(userEntity)) {
            try {
                LambdaQueryWrapper queryWrapper = new LambdaQueryWrapper<RamUserEntity>().eq(RamUserEntity::getUserName, userName);
                userEntity = ramUserMapper.selectOne(queryWrapper);
            } catch (Exception e) {
                e.printStackTrace();
            }
            if (Objects.nonNull(userEntity)) {
                redisTemplate.opsForValue().set(userName, userEntity);
            }
        }
        return userEntity;
    }
}
