package com.sugon.cloud.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.sugon.cloud.entity.Oauth2ClientEntity;
import org.apache.ibatis.annotations.Select;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface Oauth2ClientMapper extends BaseMapper<Oauth2ClientEntity> {

    @Select("select * from oauth2_registered_client")
    List<Oauth2ClientEntity> selectAll();
}
