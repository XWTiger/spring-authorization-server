package com.sugon.cloud.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.sugon.cloud.entity.RamUserEntity;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface RamUserMapper extends BaseMapper<RamUserEntity> {



    @Select("update ram_user set status = false where TIMESTAMPDIFF(DAY,last_login,CURDATE()) > #{day}")
    void updateByLastLoginDate(@Param("day") long day);

    @Select("select * from ram_user where TIMESTAMPDIFF(DAY,last_login,CURDATE()) > #{day} and status = true")
    List<RamUserEntity> findByDate(@Param("day") long day);

    @Select("update ram_user set time_limit = null where id = #{id}")
    void updateNullById(@Param("id") String id);
}
