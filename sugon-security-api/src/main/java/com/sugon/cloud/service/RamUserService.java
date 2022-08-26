//package com.sugon.cloud.service;
//
//import com.baomidou.mybatisplus.extension.service.IService;
//import com.sugon.app.web.rest.PasswordEntity;
//import com.sugon.app.web.rest.vm.ResultModel;
//import com.sugon.cloud.common.ResultModel;
//import com.sugon.cloud.entity.RamUserEntity;
//
//import java.util.List;
//
//
//public interface RamUserService extends IService<RamUserEntity> {
//
//    void saveUserWithRole(RamUserEntity ramUserEntity, String roles) throws Exception;
//
//    void editUserWithRole(RamUserEntity ramUserEntity, String roles);
//
//    /*void saveUserRole(String userId, String roles);*/
//
//    void editUseRole(String userId, String roles);
//
//    int userAssociateGroup(String userId, String[] groupId);
//
//    List<RamUserEntity> getUserByGroupId(String groupId) throws Exception;
//
//    ResultModel changePassword(PasswordEntity passwordEntity, boolean resetPassword) throws Exception;
//
//    boolean isBuiltinUser(String userId);
//
//    boolean isBuiltinUserRole(String userId, String roleType);
//
//    ResultModel checkPassword(String userId, String password);
//
//    void updateByLastLoginDate(long day);
//
//    List<RamUserEntity> findByDate(long day);
//
//    void editUserRoleApp(String userId, String roles);
//
//}
