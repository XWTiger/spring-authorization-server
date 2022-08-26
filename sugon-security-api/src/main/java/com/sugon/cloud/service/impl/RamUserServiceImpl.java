//package com.sugon.cloud.service.impl;
//
//import com.alibaba.fastjson.JSONObject;
//import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
//import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
//import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
//import com.sugon.app.ram.entity.RamGroupUserEntity;
//import com.sugon.app.ram.entity.RamRoleEntity;
//import com.sugon.app.ram.entity.RamUserEntity;
//import com.sugon.app.ram.entity.RamUserRoleEntity;
//import com.sugon.app.ram.mapper.RamGroupUserMapper;
//import com.sugon.app.ram.mapper.RamRoleMapper;
//import com.sugon.app.ram.mapper.RamUserMapper;
//import com.sugon.app.ram.mapper.RamUserRoleMapper;
//import com.sugon.app.ram.service.RamRoleService;
//import com.sugon.app.ram.service.RamUserRoleService;
//import com.sugon.app.ram.service.RamUserService;
//import com.sugon.app.security.SecurityUtils;
//import com.sugon.app.service.KeystoneCommonService;
//import com.sugon.app.service.OsRegisterService;
//import com.sugon.app.service.OsUserService;
//import com.sugon.app.util.TypeUtil;
//import com.sugon.app.web.rest.PasswordEntity;
//import com.sugon.app.web.rest.util.AESUtil;
//import com.sugon.app.web.rest.util.MD5Util;
//import com.sugon.app.web.rest.util.RSAUtil;
//import com.sugon.app.web.rest.vm.OsRegisterVM;
//import com.sugon.app.web.rest.vm.ResultModel;
//import com.sugon.cloud.entity.RamUserEntity;
//import com.sugon.cloud.mapper.RamUserMapper;
//import com.sugon.cloud.service.RamUserService;
//import com.sugon.openstack4j.api.OSClient;
//import com.sugon.openstack4j.api.identity.v3.UserService;
//import com.sugon.openstack4j.model.identity.v3.User;
//import org.apache.commons.lang3.StringUtils;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.data.redis.core.RedisTemplate;
//import org.springframework.stereotype.Service;
//import org.springframework.transaction.annotation.Transactional;
//import org.springframework.util.ObjectUtils;
//
//import java.util.*;
//
//@Service
//public class RamUserServiceImpl extends ServiceImpl<RamUserMapper, RamUserEntity> implements RamUserService {
//    Logger logger = LoggerFactory.getLogger(RamUserServiceImpl.class);
////    public static final String[] BuiltinUserType = { "admin","system", "security", "audit"};
//    @Autowired
//    private RamUserRoleMapper ramUserRoleMapper;
//    @Autowired
//    private RamGroupUserMapper ramGroupUserMapper;
//    @Autowired
//    private RamUserMapper ramUserMapper;
//    @Autowired
//    private OsRegisterService osRegisterService;
//    @Autowired
//    private OsUserService osUserService;
//    @Autowired
//    private RamRoleMapper ramRoleMapper;
//    @Autowired
//    private KeystoneCommonService keystoneCommonService;
//    @Autowired
//    private RedisTemplate redisTemplate;
//    @Value("${cloud.view}")
//    private boolean cloudView;
//    @Autowired
//    private RamUserRoleService userRoleService;
//    @Autowired
//    private RamRoleService ramRoleService;
//
//    @Override
//    @Transactional(rollbackFor=Exception.class)
//    public void saveUserWithRole(RamUserEntity ramUserEntity, String roles) throws Exception {
//        OsRegisterVM registerVM = new OsRegisterVM();
//        registerVM.setName(ramUserEntity.getUserName());
//        registerVM.setDescription(ramUserEntity.getComments());
//        registerVM.setPhone(ramUserEntity.getMobile());
//        registerVM.setEmail(ramUserEntity.getEmail());
//        registerVM.setDomainId("default");
//        String password = ramUserEntity.getPassword();
//        String publicKey = ramUserEntity.getPublicKey();
//        String passwd = this.decrypt(publicKey,password);
//        registerVM.setPassword(passwd);
//        //加盐
//        String salt = MD5Util.randomGen(8);
//        String passwordNew = AESUtil.encrypt(passwd,MD5Util.string2MD5(salt));
//        ramUserEntity.setSalt(salt);
//        ramUserEntity.setPassword(passwordNew);
//        if(StringUtils.isEmpty(ramUserEntity.getOwnerId())){
//            if(cloudView){
//                User user = osRegisterService.registerUser(registerVM);
//                if(null!=user){
//                    this.save(ramUserEntity);
//                    this.editUseRole(ramUserEntity.getId(), roles);
//                }
//            }else {
//                this.save(ramUserEntity);
//                this.editUseRole(ramUserEntity.getId(), roles);
//            }
//        }else {
//            this.save(ramUserEntity);
//            this.editUseRole(ramUserEntity.getId(), roles);
//        }
//
//    }
//
//    @Override
//    @Transactional
//    public void editUserWithRole(RamUserEntity ramUserEntity, String roles) {
//        this.updateById(ramUserEntity);
//        this.editUseRole(ramUserEntity.getId(), roles);
//    }
//
//    /*@Override
//    public void saveUserRole(String userId, String roles) {
//        if(StringUtils.isNotEmpty(roles)) {
//            String[] arr = roles.split(",");
//            for (String roleId : arr) {
//                RamUserRoleEntity userRole = new RamUserRoleEntity(userId, roleId);
//                ramUserRoleMapper.insert(userRole);
//            }
//        }
//    }*/
//
//    @Override
//    public void editUseRole(String userId, String roles) {
//
//        //先删后加
//        ramUserRoleMapper.delete(new QueryWrapper<RamUserRoleEntity>().lambda().eq(RamUserRoleEntity::getRamUserId, userId));
//        if (StringUtils.isNotEmpty(roles)) {
//            String[] arr = roles.split(",");
//            String builtinRoleId = null;
//            RamUserEntity userEntity = this.getById(userId);
//            if (Arrays.asList(TypeUtil.BuiltinUserType).contains(userEntity.getType())){
//                Map map = new HashMap();
//                map.put("role_type",userEntity.getType());
//                List<RamRoleEntity> roleEntities = ramRoleMapper.selectByMap(map);
//                builtinRoleId = roleEntities.get(0).getId();
//                if (!Arrays.asList(arr).contains(builtinRoleId)){
//                    RamUserRoleEntity userRole = new RamUserRoleEntity(userId, builtinRoleId);
//                    ramUserRoleMapper.insert(userRole);
//                }
//            }
//            for (String roleId : arr) {
//                RamUserRoleEntity userRole = new RamUserRoleEntity(userId, roleId);
//                ramUserRoleMapper.insert(userRole);
//            }
//        }
//    }
//
//    @Override
//    public int userAssociateGroup(String userId, String[] groupId) {
//        int insertRamGroupUser = 0;
//        //先删用户下的所有组后加
//        ramGroupUserMapper.delete(new QueryWrapper<RamGroupUserEntity>().lambda().eq(RamGroupUserEntity::getRamUserId, userId));
//        if (ObjectUtils.isEmpty(groupId)){
//            return 1;
//        }
//        for (int i = 0; i < groupId.length; i++) {
//            if (StringUtils.isNotEmpty(groupId[i])) {
//                RamGroupUserEntity groupUser = new RamGroupUserEntity(groupId[i], userId);
//                insertRamGroupUser = ramGroupUserMapper.insert(groupUser);
//            }
//        }
//        return insertRamGroupUser;
//    }
//
//    @Override
//    public List<RamUserEntity> getUserByGroupId(String groupId) throws Exception {
//        try {
//            Map map = new HashMap<>();
//            map.put("groupId",groupId);
//            List<RamUserEntity> list = ramUserMapper.getUserByGroupId(map);
//            list.forEach(s->{s.setPassword("");s.setSalt("");});
//            return list;
//        } catch (Exception e) {
//            throw new Exception(e.getMessage());
//        }
//    }
//
//    @Override
//    @Transactional(rollbackFor=Exception.class)
//    public ResultModel changePassword(PasswordEntity passwordEntity,boolean resetPassword) throws Exception {
//        ResultModel resultModel = new ResultModel();
//        try {
//            RamUserEntity ramUserEntity = this.getById(passwordEntity.getUserId());
//            if(null==ramUserEntity){
//                resultModel.setStatusCode(false);
//                resultModel.setStatusMes("修改密码失败，该用户不存在");
//                return resultModel;
//            }
//            String publicKey = passwordEntity.getPublicKey();
//            String passwordOld = "";
//            String passwdOld = "";
//            String passwordData = "";
//            //盐
//            String salt = ramUserEntity.getSalt();
//            //校验密码
//            if (!resetPassword){
//                passwordOld = passwordEntity.getOldPassword();
//                passwdOld = this.decryptNotDel(publicKey,passwordOld);
//                passwordData = AESUtil.encrypt(passwdOld,MD5Util.string2MD5(salt));
//                logger.info("=========passwordOld============"+passwordOld);
//                logger.info("=========publicKey============"+publicKey);
//                logger.info("=========passwdOld============"+passwdOld);
//                logger.info("=========passwordData============"+passwordData);
//            }else {
//                passwordData = ramUserEntity.getPassword();
//                passwdOld = AESUtil.decrypt(passwordData,MD5Util.string2MD5(salt));
//            }
//            if(!resetPassword&&!ramUserEntity.getPassword().equals(passwordData)){
//                resultModel.setStatusCode(false);
//                resultModel.setStatusMes("密码错误");
//                return resultModel;
//            }
//            String passwordNew = passwordEntity.getNewPassword();
//            String passwdNew = this.decrypt(publicKey,passwordNew);
//            if(!resetPassword&&passwdOld.equals(passwdNew)){
//                resultModel.setStatusCode(false);
//                resultModel.setStatusMes("新密码不能和旧密码一致");
//                return resultModel;
//            }
//            //主账号同步底层修改密码
//            if(StringUtils.isEmpty(ramUserEntity.getOwnerId())){
//                if(cloudView){
//                    OSClient.OSClientV3 osClientV3 = keystoneCommonService.getOSClientByCredentials();
//                    UserService userService = osClientV3.identity().users();
//                    User user = userService.getByName(ramUserEntity.getUserName(),"default");
//                    passwordEntity.setUserId(user.getId());
//                    passwordEntity.setOldPassword(passwdOld);
//                    passwordEntity.setNewPassword(passwdNew);
//                    osUserService.changePassword(passwordEntity);
//                }
//            }
//
//            String passwordDataNew = AESUtil.encrypt(passwdNew,MD5Util.string2MD5(salt));
//            RamUserEntity ramUserEntityN = new RamUserEntity();
//            ramUserEntityN.setId(ramUserEntity.getId());
//            ramUserEntityN.setPassword(passwordDataNew);
//            ramUserEntityN.setLastPasswordTime(new Date());
//            this.updateById(ramUserEntityN);
//            resultModel.setStatusMes("用户密码修改成功");
//        }catch (Exception e){
//            e.printStackTrace();
//            logger.error("====================="+e.getMessage());
//            resultModel.setStatusCode(false);
//            resultModel.setStatusMes("用户密码修改失败");
//            if (e.getMessage() != null && e.getMessage().equalsIgnoreCase("解密失败")){
//                resultModel.setStatusMes("用户密码修改失败："+e.getMessage());
//            }
//        }
//        return resultModel;
//    }
//
//    @Override
//    public boolean isBuiltinUser(String userId) {
//        RamUserEntity ramUserEntity = this.getById(userId);
//        if (ramUserEntity != null && Arrays.asList(TypeUtil.BuiltinUserHasMaster).contains(ramUserEntity.getType())){
//            return true;
//        }
//        return false;
//    }
//
//    @Override
//    public boolean isBuiltinUserRole(String userId,String roleType){
//        if (StringUtils.isEmpty(roleType)){
//            return false;
//        }
//        if (StringUtils.isEmpty(userId)){
//            JSONObject user = SecurityUtils.getCurrentUser();
//            userId = user.getString("userId");
//        }
//        Map map = new HashMap<>();
//        map.put("userId",userId);
//        List<RamRoleEntity> roleList = ramRoleMapper.getUserRole(map);
//        if (roleList != null){
//            for (RamRoleEntity roleEntity:roleList) {
//                if (roleType.equals(roleEntity.getRoleType())){
//                    return true;
//                }
//            }
//        }
//        return false;
//    }
//
//    @Override
//    public ResultModel checkPassword(String userId, String password) {
//        ResultModel resultModel = new ResultModel();
//       RamUserEntity ramUserEntity = ramUserMapper.selectById(userId);
//        String salt = ramUserEntity.getSalt();
//        //校验密码
//        String dataBassword = ramUserEntity.getPassword();
//        String passwordData = AESUtil.encrypt(password,MD5Util.string2MD5(salt));
//        if(dataBassword.equals(passwordData)){
//            resultModel.setContent(true);
//            return resultModel;
//        }else{
//            resultModel.setStatusCode(false);
//            resultModel.setStatusMes("密码错误");
//            resultModel.setContent("密码错误");
//        }
//        return resultModel;
//    }
//
//    @Override
//    public void updateByLastLoginDate(long day) {
//        ramUserMapper.updateByLastLoginDate(day);
//    }
//
//    @Override
//    public List<RamUserEntity> findByDate(long day) {
//        return ramUserMapper.findByDate(day);
//    }
//
//    /**
//     * 只编辑系统角色
//     * @param userId
//     * @param roles
//     */
//    @Override
//    public void editUserRoleApp(String userId, String roles) {
//        if (StringUtils.isNotEmpty(roles)) {
//            //先删后加
//            LambdaQueryWrapper<RamRoleEntity> queryWrapper = new LambdaQueryWrapper<RamRoleEntity>();
//            queryWrapper.eq(RamRoleEntity::getRoleType,TypeUtil.Type_application);
//            List<RamRoleEntity> userRoles =  ramRoleService.list(queryWrapper);
//            List<String> appRoleId = new ArrayList<>();
//            if (!ObjectUtils.isEmpty(userRoles)){
//                for (RamRoleEntity e:userRoles ) {
//                    appRoleId.add(e.getId());
//                }
//            }
//            LambdaQueryWrapper<RamUserRoleEntity> userRoleWrapper = new LambdaQueryWrapper<RamUserRoleEntity>();
//            userRoleWrapper.eq(RamUserRoleEntity::getRamUserId, userId);
//            if (!ObjectUtils.isEmpty(appRoleId)){
//                userRoleWrapper.in(RamUserRoleEntity::getRamRoleId,appRoleId);
//            }
//            userRoleService.remove(userRoleWrapper);
//            //添加
//            String[] arr = roles.split(",");
//            String builtinRoleId = null;
//            RamUserEntity userEntity = this.getById(userId);
//            if (Arrays.asList(TypeUtil.BuiltinUserType).contains(userEntity.getType())){
//                Map map = new HashMap();
//                map.put("role_type",userEntity.getType());
//                List<RamRoleEntity> roleEntities = ramRoleMapper.selectByMap(map);
//                builtinRoleId = roleEntities.get(0).getId();
//                if (!Arrays.asList(arr).contains(builtinRoleId)){
//                    RamUserRoleEntity userRole = new RamUserRoleEntity(userId, builtinRoleId);
//                    ramUserRoleMapper.insert(userRole);
//                }
//            }
//            for (String roleId : arr) {
//                RamUserRoleEntity userRole = new RamUserRoleEntity(userId, roleId);
//                ramUserRoleMapper.insert(userRole);
//            }
//        }
//    }
//
//    private String decrypt (String publicKey, String password) throws Exception {
//        String privateKey = String.valueOf(redisTemplate.opsForValue().get(publicKey));
//        redisTemplate.delete(publicKey);
//        String decryptPassword = null;
//        try {
//            decryptPassword = new String(RSAUtil.decryptByPrivateKey(org.apache.commons.codec.binary.Base64.decodeBase64(password), privateKey));
//        } catch (Exception e) {
//            e.printStackTrace();
//            throw new Exception("解密失败");
//        }
//        return decryptPassword;
//    }
//
//    private String decryptNotDel (String publicKey, String password) {
//        String privateKey = String.valueOf(redisTemplate.opsForValue().get(publicKey));
//        logger.info("============privateKey============"+privateKey);
//        String decryptPassword = null;
//        try {
//            decryptPassword = new String(RSAUtil.decryptByPrivateKey(org.apache.commons.codec.binary.Base64.decodeBase64(password), privateKey));
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//        return decryptPassword;
//    }
//}
