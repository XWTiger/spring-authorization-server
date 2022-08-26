//package com.sugon.cloud.controller.ram;
//
//import com.alibaba.fastjson.JSONObject;
//import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
//import com.baomidou.mybatisplus.core.metadata.IPage;
//import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
//import com.github.pagehelper.PageHelper;
//import com.github.pagehelper.PageInfo;
//import com.sugon.app.aop.logging.OperationRamUserLog;
//import com.sugon.app.base.BaseController;
//import com.sugon.app.common.CommonDateUtils;
//import com.sugon.app.common.CommonInstance;
//import com.sugon.app.config.osconfig.OsConfig;
//import com.sugon.app.oauth2.entity.OAuth2ClientEntity;
//import com.sugon.app.oauth2.mapper.OAuth2ClientMapper;
//import com.sugon.app.ram.entity.*;
//import com.sugon.app.ram.mapper.RamUserMapper;
//import com.sugon.app.ram.service.*;
//import com.sugon.app.ram.util.MailUtil;
//import com.sugon.app.security.SecurityUtils;
//import com.sugon.app.service.OsUserService;
//import com.sugon.app.service.impl.UserDetailsServiceImpl;
//import com.sugon.app.util.TypeUtil;
//import com.sugon.app.web.rest.PasswordEntity;
//import com.sugon.app.web.rest.util.RSAUtil;
//import com.sugon.app.web.rest.vm.ResultModel;
//import com.sugon.cloud.common.ResultModel;
//import com.sugon.cloud.entity.RamUserEntity;
//import com.sugon.cloud.mapper.RamUserMapper;
//import com.sugon.cloud.service.RamUserService;
//import com.sugon.entity.vo.OsProjectEntity;
//import com.sugon.openstack4j.model.identity.v3.User;
//import io.swagger.annotations.Api;
//import io.swagger.annotations.ApiImplicitParam;
//import io.swagger.annotations.ApiImplicitParams;
//import io.swagger.annotations.ApiOperation;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.data.redis.core.RedisTemplate;
//import org.springframework.format.annotation.DateTimeFormat;
//import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;
//import org.springframework.util.CollectionUtils;
//import org.springframework.util.StringUtils;
//import org.springframework.web.bind.annotation.*;
//
//import java.util.Date;
//import java.util.List;
//import java.util.Map;
//import java.util.Objects;
//import java.util.stream.Collectors;
//
//@RestController
//@RequestMapping("/api/ram/users")
//@Api(tags = "ram用户管理", description = "  ")
//public class RamUserController extends BaseController<RamUserEntity, RamUserService> {
//    Logger logger = LoggerFactory.getLogger(RamUserController.class);
//    @Autowired
//    private RamUserService ramUserService;
//    @Autowired
//    private OsUserService osUserService;
//    @Autowired
//    private RamGlobalsettingsService ramGlobalsettingsService;
//    @Autowired
//    private OsConfig osConfig;
//    @Autowired
//    private MailUtil mailUtil;
//    @Autowired
//    private RamPolicyService ramPolicyService;
//    @Autowired
//    private RamRoleService ramRoleService;
//    @Autowired
//    private UserDetailsServiceImpl userDetailsService;
//    @Autowired
//    private RedisTemplate redisTemplate;
//    @Autowired
//    private RamGroupUserService ramGroupUserService;
//    @Autowired
//    private RamUserRoleService ramUserRoleService;
//
//    @Autowired
//    private RamUserMapper ramUserMapper;
//
//    @Value("${cloud.view}")
//    private boolean cloudView;
//
//    @GetMapping()
//    @ApiOperation("获取用户列表")
//    @ApiImplicitParams({@ApiImplicitParam(name = "page_num", value = "页码", paramType = "query", dataType = "int"),
//            @ApiImplicitParam(name = "page_size", value = "每页显示条数", paramType = "query", dataType = "int"),
//            @ApiImplicitParam(name = "user_name", value = "用户名", paramType = "query", dataType = "string"),
//            @ApiImplicitParam(name = "main_user_id", value = "主账号id", paramType = "query", dataType = "string")})
//    public ResultModel getAllUsersByParam(@RequestParam(value = "page_num", required = false) Integer pageNum,
//                                          @RequestParam(value = "page_size", required = false) Integer pageSize,
//                                          @RequestParam(value = "user_name", required = false) String userName,
//                                          @RequestParam(value = "main_user_id", required = false) String mainUserId) {
//        ResultModel resultModel = new ResultModel();
//        try {
//            LambdaQueryWrapper<RamUserEntity> queryWrapper = new LambdaQueryWrapper<RamUserEntity>();
//            Page<RamUserEntity> page = new Page<RamUserEntity>(pageNum, pageSize);
//            if (!StringUtils.isEmpty(userName)) {
//                queryWrapper.like(RamUserEntity::getUserName, userName);
//            }
//            JSONObject user = SecurityUtils.getCurrentUser();
//            String userID = user.getString("userId");
//            queryWrapper.notIn(RamUserEntity::getType, TypeUtil.BuiltinUserType);
//            if (!StringUtils.isEmpty(mainUserId)){
//                queryWrapper.eq(RamUserEntity::getOwnerId, mainUserId);
//            }else if (ramUserService.isBuiltinUserRole(null, TypeUtil.Type_admin) ||
//                    ramUserService.isBuiltinUserRole(null, TypeUtil.Type_security)) {
//                queryWrapper.and(wapper -> wapper.eq(RamUserEntity::getType,TypeUtil.Type_master)
//                        .or().eq(RamUserEntity::getOwnerId, userID));
//            }else {
//                queryWrapper.eq(RamUserEntity::getOwnerId, userID);
//            }
//            queryWrapper.orderBy(true, false, RamUserEntity::getCreateAt);
//            PageHelper.startPage(pageNum,pageSize);
//            List<RamUserEntity> userPageCL = ramUserService.list(queryWrapper);
//            userPageCL.forEach(s->{s.setPassword("");s.setSalt("");});
//            PageInfo<RamUserEntity> pageInfo = new PageInfo<>(userPageCL);
//            resultModel.setContent(new IPageEntity(pageInfo));
//            resultModel.setStatusMes("获取列表成功");
//        } catch (Exception e) {
//            logger.error("getAllUsersByParam error", e);
//            resultModel.setStatusCode(false);
//            resultModel.setStatusMes("获取user列表失败");
//        }
//        return resultModel;
//    }
//
//    @PostMapping("/names")
//    @ApiOperation("获取用户名称列表")
//    public ResultModel getUserNamesByUserIds(@RequestBody List<String> ids) {
//        ResultModel resultModel = new ResultModel();
//        try {
//            List<RamUserEntity> list = (List<RamUserEntity>) ramUserService.listByIds(ids);
//            if (!CollectionUtils.isEmpty(list)) {
//                Map map = list.stream().collect(Collectors.toMap(key -> key.getId(), o -> o));
//                resultModel.setContent(map);
//                return resultModel;
//            }
//        } catch (Exception e) {
//            logger.error("createUser error", e);
//            resultModel.setStatusCode(false);
//            resultModel.setStatusMes("查询用户失败");
//        }
//        return resultModel;
//    }
//
//    @PostMapping()
//    @ApiOperation("创建用户")
//    @OperationRamUserLog(value = "创建子账号", type = "user", entityName = "RamUserEntity", entityIndex = "0")
//    public ResultModel createUser(@RequestBody RamUserEntity ramUserEntity) {
//        ResultModel resultModel = new ResultModel();
//        try {
//            ramUserEntity.setType(TypeUtil.Type_ram);
//            if("systemadmin".equalsIgnoreCase(ramUserEntity.getUserName())){
//                resultModel.setStatusCode(false);
//                resultModel.setStatusMes(" systemadmin不允许注册");
//                return resultModel;
//            }
//            LambdaQueryWrapper<RamUserEntity> queryWrapper = new LambdaQueryWrapper<RamUserEntity>();
//            queryWrapper.eq(RamUserEntity::getUserName, ramUserEntity.getUserName());
//            RamUserEntity ramUserEntityQ = ramUserService.getOne(queryWrapper);
//            if (null != ramUserEntityQ) {
//                resultModel.setStatusCode(false);
//                resultModel.setStatusMes("用户名已存在，创建用户失败");
//                return resultModel;
//            }
//            JSONObject jsonObject = SecurityUtils.getCurrentUser();
//            ramUserEntity.setOwnerId(jsonObject.getString("userId"));
//            ramUserEntity.setCreateBy(jsonObject.getString("username"));
//            ramUserEntity.setCreateAt(new Date());
//            RamGlobalsettingsEntity ramGlobalsettingsEntity = ramGlobalsettingsService.getOne(new LambdaQueryWrapper<RamGlobalsettingsEntity>().eq(RamGlobalsettingsEntity::getPolicyName, "status").eq(RamGlobalsettingsEntity::getPolicyType, "user"));
//            if (ramGlobalsettingsEntity != null) {
//                if ("true".equals(ramGlobalsettingsEntity.getPolicyDocument())) {
//                    ramUserEntity.setStatus(true);
//                } else {
//                    ramUserEntity.setStatus(false);
//                }
//            } else {
//                ramUserEntity.setStatus(false);
//            }
//            ramUserService.saveUserWithRole(ramUserEntity, null);
//            mailUtil.send("创建子账户的通知！", "创建子账户：" + ramUserEntity.getUserName());
//            resultModel.setStatusMes("创建用户成功");
//        } catch (Exception e) {
//            logger.error("createUser error", e);
//            resultModel.setStatusCode(false);
//            resultModel.setStatusMes("创建用户失败");
//            if (e.getMessage() != null && e.getMessage().equalsIgnoreCase("解密失败")){
//                resultModel.setStatusMes("创建用户失败："+e.getMessage());
//            }
//        }
//        return resultModel;
//    }
//
//    @PostMapping("/register")
//    @ApiOperation("注册用户")
//    @OperationRamUserLog(value = "注册用户", type = "user", entityName = "RamUserEntity", entityIndex = "0")
//    public ResultModel registerUser(@RequestBody RamUserEntity ramUserEntity) {
//        ResultModel resultModel = new ResultModel();
//        try {
//            ramUserEntity.setType(TypeUtil.Type_master);
//            if("systemadmin".equalsIgnoreCase(ramUserEntity.getUserName())){
//                resultModel.setStatusCode(false);
//                resultModel.setStatusMes(" systemadmin不允许注册");
//                return resultModel;
//            }
//            LambdaQueryWrapper<RamUserEntity> queryWrapper = new LambdaQueryWrapper<RamUserEntity>();
//            queryWrapper.eq(RamUserEntity::getUserName, ramUserEntity.getUserName());
//            RamUserEntity ramUserEntityQ = ramUserService.getOne(queryWrapper);
//            if (null != ramUserEntityQ) {
//                resultModel.setStatusCode(false);
//                resultModel.setStatusMes("用户名已存在，创建用户失败");
//                return resultModel;
//            }
//            if(cloudView){
//                boolean exist = osUserService.checkUser(osConfig.getDomainName(), ramUserEntity.getUserName());
//                if (!exist) {
//                    resultModel.setStatusCode(false);
//                    resultModel.setStatusMes("底层用户已经存在");
//                    return resultModel;
//                }
//            }
//            ramUserEntity.setCreateAt(new Date());
//            //获取主账号默认权限
//            LambdaQueryWrapper<RamRoleEntity> rolequeryWrapper = new LambdaQueryWrapper<RamRoleEntity>();
//            rolequeryWrapper.eq(RamRoleEntity::getRoleType, "master");
//            RamRoleEntity ramRoleEntity = ramRoleService.getOne(rolequeryWrapper);
//            RamGlobalsettingsEntity ramGlobalsettingsEntity = ramGlobalsettingsService.getOne(new LambdaQueryWrapper<RamGlobalsettingsEntity>().eq(RamGlobalsettingsEntity::getPolicyName, "status").eq(RamGlobalsettingsEntity::getPolicyType, "user"));
//            if (ramGlobalsettingsEntity != null) {
//                if ("true".equals(ramGlobalsettingsEntity.getPolicyDocument())) {
//                    ramUserEntity.setStatus(true);
//                } else {
//                    ramUserEntity.setStatus(false);
//                }
//            } else {
//                ramUserEntity.setStatus(false);
//            }
//            ramUserService.saveUserWithRole(ramUserEntity, ramRoleEntity != null ? ramRoleEntity.getId() : null);
//            //mailUtil.send("创建账户的通知！", "创建账户：" + ramUserEntity.getUserName());
//            ramUserEntity.setPassword(null);
//            resultModel.setContent(ramUserEntity);
//            resultModel.setStatusMes("注册用户成功");
//        } catch (Exception e) {
//            logger.error("registerUser error", e);
//            resultModel.setStatusCode(false);
//            resultModel.setStatusMes("注册用户失败");
//        }
//        return resultModel;
//    }
//
//    @GetMapping("/names/{user_name}")
//    @ApiOperation("查询用户")
//    public ResultModel getUserByname(@PathVariable("user_name") String userName) {
//        ResultModel resultModel = new ResultModel();
//        try {
//            LambdaQueryWrapper<RamUserEntity> queryWrapper = new LambdaQueryWrapper<RamUserEntity>();
//            queryWrapper.eq(RamUserEntity::getUserName, userName);
//            RamUserEntity ramUserEntity = ramUserService.getOne(queryWrapper);
//            ramUserEntity.setPassword("");
//            ramUserEntity.setSalt("");
//            resultModel.setContent(ramUserEntity);
//        } catch (Exception e) {
//            logger.error("getUserByname error", e);
//            resultModel.setStatusCode(false);
//            resultModel.setStatusMes("查询用户失败");
//        }
//        return resultModel;
//    }
//
//    @GetMapping("/{id}")
//    @ApiOperation("查询用户")
//    public ResultModel getUserById(@PathVariable("id") String id) {
//        ResultModel resultModel = new ResultModel();
//        try {
//            RamUserEntity ramUserEntity = ramUserService.getById(id);
//            if (cloudView){
//                String userName = ramUserEntity.getUserName();
//                if ("ram".equals(ramUserEntity.getType()) && !StringUtils.isEmpty(ramUserEntity.getOwnerId())){
//                    userName = ramUserService.getById(ramUserEntity.getOwnerId()).getUserName();
//                }
//                User user = osUserService.getUserByName(userName);
//                if (Objects.nonNull(user)){
//                    ramUserEntity.setProjectId(user.getDefaultProjectId());
//                }
//            }
//            ramUserEntity.setPassword("");
//            ramUserEntity.setSalt("");
//            resultModel.setContent(ramUserEntity);
//        } catch (Exception e) {
//            logger.error("getUserById error", e);
//            resultModel.setStatusCode(false);
//            resultModel.setStatusMes("查询用户失败");
//        }
//        return resultModel;
//    }
//
//
//    @DeleteMapping("/{id}")
//    @ApiOperation("删除用户")
//    /*@OperationRamUserLog(value = "删除用户", type = "user", idIndex = "0")*/
//    public ResultModel deleteUser(@PathVariable("id") String id) {
//        ResultModel resultModel = new ResultModel();
//        try {
//            RamUserEntity ramUserEntity = ramUserService.getById(id);
//            if(Objects.isNull(ramUserEntity)){
//                resultModel.setStatusCode(false);
//                resultModel.setStatusMes("删除用户失败,该用户不存在");
//                return resultModel;
//            }
//            resultModel.setResouce(ramUserEntity.getUserName());
//            if (ramUserService.isBuiltinUser(id)) {
//                resultModel.setStatusCode(false);
//                resultModel.setStatusMes("删除用户失败,内置用户和主账号无法删除！");
//                return resultModel;
//            }
//            ramUserService.removeById(id);
//            resultModel.setContent(id);
//            resultModel.setResouce(ramUserEntity.getUserName());
//            mailUtil.send("删除用户的通知！", "删除用户" +ramUserEntity.getUserName() );
//            resultModel.setStatusMes("删除用户成功");
//        } catch (Exception e) {
//            logger.error("deleteUser error", e);
//            resultModel.setStatusCode(false);
//            resultModel.setStatusMes("删除用户失败");
//        }
//        return resultModel;
//    }
//
//    @PutMapping("/{id}")
//    @ApiOperation("修改用户")
//    /*@OperationRamUserLog(value = "修改用户", type = "user", idIndex = "0")*/
//    public ResultModel editUser(@PathVariable("id") String id, @RequestBody RamUserEntity ramUserEntity) {
//        ResultModel resultModel = new ResultModel();
//        try {
//            RamUserEntity ramUser = ramUserService.getById(id);
//            if(Objects.isNull(ramUser)){
//                resultModel.setStatusCode(false);
//                resultModel.setStatusMes("修改用户失败,该用户不存在");
//                return resultModel;
//            }
//            if (!StringUtils.isEmpty(ramUserEntity.getPassword())){
//                resultModel.setStatusCode(false);
//                resultModel.setStatusMes("修改用户失败,该接口禁止修改密码");
//                return resultModel;
//            }
//            if (!StringUtils.isEmpty(ramUserEntity.getSalt())){
//                resultModel.setStatusCode(false);
//                resultModel.setStatusMes("修改用户失败,该接口禁止修改Salt");
//                return resultModel;
//            }
//            JSONObject user = SecurityUtils.getCurrentUser();
//            String userId= user.getString("userId");
//            String userName = user.getString("username");
//            String ownerId = ramUser.getOwnerId();
//            if ( !(userId.equals(id) || "admin".equals(userName) || "securityadmin".equals(userName) || (!StringUtils.isEmpty(ownerId) && ownerId.equals(userId)))){
//                resultModel.setStatusCode(false);
//                resultModel.setStatusMes("修改用户失败,无法越权修改其他用户");
//                return resultModel;
//            }
//            resultModel.setResouce(ramUserEntity.getUserName());
//            if(ramUserEntity.getComments()==null) ramUserEntity.setComments("");
//            if(ramUserEntity.getEmail()==null) ramUserEntity.setEmail("");
//            if(ramUserEntity.getMobile()==null) ramUserEntity.setMobile("");
//            if(ramUserEntity.getDisplayName()==null) ramUserEntity.setDisplayName("");
//            ramUser.setComments(ramUserEntity.getComments());
//            ramUser.setEmail(ramUserEntity.getEmail());
//            ramUser.setMobile(ramUserEntity.getMobile());
//            ramUser.setDisplayName(ramUserEntity.getDisplayName());
//            ramUserService.updateById(ramUser);
//            resultModel.setContent(id);
//            mailUtil.send("修改用户的通知！", "修改用户" + ramUser.getUserName());
//            resultModel.setStatusMes("修改用户成功");
//        } catch (Exception e) {
//            logger.error("editUser error", e);
//            resultModel.setStatusCode(false);
//            resultModel.setStatusMes("修改用户失败");
//        }
//        return resultModel;
//    }
//
//    @PutMapping("/{id}/time_limit")
//    @ApiOperation("设置用户过期时间")
//    /*@OperationRamUserLog(value = "设置用户过期时间", type = "user", idIndex = "0")*/
//    public ResultModel editLimit(@PathVariable("id") String id, @RequestParam(required = false,value = "time_limit") @DateTimeFormat(pattern = "yyyy-MM-dd HH:mm:ss") Date timeLimit) {
//        ResultModel resultModel = new ResultModel();
//        try {
//            RamUserEntity ramUser = ramUserService.getById(id);
//            if(Objects.isNull(ramUser)){
//                resultModel.setStatusCode(false);
//                resultModel.setStatusMes("设置用户过期时间失败,该用户不存在");
//                return resultModel;
//            }
//            resultModel.setResouce(ramUser.getUserName());
//            if (Objects.isNull(timeLimit)){
//                ramUserMapper.updateNullById(id);
//            }else{
//                RamUserEntity ramUserEntity = new RamUserEntity();
//                ramUserEntity.setTimeLimit(timeLimit);
//                ramUserEntity.setId(id);
//                ramUserService.updateById(ramUserEntity);
//            }
//            resultModel.setContent(id);
//            mailUtil.send("设置用户过期时间的通知！", "设置"+ramUser.getUserName()+"用户过期时间");
//            resultModel.setStatusMes("设置用户过期时间成功");
//        } catch (Exception e) {
//            logger.error("editLimit error", e);
//            resultModel.setStatusCode(false);
//            resultModel.setStatusMes("设置用户过期时间失败");
//        }
//        return resultModel;
//    }
//
//    @PutMapping("/{id}/status")
//    @ApiOperation("修改用户状态")
//    public ResultModel editUser(@PathVariable("id") String id, Boolean status) {
//        ResultModel resultModel = new ResultModel();
//        try {
//            RamUserEntity  userEntity  = ramUserService.getById(id);
//            if(Objects.isNull(userEntity)){
//                resultModel.setStatusCode(false);
//                resultModel.setStatusMes("用户不存在");
//                return resultModel;
//            }
//            resultModel.setResouce(userEntity.getUserName());
//            RamUserEntity ramUserEntity = new RamUserEntity();
//            ramUserEntity.setId(id);
//            ramUserEntity.setStatus(status);
//            ramUserService.updateById(ramUserEntity);
//            resultModel.setContent(id);
//            mailUtil.send("修改用户状态的通知！", "修改"+ userEntity.getUserName()+"用户状态!");
//            resultModel.setStatusMes("修改用户状态成功");
//        } catch (Exception e) {
//            logger.error("editUser error", e);
//            resultModel.setStatusCode(false);
//            resultModel.setStatusMes("修改用户状态失败");
//        }
//        return resultModel;
//    }
//
//    @PutMapping("/{id}/resetIp")
//    @ApiOperation("设置用户IP限制")
//    public ResultModel resetUserIpLogin(@PathVariable("id") String id, String ip) {
//        ResultModel resultModel = new ResultModel();
//        try {
//            RamUserEntity  userEntity  = ramUserService.getById(id);
//            if(Objects.isNull(userEntity)){
//                resultModel.setStatusCode(false);
//                resultModel.setStatusMes("用户不存在");
//                return resultModel;
//            }
//            resultModel.setResouce(userEntity.getUserName());
//            if(ip==null) ip = "";
//            RamUserEntity ramUserEntity = new RamUserEntity();
//            ramUserEntity.setId(id);
//            ramUserEntity.setAllowIp(ip.trim());
//            ramUserService.updateById(ramUserEntity);
//            resultModel.setContent(id);
//            resultModel.setStatusMes("设置用户IP限制成功");
//        } catch (Exception e) {
//            logger.error("resetUserIpLogin error", e);
//            resultModel.setStatusCode(false);
//            resultModel.setStatusMes("设置用户IP限制失败");
//        }
//        return resultModel;
//    }
//
//
//
//
//    @RequestMapping(value = "/changPassword", method = RequestMethod.PUT)
//    @ApiOperation("修改密码")
//
//    public ResultModel changPassword(@RequestBody PasswordEntity passwordEntity) throws Exception {
//        ResultModel resultModel = new ResultModel();
//        RamUserEntity  userEntity  = ramUserService.getById(passwordEntity.getUserId());
//        if(Objects.isNull(userEntity)){
//            resultModel.setStatusCode(false);
//            resultModel.setStatusMes("修改密码失败，该用户不存在");
//            return resultModel;
//        }
//        resultModel = ramUserService.changePassword(passwordEntity,false);
//        resultModel.setResouce(userEntity.getUserName());
//        mailUtil.send("修改用户密码的通知！", "修改"+userEntity.getUserName()+"用户密码");
//        return resultModel;
//    }
//
//    @RequestMapping(value = "/resetPassword", method = RequestMethod.PUT)
//    @ApiOperation("重置密码")
//    public ResultModel resetPassword(@RequestBody PasswordEntity passwordEntity) throws Exception {
//        ResultModel resultModel = new ResultModel();
//        RamUserEntity  userEntity  = ramUserService.getById(passwordEntity.getUserId());
//        if(Objects.isNull(userEntity)){
//            resultModel.setStatusCode(false);
//            resultModel.setStatusMes("重置密码失败，该用户不存在");
//            return resultModel;
//        }
//        resultModel = ramUserService.changePassword(passwordEntity,true);
//        resultModel.setResouce(userEntity.getUserName());
//        mailUtil.send("重置用户密码的通知！", "重置"+userEntity.getUserName()+"用户密码");
//        return resultModel;
//    }
//
//    @RequestMapping(value = "/check-password", method = RequestMethod.GET)
//    @ApiOperation("检查密码")
//    @ApiImplicitParams({@ApiImplicitParam(name = "user_id", value = "用户ID", required = true, paramType = "query"),
//            @ApiImplicitParam(name = "password", value = "密码", required = true, paramType = "query")})
//    public ResultModel checkPassword(@RequestParam(name = "user_id") String userId,
//                                     @RequestParam(name = "password") String password,
//                                     @RequestParam(name = "publicKey") String publicKey) throws Exception {
//        if ( publicKey != null) {
//            password =  this.decrypt(publicKey, password);
//        }
//        ResultModel resultModel = ramUserService.checkPassword(userId, password);
//        return resultModel;
//    }
//
//
//
//
//    @GetMapping("should-change-password")
//    public ResultModel shouldChangePassword () {
//        ResultModel resultModel = new ResultModel();
//        JSONObject jsonObject = SecurityUtils.getCurrentUser();
//        int interval = 0;
//        int day = 0;
//        String changePasswordInterval = userDetailsService.getValue(CommonInstance.CLOBAL_SETTING_PASSWORD,CommonInstance.CHANGE_PASSWORD_INTERVAL);
//        if (org.apache.commons.lang3.StringUtils.isEmpty(changePasswordInterval)) {
//            changePasswordInterval = "90";
//        }
//        try {
//            RamUserEntity ramUserEntity = ramUserService.getById(jsonObject.getString("userId"));
//            Date lastPasswordTime = ramUserEntity.getLastPasswordTime();
//            day = CommonDateUtils.calculateTotalDay(lastPasswordTime);
//            interval = Integer.parseInt(changePasswordInterval);
//            if (interval > 90) interval = 90;
//        } catch (Exception e) {
//            interval = 90;
//            logger.error("shouldChangePassword error",e);
//        }
//        if (day > interval) {
//            resultModel.setContent(true);
//            resultModel.setStatusMes("未修改密码时间达到系统上限，请修改密码");
//        } else {
//            resultModel.setContent(false);
//        }
//        return resultModel;
//    }
//
//    private String decrypt (String publicKey, String password) {
//        String privateKey = String.valueOf(redisTemplate.opsForValue().get(publicKey));
//        redisTemplate.delete(publicKey);
//        try {
//            String decryptPassword = new String(RSAUtil.decryptByPrivateKey(org.apache.commons.codec.binary.Base64.decodeBase64(password), privateKey));
//            System.out.println("decrypt password" + decryptPassword);
//            return decryptPassword;
//        } catch (Exception e) {
//            logger.error("decrypt password error", e);
//        }
//        return password;
//    }
//
//    @DeleteMapping("/{id}/group")
//    @ApiOperation("用户删除用户组")
//    @OperationRamUserLog(value = "从用户组中移除用户", type = "user", idIndex = "0")
//    public ResultModel userDelGroup(@PathVariable("id") String id, @RequestBody List<String> group_ids) {
//        ResultModel resultModel = new ResultModel();
//        try {
//            RamUserEntity ramUserEntity = ramUserService.getById(id);
//            if (Objects.nonNull(ramUserEntity)){
//                resultModel.setResouce(ramUserEntity.getUserName());
//            }
//            LambdaQueryWrapper<RamGroupUserEntity> queryWrapper = new LambdaQueryWrapper<RamGroupUserEntity>();
//            queryWrapper.eq(RamGroupUserEntity::getRamUserId,id);
//            queryWrapper.in(RamGroupUserEntity::getGroupId,group_ids);
//            boolean flag = ramGroupUserService.remove(queryWrapper);
//            if (flag) {
//                resultModel.setContent(id);
//                resultModel.setStatusMes("从用户组中移除成功");
//            } else {
//                resultModel.setStatusCode(false);
//                resultModel.setStatusMes("从用户组中移除失败");
//            }
//        } catch (Exception e) {
//            logger.error("userDelGroup error", e);
//            resultModel.setStatusCode(false);
//            resultModel.setStatusMes("从用户组中移除失败");
//        }
//        return resultModel;
//    }
//
//    @DeleteMapping("/{id}/role")
//    @ApiOperation("用户删除角色")
//    @OperationRamUserLog(value = "用户删除角色", type = "user", idIndex = "0")
//    public ResultModel userDelRole(@PathVariable("id") String id, @RequestBody List<String> role_ids) {
//        ResultModel resultModel = new ResultModel();
//        try {
//            RamUserEntity ramUserEntity = ramUserService.getById(id);
//            if (Objects.nonNull(ramUserEntity)){
//                resultModel.setResouce(ramUserEntity.getUserName());
//            }
//            LambdaQueryWrapper<RamUserRoleEntity> queryWrapper = new LambdaQueryWrapper<RamUserRoleEntity>();
//            queryWrapper.eq(RamUserRoleEntity::getRamUserId,id);
//            queryWrapper.in(RamUserRoleEntity::getRamRoleId,role_ids);
//            boolean flag = ramUserRoleService.remove(queryWrapper);
//            if (flag) {
//                resultModel.setContent(id);
//                resultModel.setStatusMes("用户删除角色成功");
//            } else {
//                resultModel.setStatusCode(false);
//                resultModel.setStatusMes("用户删除角色失败");
//            }
//        } catch (Exception e) {
//            logger.error("userDelRole error", e);
//            resultModel.setStatusCode(false);
//            resultModel.setStatusMes("用户删除角色失败");
//        }
//        return resultModel;
//    }
//
//    @GetMapping("/{username}/check")
//    @ApiOperation("主账号检查用户资源")
//    @OperationRamUserLog(value = "主账号检查用户资源", type = "user", idIndex = "0")
//    public ResultModel check(@PathVariable("username") String username) {
//        ResultModel resultModel = new ResultModel();
//        try {
//            LambdaQueryWrapper<RamUserEntity> queryWrapperUser = new LambdaQueryWrapper<RamUserEntity>();
//            queryWrapperUser.eq(RamUserEntity::getUserName, username);
//            RamUserEntity ramUserEntity = ramUserService.getOne(queryWrapperUser);
//            LambdaQueryWrapper<RamUserEntity> queryWrapper = new LambdaQueryWrapper<RamUserEntity>();
//            Page<RamUserEntity> page = new Page<RamUserEntity>(1, 1);
//            queryWrapper.notIn(RamUserEntity::getType, TypeUtil.BuiltinUserType);
//            if (ramUserService.isBuiltinUserRole(ramUserEntity.getId(), TypeUtil.Type_admin) ||
//                    ramUserService.isBuiltinUserRole(ramUserEntity.getId(), TypeUtil.Type_security)) {
//                queryWrapper.and(wapper -> wapper.eq(RamUserEntity::getType,TypeUtil.Type_master)
//                        .or().eq(RamUserEntity::getOwnerId, ramUserEntity.getId()));
//            }else {
//                queryWrapper.eq(RamUserEntity::getOwnerId, ramUserEntity.getId());
//            }
//            queryWrapper.orderBy(true, false, RamUserEntity::getCreateAt);
//            IPage<RamUserEntity> userPageCL = ramUserService.page(page, queryWrapper);
//            if (userPageCL.getTotal()>0){
//                resultModel.setContent(false);
//                resultModel.setStatusCode(false);
//                resultModel.setStatusMes("请先删除项目中的子用户");
//            }else{
//                resultModel.setContent(true);
//                resultModel.setStatusMes("项目内没有子用户");
//            }
//        } catch (Exception e) {
//            logger.error("getAllUsersByParam error", e);
//            resultModel.setStatusCode(false);
//            resultModel.setStatusMes("获取user列表失败");
//        }
//        return resultModel;
//    }
//
//
//
//
//
//}
