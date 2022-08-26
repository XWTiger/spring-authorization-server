CREATE TABLE IF  NOT  EXISTS `oauth2_authorization` (
  `id` varchar(100) NOT NULL,
  `registered_client_id` varchar(100) NOT NULL,
  `principal_name` varchar(200) NOT NULL,
  `authorization_grant_type` varchar(100) NOT NULL,
  `attributes` blob,
  `state` varchar(500) DEFAULT NULL,
  `authorization_code_value` blob,
  `authorization_code_issued_at` timestamp NULL DEFAULT NULL,
  `authorization_code_expires_at` timestamp NULL DEFAULT NULL,
  `authorization_code_metadata` blob,
  `access_token_value` blob,
  `access_token_issued_at` timestamp NULL DEFAULT NULL,
  `access_token_expires_at` timestamp NULL DEFAULT NULL,
  `access_token_metadata` blob,
  `access_token_type` varchar(100) DEFAULT NULL,
  `access_token_scopes` varchar(1000) DEFAULT NULL,
  `oidc_id_token_value` blob,
  `oidc_id_token_issued_at` timestamp NULL DEFAULT NULL,
  `oidc_id_token_expires_at` timestamp NULL DEFAULT NULL,
  `oidc_id_token_metadata` blob,
  `refresh_token_value` blob,
  `refresh_token_issued_at` timestamp NULL DEFAULT NULL,
  `refresh_token_expires_at` timestamp NULL DEFAULT NULL,
  `refresh_token_metadata` blob,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF  NOT  EXISTS `oauth2_authorization_consent` (
  `registered_client_id` varchar(100) NOT NULL,
  `principal_name` varchar(200) NOT NULL,
  `authorities` varchar(1000) NOT NULL,
  PRIMARY KEY (`registered_client_id`,`principal_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


CREATE TABLE IF  NOT  EXISTS `oauth2_registered_client` (
  `id` varchar(100) NOT NULL,
  `client_id` varchar(100) NOT NULL,
  `client_id_issued_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `client_secret` varchar(200) DEFAULT NULL,
  `client_secret_expires_at` timestamp NULL DEFAULT NULL,
  `client_name` varchar(200) NOT NULL,
  `client_authentication_methods` varchar(1000) NOT NULL,
  `authorization_grant_types` varchar(1000) NOT NULL,
  `redirect_uris` varchar(1000) DEFAULT NULL,
  `scopes` varchar(1000) NOT NULL,
  `client_settings` varchar(2000) NOT NULL,
  `token_settings` varchar(2000) NOT NULL,
  `type` varchar(255) DEFAULT NULL COMMENT '类型',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF  NOT  EXISTS `ram_user` (
  `id` varchar(40) NOT NULL COMMENT '唯一标识',
  `user_name` varchar(255) NOT NULL COMMENT '用户名',
  `display_name` varchar(255) DEFAULT NULL COMMENT '显示名',
  `comments` varchar(255) DEFAULT NULL COMMENT '描述',
  `email` varchar(255) DEFAULT NULL COMMENT '邮件',
  `mobile` varchar(255) DEFAULT NULL COMMENT '手机',
  `password` varchar(255) DEFAULT NULL COMMENT '密码',
  `type` varchar(255) DEFAULT NULL COMMENT '用户类型',
  `salt` varchar(255) DEFAULT NULL COMMENT '盐',
  `owner_id` varchar(255) DEFAULT NULL COMMENT '主账号ID',
  `status` tinyint(1) DEFAULT NULL COMMENT '状态',
  `last_login` datetime DEFAULT NULL COMMENT '上次登陆',
  `time_limit` datetime DEFAULT NULL COMMENT '过期时间',
  `last_password_time` datetime DEFAULT NULL COMMENT '上次改密',
  `create_by` varchar(255) DEFAULT NULL COMMENT '创建人',
  `create_at` datetime DEFAULT NULL COMMENT '创建时间',
  `origin` varchar(16) DEFAULT NULL,
  `origin_user_id` varchar(128) DEFAULT NULL,
  `origin_user_name` varchar(64) DEFAULT NULL,
  `allow_ip` varchar(64) DEFAULT NULL COMMENT '允许登录IP',
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE KEY `user_index` (`user_name`) USING BTREE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;