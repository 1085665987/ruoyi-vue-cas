package com.ruoyi.framework.security;

import lombok.Data;

import java.io.Serializable;

/**
 * 用户登录对象
 *
 * @author ruoyi
 */
@Data
public class LoginBody implements Serializable {
    private static final long serialVersionUID = -6328182662943473668L;

    // 用户名
    private String username;
    // 用户密码
    private String password;
    // 验证码
    private String code;
    // 唯一标识
    private String uuid;
}
