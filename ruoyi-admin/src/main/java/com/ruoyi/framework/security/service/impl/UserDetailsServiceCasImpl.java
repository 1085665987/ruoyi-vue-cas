package com.ruoyi.framework.security.service.impl;

import com.ruoyi.common.enums.UserStatus;
import com.ruoyi.common.exception.ServiceException;
import com.ruoyi.common.utils.StringUtils;
import com.ruoyi.framework.security.LoginUser;
import com.ruoyi.framework.security.service.SysPermissionService;
import com.ruoyi.project.system.domain.SysUser;
import com.ruoyi.project.system.service.ISysUserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.cas.authentication.CasAssertionAuthenticationToken;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Map;

/**
 * @author MikuHoney
 * @description 用于加载用户信息，实现UserDetailsService接口，或者实现AuthenticationUserDetailsService接口。
 * @date 2022/7/26 17:02
 */
@Service
public class UserDetailsServiceCasImpl implements AuthenticationUserDetailsService<CasAssertionAuthenticationToken> {
    private static final Logger log = LoggerFactory.getLogger(UserDetailsServiceCasImpl.class);

    @Autowired
    private ISysUserService userService;

    @Autowired
    private SysPermissionService permissionService;

    @Override
    public UserDetails loadUserDetails(CasAssertionAuthenticationToken token) throws UsernameNotFoundException {
        // 获取用户名
        String username = token.getName();
        // 通过用户名查询用户
        SysUser user = userService.selectUserByUserName("admin");
        if (StringUtils.isNull(user)) {
            log.info("登录用户：{} 不存在。", username);
            throw new ServiceException("登录用户：" + username + " 不存在。");
        } else if (UserStatus.DELETED.getCode().equals(user.getDelFlag())) {
            log.info("登录用户：{} 已被删除。", username);
            throw new ServiceException("对不起，您的账号：" + username + " 已被删除。");
        } else if (UserStatus.DISABLE.getCode().equals(user.getStatus())) {
            log.info("登录用户：{} 已被停用。", username);
            throw new ServiceException("对不起，您的账号：" + username + " 已停用。");
        }
        return createLoginUser(user, token.getAssertion().getPrincipal().getAttributes());
    }

    public UserDetails createLoginUser(SysUser user, Map<String, Object> attributes) {
        return new LoginUser(user.getUserId(), user.getDeptId(), user, permissionService.getMenuPermission(user), attributes);
    }
}
