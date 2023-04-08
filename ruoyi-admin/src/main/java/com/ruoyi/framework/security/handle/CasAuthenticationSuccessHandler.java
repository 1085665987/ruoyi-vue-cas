package com.ruoyi.framework.security.handle;

import com.ruoyi.common.constant.CacheConstants;
import com.ruoyi.common.constant.Constants;
import com.ruoyi.framework.config.properties.CasProperties;
import com.ruoyi.framework.redis.RedisCache;
import com.ruoyi.framework.security.LoginUser;
import com.ruoyi.framework.security.service.TokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.concurrent.TimeUnit;

/**
 * @author MikuHoney
 * @description CAS认证中心
 * @date 2022/7/26 17:05
 */
@Service
public class CasAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {
    private static final Logger log = LoggerFactory.getLogger(CasAuthenticationSuccessHandler.class);
    private static final RequestCache requestCache = new HttpSessionRequestCache();

    @Autowired
    private RedisCache redisCache;

    @Autowired
    private TokenService tokenService;

    @Autowired
    private CasProperties casProperties;

    // 令牌有效期（默认30分钟）
    @Value("${token.expireTime}")
    private int expireTime;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws ServletException, IOException {
        String targetUrlParameter = getTargetUrlParameter();
        if (isAlwaysUseDefaultTargetUrl() || (targetUrlParameter != null && StringUtils.hasText(request.getParameter(targetUrlParameter)))) {
            requestCache.removeRequest(request, response);
            super.onAuthenticationSuccess(request, response, authentication);
            return;
        }
        clearAuthenticationAttributes(request);
        LoginUser userDetails = (LoginUser) authentication.getPrincipal();
        String token = tokenService.createToken(userDetails);
        // 打印日志
        log.debug("CAS认证中心的ticket:"+authentication.getCredentials().toString());
        // 往Redis中设置token
        redisCache.setCacheObject(CacheConstants.LOGIN_TICKET_KEY+authentication.getCredentials().toString(), token, expireTime, TimeUnit.MINUTES);
        // 往Cookie中设置token
        Cookie casCookie = new Cookie(Constants.WEB_TOKEN_KEY, token);
        casCookie.setMaxAge(expireTime * 60);
        response.addCookie(casCookie);
        // 设置后端认证成功标识
        HttpSession httpSession = request.getSession();
        httpSession.setAttribute(Constants.CAS_TOKEN, token);
        httpSession.setMaxInactiveInterval(expireTime * 60);
        // 登录成功后跳转到前端登录页面
        getRedirectStrategy().sendRedirect(request, response, casProperties.getWebUrl());
    }
}
