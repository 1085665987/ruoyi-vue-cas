package com.ruoyi.framework.security.handle;

import com.alibaba.fastjson2.JSON;
import com.ruoyi.common.constant.CacheConstants;
import com.ruoyi.common.constant.Constants;
import com.ruoyi.common.constant.HttpStatus;
import com.ruoyi.common.utils.ServletUtils;
import com.ruoyi.common.utils.StringUtils;
import com.ruoyi.common.utils.spring.SpringUtils;
import com.ruoyi.framework.manager.AsyncManager;
import com.ruoyi.framework.manager.factory.AsyncFactory;
import com.ruoyi.framework.redis.RedisCache;
import com.ruoyi.framework.security.LoginUser;
import com.ruoyi.framework.security.service.TokenService;
import com.ruoyi.framework.web.domain.AjaxResult;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.jasig.cas.client.Protocol;
import org.jasig.cas.client.configuration.ConfigurationKeys;
import org.jasig.cas.client.session.HashMapBackedSessionMappingStorage;
import org.jasig.cas.client.session.SessionMappingStorage;
import org.jasig.cas.client.util.CommonUtils;
import org.jasig.cas.client.util.XmlUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.config.YamlMapFactoryBean;
import org.springframework.core.io.ClassPathResource;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.xml.bind.DatatypeConverter;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.zip.Inflater;

/**
 * @author MikuHoney
 * @description 单点退出过滤器实现类
 * @date 2022/8/1 21:00
 */
public final class SingleSignOutHandlerImpl {

    private final static int DECOMPRESSION_FACTOR = 10;

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private SessionMappingStorage sessionMappingStorage = new HashMapBackedSessionMappingStorage();

    private String artifactParameterName = Protocol.CAS2.getArtifactParameterName();

    private String logoutParameterName = ConfigurationKeys.LOGOUT_PARAMETER_NAME.getDefaultValue();

    private String relayStateParameterName = ConfigurationKeys.RELAY_STATE_PARAMETER_NAME.getDefaultValue();

    private String logoutCallbackPath;

    private boolean artifactParameterOverPost = false;

    private boolean eagerlyCreateSessions = true;

    private List<String> safeParameters;

    private final LogoutStrategy logoutStrategy = isServlet30() ? new Servlet30LogoutStrategy() : new Servlet25LogoutStrategy();

    public void setSessionMappingStorage(final SessionMappingStorage storage) {
        this.sessionMappingStorage = storage;
    }

    public void setArtifactParameterOverPost(final boolean artifactParameterOverPost) {
        this.artifactParameterOverPost = artifactParameterOverPost;
    }

    public SessionMappingStorage getSessionMappingStorage() {
        return this.sessionMappingStorage;
    }

    public void setArtifactParameterName(final String name) {
        this.artifactParameterName = name;
    }

    public void setLogoutParameterName(final String name) {
        this.logoutParameterName = name;
    }

    public void setLogoutCallbackPath(final String logoutCallbackPath) {
        this.logoutCallbackPath = logoutCallbackPath;
    }

    public void setRelayStateParameterName(final String name) {
        this.relayStateParameterName = name;
    }

    public void setEagerlyCreateSessions(final boolean eagerlyCreateSessions) {
        this.eagerlyCreateSessions = eagerlyCreateSessions;
    }

    public synchronized void init() {
        if (this.safeParameters == null) {
            CommonUtils.assertNotNull(this.artifactParameterName, "artifactParameterName cannot be null.");
            CommonUtils.assertNotNull(this.logoutParameterName, "logoutParameterName cannot be null.");
            CommonUtils.assertNotNull(this.sessionMappingStorage, "sessionMappingStorage cannot be null.");
            CommonUtils.assertNotNull(this.relayStateParameterName, "relayStateParameterName cannot be null.");

            if (this.artifactParameterOverPost) {
                this.safeParameters = Arrays.asList(this.logoutParameterName, this.artifactParameterName);
            } else {
                this.safeParameters = Collections.singletonList(this.logoutParameterName);
            }
        }
    }

    private boolean isTokenRequest(final HttpServletRequest request) {
        return CommonUtils.isNotBlank(CommonUtils.safeGetParameter(request, this.artifactParameterName, this.safeParameters));
    }

    private boolean isLogoutRequest(final HttpServletRequest request) {
        if ("POST".equalsIgnoreCase(request.getMethod())) {
            return !isMultipartRequest(request)
                    && pathEligibleForLogout(request)
                    && CommonUtils.isNotBlank(CommonUtils.safeGetParameter(request, this.logoutParameterName,
                    this.safeParameters));
        }

        if ("GET".equalsIgnoreCase(request.getMethod())) {
            return CommonUtils.isNotBlank(CommonUtils.safeGetParameter(request, this.logoutParameterName, this.safeParameters));
        }
        return false;
    }

    private boolean pathEligibleForLogout(final HttpServletRequest request) {
        return logoutCallbackPath == null || logoutCallbackPath.equals(getPath(request));
    }

    private String getPath(final HttpServletRequest request) {
        return request.getServletPath() + CommonUtils.nullToEmpty(request.getPathInfo());
    }

    public boolean process(final HttpServletRequest request, final HttpServletResponse response) {
        if (isTokenRequest(request)) {
            logger.trace("Received a token request");
            recordSession(request);
            return true;
        }

        if (isLogoutRequest(request)) {
            logger.trace("Received a logout request");
            destroySession(request, response);
            return false;
        }
        logger.trace("Ignoring URI for logout: {}", request.getRequestURI());
        return true;
    }

    private void recordSession(final HttpServletRequest request) {
        final HttpSession session = request.getSession(this.eagerlyCreateSessions);

        if (session == null) {
            logger.debug("No session currently exists (and none created).  Cannot record session information for single sign out.");
            return;
        }

        final String token = CommonUtils.safeGetParameter(request, this.artifactParameterName, this.safeParameters);
        logger.debug("用户登录认证的ticket:"+token);
        logger.debug("Recording session for token {}", token);

        try {
            this.sessionMappingStorage.removeBySessionById(session.getId());
        } catch (final Exception ignored) {

        }
        sessionMappingStorage.addSessionById(token, session);
    }

    private String uncompressLogoutMessage(final String originalMessage) {
        final byte[] binaryMessage = DatatypeConverter.parseBase64Binary(originalMessage);

        Inflater decompresser = null;
        try {
            decompresser = new Inflater();
            decompresser.setInput(binaryMessage);
            final byte[] result = new byte[binaryMessage.length * DECOMPRESSION_FACTOR];

            final int resultLength = decompresser.inflate(result);

            return new String(result, 0, resultLength, StandardCharsets.UTF_8);
        } catch (final Exception e) {
            logger.error("Unable to decompress logout message", e);
            throw new RuntimeException(e);
        } finally {
            if (decompresser != null) {
                decompresser.end();
            }
        }
    }

    @SuppressWarnings("unchecked")
    private void destroySession(final HttpServletRequest request, final HttpServletResponse response) {
        String logoutMessage = CommonUtils.safeGetParameter(request, this.logoutParameterName, this.safeParameters);
        if (CommonUtils.isBlank(logoutMessage)) {
            logger.error("Could not locate logout message of the request from {}", this.logoutParameterName);
            return;
        }

        if (!logoutMessage.contains("SessionIndex")) {
            logoutMessage = uncompressLogoutMessage(logoutMessage);
        }

        logger.trace("Logout request: {}", logoutMessage);
        final String token = XmlUtils.getTextForElement(logoutMessage, "SessionIndex");
        logger.debug("用户退出系统的ticket:"+token);

        // 字符串非空判断
        if (CommonUtils.isNotBlank(token)) {
            // 获取Spring的Bean实例
            RedisCache redisCache = SpringUtils.getBean("redisCache");
            TokenService tokenService = SpringUtils.getBean("tokenService");
            // 获取Redis中jwt生成的token
            String loginToken = redisCache.getCacheObject(CacheConstants.LOGIN_TICKET_KEY+token);
            // 字符串非空判断
            if (StringUtils.isNotEmpty(loginToken)) {
                // 删除Redis中jwt生成的token
                redisCache.deleteObject(CacheConstants.LOGIN_TICKET_KEY+token);
                // 新建实例
                YamlMapFactoryBean yamlMapFb = new YamlMapFactoryBean();
                // 读取文件
                yamlMapFb.setResources(new ClassPathResource("application.yml"));
                // 获取配置
                String secret = (String) ((Map<String, Object>) Objects.requireNonNull(yamlMapFb.getObject()).get("token")).get("secret");
                try {
                    // 解密jwt生成的token
                    Claims claims = Jwts.parser()
                            .setSigningKey(secret)
                            .parseClaimsJws(loginToken)
                            .getBody();
                    // 解析对应的权限以及用户信息
                    String uuid = (String) claims.get(Constants.LOGIN_USER_KEY);
                    // 获取Redis的key
                    String userKey = CacheConstants.LOGIN_TOKEN_KEY + uuid;
                    // 获取Redis中登录用户的信息
                    LoginUser loginUser = redisCache.getCacheObject(userKey);
                    // 对象非空判断
                    if (StringUtils.isNotNull(loginUser)) {
                        // 用户账号
                        String userName = loginUser.getUsername();
                        // 删除用户缓存记录
                        tokenService.delLoginUser(loginUser.getToken());
                        // 记录用户退出日志
                        AsyncManager.me().execute(AsyncFactory.recordLogininfor(userName, Constants.LOGOUT, "退出成功"));
                    }
                    // 将字符串渲染到客户端
                    ServletUtils.renderString(response, JSON.toJSONString(AjaxResult.error(HttpStatus.SUCCESS, "退出成功")));
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

            final HttpSession session = this.sessionMappingStorage.removeSessionByMappingId(token);

            if (session != null) {
                final String sessionID = session.getId();
                logger.debug("Invalidating session [{}] for token [{}]", sessionID, token);

                try {
                    session.invalidate();
                } catch (final IllegalStateException e) {
                    logger.debug("Error invalidating session.", e);
                }
                this.logoutStrategy.logout(request);
            }
        }
    }

    private boolean isMultipartRequest(final HttpServletRequest request) {
        return request.getContentType() != null && request.getContentType().toLowerCase().startsWith("multipart");
    }

    private static boolean isServlet30() {
        try {
            return HttpServletRequest.class.getMethod("logout") != null;
        } catch (final NoSuchMethodException e) {
            return false;
        }
    }

    private interface LogoutStrategy {
        void logout(HttpServletRequest request);
    }

    private static class Servlet25LogoutStrategy implements LogoutStrategy {
        @Override
        public void logout(final HttpServletRequest request) {

        }
    }

    private class Servlet30LogoutStrategy implements LogoutStrategy {
        @Override
        public void logout(final HttpServletRequest request) {
            try {
                request.logout();
            } catch (final ServletException e) {
                logger.debug("Error performing request.logout.");
            }
        }
    }
}
