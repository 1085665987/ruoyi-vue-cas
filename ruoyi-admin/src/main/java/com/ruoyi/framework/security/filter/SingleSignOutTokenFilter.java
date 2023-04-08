package com.ruoyi.framework.security.filter;

import com.ruoyi.framework.security.handle.SingleSignOutHandlerImpl;
import org.jasig.cas.client.configuration.ConfigurationKeys;
import org.jasig.cas.client.session.SessionMappingStorage;
import org.jasig.cas.client.util.AbstractConfigurationFilter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * @author MikuHoney
 * @description 单点退出过滤器
 * @date 2022/8/1 20:59
 */
public final class SingleSignOutTokenFilter extends AbstractConfigurationFilter {

    private static final SingleSignOutHandlerImpl HANDLER = new SingleSignOutHandlerImpl();

    private final AtomicBoolean handlerInitialized = new AtomicBoolean(false);

    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {
        super.init(filterConfig);
        if (!isIgnoreInitConfiguration()) {
            setArtifactParameterName(getString(ConfigurationKeys.ARTIFACT_PARAMETER_NAME));
            setLogoutParameterName(getString(ConfigurationKeys.LOGOUT_PARAMETER_NAME));
            setRelayStateParameterName(getString(ConfigurationKeys.RELAY_STATE_PARAMETER_NAME));
            setLogoutCallbackPath(getString(ConfigurationKeys.LOGOUT_CALLBACK_PATH));
            HANDLER.setArtifactParameterOverPost(getBoolean(ConfigurationKeys.ARTIFACT_PARAMETER_OVER_POST));
            HANDLER.setEagerlyCreateSessions(getBoolean(ConfigurationKeys.EAGERLY_CREATE_SESSIONS));
        }
        HANDLER.init();
        handlerInitialized.set(true);
    }

    public void setArtifactParameterName(final String name) {
        HANDLER.setArtifactParameterName(name);
    }

    public void setLogoutParameterName(final String name) {
        HANDLER.setLogoutParameterName(name);
    }

    public void setRelayStateParameterName(final String name) {
        HANDLER.setRelayStateParameterName(name);
    }

    public void setLogoutCallbackPath(final String logoutCallbackPath) {
        HANDLER.setLogoutCallbackPath(logoutCallbackPath);
    }

    public void setSessionMappingStorage(final SessionMappingStorage storage) {
        HANDLER.setSessionMappingStorage(storage);
    }

    @Override
    public void doFilter(final ServletRequest servletRequest, final ServletResponse servletResponse, final FilterChain filterChain) throws IOException, ServletException {
        final HttpServletRequest request = (HttpServletRequest) servletRequest;
        final HttpServletResponse response = (HttpServletResponse) servletResponse;

        if (!this.handlerInitialized.getAndSet(true)) {
            HANDLER.init();
        }

        if (HANDLER.process(request, response)) {
            filterChain.doFilter(servletRequest, servletResponse);
        }
    }

    @Override
    public void destroy() {

    }

    private static SingleSignOutHandlerImpl getSingleSignOutHandler() {
        return HANDLER;
    }
}
