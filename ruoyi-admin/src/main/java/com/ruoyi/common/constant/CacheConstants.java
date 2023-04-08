package com.ruoyi.common.constant;

import org.springframework.beans.factory.config.YamlMapFactoryBean;
import org.springframework.core.io.ClassPathResource;

import java.util.Map;
import java.util.Objects;

/**
 * 缓存的key 常量
 *
 * @author ruoyi
 */
@SuppressWarnings("unchecked")
public class CacheConstants {
    // Redis缓存前缀
    public static String cacheConstantsPrefix = new String();
    // 静态块初始化
    static {
        cacheConstantsPrefix = getCacheConstantsPrefix();
    }

    // Redis缓存前缀统一前缀
    public static final String REDIS_KEY_GENERAL_PREFIX = "efong_constants:";
    // 登录用户RedisKey
    public static final String LOGIN_TOKEN_KEY = cacheConstantsPrefix + "login_tokens:";
    // 用户票据RedisKey
    public static final String LOGIN_TICKET_KEY = cacheConstantsPrefix + "login_ticket:";
    // 验证码RedisKey
    public static final String CAPTCHA_CODE_KEY = cacheConstantsPrefix + "captcha_codes:";
    // 参数管理RedisKey
    public static final String SYS_CONFIG_KEY = cacheConstantsPrefix + "sys_config:";
    // 字典管理RedisKey
    public static final String SYS_DICT_KEY = cacheConstantsPrefix + "sys_dict:";
    // 防重提交RedisKey
    public static final String REPEAT_SUBMIT_KEY = cacheConstantsPrefix + "repeat_submit:";
    // 限流处理RedisKey
    public static final String RATE_LIMIT_KEY = cacheConstantsPrefix + "rate_limit:";

    /**
     * 获取Redis缓存前缀
     * @return Redis缓存前缀
     */
    public static String getCacheConstantsPrefix(){
        // 新建实例
        YamlMapFactoryBean yamlMapFb = new YamlMapFactoryBean();
        // 读取文件
        yamlMapFb.setResources(new ClassPathResource("application.yml"));
        // 获取配置
        String appName = (String) ((Map<String, Object>) Objects.requireNonNull(yamlMapFb.getObject()).get("app")).get("name");
        // 返回结果
        return REDIS_KEY_GENERAL_PREFIX + appName + ":";
    }
}
