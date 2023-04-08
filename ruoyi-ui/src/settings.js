export default {
    /**
     * 网页标题
     */
    title: import.meta.env.VITE_APP_TITLE,

    /**
     * 侧边栏主题(深色主题theme-dark|浅色主题theme-light)
     */
    sideTheme: 'theme-dark',

    /**
     * 是否系统布局配置
     */
    showSettings: false,

    /**
     * 是否显示顶部导航
     */
    topNav: false,

    /**
     * 是否显示tagsView
     */
    tagsView: true,

    /**
     * 是否固定头部
     */
    fixedHeader: false,

    /**
     * 是否显示logo
     */
    sidebarLogo: true,

    /**
     * 是否显示动态标题
     */
    dynamicTitle: false,

    /**
     * 需要显示error日志的环境
     */
    errorLog: 'production',

    /**
     * 开启cas
     */
    casEnable: true,

    /**
     * 单点url
     */
    casUrl: 'http://127.0.0.1:8888/cas/login',

    /**
     * 后台登录url
     */
    apploginUrl: import.meta.env.VITE_FRONT_END_HOST_AND_PORT+import.meta.env.VITE_APP_BASE_API+'/cas/index',

    /**
     * 单点登录url
     */
    casloginUrl: 'http://127.0.0.1:8888/cas/login?service='+import.meta.env.VITE_FRONT_END_HOST_AND_PORT+'/index',

    /**
     * 单点登出url
     */
    caslogoutUrl: 'http://127.0.0.1:8888/cas/logout?service=http://127.0.0.1:8888/cas/login?service='+import.meta.env.VITE_FRONT_END_HOST_AND_PORT+'/index',
}
