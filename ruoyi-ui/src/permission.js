import router from './router'
import {ElMessage} from 'element-plus'
import NProgress from 'nprogress'
import 'nprogress/nprogress.css'
import {isHttp} from '@/utils/validate'
import defaultSettings from '@/settings'
import {isRelogin} from '@/utils/request'
import useUserStore from '@/store/modules/user'
import {getToken, removeAllCookie} from '@/utils/auth'
import useSettingsStore from '@/store/modules/settings'
import usePermissionStore from '@/store/modules/permission'

NProgress.configure({showSpinner: false});

const whiteList = ['/login', '/auth-redirect', '/bind', '/register'];

router.beforeEach((to, from, next) => {
    NProgress.start()
    if (getToken()) {
        // 存在token
        to.meta.title && useSettingsStore().setTitle(to.meta.title)
        if (to.path === '/login') {
            next({path: '/'})
            NProgress.done()
        } else {
            if (useUserStore().roles.length === 0) {
                isRelogin.show = true
                // 判断当前用户是否已拉取完用户信息
                useUserStore().getInfo().then(() => {
                    isRelogin.show = false
                    usePermissionStore().generateRoutes().then(accessRoutes => {
                        // 根据roles权限生成可访问的路由表
                        accessRoutes.forEach(route => {
                            if (!isHttp(route.path)) {
                                // 动态添加可访问路由表
                                router.addRoute(route)
                            }
                        })
                        // hack方法确保addRoutes已完成
                        next({...to, replace: true})
                    })
                }).catch(err => {

                })
            } else {
                next()
            }
        }
    } else {
        // 没有token
        removeAllCookie()
        window.location.href = defaultSettings.apploginUrl
        NProgress.done()
    }
})

router.afterEach(() => {
    NProgress.done()
})
