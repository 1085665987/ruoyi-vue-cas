import path from 'path'
import {defineConfig, loadEnv} from 'vite'
import createVitePlugins from './vite/plugins'

// https://vitejs.dev/config/
export default defineConfig(({mode, command}) => {
    const env = loadEnv(mode, process.cwd())
    const {VITE_APP_ENV, VITE_APP_BASE_API, VITE_FRONT_END_PORT, VITE_FRONT_END_HOST, VITE_BACK_END_HOST_AND_PORT} = env
    return {
        // 部署生产环境和开发环境下的URL。
        // 默认情况下vite会假设你的应用是被部署在一个域名的根路径上。
        // 如果应用被部署在一个子路径上，你就需要用这个选项指定这个子路径。例如，如果你的应用被部署在[https://www.ruoyi.vip/admin/]，则设置baseUrl为[/admin/]。
        base: VITE_APP_ENV === 'production' ? '/' : '/',
        plugins: createVitePlugins(env, command === 'build'),
        resolve: {
            // https://cn.vitejs.dev/config/#resolve-alias
            alias: {
                // 设置路径
                '~': path.resolve(__dirname, './'),
                // 设置别名
                '@': path.resolve(__dirname, './src')
            },
            // https://cn.vitejs.dev/config/#resolve-extensions
            extensions: ['.mjs', '.js', '.ts', '.jsx', '.tsx', '.json', '.vue']
        },
        // vite相关配置
        server: {
            port: VITE_FRONT_END_PORT,
            host: VITE_FRONT_END_HOST,
            open: true,
            proxy: {
                // https://cn.vitejs.dev/config/#server-proxy
                [VITE_APP_BASE_API]: {
                    target: VITE_BACK_END_HOST_AND_PORT,
                    changeOrigin: true,
                    rewrite: (p) => p.replace(VITE_APP_BASE_API, '')
                }
            },
            // 是否开启热更新
            hmr: false
        },
        // fix:error:stdin>:warning: @charset must be the first rule in the file
        css: {
            postcss: {
                plugins: [
                    {
                        postcssPlugin: 'internal:charset-removal',
                        AtRule: {
                            charset: (atRule) => {
                                if (atRule.name === 'charset') {
                                    atRule.remove();
                                }
                            }
                        }
                    }
                ]
            }
        }
    }
});
