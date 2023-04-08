import Cookies from 'js-cookie'

const TokenKey = 'Admin-Token-App2'
const JsessionId = 'JSESSIONID'

export function getToken() {
    return Cookies.get(TokenKey)
}

export function setToken(token) {
    return Cookies.set(TokenKey, token)
}

export function removeToken() {
    return Cookies.remove(TokenKey)
}

export function removeJsessionId() {
    return Cookies.remove(JsessionId)
}

export function removeAllCookie() {
    removeToken()
    removeJsessionId()
}
