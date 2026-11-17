const TOKEN_KEY = "pojun_token";
const SESSION_FLAG = "pojun_session";
const COOKIE_MAX_AGE = 24 * 60 * 60; // 与服务端 jwtTTL 一致（秒）

export interface CurrentUser {
  id: string;
  name: string;
  username: string;
  email: string;
  avatar: string;
  role: string;
}

function hasSessionFlag(): boolean {
  if (typeof document === "undefined") return false;
  return document.cookie.split(";").some((part) => part.trim().startsWith(`${SESSION_FLAG}=1`));
}

export const auth = {
  // 不再从 localStorage 读取 JWT。登录态只看服务端下发的非敏感标记；
  // 真正的 token 在 HttpOnly cookie 里，脚本读不到。
  getToken(): string | null {
    if (typeof window === "undefined") return null;
    if (process.env.NEXT_PUBLIC_MOCK === "1") return "mock-demo";
    return hasSessionFlag() ? "cookie-session" : null;
  },

  setToken(_token: string): void {
    localStorage.removeItem(TOKEN_KEY);
    document.cookie = `${SESSION_FLAG}=1; path=/; max-age=${COOKIE_MAX_AGE}; SameSite=Strict`;
  },

  clearToken(): void {
    localStorage.removeItem(TOKEN_KEY);
    document.cookie = `${TOKEN_KEY}=; path=/; max-age=0`;
    document.cookie = `${SESSION_FLAG}=; path=/; max-age=0`;
    if (process.env.NEXT_PUBLIC_MOCK === "1") return;
    void fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" }).catch(() => undefined);
  },

  // 展示用。JWT 不再放在脚本可读的位置，登录名固定为平台唯一账户。
  getCurrentUser(): CurrentUser | null {
    if (!this.getToken()) return null;
    return { id: "1", name: "POJUN", username: "POJUN", email: "", avatar: "", role: "operator" };
  },
};
