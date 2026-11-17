package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	jwtKeyFilename = "jwt.key"
	authPassKey    = "auth.password_hash"
	// 会话缩短到 24 小时。改密码仍会轮换签名 key，使已发出的 token 立即失效。
	jwtTTL   = 24 * time.Hour
	keyChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// 下限与 setup 页的前端校验一致——校验只放在前端等于没放，直接打 API 就能
	// 绕过。上限是 bcrypt 的硬限制：超过 72 字节 GenerateFromPassword 会返回
	// ErrPasswordTooLong，提前挡掉好过让用户收到一句含义不明的「密码加密失败」。
	minPasswordRunes = 8
	maxPasswordBytes = 72
)

// errDataSourceUnavailable 是密码相关读操作失败时统一的回复。这些 handler 绝不能
// 把"读不到"当成"没有设置"：authInit 曾因此在数据库报错时放行，让未认证请求覆盖
// 掉已有的管理员密码。
const errDataSourceUnavailable = "数据源暂时不可用，请稍后重试"

// validatePassword 返回空串表示通过，否则返回可直接展示给用户的中文原因。
func validatePassword(pw string) string {
	if utf8.RuneCountInString(pw) < minPasswordRunes {
		return fmt.Sprintf("密码长度至少 %d 位", minPasswordRunes)
	}
	if len(pw) > maxPasswordBytes {
		return fmt.Sprintf("密码长度不能超过 %d 字节", maxPasswordBytes)
	}
	return ""
}

// loadOrCreateJWTKey reads the 32-byte signing key from keyDir/jwt.key. keyDir is
// the project base dir (next to the executable), NOT the browsable workspace root
// (dataDir) — the signing key must never be listable/downloadable via the file
// manager. Legacy installs kept it at dataDir/jwt.key; if present there and not yet
// at the new location, it is migrated (key preserved, so sessions stay valid) and
// the old file removed so it disappears from the workspace. On first run a random
// key is generated and persisted.
func loadOrCreateJWTKey(keyDir, dataDir string) ([]byte, error) {
	path := filepath.Join(keyDir, jwtKeyFilename)
	// one-time migration out of the old in-workspace location.
	if legacy := filepath.Join(dataDir, jwtKeyFilename); legacy != path {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if data, rerr := os.ReadFile(legacy); rerr == nil {
				if werr := os.WriteFile(path, data, 0o600); werr == nil {
					_ = os.Remove(legacy)
					log.Printf("[auth] JWT key 已从 %s 迁移到 %s（移出可浏览工作区）", legacy, path)
				}
			}
		}
	}
	if data, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(data))) >= 32 {
		return []byte(strings.TrimSpace(string(data))), nil
	}
	buf := make([]byte, 32)
	for i := range buf {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(keyChars))))
		if err != nil {
			return nil, fmt.Errorf("generate jwt key: %w", err)
		}
		buf[i] = keyChars[n.Int64()]
	}
	if err := os.WriteFile(path, buf, 0600); err != nil {
		return nil, fmt.Errorf("write jwt key: %w", err)
	}
	log.Printf("[auth] 新 JWT key 已写入 %s", path)
	return buf, nil
}

// currentJWTKey 原子读取当前签名 key（改密码轮换后立即变化）。
func (s *Server) currentJWTKey() []byte {
	if v, ok := s.jwtKey.Load().([]byte); ok {
		return v
	}
	return nil
}

// rotateJWTKey 生成新 key 原子替换并落盘：**所有已签发 token 立即失效**。
// 改密码必须轮换——否则公网上泄露的旧 token 能一直用到 7 天自然过期，
// 「改密码踢掉攻击者」就成了一句空话。
func (s *Server) rotateJWTKey() error {
	buf := make([]byte, 32)
	for i := range buf {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(keyChars))))
		if err != nil {
			return fmt.Errorf("generate jwt key: %w", err)
		}
		buf[i] = keyChars[n.Int64()]
	}
	if err := os.WriteFile(filepath.Join(s.keyDir, jwtKeyFilename), buf, 0o600); err != nil {
		return fmt.Errorf("write jwt key: %w", err)
	}
	s.jwtKey.Store(buf)
	log.Printf("[auth] JWT key 已轮换（改密码），全部旧会话失效")
	return nil
}

// clientIP 取连接对端地址。只有当对端属于 POJUN_TRUSTED_PROXIES（IP 或 CIDR，
// 逗号分隔）时，才读取反代写入的 X-Real-IP / X-Forwarded-For。未配置时忽略
// 这两个头，避免伪造来源绕过每 IP 限流。
func clientIP(r *http.Request) string {
	host := remoteHost(r)
	if !trustedProxy(host) {
		return host
	}
	if xr := strings.TrimSpace(r.Header.Get("X-Real-IP")); xr != "" {
		return xr
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	return host
}

func remoteHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func trustedProxy(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, part := range strings.Split(os.Getenv("POJUN_TRUSTED_PROXIES"), ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if parsed := net.ParseIP(part); parsed != nil && parsed.Equal(ip) {
			return true
		}
		if _, network, err := net.ParseCIDR(part); err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

// loginLimiter 是登录/初始化接口的进程级防爆破闸门：
// 每 IP 在 10 分钟窗口内失败 5 次 → 锁该 IP 15 分钟。
//
// 不再使用「全局失败次数锁死所有地址」。那个全员锁可以被伪造来源或分布式
// 失败把管理员自己的登录一起锁住。来源伪造改由「默认不信任转发头」挡住。
// 内存态即可：重启清零只影响攻击者的等待时间，不影响正确性。
// 返回 (允许, 剩余锁定时长)。
type loginLimiter struct {
	mu          sync.Mutex
	fails       map[string][]time.Time // ip → 失败时间序列（滑动窗口）
	lockedUntil map[string]time.Time   // ip → 锁定截止
}

var loginLimit = &loginLimiter{fails: map[string][]time.Time{}, lockedUntil: map[string]time.Time{}}

const (
	loginMaxFailsPerIP   = 5
	loginFailWindow      = 10 * time.Minute
	loginLockoutPerIP    = 15 * time.Minute
	loginFailureMinDelay = 300 * time.Millisecond // 失败响应的人为下限，抹平时序差
)

func (l *loginLimiter) allow(ip string) (bool, time.Duration) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if until, ok := l.lockedUntil[ip]; ok && now.Before(until) {
		return false, until.Sub(now)
	}
	// 惰性清理过期窗口，防 map 随扫描流量无限增长。
	for k, until := range l.lockedUntil {
		if now.After(until) && len(l.fails[k]) == 0 {
			delete(l.lockedUntil, k)
		}
	}
	return true, 0
}

func (l *loginLimiter) recordFail(ip string) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	// per-IP 滑动窗口。
	f := append(l.fails[ip], now)
	cut := now.Add(-loginFailWindow)
	i := 0
	for i < len(f) && f[i].Before(cut) {
		i++
	}
	f = f[i:]
	l.fails[ip] = f
	if len(f) >= loginMaxFailsPerIP {
		l.lockedUntil[ip] = now.Add(loginLockoutPerIP)
		l.fails[ip] = nil
	}
}

func (l *loginLimiter) recordSuccess(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, ip)
	delete(l.lockedUntil, ip)
}

// loginGuard 统一包住 login/init 的防爆破语义：超限直接 429，失败记一笔并
// 人为拖慢响应。返回 false 表示已写响应、调用方直接 return。
func loginGuard(w http.ResponseWriter, r *http.Request, action string) bool {
	ip := clientIP(r)
	if ok, wait := loginLimit.allow(ip); !ok {
		log.Printf("[auth] %s 限流触发 ip=%s 剩余=%s", action, ip, wait.Truncate(time.Second))
		writeErr(w, http.StatusTooManyRequests, "尝试过于频繁，请稍后再试")
		return false
	}
	if action == "login-fail" {
		loginLimit.recordFail(ip)
		log.Printf("[auth] 登录失败 ip=%s", ip)
		time.Sleep(loginFailureMinDelay)
	}
	return true
}

// signJWT issues an HS256 token for user POJUN. Lifetime is jwtTTL.
func signJWT(key []byte) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject:   "POJUN",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(jwtTTL)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}).SignedString(key)
}

// verifyJWT returns true when tokenStr is a valid, non-expired HS256 token.
func verifyJWT(tokenStr string, key []byte) bool {
	t, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return key, nil
	})
	return err == nil && t.Valid
}

// sseQueryTokenPaths 是唯一接受 ?token= 查询参数的端点白名单：浏览器 EventSource
// 无法带 Authorization 头,这些 URL 直连的 SSE 流端点历史上靠 query token 认证。
// 其余任何路径不再从 query 取 token（N1 收敛）——token 会进访问日志/X-Forwarded 头/
// Referer,能走 cookie（前端已配好）的路径不该把这个风险留着。EventSource 同源默认带
// cookie,query 只是 cookie 不可用时的后备。side-questions 的 events 端点带请求 id,
// 由 queryTokenAllowed 里的前缀+后缀判断覆盖。
var sseQueryTokenPaths = map[string]bool{
	"/api/exploration/activity/stream": true,
	"/api/logs/stream":                 true,
	"/api/update/stream":               true,
}

// queryTokenAllowed reports whether ?token= may be trusted for this request:
// only the four URL-direct SSE stream endpoints (see sseQueryTokenPaths).
func queryTokenAllowed(r *http.Request) bool {
	if sseQueryTokenPaths[r.URL.Path] {
		return true
	}
	// side-questions events 按请求 id 动态:/api/side-questions/<id>/events
	return strings.HasPrefix(r.URL.Path, "/api/side-questions/") && strings.HasSuffix(r.URL.Path, "/events")
}

// extractToken reads the JWT from Authorization: Bearer header, or the
// pojun_token cookie. ?token= query is only honored on the SSE stream endpoints
// (queryTokenAllowed) — elsewhere the token would leak into access logs and
// Referer headers without giving up anything the cookie doesn't already do.
func extractToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	if c, err := r.Cookie("pojun_token"); err == nil && c.Value != "" {
		return c.Value
	}
	if queryTokenAllowed(r) {
		return r.URL.Query().Get("token")
	}
	return ""
}

// requireAuth wraps h with JWT validation.
// /api/auth/* and /api/health are exempt.
func (s *Server) requireAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/api/auth/") || p == "/api/health" {
			h.ServeHTTP(w, r)
			return
		}
		tok := extractToken(r)
		if tok == "" {
			writeErr(w, 401, "未授权")
			return
		}
		if !verifyJWT(tok, s.currentJWTKey()) {
			writeErr(w, 401, "token 无效或已过期")
			return
		}
		h.ServeHTTP(w, r)
	})
}

// GET /api/auth/status — reports whether the admin password has been initialised.
// 读失败必须回 503 而不是 initialized:false：前端在 initialized:false 时会把用户
// 送到 /setup 去设置密码（login/page.tsx），把数据库故障包装成 200 等于把用户往
// 覆盖已有密码的路上推。
func (s *Server) authStatus(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	hash, _, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	writeJSON(w, 200, map[string]any{"initialized": hash != ""})
}

// prepareInitToken 在进程启动时调用。已经有管理员密码则不生成口令，避免
// 任何路径把已初始化实例重新打开。数据库暂时读失败时也不生成。
func (s *Server) prepareInitToken() {
	if s == nil || s.m == nil || s.m.pg == nil {
		return
	}
	hash, _, err := s.m.pg.GetSetting(authPassKey)
	if err != nil || hash != "" {
		return
	}
	s.initMu.Lock()
	defer s.initMu.Unlock()
	if s.initToken == "" {
		s.mintInitTokenLocked()
	}
}

// mintInitTokenLocked 生成一次性初始化口令。POJUN_INIT_TOKEN 若已设置则采用
// 它且不把值写进日志；否则生成随机值并打印一次，供操作员抄到初始化页面。
// 同 UID 进程可以读到日志，这不能挡住本机同用户。它挡住的是还没拿到口令的
// 网络访问者。调用方必须持有 initMu。
func (s *Server) mintInitTokenLocked() {
	if v := strings.TrimSpace(os.Getenv("POJUN_INIT_TOKEN")); v != "" {
		s.initToken = v
		log.Printf("[auth] 实例尚未初始化：使用环境变量 POJUN_INIT_TOKEN（值不打印）。成功设置密码后该口令作废")
		return
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		log.Printf("[auth] 无法生成初始化口令，拒绝开放 /api/auth/init: %v", err)
		s.initToken = ""
		return
	}
	s.initToken = hex.EncodeToString(buf)
	log.Printf("[auth] 首次初始化口令（仅本次进程有效，成功后作废）: %s", s.initToken)
	log.Printf("[auth] 同用户可以阅读上述日志。这不是对本机同 UID 进程的隔离，只用于挡住未持有口令的网络访问者")
}

func initTokenEqual(got, want string) bool {
	if got == "" || want == "" || len(got) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func sessionCookieSecure() bool { return os.Getenv("POJUN_COOKIE_SECURE") == "1" }

func (s *Server) setSessionCookies(w http.ResponseWriter, token string) {
	secure := sessionCookieSecure()
	maxAge := int(jwtTTL.Seconds())
	http.SetCookie(w, &http.Cookie{
		Name: "pojun_token", Value: token, Path: "/", MaxAge: maxAge,
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: secure,
	})
	http.SetCookie(w, &http.Cookie{
		Name: "pojun_session", Value: "1", Path: "/", MaxAge: maxAge,
		HttpOnly: false, SameSite: http.SameSiteStrictMode, Secure: secure,
	})
}

func clearSessionCookies(w http.ResponseWriter) {
	secure := sessionCookieSecure()
	http.SetCookie(w, &http.Cookie{
		Name: "pojun_token", Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: secure,
	})
	http.SetCookie(w, &http.Cookie{
		Name: "pojun_session", Value: "", Path: "/", MaxAge: -1,
		HttpOnly: false, SameSite: http.SameSiteStrictMode, Secure: secure,
	})
}

// POST /api/auth/init — 仅在尚未设置密码时生效，并且必须出示一次性初始化口令。
// 已有密码时保持 403，不改哈希、不轮换口令。并发下只有一次 INSERT 能成功。
func (s *Server) authInit(w http.ResponseWriter, r *http.Request) {
	if !loginGuard(w, r, "init") {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req struct {
		Password  string `json:"password"`
		InitToken string `json:"init_token"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if header := strings.TrimSpace(r.Header.Get("X-Pojun-Init-Token")); header != "" {
		req.InitToken = header
	}
	req.InitToken = strings.TrimSpace(req.InitToken)

	s.initMu.Lock()
	defer s.initMu.Unlock()

	existing, _, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if existing != "" {
		writeErr(w, 403, "密码已设置")
		return
	}
	if s.initToken == "" {
		s.mintInitTokenLocked()
	}
	if !initTokenEqual(req.InitToken, s.initToken) {
		writeErr(w, 403, "初始化口令无效")
		return
	}
	if req.Password == "" {
		writeErr(w, 400, "密码不能为空")
		return
	}
	if msg := validatePassword(req.Password); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "密码加密失败")
		return
	}
	// INSERT ... ON CONFLICT DO NOTHING：bcrypt 期间别的请求可能已经写入。
	// 锁保证本进程内只有一个请求走到这里；数据库约束挡住多进程。
	inserted, err := pg.InsertSettingIfAbsent(authPassKey, string(hash))
	if err != nil {
		writeErr(w, 500, "保存失败: "+err.Error())
		return
	}
	if !inserted {
		writeErr(w, 403, "密码已设置")
		return
	}
	s.initToken = ""
	tok, err := signJWT(s.currentJWTKey())
	if err != nil {
		writeErr(w, 500, "token 生成失败")
		return
	}
	s.setSessionCookies(w, tok)
	writeJSON(w, 200, map[string]any{"token": tok})
}

// POST /api/auth/logout — 清掉会话 cookie。不要求当前 token 仍然有效。
func (s *Server) authLogout(w http.ResponseWriter, r *http.Request) {
	clearSessionCookies(w)
	writeJSON(w, 200, map[string]any{"ok": true})
}

// POST /api/auth/change-password — changes the admin password. Requires a valid
// token (this route is under /api/auth/* which requireAuth exempts, so the token
// is validated here) AND the current password.
func (s *Server) authChangePassword(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	if !verifyJWT(extractToken(r), s.currentJWTKey()) {
		writeErr(w, 401, "未授权")
		return
	}
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if req.NewPassword == "" {
		writeErr(w, 400, "新密码不能为空")
		return
	}
	if msg := validatePassword(req.NewPassword); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	hash, ok, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if !ok || hash == "" {
		writeErr(w, 403, "密码未初始化，请先设置密码")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.OldPassword)); err != nil {
		writeErr(w, 401, "当前密码错误")
		return
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "密码加密失败")
		return
	}
	if err := pg.SetSetting(authPassKey, string(newHash)); err != nil {
		writeErr(w, 500, "保存失败: "+err.Error())
		return
	}
	// 轮换签名 key：旧密码可能已经泄露（改密码本身往往就是怀疑泄露的动作），
	// 不轮换的话用旧 token 的会话全部存活到自然过期。
	if err := s.rotateJWTKey(); err != nil {
		// 密码已改成功、轮换失败：不回滚（密码改了比没改安全），但要显式告警。
		log.Printf("[auth] 改密码后 JWT key 轮换失败: %v（旧 token 仍然有效，请重启服务强制轮换）", err)
	}
	clearSessionCookies(w)
	writeJSON(w, 200, map[string]any{"ok": true})
}

// POST /api/auth/login — validates username/password and returns a JWT.
func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	if !loginGuard(w, r, "login") {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if req.Username != "POJUN" && req.Username != "ARTEX" { // v0.4.19 改名：兼容旧用户名
		writeErr(w, 401, "用户名或密码错误")
		return
	}
	hash, ok, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if !ok || hash == "" {
		writeErr(w, 403, "密码未初始化，请先设置密码")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
		loginGuard(w, r, "login-fail")
		writeErr(w, 401, "用户名或密码错误")
		return
	}
	loginLimit.recordSuccess(clientIP(r))
	tok, err := signJWT(s.currentJWTKey())
	if err != nil {
		writeErr(w, 500, "token 生成失败")
		return
	}
	s.setSessionCookies(w, tok)
	writeJSON(w, 200, map[string]any{"token": tok})
}
