package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"math/rand"
	"time"
	"github.com/gorilla/mux"
	"flag"
        _ "embed"
)

//go:embed PortLink.png
var favicon []byte

const jsonFilePath = "db.json"

type User struct {
	Password string `json:"password"`
	Https    bool   `json:"https"`
	Host       string `json:"host"`
	Port     string `json:"port"`
	AccessKey string `json:"accessKey"`
}

var reservedchannel_ids = []string{"api", "admin", "register", "login", "static"}

func main() {
	rand.Seed(time.Now().UnixNano())
	router := mux.NewRouter()
	
	portPtr := flag.String("p", "3000", "服务运行的端口")
	flag.Parse()

	// 主页面
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html;charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, getIndex())
	}).Methods("GET")

	// 注册页面
	router.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html;charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, getRegisterHtml())
	}).Methods("GET")

	// 添加路由来提供嵌入的图片
	router.HandleFunc("/favicon.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Write(favicon)
	}).Methods("GET")

	// API路由处理
	router.HandleFunc("/api/update", handleJsonUpdate).Methods("POST")
	router.HandleFunc("/api/create", handleJsonCreate).Methods("POST")
	router.HandleFunc("/api/verify", handleJsonVerify).Methods("POST")

	// 重定向处理
	router.HandleFunc("/{channel_id:.+}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		channel_id := vars["channel_id"]
		pathParts := strings.Split(r.URL.Path, "/")
		if len(pathParts) < 2 {
    			w.WriteHeader(http.StatusBadRequest)
    			fmt.Fprint(w, "无效的路径")
    			return
		}
		channel_id = pathParts[1]
		handleJsonRedirect(r, channel_id, pathParts, w)
	}).Methods("GET", "POST")

	// 启动服务器
	port := fmt.Sprintf(":%s", *portPtr)
	fmt.Printf("服务器运行在 http://localhost%s\n", port)
	http.ListenAndServe(port, router)
}

func getJsonData(channel_id string) *User {
	data := make(map[string]User)
	file, err := os.Open(jsonFilePath)
	if err != nil {
		return nil
	}
	defer file.Close()

	byteValue, _ := ioutil.ReadAll(file)
	json.Unmarshal(byteValue, &data)

	if user, ok := data[channel_id]; ok {
		return &user
	}
	return nil
}

func setJsonData(channel_id string, userData User) bool {
	data := make(map[string]User)
	file, err := os.Open(jsonFilePath)
	if err == nil {
		defer file.Close()
		byteValue, _ := ioutil.ReadAll(file)
		json.Unmarshal(byteValue, &data)
	}

	data[channel_id] = userData

	file, err = os.Create(jsonFilePath)
	if err != nil {
		return false
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	encoder.Encode(data)
	return true
}

func validateParams(params map[string]interface{}) (bool, string) {
	required := []string{"channel_id", "password", "host", "port"}
	missing := []string{}

	for _, field := range required {
		if _, ok := params[field]; !ok || params[field] == "" {
			missing = append(missing, field)
		}
	}

	if len(missing) > 0 {
		return false, fmt.Sprintf("缺失必要参数: %s", strings.Join(missing, ", "))
	}

	return true, ""
}

func parseCookies(cookieHeader string) map[string]string {
	cookies := make(map[string]string)
	if cookieHeader == "" {
		return cookies
	}

	for _, cookie := range strings.Split(cookieHeader, ";") {
		parts := strings.SplitN(strings.TrimSpace(cookie), "=", 2)
		if len(parts) == 2 {
			name, err1 := url.QueryUnescape(parts[0])
			value, err2 := url.QueryUnescape(parts[1])
			if err1 == nil && err2 == nil {
				cookies[name] = value
			}
		}
	}
	return cookies
}

func handleJsonRedirect(r *http.Request, channel_id string, pathParts []string, w http.ResponseWriter) {
	user := getJsonData(channel_id)
	if user == nil {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "通道ID不存在")
		return
	}

	if user.AccessKey != "" {
		cookies := parseCookies(r.Header.Get("Cookie"))
		accessToken := cookies[fmt.Sprintf("access_%s", channel_id)]

		if accessToken != user.AccessKey {
			w.Header().Set("Content-Type", "text/html;charset=utf-8")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, getPasswordHtml(channel_id))
			return
		}
	}

	// 解析请求的 URL
	u, _ := url.Parse(r.URL.String())

	protocol := "http"
	if user.Https {
		protocol = "https"
	}

	// 获取请求的路径（不包括用户ID部分）
	// 确保路径处理正确，避免出现多余的问号
	requestedPath := strings.TrimPrefix(u.Path, "/"+channel_id)
	if requestedPath == "" {
		requestedPath = "/"
	}

	// 获取查询参数
	queryParams := u.RawQuery

	// 构建目标 URL
	targetURL := &url.URL{
		Scheme:   protocol,
		Host:     fmt.Sprintf("%s:%s", user.Host, user.Port),
		Path:     requestedPath,
		RawQuery: queryParams,
	}

	// 设置重定向
	w.Header().Set("Location", targetURL.String())
	w.WriteHeader(http.StatusFound)
}

func handleJsonVerify(w http.ResponseWriter, r *http.Request) {
	var params map[string]interface{}
	body, _ := ioutil.ReadAll(r.Body)
	json.Unmarshal(body, &params)

	channel_id, ok := params["channel_id"].(string)
	if !ok || channel_id == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "参数不完整")
		return
	}

	accessKey, ok := params["accessKey"].(string)
	if !ok || accessKey == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "参数不完整")
		return
	}

	user := getJsonData(channel_id)
	if user == nil {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "通道ID不存在")
		return
	}

	if user.AccessKey != accessKey {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "访问密码错误")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     fmt.Sprintf("access_%s", channel_id),
		Value:    accessKey,
		Path:     "/",
		MaxAge:   2592000,
		HttpOnly: true,
	})

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "验证成功")
}

func handleJsonUpdate(w http.ResponseWriter, r *http.Request) {
	var params map[string]interface{}
	body, _ := ioutil.ReadAll(r.Body)
	json.Unmarshal(body, &params)

	valid, message := validateParams(params)
	if !valid {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, message)
		return
	}

	channel_id, _ := params["channel_id"].(string)
	password, _ := params["password"].(string)
	https, _ := params["https"].(bool)
	host, _ := params["host"].(string)
	port, _ := params["port"].(string)
	accessKey, _ := params["accessKey"].(string)

	user := getJsonData(channel_id)
	if user == nil {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "通道ID不存在")
		return
	}

	if user.Password != password {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "未认证")
		return
	}

	userData := User{
		Password: password,
		Https:    https,
		Host:       host,
		Port:     port,
		AccessKey: accessKey,
	}

	if setJsonData(channel_id, userData) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "更新成功")
	} else {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "更新失败，请重试")
	}
}

func handleJsonCreate(w http.ResponseWriter, r *http.Request) {
	var params map[string]interface{}
	body, _ := ioutil.ReadAll(r.Body)
	json.Unmarshal(body, &params)

	valid, message := validateParams(params)
	if !valid {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, message)
		return
	}

	channel_id, _ := params["channel_id"].(string)
	password, _ := params["password"].(string)
	https, _ := params["https"].(bool)
	host, _ := params["host"].(string)
	port, _ := params["port"].(string)
	accessKey, _ := params["accessKey"].(string)

	if isReservedchannel_id(channel_id) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "通道ID不可用")
		return
	}

	if getJsonData(channel_id) != nil {
		w.WriteHeader(http.StatusConflict)
		fmt.Fprint(w, "通道ID已存在")
		return
	}

	finalPassword := password
	if finalPassword == "" {
		finalPassword = generateRandomPassword(12)
	}

	userData := User{
		Password: finalPassword,
		Https:    https,
		Host:       host,
		Port:     port,
		AccessKey: accessKey,
	}

	if setJsonData(channel_id, userData) {
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, "注册成功，密码为: %s", finalPassword)
	} else {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "注册失败，请重试")
	}
}

func isReservedchannel_id(channel_id string) bool {
	for _, reserved := range reservedchannel_ids {
		if strings.ToLower(channel_id) == reserved {
			return true
		}
	}
	return false
}

func generateRandomPassword(length int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+"
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		result[i] = chars[rand.Intn(len(chars))]
	}
	return string(result)
}

func getIndex() string {
	return `
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>内网跳转穿透工具</title>
    <link rel="icon" type="image/png" href="/favicon.png">
    <style>
        /* 全局样式 */
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            color: #333;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: flex-start; 
            height: 100vh;
            background-image: url('https://mi-d.cn/nlt/download.webp'); 
            background-size: cover; 
            background-position: center; 
            padding-top: 10vh; 
        }

        /* 容器样式 */
        .container {
            text-align: center;
            max-width: 600px;
            width: 100%;
            padding: 20px; 
        }

        /* Logo 样式 */
        .logo {
            width: 50%; 
            max-width: 400px; 
            height: auto; 
            margin-bottom: 20px; 
        }

        /* 标题样式 */
        h1 {
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 20px;
            color: #000;
        }

        /* 输入框和按钮容器 */
        .input-group {
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 10px;
            margin-bottom: 10px;
        }

        /* 输入框样式 */
        input[type="text"] {
            width: 300px;
            padding: 10px;
            font-size: 14px;
            border: 1px solid #ddd;
            border-radius: 8px;
            outline: none;
            transition: border-color 0.3s ease;
        }

        input[type="text"]:focus {
            border-color: #007bff;
        }

        /* 按钮样式 */
        button {
            padding: 10px 20px;
            font-size: 14px;
            font-weight: 500;
            color: #fff;
            background-color: #007bff;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            transition: background-color 0.3s ease;
        }

        button:hover {
            background-color: #0056b3;
        }

        /* 提示文字样式 */
        .tip {
            font-size: 12px;
            color: #666;
            margin-top: 10px;
        }

        .tip a {
            color: #007bff;
            text-decoration: none;
        }

        .tip a:hover {
            text-decoration: underline;
        }

        /* 核心优势样式 */
        .advantages {
            margin-top: 20px; 
            text-align: left;
            background-color: rgba(255, 255, 255, 0.8); 
            padding: 15px; 
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            width: 90%; 
            max-width: 400px; 
            margin-left: auto;
            margin-right: auto; 
        }

        .advantages h2 {
            font-size: 16px;
            font-weight: 600;
            margin-bottom: 10px; 
            color: #000;
        }

        .advantages ul {
            list-style-type: none;
            padding: 0;
            margin: 0;
        }

        .advantages ul li {
            font-size: 14px;
            color: #333;
            margin-bottom: 8px; 
            padding-left: 20px;
            position: relative;
        }

        .advantages ul li::before {
            content: "✔";
            position: absolute;
            left: 0;
            color: #007bff;
        }

        /* 响应式设计 */
        @media (max-width: 480px) {
            body {
                padding-top: 5vh; 
            }

            .container {
                padding: 15px; 
            }

            h1 {
                font-size: 20px;
            }

            .input-group {
                flex-direction: column;
                gap: 10px;
            }

            input[type="text"] {
                width: 100%; 
                max-width: 300px; 
            }

            button {
                width: 100%; 
                max-width: 300px; 
            }

            .logo {
                width: 72%; 
            }

            .advantages {
                padding: 10px; 
                width: 100%; 
                max-width: none; 
            }

            .advantages h2 {
                font-size: 18px;
            }

            .advantages ul li {
                font-size: 14px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>操作简单，点对点高速直联，高效稳定</h1>
        <div class="input-group">
            <input type="text" id="inputText" placeholder="请输入内网通ID">
            <button onclick="redirect()">穿透内网</button>
        </div>
        <div class="tip"><a href="/register" target="_blank">注册</a>
        </div>

        <!-- 核心优势 -->
        <div class="advantages">
            <h2>产品核心优势</h2>
            <ul>
                <li><strong>永久免费：</strong>还有什么东西能比免费更好。</li>
                
                <li><strong>配置简单：</strong>设备要求低，配置简单。</li>
                <li><strong>无需工具：</strong>WEB应用直接浏览器访问，客户端无需工具。</li>
                <li><strong>高速直联：</strong>STUN内网穿透，免服务器中转点对点更高效。</li>
                <li><strong>固定地址：</strong>穿透地址永不过期，也不需要频繁验证。</li>
                <li><strong>跳转加密：</strong>可加入验证密码，提升部分应用安全性。</li>
                <li><strong>携带后缀：</strong>支持携带后缀跳转，无公网IP也能分享文件。</li>
            </ul>
        </div>
    </div>

    <script>
        // 跳转函数
        function redirect() {
            const inputText = document.getElementById('inputText').value.trim();
            if (inputText) {
                window.location.href = '/' + encodeURIComponent(inputText);
            } else {
                alert('请输入内网通ID');
            }
        }

        // 监听输入框的回车键事件
        document.getElementById('inputText').addEventListener('keydown', function (event) {
            if (event.key === 'Enter') { 
                redirect(); 
            }
        });
    </script>
</body>
</html>
    `
}

func getPasswordHtml(channel_id string) string {
	return fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>访问验证</title>
    <link rel="icon" type="image/png" href="/favicon.png">
    <style>
        body { font-family: Arial, sans-serif; max-width: 400px; margin: 40px auto; padding: 20px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; }
        input[type="password"] { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
        button { padding: 10px 20px; background: #007bff; color: white; border: none; cursor: pointer; border-radius: 4px; }
        button:hover { background: #0056b3; }
        .error { color: #dc3545; display: none; padding: 10px; background: #f8d7da; border-radius: 4px; margin-bottom: 15px; }
    </style>
</head>
<body>
    <h2>访问验证</h2>
    <div id="error" class="error"></div>
    <div class="form-group">
        <label>请输入访问密码</label>
        <input type="password" id="accessKey" placeholder="输入访问密码">
    </div>
    <button onclick="verify()">验证</button>

    <script>
    async function verify() {
        const accessKey = document.getElementById('accessKey').value.trim()
        if (!accessKey) {
            document.getElementById('error').style.display = 'block'
            document.getElementById('error').textContent = '请输入访问密码'
            return
        }

        try {
            const response = await fetch('/api/verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    channel_id: '%s',
                    accessKey: accessKey
                })
            })

            if (response.status === 200) {
                window.location.reload()
            } else {
                const error = await response.text()
                document.getElementById('error').style.display = 'block'
                document.getElementById('error').textContent = error
            }
        } catch (e) {
            document.getElementById('error').style.display = 'block'
            document.getElementById('error').textContent = '验证失败，请稍后重试'
        }
    }

    document.getElementById('accessKey').addEventListener('keydown', function(event) {
        if (event.key === 'Enter') {
            verify()
        }
    })
    </script>
</body>
</html>`, channel_id)
}

func getRegisterHtml() string {
	return `
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>内网跳转 - 注册</title>
    <link rel="icon" type="image/png" href="/favicon.png">
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; }
        input[type="text"], input[type="password"] { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
        button { padding: 10px 20px; background: #007bff; color: white; border: none; cursor: pointer; border-radius: 4px; }
        button:hover { background: #0056b3; }
        .error { color: #dc3545; display: none; padding: 10px; background: #f8d7da; border-radius: 4px; margin-bottom: 15px; }
        .cookie-warning { background: #fff3cd; color: #856404; padding: 10px; border-radius: 4px; margin-bottom: 15px; display: none; }
        .help { margin-top: 20px; padding: 15px; background: #f8f9fa; border-radius: 4px; }
        .help a { color: #007bff; text-decoration: none; }
        .help a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <h1>内网跳转注册</h1>
    <div class="help">
        <p>📖<a href="https://github.com/loecom/PortLink" target="_blank">使用说明</a></p>
    </div>
    <div id="cookie-warning" class="cookie-warning">请启用浏览器 Cookie 功能以确保正常使用</div>
    <div id="error" class="error"></div>
    <div class="form-group">
        <label>通道ID</label>
        <input type="text" id="channel_id" placeholder="输入通道ID">
    </div>
    <div class="form-group">
        <label>鉴权密码</label>
        <input type="password" id="password" placeholder="输入鉴权密码">
    </div>
    <div class="form-group">
        <label>HOST地址</label>
        <input type="text" id="host" value="127.0.0.1" placeholder="输入HOST地址">
    </div>
    <div class="form-group">
        <label>端口</label>
        <input type="text" id="port" value="5666" placeholder="输入端口">
    </div>
    <div class="form-group">
        <label>访问密码（可选）</label>
        <input type="password" id="accessKey" placeholder="设置访问密码，留空则无需密码">
    </div>
    <div class="form-group">
        <label>
            <input type="checkbox" id="https"> 启用HTTPS
        </label>
    </div>
    <button onclick="register()">注册</button>

    <script>
    function checkCookies() {
        try {
            document.cookie = "cookietest=1";
            var ret = document.cookie.indexOf("cookietest=") != -1;
            document.cookie = "cookietest=1; expires=Thu, 01-Jan-1970 00:00:01 GMT";
            if (!ret) {
                document.getElementById('cookie-warning').style.display = 'block';
            }
            return ret;
        } catch (e) {
            document.getElementById('cookie-warning').style.display = 'block';
            return false;
        }
    }

    window.onload = checkCookies;

    async function register() {
        if (!checkCookies()) {
            document.getElementById('error').style.display = 'block';
            document.getElementById('error').textContent = '请启用浏览器 Cookie 功能后重试';
            return;
        }

        const data = {
            channel_id: document.getElementById('channel_id').value.trim(),
            password: document.getElementById('password').value,
            host: document.getElementById('host').value.trim(),
            port: document.getElementById('port').value.trim(),
            https: document.getElementById('https').checked,
            accessKey: document.getElementById('accessKey').value.trim()
        };

        try {
            const response = await fetch('/api/create', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });

            if (response.status === 201) {
                alert('注册成功！');
                location.reload();
            } else {
                const error = await response.text();
                document.getElementById('error').style.display = 'block';
                document.getElementById('error').textContent = error;
            }
        } catch (e) {
            document.getElementById('error').style.display = 'block';
            document.getElementById('error').textContent = '注册失败，请稍后重试';
        }
    }
    </script>
</body>
</html>`
}
