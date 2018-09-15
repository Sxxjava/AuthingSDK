using AuthingSDK.exceptions;
using AuthingSDK.helpers;
using AuthingSDK.model;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace AuthingSDK
{
    class AuthingInner
    {
        protected internal string clientId;
        protected internal string appSecret;
        protected internal string ownerToken;
        protected internal string userToken;
        private string oathUrl = "https://oauth.authing.cn/graphql";
        private string usersUrl = "https://users.authing.cn/graphql";
        private string publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC4xKeUgQ+Aoz7TLfAfs9+paePb" +
                    "5KIofVthEopwrXFkp8OCeocaTHt9ICjTT2QeJh6cZaDaArfZ873GPUn00eOIZ7Ae" +
                    "+TiA2BKHbCvloW3w5Lnqm70iSsUi5Fmu9/2+68GZRH9L7Mlh8cFksCicW2Y2W2uM" +
                    "GKl64GDcIq3au+aqJQIDAQAB";

        protected internal AuthingInner(string clientId, string appSecret)
        {
            this.clientId = clientId;
            this.appSecret = appSecret;
            GetAccessTokenByAppSecret();
        }
        protected internal AuthingInner()
        {

        }
        /// <summary>
        /// 获取访问Token
        /// </summary>
        /// <returns></returns>
        protected internal string GetAccessTokenByAppSecret()
        {
            if (ownerToken == null || ownerToken == "")
            {
                string query = " query getAccessTokenByAppSecret($id: String!, $secret: String!) { getAccessTokenByAppSecret(secret: $secret,clientId: $id) } ";
                Dictionary<string, object> variables = new Dictionary<string, object>();
                variables.Add("secret", this.appSecret);
                variables.Add("id", this.clientId);

                PostEntity postEntity = new PostEntity(query, variables);
                string result = HttpClientHelper.DoPost(usersUrl, postEntity, null);
                var jobj = JObject.Parse(result);
                if (jobj["data"] == null || jobj["data"]["getAccessTokenByAppSecret"] == null)
                {
                    throw new AuthingException("wrong clientId or secret");
                }
                this.ownerToken = jobj["data"]["getAccessTokenByAppSecret"].ToString();
            }
            return ownerToken;
        }
        /// <summary>
        /// 注册用户
        /// </summary>
        /// <param name="option"></param>
        /// <returns></returns>
        protected internal string Register(Option option)
        {
            option.CheckByKeys(new string[] { "registerInClient", "email", "password" });
            string query = "  mutation register(\n" +
                    "    $unionid: String,\n" +
                    "    $email: String, \n" +
                    "    $password: String, \n" +
                    "    $lastIP: String, \n" +
                    "    $forceLogin: Boolean,\n" +
                    "    $registerInClient: String!,\n" +
                    "    $oauth: String,\n" +
                    "    $username: String,\n" +
                    "    $nickname: String,\n" +
                    "    $registerMethod: String,\n" +
                    "    $photo: String\n" +
                    ") {\n" +
                    "    register(userInfo: {\n" +
                    "        unionid: $unionid,\n" +
                    "        email: $email,\n" +
                    "        password: $password,\n" +
                    "        lastIP: $lastIP,\n" +
                    "        forceLogin: $forceLogin,\n" +
                    "        registerInClient: $registerInClient,\n" +
                    "        oauth: $oauth,\n" +
                    "        registerMethod: $registerMethod,\n" +
                    "        photo: $photo,\n" +
                    "        username: $username,\n" +
                    "        nickname: $nickname\n" +
                    "    }) {\n" +
                    "        _id,\n" +
                    "        email,\n" +
                    "        emailVerified,\n" +
                    "        username,\n" +
                    "        nickname,\n" +
                    "        company,\n" +
                    "        photo,\n" +
                    "        browser,\n" +
                    "        password,\n" +
                    "        token,\n" +
                    "        group {\n" +
                    "            name\n" +
                    "        },\n" +
                    "        blocked\n" +
                    "    }\n" +
                    "}";
            string password = (string)option.GetBykey("password");
            try
            {
                password = RSAHelper.EncryptWithPublicKey(publicKey, Encoding.UTF8.GetBytes(password));
                option.UpdateValue("password", password);
            }
            catch (Exception ex)
            {
                throw new AuthingException("encrypt password fail", ex);
            }
            PostEntity postField = new PostEntity(query, option);
            string resJson = HttpClientHelper.DoPost(usersUrl, postField, null);
            return resJson;
        }
        /// <summary>
        /// 登录
        /// </summary>
        /// <param name="option"></param>
        /// <returns></returns>
        protected internal string Login(Option option)
        {
            option.CheckByKeys(new string[] { "registerInClient", "email", "password" });
            string query = "mutation login($unionid: String, $email: String, $password: String, $lastIP: String, $registerInClient: String!, $verifyCode: String) {\n" +
                "    login(unionid: $unionid, email: $email, password: $password, lastIP: $lastIP, registerInClient: $registerInClient, verifyCode: $verifyCode) {\n" +
                "        _id\n" +
                "        email\n" +
                "        emailVerified\n" +
                "        username\n" +
                "        nickname\n" +
                "        company\n" +
                "        photo\n" +
                "        browser\n" +
                "        token\n" +
                "        tokenExpiredAt\n" +
                "        loginsCount\n" +
                "        lastLogin\n" +
                "        lastIP\n" +
                "        signedUp\n" +
                "        blocked\n" +
                "        isDeleted\n" +
                "    }\n" +
                "}";
            string password = (string)option.GetBykey("password");
            try
            {
                password = RSAHelper.EncryptWithPublicKey(publicKey, Encoding.UTF8.GetBytes(password));
                option.UpdateValue("password", password);
            }
            catch (Exception ex)
            {
                throw new AuthingException("encrypt password fail", ex);
            }
            PostEntity postEntity = new PostEntity(query, option);
            string resJson = HttpClientHelper.DoPost(usersUrl, postEntity, null);
            var jobj = JObject.Parse(resJson);
            if (jobj["data"] != null && jobj["data"]["login"] != null)
            {
                userToken = jobj["data"]["login"]["token"].ToString();
            }
            return resJson;
        }
        /// <summary>
        /// 读取在Authing控制台中配置的OAuth信息
        /// </summary>
        /// <param name="option"></param>
        /// <returns></returns>
        protected internal string ReadOAuthList(Option option)
        {
            option.CheckByKey("clientId");
            string query = "  query ReadOAuthList($clientId: String!) {\n" +
                "        ReadOauthList(clientId: $clientId) {\n" +
                "            _id\n" +
                "            name\n" +
                "            image\n" +
                "            description\n" +
                "            enabled\n" +
                "            client\n" +
                "            user\n" +
                "            url\n" +
                "        }\n" +
                "    }";
            PostEntity postEntity = new PostEntity(query, option);
            string resJson = HttpClientHelper.DoPost(oathUrl, postEntity, null);
            return resJson;
        }
        /// <summary>
        /// 获取用户信息
        /// </summary>
        /// <param name="option"></param>
        /// <returns></returns>
        protected internal string User(Option option)
        {
            option.CheckByKeys(new string[] { "registerInClient", "id" });
            string query = "  query user($id: String!, $registerInClient: String!){\n" +
                "    user(id: $id, registerInClient: $registerInClient) {\n" +
                "        _id\n" +
                "        email\n" +
                "        emailVerified\n" +
                "        username\n" +
                "        nickname\n" +
                "        company\n" +
                "        photo\n" +
                "        browser\n" +
                "        registerInClient\n" +
                "        registerMethod\n" +
                "        oauth\n" +
                "        token\n" +
                "        tokenExpiredAt\n" +
                "        loginsCount\n" +
                "        lastLogin\n" +
                "        lastIP\n" +
                "        signedUp\n" +
                "        blocked\n" +
                "        isDeleted\n" +
                "    }\n" +
                "\n" +
                "}";
            PostEntity postEntity = new PostEntity(query, option);
            Dictionary<HttpRequestHeader, string> headers = new Dictionary<HttpRequestHeader, string>();
            headers.Add(HttpRequestHeader.Authorization, "Bearer " + ownerToken); //"Authorization"
            string resJson = HttpClientHelper.DoPost(usersUrl, postEntity, headers);
            return resJson;
        }
        /// <summary>
        /// 获取用户列表
        /// </summary>
        /// <param name="option"></param>
        /// <returns></returns>
        protected internal string Users(Option option)
        {
            option.CheckByKeys(new string[] { "registerInClient", "page", "count" });
            string query = "query users($registerInClient: String, $page: Int, $count: Int){\n" +
                "  users(registerInClient: $registerInClient, page: $page, count: $count) {\n" +
                "    totalCount\n" +
                "    list {\n" +
                "      _id\n" +
                "      email\n" +
                "      emailVerified\n" +
                "      username\n" +
                "      nickname\n" +
                "      company\n" +
                "      photo\n" +
                "      browser\n" +
                "      password\n" +
                "      registerInClient\n" +
                "      token\n" +
                "      tokenExpiredAt\n" +
                "      loginsCount\n" +
                "      lastLogin\n" +
                "      lastIP\n" +
                "      signedUp\n" +
                "      blocked\n" +
                "      isDeleted\n" +
                "      group {\n" +
                "        _id\n" +
                "        name\n" +
                "        descriptions\n" +
                "        createdAt\n" +
                "      }\n" +
                "      clientType {\n" +
                "        _id\n" +
                "        name\n" +
                "        description\n" +
                "        image\n" +
                "        example\n" +
                "      }\n" +
                "      userLocation {\n" +
                "        _id\n" +
                "        when\n" +
                "        where\n" +
                "      }\n" +
                "      userLoginHistory {\n" +
                "        totalCount\n" +
                "        list{\n" +
                "          _id\n" +
                "          when\n" +
                "          success\n" +
                "          ip\n" +
                "          result\n" +
                "        }\n" +
                "      }\n" +
                "      systemApplicationType {\n" +
                "        _id\n" +
                "        name\n" +
                "        descriptions\n" +
                "        price\n" +
                "      }\n" +
                "    }\n" +
                "  }\n" +
                "}";
            PostEntity postEntity = new PostEntity(query, option);
            Dictionary<HttpRequestHeader, string> headers = new Dictionary<HttpRequestHeader, string>();
            headers.Add(HttpRequestHeader.Authorization, "Bearer " + ownerToken); //"Authorization"
            string resJson = HttpClientHelper.DoPost(usersUrl, postEntity, headers);
            return resJson;
        }
        /// <summary>
        /// 检查登录状态
        /// </summary>
        /// <returns></returns>
        protected internal string CheckLoginStatus()
        {
            if (userToken == "" || userToken == null)
            {
                throw new AuthingException("can not find ownerToken,please login again");
            }
            string query = "query checkLoginStatus {\n" +
                    "    checkLoginStatus {\n" +
                    "        status\n" +
                    "        code\n" +
                    "        message\n" +
                    "    }\n" +
                    "}";
            PostEntity postEntity = new PostEntity(query, new Option());
            Dictionary<HttpRequestHeader, string> headers = new Dictionary<HttpRequestHeader, string>();
            headers.Add(HttpRequestHeader.Authorization, "Bearer " + userToken); //"Authorization"
            string resJson = HttpClientHelper.DoPost(usersUrl, postEntity, headers);
            return resJson;
        }
        /// <summary>
        /// 批量删除用户
        /// </summary>
        /// <param name="option"></param>
        /// <returns></returns>
        protected internal string RemoveUsers(Option option)
        {
            if (ownerToken == "" || ownerToken == null)
            {
                throw new AuthingException("can not find ownerToken,please login again");
            }
            option.CheckByKeys(new string[] { "ids", "registerInClient" });
            string query = "mutation removeUsers($ids: [String], $registerInClient: String, $operator: String){\n" +
                "  removeUsers(ids: $ids, registerInClient: $registerInClient, operator: $operator) {\n" +
                "    _id\n" +
                "  }\n" +
                "}";
            PostEntity postEntity = new PostEntity(query, option);
            Dictionary<HttpRequestHeader, string> headers = new Dictionary<HttpRequestHeader, string>();
            headers.Add(HttpRequestHeader.Authorization, "Bearer " + ownerToken); //"Authorization"
            string resJson = HttpClientHelper.DoPost(usersUrl, postEntity, headers);
            return resJson;
        }

        /// <summary>
        /// 更新用户信息
        /// </summary>
        /// <param name="option"></param>
        /// <returns></returns>
        protected internal string UpdateUser(Option option)
        {
            if (ownerToken == "" || ownerToken == null)
            {
                throw new AuthingException("can not find ownerToken,please login again");
            }
            option.CheckByKeys(new string[] { "_id", "registerInClient" });
            string query = "mutation UpdateUser(\n" +
                    "    _id: String!,\n" +
                    "   email: String,\n" +
                    "   emailVerified: Boolean,\n" +
                    "   username: String,\n" +
                    "   nickname: String,\n" +
                    "   company: String,\n" +
                    "   photo: String,\n" +
                    "   browser: String,\n" +
                    "   password: String,\n" +
                    "   oldPassword: String,\n" +
                    "   registerInClient: String!,\n" +
                    "   token: String,\n" +
                    "   tokenExpiredAt: String,\n" +
                    "   loginsCount: Int,\n" +
                    "   lastLogin: String,\n" +
                    "   lastIP: String,\n" +
                    "   signedUp: String,\n" +
                    "   blocked: Boolean,\n" +
                    "   isDeleted: Boolean\n" +
                    "   ){\n" +
                    "    updateUser(options: {\n" +
                    "     _id: $_id,\n" +
                    "    email: $email,\n" +
                    "    emailVerified: $emailVerified,\n" +
                    "    username: $username,\n" +
                    "    nickname: $nickname,\n" +
                    "    company: $company,\n" +
                    "    photo: $photo,\n" +
                    "    browser: $browser,\n" +
                    "    password: $password,\n" +
                    "    oldPassword: $oldPassword,\n" +
                    "    registerInClient: $registerInClient,\n" +
                    "    token: $token,\n" +
                    "    tokenExpiredAt: $tokenExpiredAt,\n" +
                    "    loginsCount: $loginsCount,\n" +
                    "    lastLogin: $lastLogin,\n" +
                    "    lastIP: $lastIP,\n" +
                    "    signedUp: $signedUp,\n" +
                    "    blocked: $blocked,\n" +
                    "    isDeleted: $isDeleted\n" +
                    "    }) {\n" +
                    "    _id\n" +
                    "    email\n" +
                    "    emailVerified\n" +
                    "    username\n" +
                    "    nickname\n" +
                    "    company\n" +
                    "    photo\n" +
                    "    browser\n" +
                    "    registerInClient\n" +
                    "    registerMethod\n" +
                    "    oauth\n" +
                    "    token\n" +
                    "    tokenExpiredAt\n" +
                    "    loginsCount\n" +
                    "    lastLogin\n" +
                    "    lastIP\n" +
                    "    signedUp\n" +
                    "    blocked\n" +
                    "    isDeleted\n" +
                    "    }\n" +
                    "}";
            PostEntity postEntity = new PostEntity(query, option);
            Dictionary<HttpRequestHeader, string> headers = new Dictionary<HttpRequestHeader, string>();
            headers.Add(HttpRequestHeader.Authorization, "Bearer " + ownerToken); //"Authorization"
            string resJson = HttpClientHelper.DoPost(usersUrl, postEntity, headers);
            return resJson;
        }
        /// <summary>
        /// 发送验证邮件
        /// </summary>
        /// <param name="option"></param>
        /// <returns></returns>
        protected internal string SendVerifyEmail(Option option)
        {
            if (ownerToken == "" || ownerToken == null)
            {
                throw new AuthingException("can not find ownerToken,please login again");
            }
            option.CheckByKeys(new string[] { "email", "client" });
            string query = "mutation sendVerifyEmail(\n" +
                    "    $email: String!,\n" +
                    "    $client: String!\n" +
                    "){\n" +
                    "    sendVerifyEmail(\n" +
                    "        email: $email,\n" +
                    "        client: $client\n" +
                    "    ) {\n" +
                    "        message,\n" +
                    "        code,\n" +
                    "        status\n" +
                    "    }\n" +
                    "}";
            PostEntity postEntity = new PostEntity(query, option);
            Dictionary<HttpRequestHeader, string> headers = new Dictionary<HttpRequestHeader, string>();
            headers.Add(HttpRequestHeader.Authorization, "Bearer " + ownerToken); //"Authorization"
            string resJson = HttpClientHelper.DoPost(usersUrl, postEntity, headers);
            return resJson;
        }
        /// <summary>
        /// 发送修改密码邮件
        /// </summary>
        /// <param name="option"></param>
        /// <returns></returns>
        protected internal string SendResetPasswordEmail(Option option)
        {
            if (ownerToken == "" || ownerToken == null)
            {
                throw new AuthingException("can not find ownerToken,please login again");
            }
            option.CheckByKeys(new string[] { "email", "client" });
            string query = "mutation sendResetPasswordEmail(\n" +
                "    $email: String!,\n" +
                "    $client: String!\n" +
                "){\n" +
                "    sendResetPasswordEmail(\n" +
                "        email: $email,\n" +
                "        client: $client\n" +
                "    ) {\n" +
                "          message\n" +
                "          code\n" +
                "    }\n" +
                "}";
            PostEntity postEntity = new PostEntity(query, option);
            Dictionary<HttpRequestHeader, string> headers = new Dictionary<HttpRequestHeader, string>();
            headers.Add(HttpRequestHeader.Authorization, "Bearer " + ownerToken); //"Authorization"
            string resJson = HttpClientHelper.DoPost(usersUrl, postEntity, headers);
            return resJson;
        }

        /// <summary>
        /// 验证修改密码验证码
        /// </summary>
        /// <param name="option"></param>
        /// <returns></returns>
        protected internal string VerifyResetPasswordVerifyCode(Option option)
        {
            if (ownerToken == "" || ownerToken == null)
            {
                throw new AuthingException("can not find ownerToken,please login again");
            }
            option.CheckByKeys(new string[] { "email", "client", "verifyCode" });
            string query = "mutation verifyResetPasswordVerifyCode(\n" +
                "    $email: String!,\n" +
                "    $client: String!,\n" +
                "    $verifyCode: String!\n" +
                ") {\n" +
                "    verifyResetPasswordVerifyCode(\n" +
                "        email: $email,\n" +
                "        client: $client,\n" +
                "        verifyCode: $verifyCode\n" +
                "    ) {\n" +
                "          message\n" +
                "          code\n" +
                "    }\n" +
                "}";
            PostEntity postEntity = new PostEntity(query, option);
            Dictionary<HttpRequestHeader, string> headers = new Dictionary<HttpRequestHeader, string>();
            headers.Add(HttpRequestHeader.Authorization, "Bearer " + ownerToken); //"Authorization"
            string resJson = HttpClientHelper.DoPost(usersUrl, postEntity, headers);
            return resJson;
        }
        /// <summary>
        /// 修改密码
        /// </summary>
        /// <param name="option"></param>
        /// <returns></returns>
        protected internal string ChangePassword(Option option)
        {
            if (ownerToken == "" || ownerToken == null)
            {
                throw new AuthingException("can not find ownerToken,please login again");
            }
            option.CheckByKeys(new string[] { "email", "client", "verifyCode", "password" });
            string query = "mutation changePassword(\n" +
                "    $email: String!,\n" +
                "    $client: String!,\n" +
                "    $password: String!,\n" +
                "    $verifyCode: String!\n" +
                "){\n" +
                "    changePassword(\n" +
                "        email: $email,\n" +
                "        client: $client,\n" +
                "        password: $password,\n" +
                "        verifyCode: $verifyCode\n" +
                "    ) {\n" +
                "        _id\n" +
                "        email\n" +
                "        emailVerified\n" +
                "        username\n" +
                "        nickname\n" +
                "        company\n" +
                "        photo\n" +
                "        browser\n" +
                "        registerInClient\n" +
                "        registerMethod\n" +
                "        oauth\n" +
                "        token\n" +
                "        tokenExpiredAt\n" +
                "        loginsCount\n" +
                "        lastLogin\n" +
                "        lastIP\n" +
                "        signedUp\n" +
                "        blocked\n" +
                "        isDeleted\n" +
                "    }\n" +
                "}";
            string password = (string)option.GetBykey("password");

            try
            {
                password = RSAHelper.EncryptWithPublicKey(publicKey, Encoding.UTF8.GetBytes(password));
                option.UpdateValue("password", password);
            }
            catch (Exception ex)
            {
                throw new AuthingException("encrypt password fail", ex);
            }
            PostEntity postEntity = new PostEntity(query, option);
            Dictionary<HttpRequestHeader, string> headers = new Dictionary<HttpRequestHeader, string>();
            headers.Add(HttpRequestHeader.Authorization, "Bearer " + ownerToken); //"Authorization"
            string resJson = HttpClientHelper.DoPost(usersUrl, postEntity, headers);
            return resJson;
        }
    }

    public class Authing
    {
        private AuthingInner inner;
        public Authing(string clientId, string appSecret)
        {
            if (clientId == null || clientId == "")
            {
                throw new AuthingException("clientId can not be empty!");
            }
            if (appSecret == null || appSecret == "")
            {
                throw new AuthingException("app secret can not be empty!");
            }
            inner = new AuthingInner(clientId, appSecret);
        }
        /// <summary>
        /// 获取访问Token
        /// </summary>
        /// <returns></returns>
        public string GetAccessToken()
        {
            return inner.GetAccessTokenByAppSecret();
        }
        /// <summary>
        /// 获取在Authing控制台中配置的OAuth信息
        /// </summary>
        /// <returns></returns>
        public string ReadOAuthList()
        {
            Option option = new Option();
            option.AddOption("clientId", inner.clientId);
            return inner.ReadOAuthList(option);
        }
        /// <summary>
        /// 登录
        /// </summary>
        /// <param name="email">邮箱</param>
        /// <param name="password">密码</param>
        /// <returns></returns>
        public string Login(string email, string password)
        {
            if (email == null || email == "")
            {
                throw new AuthingException("email can not be empty!");
            }
            if (password == null || password == "")
            {
                throw new AuthingException("password can not be empty!");
            }
            Option option = new Option(inner.clientId);
            option.AddOption("email", email);
            option.AddOption("password", password);
            return inner.Login(option);
        }
        /// <summary>
        /// 注册
        /// </summary>
        /// <param name="email">邮箱</param>
        /// <param name="password">密码</param>
        /// <returns></returns>
        public string Register(string email, string password)
        {
            if (email == null || email == "")
            {
                throw new AuthingException("email can not be empty!");
            }
            if (password == null || password == "")
            {
                throw new AuthingException("password can not be empty!");
            }
            Option option = new Option(inner.clientId);
            option.AddOption("email", email);
            option.AddOption("password", password);
            return inner.Register(option);
        }
        /// <summary>
        /// 获取用户列表
        /// </summary>
        /// <param name="pageIndex">页索引</param>
        /// <param name="pageSize">每页数量</param>
        /// <returns></returns>
        public string GetUserList(int pageIndex, int pageSize)
        {
            if (pageIndex < 1)
            {
                throw new AuthingException("pageIndex can not less than 1 !");
            }
            if (pageSize < 1)
            {
                throw new AuthingException("pageIndex can not less than 1 !");
            }
            Option option = new Option(inner.clientId);
            option.AddOption("page", pageIndex);
            option.AddOption("count", pageSize);
            return inner.Users(option);
        }
        /// <summary>
        /// 获取用户信息
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        public string GetUserInfo(string id)
        {
            if (id == null || id == "")
            {
                throw new AuthingException("user id can not be empty!");
            }
            Option option = new Option(inner.clientId);
            option.AddOption("id", id);
            return inner.User(option);
        }
        /// <summary>
        /// 检查用户登录状态
        /// </summary>
        /// <returns></returns>
        public string CheckLoginStatus()
        {
            return inner.CheckLoginStatus();
        }

        /// <summary>
        /// 删除用户
        /// </summary>
        /// <param name="id">用户ID</param>
        /// <returns></returns>
        public string RemoveUser(string id)
        {
            if (id == null || id == "")
            {
                throw new AuthingException("user id can not be empty!");
            }
            Option option = new Option(inner.clientId);
            option.AddOption("ids", new string[] { id });
            return inner.RemoveUsers(option);
        }

        /// <summary>
        /// 批量删除用户
        /// </summary>
        /// <param name="id">用户ID</param>
        /// <returns></returns>
        public string RemoveUsers(string[] ids)
        {
            if (ids == null || ids.Length < 1)
            {
                throw new AuthingException("user id array can not be empty!");
            }
            Option option = new Option(inner.clientId);
            option.AddOption("ids", ids);
            return inner.RemoveUsers(option);
        }
        /// <summary>
        /// 更新用户信息
        /// </summary>
        /// <param name="id">用户ID(必填)</param>
        /// <param name="email">用户邮箱(选填)</param>
        /// <param name="username">用户名(选填)</param>
        /// <param name="nickname">用户昵称(选填)</param>
        /// <param name="company">公司(选填)</param>
        /// <param name="photo">头像(选填)</param>
        /// <returns></returns>
        public string UpdateUserInfo(string id, string email, string username, string nickname, string company, string photo)
        {
            if (id == null || id == "")
            {
                throw new AuthingException("user id can not be empty!");
            }

            Option option = new Option(inner.clientId);
            option.AddOption("_id", id);

            if (email != null && email != "")
            {
                option.AddOption("email", email);
            }
            if (username != null && username != "")
            {
                option.AddOption("username", username);
            }
            if (nickname != null && nickname != "")
            {
                option.AddOption("nickname", nickname);
            }
            if (company != null && company != "")
            {
                option.AddOption("company", company);
            }
            if (photo != null && photo != "")
            {
                option.AddOption("photo", photo);
            }
            return inner.UpdateUser(option);
        }
        /// <summary>
        /// 发送验证邮件
        /// </summary>
        /// <param name="email"></param>
        /// <returns></returns>
        public string SendVerifyEmail(string email)
        {
            if (email == null || email == "")
            {
                throw new AuthingException("email can not be empty!");
            }

            Option option = new Option();
            option.AddOption("client", inner.clientId);
            option.AddOption("email", email);

            return inner.SendVerifyEmail(option);
        }

        /// <summary>
        /// 发送修改密码验证邮件
        /// </summary>
        /// <param name="email"></param>
        /// <returns></returns>
        public string SendResetPasswordEmail(string email)
        {
            if (email == null || email == "")
            {
                throw new AuthingException("email can not be empty!");
            }

            Option option = new Option();
            option.AddOption("client", inner.clientId);
            option.AddOption("email", email);

            return inner.SendResetPasswordEmail(option);
        }

        /// <summary>
        /// 验证修改密码验证码
        /// </summary>
        /// <param name="email"></param>
        /// <param name="verifyCode"></param>
        /// <returns></returns>
        public string VerifyResetPasswordVerifyCode(string email, string verifyCode)
        {
            if (email == null || email == "")
            {
                throw new AuthingException("email can not be empty!");
            }
            if (verifyCode == null || verifyCode == "")
            {
                throw new AuthingException("verify code can not be empty!");
            }
            Option option = new Option();
            option.AddOption("client", inner.clientId);
            option.AddOption("email", email);
            option.AddOption("verifyCode", verifyCode);

            return inner.VerifyResetPasswordVerifyCode(option);
        }
        /// <summary>
        /// 修改密码
        /// </summary>
        /// <param name="option"></param>
        /// <returns></returns>
        public string ChangePassword(string email, string verifyCode, string password)
        {
            if (email == "" || email == null)
            {
                throw new AuthingException("email can not be empty!");
            }
            if (verifyCode == "" || verifyCode == null)
            {
                throw new AuthingException("verify code can not be empty!");
            }
            if (password == null || password == "")
            {
                throw new AuthingException("password can not be empty!");
            }
            Option option = new Option();
            option.AddOption("client", inner.clientId);
            option.AddOption("email", email);
            option.AddOption("verifyCode", verifyCode);
            option.AddOption("password", password);

            return inner.ChangePassword(option);
        }
    }
}
