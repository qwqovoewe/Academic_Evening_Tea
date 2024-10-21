package com.ruoyi.web.controller.system;
import java.util.List;
import java.util.Set;
import com.alibaba.fastjson2.JSONObject;
import com.ruoyi.common.config.WxAppConfig;
import com.ruoyi.common.core.domain.model.LoginUser;
import com.ruoyi.common.utils.StringUtils;
import com.ruoyi.common.utils.uuid.IdUtils;
import com.ruoyi.framework.security.context.AuthenticationContextHolder;
import com.ruoyi.framework.web.service.TokenService;
import com.ruoyi.system.domain.App;
import com.ruoyi.system.mapper.SysWxUserMapper;
import com.ruoyi.system.service.ISysUserService;
import com.ruoyi.system.service.WxUserService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import com.ruoyi.common.constant.Constants;
import com.ruoyi.common.core.domain.AjaxResult;
import com.ruoyi.common.core.domain.entity.SysMenu;
import com.ruoyi.common.core.domain.entity.SysUser;
import com.ruoyi.common.core.domain.model.LoginBody;
import com.ruoyi.common.utils.SecurityUtils;
import com.ruoyi.framework.web.service.SysLoginService;
import com.ruoyi.framework.web.service.SysPermissionService;
import com.ruoyi.system.service.ISysMenuService;
import org.springframework.web.client.RestTemplate;

import javax.annotation.Resource;

import static com.ruoyi.common.constant.Constants.LOGIN_USER_KEY;
import static org.apache.http.params.HttpProtocolParams.setUserAgent;

/**
 * 登录验证
 * 
 * @author ruoyi
 */
@RestController
public class SysLoginController
{
    @Autowired
    private TokenService tokenService;
    @Autowired
    private SysLoginService loginService;
    @Autowired
    private SysWxUserMapper wxUserMapper;

    @Autowired
    private ISysMenuService menuService;

    @Autowired
    private SysPermissionService permissionService;
    @Autowired
    private WxAppConfig wxAppConfig;
    @Autowired
    private RestTemplate restTemplate;
    @Autowired
    private WxUserService wxUserService;
    @Autowired
    private App app;
    @Resource
    private AuthenticationManager authenticationManager;

    /**
     * 登录方法
     * 
     * @param loginBody 登录信息
     * @return 结果
     */
    @PostMapping("/login")
    public AjaxResult login(@RequestBody LoginBody loginBody)
    {
        AjaxResult ajax = AjaxResult.success();
        // 从 wxtoken 中解析 openId
        String openId = parseToken(loginBody.getWxtoken());
        // 生成令牌
        String token = loginService.login(loginBody.getUsername(), loginBody.getPassword(), loginBody.getCode(),
                loginBody.getUuid(),openId);
        ajax.put(Constants.TOKEN, token);
        return ajax;
    }

    /**
     * 处理微信登录请求。
     *
     * @param jscode 微信小程序的 jscode
     * @return 登录结果
     */
    @PostMapping("/wxLogin")
    public AjaxResult wxlogin(@RequestBody String jscode) {
        JSONObject qianduan = JSONObject.parseObject(jscode);
        String code = qianduan.getString("code");
        if(StringUtils.isBlank(code)){
            return AjaxResult.error("参数错误");
        }
        String url = "https://api.weixin.qq.com/sns/jscode2session?" +
                "appid=" + app.getAppid() +
                "&secret=" + app.getAppsecret() +
                "&js_code=" + code +
                "&grant_type=authorization_code";

        System.out.println(url);
        RestTemplate restTemplate = new RestTemplate();
        String response = restTemplate.getForObject(url, String.class);

        // 解析响应
        JSONObject jsonObject = JSONObject.parseObject(response);

        // 提取 openid、unionid 和 session_key
        String openid = jsonObject.getString("openid");
        String unionid = jsonObject.getString("unionid");

        String sessionKey = jsonObject.getString("session_key");

        // 检查是否成功
        if (StringUtils.isNotBlank(openid)) {
            // 判断是否绑定
            {
                if (!wxUserService.checkBind(openid)) {
                    String Token = loginService.wxLogin(openid, unionid);
                    return AjaxResult.success().put("wxToken", Token).put("bind", wxUserMapper.checkBind(openid));
                } else {
                    String Token = loginService.wxLogin(openid, unionid);

//                SysUser LoginUser=wxUserMapper.selectWxUserByOpenId(openid);
//                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken( "2023317120035", "明文密码");
//                    AuthenticationContextHolder.setContext(authenticationToken);
                    // 该方法会去调用UserDetailsServiceImpl.loadUserByUsername
//                    Authentication authentication = null;
//                    authentication = authenticationManager.authenticate(authenticationToken);
//                    LoginUser loginUser = (LoginUser) authentication.getPrincipal();
//                LoginUser loginUser =new LoginUser(LoginUser, null);
//                String realToken= tokenService.createToken(loginUser);

                    return AjaxResult.success().put("wxToken", Token).put("bind", wxUserMapper.checkBind(openid));
                }
            }
        } else {
            String errorMessage = jsonObject.getString("errmsg");
            return AjaxResult.error(errorMessage != null ? errorMessage : "登录失败");
        }

    }



    @PostMapping("/deleteBind")
    public AjaxResult clearBind(@RequestBody String wxToken) {
        String wxtoken = JSONObject.parseObject(wxToken).getString("wxToken");
        String openid = parseToken(wxtoken);
        if(wxUserMapper.checkBind(openid)){
            wxUserMapper.updateBind(openid);
            return AjaxResult.success("解绑成功");
        }
        else{
            return AjaxResult.error("未绑定");
        }
    }
    //从微信登录的Token里解析openId的方法
    public String parseToken(String token) {
        try {
            Claims claims = Jwts.parser()
                    .setSigningKey(LOGIN_USER_KEY) // 替换为你的密钥
                    .parseClaimsJws(token)
                    .getBody();
            String openId = (String) claims.get("openId"); // 从声明中获取 openId
            System.out.println(openId);
            return openId;
        } catch (JwtException | IllegalArgumentException e) {
            // 处理解析失败的情况
            throw new RuntimeException("Token 解析失败: " + e.getMessage(), e);
        }
    }
    /**
     * 获取用户信息
     * 
     * @return 用户信息
     */
    @GetMapping("getInfo")
    public AjaxResult getInfo()
    {
        SysUser user = SecurityUtils.getLoginUser().getUser();
        // 角色集合
        Set<String> roles = permissionService.getRolePermission(user);
        // 权限集合
        Set<String> permissions = permissionService.getMenuPermission(user);
        AjaxResult ajax = AjaxResult.success();
        ajax.put("user", user);
        ajax.put("roles", roles);
        ajax.put("permissions", permissions);
        return ajax;
    }

    /**
     * 获取路由信息
     * 
     * @return 路由信息
     */
    @GetMapping("getRouters")
    public AjaxResult getRouters()
    {
        Long userId = SecurityUtils.getUserId();
        List<SysMenu> menus = menuService.selectMenuTreeByUserId(userId);
        return AjaxResult.success(menuService.buildMenus(menus));
    }
}
