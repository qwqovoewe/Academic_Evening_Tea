package com.ruoyi.web.controller.system;
import java.util.List;
import java.util.Set;
import com.alibaba.fastjson2.JSONObject;
import com.ruoyi.common.config.WxAppConfig;
import com.ruoyi.common.utils.StringUtils;
import com.ruoyi.system.domain.App;
import org.springframework.beans.factory.annotation.Autowired;
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

/**
 * 登录验证
 * 
 * @author ruoyi
 */
@RestController
public class SysLoginController
{
    @Autowired
    private SysLoginService loginService;

    @Autowired
    private ISysMenuService menuService;

    @Autowired
    private SysPermissionService permissionService;
    @Autowired
    private WxAppConfig wxAppConfig;
    @Autowired
    private RestTemplate restTemplate;
    @Autowired
    private App app;

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
        // 生成令牌
        String token = loginService.login(loginBody.getUsername(), loginBody.getPassword(), loginBody.getCode(),
                loginBody.getUuid());
        ajax.put(Constants.TOKEN, token);
        return ajax;
    }
    /**
     * 微信小程序登录
     *
     * @return
     */
    @PostMapping("/wxLogin")
    public AjaxResult wxlogin(@RequestBody String jscode) {
        if(StringUtils.isBlank(jscode)){
            return AjaxResult.error("参数错误");
        }
        String url = "https://api.weixin.qq.com/sns/oauth2/access_token?" +
                "appid=" + app.getAppid() +
                "&secret=" + app.getAppsecret() +
                "&js_code=" + jscode +
                "&grant_type=authorization_code";
        RestTemplate restTemplate = new RestTemplate();
        String response = restTemplate.getForObject(url, String.class);

        // 解析响应
        JSONObject jsonObject = JSONObject.parseObject(response);

        // 提取 openid、unionid 和 access_token
        String openid = jsonObject.getString("openid");
        String unionid = jsonObject.getString("unionid");
        String accessToken = jsonObject.getString("access_token");
        String refreshToken = jsonObject.getString("refresh_token");
        // 检查是否成功
        if (StringUtils.isNotBlank(openid) && StringUtils.isNotBlank(accessToken)) {

            String Token = loginService.wxLogin(openid, unionid, accessToken);
//            return AjaxResult.success("登录成功", accessToken);
                // 返回包含token的结果

                return AjaxResult.success().put(Constants.TOKEN, Token);
        } else {
            String errorMessage = jsonObject.getString("errmsg");
            return AjaxResult.error(errorMessage != null ? errorMessage : "登录失败");
        }
    }
    //刷新accessibleToken方法
    //没用上，用的自己产的token
    private String refreshAccessTokenIfExpired(String refreshToken) {
        if (StringUtils.isBlank(refreshToken)) {
            return null;
        }
        String url = "https://api.weixin.qq.com/sns/oauth2/refresh_token?" +
                "appid=" + app.getAppid() +
                "&grant_type=refresh_token" +
                "&refresh_token=" + refreshToken;
        RestTemplate restTemplate = new RestTemplate();
        try {
            String response = restTemplate.getForObject(url, String.class);
            JSONObject jsonObject = JSONObject.parseObject(response);

            // 提取新的 access_token
            String newAccessToken = jsonObject.getString("access_token");

            if (StringUtils.isNotBlank(newAccessToken)) {
                return newAccessToken;
            } else {
                String errorMessage = jsonObject.getString("errmsg");
                return null;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return null;
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
