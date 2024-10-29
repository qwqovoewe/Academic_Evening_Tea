package com.ruoyi.web.controller.system;
import java.util.List;
import java.util.Set;
import com.alibaba.fastjson2.JSONObject;
import com.ruoyi.common.utils.StringUtils;
import com.ruoyi.framework.web.service.MyTokenService;
import com.ruoyi.system.domain.App;
import com.ruoyi.system.mapper.SysWxUserMapper;
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
    private SysWxUserMapper wxUserMapper;

    @Autowired
    private ISysMenuService menuService;
    @Autowired
    private MyTokenService tokenService;
    @Autowired
    private SysPermissionService permissionService;
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
        String openId = null;
        // 检查 wxtoken 是否为空或 null
        if (loginBody.getWxtoken() != null && !loginBody.getWxtoken().isEmpty()) {
            try {
                //解析wxtoken获取openid
                openId = tokenService.parseWxToken(loginBody.getWxtoken()).toString();
            } catch (Exception e) {
                // 处理解析失败的情况
                return AjaxResult.error("WxToken 解析失败: " + e.getMessage());
            }
        }
        // 生成令牌
        String token = loginService.login(loginBody.getUsername(), loginBody.getPassword(), loginBody.getCode(),
                loginBody.getUuid(),openId);
        ajax.put(Constants.TOKEN, token);
        return ajax;
    }

    /**
     * 处理微信登录请求。
     * @param jscode 微信小程序的 jscode
     * @return 登录结果
     */
    @PostMapping("/wxLogin")
    public AjaxResult wxlogin(@RequestBody String jscode) {
        try{
            // 解析code
            JSONObject qianduan = JSONObject.parseObject(jscode);
            String code = qianduan.getString("code");
            // 检查 code 是否为空
            if (StringUtils.isBlank(code)) {
                return AjaxResult.error("参数错误");
            }
            // 构建微信 API 请求 URL
            String url = "https://api.weixin.qq.com/sns/jscode2session?" +
                    "appid=" + app.getAppid() +
                    "&secret=" + app.getAppsecret() +
                    "&js_code=" + code +
                    "&grant_type=authorization_code";
            // 发送请求并获取响应
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
                //如果bind=0，前端再访问登录接口，实现绑定
                // 调用登录服务进行微信登录
                String Token = loginService.wxLogin(openid, unionid);
                // 查询用户绑定信息
                boolean isBound = wxUserMapper.checkBind(openid);
                return AjaxResult.success().put("wxToken", Token).put("bind", isBound);
            } else {
                // 返回错误信息
                String errorMessage = jsonObject.getString("errmsg");
                return AjaxResult.error(errorMessage != null ? errorMessage : "微信登录失败");
            }
        }catch (Exception e){
            // 异常处理
            return AjaxResult.error("系统异常"+e.getMessage());
        }
    }

    /**
     * 实现解绑
     * @param wxToken
     */
    @PostMapping("/deleteBind")
    public AjaxResult clearBind(@RequestBody String wxToken) {
        String wxtoken = JSONObject.parseObject(wxToken).getString("wxToken");
        String openid = tokenService.parseWxToken(wxtoken);
        if(wxUserMapper.checkBind(openid)){
            wxUserMapper.updateBind(openid);
            return AjaxResult.success("解绑成功");
        }
        else{
            return AjaxResult.error("未绑定");
        }
    }
    //从微信登录的Token里解析openId的方法


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
