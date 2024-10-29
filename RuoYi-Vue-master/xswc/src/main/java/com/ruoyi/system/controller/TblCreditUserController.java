package com.ruoyi.system.controller;

import com.ruoyi.common.core.domain.entity.SysUser;
import com.ruoyi.common.core.page.TableDataInfo;
import com.ruoyi.common.utils.SecurityUtils;
import com.ruoyi.system.domain.TblCreditUser;
import com.ruoyi.system.service.ITblCreditUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.List;

import com.ruoyi.common.core.controller.BaseController;

import javax.servlet.http.HttpServletRequest;
import com.ruoyi.system.mapper.SysWxUserMapper;
import com.ruoyi.framework.web.service.MyTokenService;
@RestController
@RequestMapping("/system/credituser")
public class TblCreditUserController  extends BaseController{

@Autowired
private ITblCreditUserService tblCreditUserService;
    @Autowired
    private SysWxUserMapper wxUserMapper;
    @Autowired
    private MyTokenService myTokenService;
    @GetMapping("/list")
    public TableDataInfo list(HttpServletRequest request){
        startPage();
        Long userId = SecurityUtils.getUserId();//1
        if (userId == null) {
            String wxtoken = request.getHeader("Authorization");// 获取 Authorization 头中的 wxtoken
            String openid = myTokenService.parseWxToken(wxtoken);
            SysUser Wxuser = wxUserMapper.selectWxUserByOpenId(openid);
            userId= Wxuser.getUserId();
        }
        TblCreditUser tblCreditUser = new TblCreditUser();
        tblCreditUser.setUserId(userId);
        List<TblCreditUser> tblCreditUsers = tblCreditUserService.selectTblCreditUserList(tblCreditUser);
        return getDataTable(tblCreditUsers);
    }
}
