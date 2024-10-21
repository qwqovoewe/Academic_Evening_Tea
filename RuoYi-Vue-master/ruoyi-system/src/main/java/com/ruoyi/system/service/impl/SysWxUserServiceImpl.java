package com.ruoyi.system.service.impl;

import com.ruoyi.system.mapper.SysWxUserMapper;
import com.ruoyi.system.service.WxUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class SysWxUserServiceImpl implements WxUserService {
    @Autowired
    private SysWxUserMapper sysWxUserMapper;

    @Override
    public boolean checkBind(String openid) {
        if(sysWxUserMapper.checkBind(openid)!=null)
        {
            return sysWxUserMapper.checkBind(openid);
        }
        else return false;
    }

    @Override
    public boolean checkExist(String openid) {
        if(sysWxUserMapper.checkExist(openid)==0) {
            return false;
        }
        else
            return true;
    }


}
