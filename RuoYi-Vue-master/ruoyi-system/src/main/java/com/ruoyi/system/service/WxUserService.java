package com.ruoyi.system.service;

import org.springframework.stereotype.Service;

@Service
public interface WxUserService {
    public boolean checkBind(String openid);
    public boolean checkExist(String openid);

}
