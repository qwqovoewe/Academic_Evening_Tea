package com.ruoyi.system.mapper;

import com.ruoyi.common.core.domain.entity.SysUser;
import com.ruoyi.common.core.domain.model.LoginUser;
import org.apache.ibatis.annotations.Mapper;
import org.springframework.beans.factory.annotation.Autowired;


@Mapper
public interface SysWxUserMapper {

     int insertUser(SysUser user);

    SysUser selectWxUserByOpenId(String openId);

    void updateUser(SysUser wxUser);

    void bindOldUser(String username, String openId);

    Boolean checkBind(String openid);

    void updateBind(String openid);
}
