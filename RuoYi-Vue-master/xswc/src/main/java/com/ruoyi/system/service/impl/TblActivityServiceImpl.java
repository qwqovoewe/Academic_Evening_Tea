package com.ruoyi.system.service.impl;

import java.util.List;

import com.ruoyi.common.utils.SecurityUtils;
import com.ruoyi.system.annotation.update;
import com.ruoyi.system.annotation.updateActivity;
import com.ruoyi.system.constant.ActivityConstant;
import com.ruoyi.system.constant.ResultConstant;
import com.ruoyi.system.domain.DeptActivity;
import com.ruoyi.system.domain.DeptNum;
import com.ruoyi.system.domain.TblUserActivity;
import com.ruoyi.system.example.HttpPostRequestExample;
import com.ruoyi.system.mapper.DeptActivityMapper;
import com.ruoyi.system.mapper.TblUserActivityMapper;

import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.stereotype.Service;
import com.ruoyi.system.mapper.TblActivityMapper;
import com.ruoyi.system.domain.TblActivity;
import com.ruoyi.system.service.ITblActivityService;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.RequestBody;

/**
 * 商家发布文章Service业务层处理
 * 
 * @author ruoyi
 * @date 2023-10-25
 */
@Service
public class TblActivityServiceImpl implements ITblActivityService 
{
    @Autowired
    private TblActivityMapper tblActivityMapper;

    @Autowired
    private   TblUserActivityMapper tblUserActivityMapper;

    @Autowired
    private DeptActivityMapper deptActivityMapper;

    /**
     *  用户获取发布活动详细信息
     * 
     * @param id  用户发布活动主键
     * @return 商家发布文章
     */
    @Override
    @updateActivity
    public TblActivity selectTblActivityById(Long id)
    {
        TblActivity tblActivity = tblActivityMapper.selectTblActivityById(id);
        TblUserActivity tblUserActivity = new TblUserActivity();
        tblUserActivity.setActivityId(id);
        tblUserActivity.setUserId(SecurityUtils.getUserId());
        List<TblUserActivity> isApplication = tblUserActivityMapper.selectTblUserActivityList(tblUserActivity);
        tblActivity.setIsApplication(isApplication);
        DeptActivity deptActivity = new DeptActivity();
        deptActivity.setActivityId(tblActivity.getId());
        tblActivity.setDeptActivities(deptActivityMapper.selectDeptActivityList(deptActivity));
        return tblActivity;
    }

    /**
     * 用户查询活动集合
     *
     * @param tblActivity 用户查询活动
     * @param pageNum
     * @param pageSize
     * @return 用户查询活动集合
     */
    @updateActivity
    @Override
    public List<TblActivity> selectTblActivityList(@RequestBody TblActivity tblActivity)
    {

        System.out.println(tblActivity.getPageNum());
        System.out.println(tblActivity.getPageSize());
        List<TblActivity>list= tblActivityMapper.selectTblActivityList(tblActivity);

        for(TblActivity tblActivity1:list){
            DeptActivity deptActivity = new DeptActivity();
            deptActivity.setActivityId(tblActivity1.getId());
            tblActivity1.setDeptActivities(deptActivityMapper.selectDeptActivityList(deptActivity));

        }
        return list;
    }

    /**
     * 新增用户发布活动
     * 
     * @param tblActivity 用户发布活动
     * @return 结果
     */
    @Override
    @Transactional
    public int insertTblActivity(TblActivity tblActivity)
    {
        tblActivityMapper.insertTblActivity(tblActivity);
        DeptNum[] deptNums=tblActivity.getDeptNums();
        Long acticityId=tblActivity.getId();
        //有学院限制
        if (deptNums!=null){
            for(DeptNum deptNum:deptNums){
                DeptActivity deptActivity = new DeptActivity();
                deptActivity.setActivityId(acticityId);
                deptActivity.setDeptId(deptNum.getDeptId());
                deptActivity.setMaxNum(deptNum.getMaxNum());
                deptActivity.setResNum(deptNum.getMaxNum());
                deptActivityMapper.insertDeptActivity(deptActivity);
            }
        }
        return ResultConstant.SUCEESS;
    }

    /**
     * 修改商家发布文章
     * 
     * @param tblActivity 商家发布文章
     * @return 结果
     */
    @Override
    @update
    public int updateTblActivity(TblActivity tblActivity)
    {
        Long activityId = tblActivity.getId();
        if (tblActivity.getState().equals(ActivityConstant.PASS))
        {
            HttpPostRequestExample httpPostRequestExample = new HttpPostRequestExample();
            String accessToken = httpPostRequestExample.postSendAccessToken();
            String applicationFilePath = httpPostRequestExample.postApplication(accessToken,activityId);
            String signinFilePath = httpPostRequestExample.postSignIn(accessToken, activityId);
            tblActivity.setSigninFilePath(signinFilePath);
            tblActivity.setApplicationFilePath(applicationFilePath);
        }

        return tblActivityMapper.updateTblActivity(tblActivity);
    }

    /**
     * 批量删除商家发布文章
     * 
     * @param ids 需要删除的商家发布文章主键
     * @return 结果
     */
    @Override
    public int deleteTblActivityByIds(Long[] ids)
    {
        return tblActivityMapper.deleteTblActivityByIds(ids);
    }

    /**
     * 删除商家发布文章信息
     * 
     * @param id 商家发布文章主键
     * @return 结果
     */
    @Override
    public int deleteTblActivityById(Long id)
    {
        return tblActivityMapper.deleteTblActivityById(id);
    }
}
