package com.ruoyi.system.controller;

import java.util.List;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.ruoyi.common.core.domain.entity.SysUser;
import com.ruoyi.common.utils.SecurityUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.ruoyi.common.annotation.Log;
import com.ruoyi.common.core.controller.BaseController;
import com.ruoyi.common.core.domain.AjaxResult;
import com.ruoyi.common.enums.BusinessType;
import com.ruoyi.system.domain.TblRecommendComment;
import com.ruoyi.system.service.ITblRecommendCommnetService;
import com.ruoyi.common.utils.poi.ExcelUtil;
import com.ruoyi.common.core.page.TableDataInfo;
import com.ruoyi.system.mapper.SysWxUserMapper;
import com.ruoyi.framework.web.service.MyTokenService;
/**
 * 我要推荐中用户评论Controller
 * 
 * @author ruoyi
 * @date 2023-10-25
 */
@RestController
@RequestMapping("/system/recommnedcomment")
public class TblRecommendCommentController extends BaseController
{
    @Autowired
    private ITblRecommendCommnetService tblRecommendCommnetService;
    @Autowired
    private SysWxUserMapper wxUserMapper;
    @Autowired
    private MyTokenService myTokenService;

    /**
     * 查询【请填写功能名称】列表
     */
//    @PreAuthorize("@ss.hasPermi('system:commnet:list')")
    @GetMapping("/list")
    public TableDataInfo list(TblRecommendComment tblRecommendCommnet)
    {
        startPage();
        List<TblRecommendComment> list = tblRecommendCommnetService.selectTblRecommendCommnetList(tblRecommendCommnet);
        return getDataTable(list);
    }

    /**
     * 导出【请填写功能名称】列表
     */
//    @PreAuthorize("@ss.hasPermi('system:commnet:export')")
    @Log(title = "【请填写功能名称】", businessType = BusinessType.EXPORT)
    @PostMapping("/export")
    public void export(HttpServletResponse response, TblRecommendComment tblRecommendCommnet)
    {
        List<TblRecommendComment> list = tblRecommendCommnetService.selectTblRecommendCommnetList(tblRecommendCommnet);
        ExcelUtil<TblRecommendComment> util = new ExcelUtil<TblRecommendComment>(TblRecommendComment.class);
        util.exportExcel(response, list, "【请填写功能名称】数据");
    }

    /**
     * 获取【请填写功能名称】详细信息
     */
//    @PreAuthorize("@ss.hasPermi('system:commnet:query')")
    @GetMapping(value = "/{id}")
    public AjaxResult getInfo(@PathVariable("id") Long id)
    {
        return success(tblRecommendCommnetService.selectTblRecommendCommnetById(id));
    }

    /**
     * 新增【请填写功能名称】
     */
//    @PreAuthorize("@ss.hasPermi('system:commnet:add')")
    @Log(title = "【请填写功能名称】", businessType = BusinessType.INSERT)
    @PostMapping
    public AjaxResult add(@RequestBody TblRecommendComment tblRecommendCommnet, HttpServletRequest request)
    {
        Long userId = SecurityUtils.getUserId();//1
        if (userId == null) {
            String wxtoken = request.getHeader("Authorization");// 获取 Authorization 头中的 wxtoken
            String openid = myTokenService.parseWxToken(wxtoken);
            SysUser Wxuser = wxUserMapper.selectWxUserByOpenId(openid);
            userId= Wxuser.getUserId();
        }
        tblRecommendCommnet.setUserId(userId);
        return toAjax(tblRecommendCommnetService.insertTblRecommendCommnet(tblRecommendCommnet));
    }

    /**
     * 修改【请填写功能名称】
     */
//    @PreAuthorize("@ss.hasPermi('system:commnet:edit')")
    @Log(title = "【请填写功能名称】", businessType = BusinessType.UPDATE)
    @PutMapping
    public AjaxResult edit(@RequestBody TblRecommendComment tblRecommendCommnet)
    {
        return toAjax(tblRecommendCommnetService.updateTblRecommendCommnet(tblRecommendCommnet));
    }

    /**
     * 删除【请填写功能名称】
     */
//    @PreAuthorize("@ss.hasPermi('system:commnet:remove')")
    @Log(title = "【请填写功能名称】", businessType = BusinessType.DELETE)
	@DeleteMapping("/{ids}")
    public AjaxResult remove(@PathVariable Long[] ids)
    {
        return toAjax(tblRecommendCommnetService.deleteTblRecommendCommnetByIds(ids));
    }
}
