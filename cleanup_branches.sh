#!/bin/bash

# 分支清理脚本 (Branch Cleanup Script)
# ⚠️ 警告：所有PR都是OPEN状态！请先审查和关闭PR再运行此脚本
# ⚠️ WARNING: All PRs are OPEN! Review and close PRs before running this script

set -e

echo "================================================"
echo "  分支清理脚本 / Branch Cleanup Script"
echo "================================================"
echo ""
echo "⚠️  重要警告 / IMPORTANT WARNING:"
echo "   所有8个PR都处于OPEN状态！"
echo "   All 8 PRs are in OPEN status!"
echo ""
echo "   建议流程 / Recommended process:"
echo "   1. 审查PR / Review PRs"
echo "   2. 合并或关闭PR / Merge or close PRs"  
echo "   3. 运行此脚本删除分支 / Run this script to delete branches"
echo ""
echo "================================================"
echo ""

# 可以安全删除的分支（无活跃PR）
SAFE_TO_DELETE=(
    "codex/optimize-login-screen-and-mobile-layout-xs92z6"
)

# 只有在对应PR关闭后才能删除的分支
REQUIRE_PR_CLOSED=(
    "codex/optimize-login-screen-and-mobile-layout"  # PR #4
    "codex/optimize-login-screen-and-mobile-layout-ym1ljr"  # PR #5
    "copilot/fix-login-redirection-issue"  # PR #6
    "copilot/cleanup-obsolete-files"  # PR #7
    "copilot/cleanup-obsolete-files-again"  # PR #8
    "copilot/fix-login-issue-in-app"  # PR #9
)

echo "可以安全删除（无活跃PR）/ Safe to delete (no active PR):"
for branch in "${SAFE_TO_DELETE[@]}"; do
    echo "  ✓ $branch"
done

echo ""
echo "需要先关闭PR才能删除 / Require PR closure before deletion:"
for branch in "${REQUIRE_PR_CLOSED[@]}"; do
    echo "  ⚠ $branch"
done

echo ""
echo "================================================"
read -p "删除无PR的分支？/ Delete branches with no PR? [y/N]: " confirm_safe

if [[ "$confirm_safe" == "y" || "$confirm_safe" == "Y" ]]; then
    for branch in "${SAFE_TO_DELETE[@]}"; do
        echo "删除 / Deleting: $branch"
        if git push origin --delete "$branch" 2>&1; then
            echo "  ✅ 成功 / Success"
        else
            echo "  ❌ 失败 / Failed"
        fi
        echo ""
    done
fi

echo ""
echo "================================================"
echo "⚠️  警告 / WARNING:"
echo "   以下分支有活跃的PR，请先在GitHub上关闭PR！"
echo "   The following branches have active PRs - close PRs on GitHub first!"
echo ""
echo "   PR #4: codex/optimize-login-screen-and-mobile-layout"
echo "   PR #5: codex/optimize-login-screen-and-mobile-layout-ym1ljr"
echo "   PR #6: copilot/fix-login-redirection-issue"
echo "   PR #7: copilot/cleanup-obsolete-files"
echo "   PR #8: copilot/cleanup-obsolete-files-again"
echo "   PR #9: copilot/fix-login-issue-in-app"
echo ""
read -p "已关闭所有PR？确认删除这些分支？/ PRs closed? Delete these branches? [y/N]: " confirm_danger

if [[ "$confirm_danger" == "y" || "$confirm_danger" == "Y" ]]; then
    echo ""
    echo "⚠️  最后确认 / FINAL CONFIRMATION:"
    echo "   这将删除6个分支！确定所有对应的PR都已关闭或合并？"
    echo "   This will delete 6 branches! Confirm all associated PRs are closed/merged?"
    read -p "输入 'DELETE' 确认 / Type 'DELETE' to confirm: " final_confirm
    
    if [[ "$final_confirm" == "DELETE" ]]; then
        for branch in "${REQUIRE_PR_CLOSED[@]}"; do
            echo "删除 / Deleting: $branch"
            if git push origin --delete "$branch" 2>&1; then
                echo "  ✅ 成功 / Success"
            else
                echo "  ❌ 失败 / Failed"
            fi
            echo ""
        done
    else
        echo "操作已取消 / Operation cancelled"
    fi
else
    echo "跳过删除有PR的分支 / Skipping branches with PRs"
fi

echo ""
echo "================================================"
echo "完成 / Completed!"
echo ""
echo "剩余分支 / Remaining branches:"
git branch -r | grep -v "HEAD" || echo "  (无远程分支 / No remote branches)"
echo ""
echo "建议下一步 / Next steps:"
echo "1. 检查 GitHub PR 状态 / Check GitHub PR status"
echo "2. 合并有价值的PR / Merge valuable PRs"
echo "3. 关闭重复的PR / Close duplicate PRs"
echo "4. 完成此PR后删除当前分支 / Delete current branch after completing this PR"
echo "================================================"
