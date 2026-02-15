#!/bin/bash

# 分支清理脚本 (Branch Cleanup Script)
# 此脚本用于删除已完成工作的旧分支
# This script is used to delete old branches that have completed their work

set -e

echo "================================================"
echo "  分支清理脚本 / Branch Cleanup Script"
echo "================================================"
echo ""

# 定义要删除的分支列表
BRANCHES_TO_DELETE=(
    "codex/optimize-login-screen-and-mobile-layout"
    "codex/optimize-login-screen-and-mobile-layout-xs92z6"
    "codex/optimize-login-screen-and-mobile-layout-ym1ljr"
    "copilot/cleanup-obsolete-files"
    "copilot/cleanup-obsolete-files-again"
    "copilot/fix-login-redirection-issue"
)

# 可选删除（需要先检查PR状态）
OPTIONAL_BRANCHES=(
    "copilot/fix-login-issue-in-app"
)

echo "将要删除以下分支 (The following branches will be deleted):"
echo ""
for branch in "${BRANCHES_TO_DELETE[@]}"; do
    echo "  - $branch"
done

echo ""
echo "可选删除（如PR已合并）(Optional - delete if PR is merged):"
for branch in "${OPTIONAL_BRANCHES[@]}"; do
    echo "  - $branch"
done

echo ""
echo "================================================"
read -p "是否继续？(Continue?) [y/N]: " confirm

if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo "操作已取消 (Operation cancelled)"
    exit 0
fi

echo ""
echo "开始删除分支... (Starting branch deletion...)"
echo ""

# 删除远程分支
for branch in "${BRANCHES_TO_DELETE[@]}"; do
    echo "删除分支 (Deleting): $branch"
    if git push origin --delete "$branch" 2>&1; then
        echo "  ✅ 成功删除 (Successfully deleted)"
    else
        echo "  ❌ 删除失败 (Failed to delete)"
    fi
    echo ""
done

echo "================================================"
echo "基本清理完成！(Basic cleanup completed!)"
echo ""
read -p "是否删除可选分支？(Delete optional branches?) [y/N]: " confirm_optional

if [[ "$confirm_optional" == "y" || "$confirm_optional" == "Y" ]]; then
    for branch in "${OPTIONAL_BRANCHES[@]}"; do
        echo "删除分支 (Deleting): $branch"
        if git push origin --delete "$branch" 2>&1; then
            echo "  ✅ 成功删除 (Successfully deleted)"
        else
            echo "  ❌ 删除失败 (Failed to delete)"
        fi
        echo ""
    done
fi

echo "================================================"
echo "清理完成！(Cleanup completed!)"
echo ""
echo "剩余分支 (Remaining branches):"
git branch -r | grep -v "HEAD"
echo ""
echo "建议：完成此PR后，也删除 copilot/remove-redundant-branches 分支"
echo "Suggestion: After completing this PR, also delete the copilot/remove-redundant-branches branch"
echo "================================================"
