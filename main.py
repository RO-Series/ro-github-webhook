"""
AstrBot GitHub Webhook 推送插件
接收 GitHub Webhook 推送，支持全部 75 种事件类型，
通过 QQ 官方机器人发送通知。
"""

import asyncio
import hashlib
import hmac
import json
import time
from collections import deque
from typing import Optional

from aiohttp import web

from astrbot.api import logger
from astrbot.api import all as api
from astrbot.api.event import filter
from astrbot.api.message_components import Plain
from astrbot.api.star import Context, Star, register


# 全部 GitHub Webhook 事件列表
ALL_GITHUB_EVENTS = [
    "branch_protection_configuration", "branch_protection_rule", "check_run",
    "check_suite", "code_scanning_alert", "commit_comment", "create",
    "custom_property", "custom_property_values", "delete", "dependabot_alert",
    "deploy_key", "deployment", "deployment_protection_rule", "deployment_review",
    "deployment_status", "discussion", "discussion_comment", "fork",
    "github_app_authorization", "gollum", "installation", "installation_repositories",
    "installation_target", "issue_comment", "issue_dependencies", "issues", "label",
    "marketplace_purchase", "member", "membership", "merge_group", "meta", "milestone",
    "org_block", "organization", "package", "page_build", "personal_access_token_request",
    "ping", "project", "project_card", "project_column", "projects_v2",
    "projects_v2_item", "projects_v2_status_update", "public", "pull_request",
    "pull_request_review", "pull_request_review_comment", "pull_request_review_thread",
    "push", "registry_package", "release", "repository", "repository_advisory",
    "repository_dispatch", "repository_import", "repository_ruleset",
    "repository_vulnerability_alert", "secret_scanning_alert",
    "secret_scanning_alert_location", "secret_scanning_scan", "security_advisory",
    "security_and_analysis", "sponsorship", "star", "status", "sub_issues", "team",
    "team_add", "watch", "workflow_dispatch", "workflow_job", "workflow_run",
]


@register(
    "ro_github_webhook",
    "RO-Series",
    "接收 GitHub Webhook 并通过 QQ 官方机器人推送通知",
    "1.0.0",
    "https://github.com/RO-Series/ro-github-webhook",
)
class GithubWebhookPlugin(Star):
    """GitHub Webhook 推送插件"""

    def __init__(self, context: Context, config: dict):
        super().__init__(context)
        self.config = config
        self._web_app: Optional[web.Application] = None
        self._web_runner: Optional[web.AppRunner] = None
        self._web_site: Optional[web.TCPSite] = None

        # 速率限制器
        rate_limit = int(self.config.get("rate_limit", 30))
        if rate_limit > 0:
            self._rate_limiter = _RateLimiter(max_requests=rate_limit)
        else:
            self._rate_limiter = None

    # ==================== 生命周期 ====================

    @filter.on_astrbot_loaded()
    async def on_astrbot_loaded(self):
        """AstrBot 初始化完成后启动 Webhook 服务器"""
        await self._start_webhook_server()

    async def terminate(self):
        """插件卸载时停止 Webhook 服务器"""
        await self._stop_webhook_server()

    # ==================== Webhook 服务器 ====================

    async def _start_webhook_server(self):
        """启动 aiohttp Webhook 服务器"""
        port = int(self.config.get("port", 8080))
        try:
            # 清理已有实例
            if self._web_site:
                await self._web_site.stop()
            if self._web_runner:
                await self._web_runner.cleanup()

            self._web_app = web.Application()
            # Webhook 接收端点：POST /webhook
            self._web_app.router.add_post("/webhook", self._handle_webhook)
            # 兼容根路径 POST
            self._web_app.router.add_post("/", self._handle_webhook)
            # 健康检查端点
            self._web_app.router.add_get("/", self._handle_health)
            self._web_app.router.add_get("/webhook", self._handle_health)

            self._web_runner = web.AppRunner(self._web_app)
            await self._web_runner.setup()
            self._web_site = web.TCPSite(self._web_runner, "0.0.0.0", port)
            await self._web_site.start()
            logger.info(
                f"[GithubWebhook] Webhook 服务器已启动，监听端口 {port}，"
                f"Webhook 地址: http://<服务器IP>:{port}/webhook"
            )
        except OSError as e:
            logger.error(f"[GithubWebhook] 端口 {port} 启动失败: {e}")
        except Exception as e:
            logger.error(f"[GithubWebhook] Webhook 服务器启动异常: {e}")

    async def _stop_webhook_server(self):
        """停止 Webhook 服务器"""
        try:
            if self._web_site:
                await self._web_site.stop()
            if self._web_runner:
                await self._web_runner.cleanup()
            logger.info("[GithubWebhook] Webhook 服务器已停止")
        except Exception as e:
            logger.error(f"[GithubWebhook] 停止服务器异常: {e}")
        finally:
            self._web_site = None
            self._web_runner = None
            self._web_app = None

    async def _handle_health(self, request: web.Request) -> web.Response:
        """健康检查端点"""
        return web.json_response({"status": "ok", "plugin": "github_webhook"})

    async def _handle_webhook(self, request: web.Request) -> web.Response:
        """处理 GitHub Webhook 推送"""
        # 速率限制检查
        if self._rate_limiter:
            is_allowed, retry_after = await self._rate_limiter.is_allowed()
            if not is_allowed:
                current, max_req = self._rate_limiter.get_usage()
                logger.warning(
                    f"[GithubWebhook] 速率限制触发 ({current}/{max_req} requests/min)"
                )
                return web.Response(
                    status=429,
                    text=f"Rate limit exceeded. Retry after {retry_after} seconds.",
                    headers={"Retry-After": str(retry_after)},
                )

        event_type = request.headers.get("X-GitHub-Event", "")
        signature_256 = request.headers.get("X-Hub-Signature-256", "")
        delivery_id = request.headers.get("X-GitHub-Delivery", "")

        body = await request.read()

        # 签名验证
        secret = str(self.config.get("secret", ""))
        if secret:
            if not self._verify_signature(body, signature_256, secret):
                logger.warning(f"[GithubWebhook] 签名验证失败 delivery={delivery_id}")
                return web.Response(status=401, text="Invalid signature")

        # 解析 payload
        try:
            payload = json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return web.Response(status=400, text="Invalid JSON payload")

        # ping 事件直接返回
        if event_type == "ping":
            logger.info(f"[GithubWebhook] 收到 ping 事件 delivery={delivery_id}")
            return web.Response(text="Pong")

        # 检查事件是否启用
        enabled_events = self.config.get("enabled_events", [])
        if enabled_events and event_type not in enabled_events:
            return web.Response(status=200, text="Event not enabled, skipped")

        # 分发事件
        try:
            markdown = self._format_event(event_type, payload)
            if markdown:
                await self._send_notification(markdown)
                logger.info(f"[GithubWebhook] 事件 {event_type} 已推送 delivery={delivery_id}")
        except Exception as e:
            logger.error(f"[GithubWebhook] 处理事件 {event_type} 失败: {e}")

        return web.Response(status=200, text="OK")

    @staticmethod
    def _verify_signature(body: bytes, signature: str, secret: str) -> bool:
        """验证 HMAC-SHA256 签名"""
        if not signature or not signature.startswith("sha256="):
            return False
        expected = "sha256=" + hmac.new(
            secret.encode("utf-8"), body, hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, signature)

    # ==================== 事件分发 ====================

    def _format_event(self, event_type: str, payload: dict) -> Optional[str]:
        """根据事件类型分发到对应的格式化方法"""
        method_name = f"_evt_{event_type.replace('-', '_')}"
        handler = getattr(self, method_name, None)
        if handler and callable(handler):
            try:
                return handler(payload)
            except Exception as e:
                logger.error(f"[GithubWebhook] 格式化事件 {event_type} 出错: {e}")
                return self._format_default(event_type, payload)
        return self._format_default(event_type, payload)

    def _format_default(self, event_type: str, payload: dict) -> str:
        """默认格式化（未实现专门处理的事件）"""
        repo = payload.get("repository", {}).get("full_name", "未知仓库")
        action = payload.get("action", "")
        action_str = f"（{action}）" if action else ""
        return f"**🔔 GitHub 通知**\n📦 仓库：{repo}\n📋 事件：`{event_type}`{action_str}"

    # ==================== 通知发送 ====================

    async def _send_notification(self, message: str):
        """通过 AstrBot 发送通知消息到目标会话"""
        target_umo = str(self.config.get("target_umo", "")).strip()

        if not target_umo:
            logger.warning("[GithubWebhook] 未配置目标会话 UMO (target_umo)，跳过推送")
            return

        try:
            message_chain = api.MessageChain([Plain(message)])
            result = await self.context.send_message(target_umo, message_chain)
            logger.info(f"[GithubWebhook] 消息已发送到 {target_umo}, result: {result}")
            if not result:
                logger.warning(f"[GithubWebhook] 未找到平台: {target_umo}")
        except Exception as e:
            logger.error(f"[GithubWebhook] 发送消息失败: {e}")

    # ==================== 事件格式化方法 ====================

    def _repo_name(self, payload: dict) -> str:
        return payload.get("repository", {}).get("full_name", "未知仓库")

    def _sender_login(self, payload: dict) -> str:
        return payload.get("sender", {}).get("login", "未知用户")

    def _action(self, payload: dict) -> str:
        return payload.get("action", "")

    # ---------- 分支保护 ----------

    def _evt_branch_protection_configuration(self, payload: dict) -> str:
        action = self._action(payload)
        return (
            f"**🔐 分支保护配置**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"👤 操作人：{self._sender_login(payload)}\n"
            f"📋 动作：`{action}`"
        )

    def _evt_branch_protection_rule(self, payload: dict) -> str:
        action = self._action(payload)
        rule = payload.get("rule", {})
        rule_name = rule.get("name", "未知规则")
        return (
            f"**🔐 分支保护规则**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"📏 规则：{rule_name}\n"
            f"📋 动作：`{action}`"
        )

    # ---------- Checks ----------

    def _evt_check_run(self, payload: dict) -> str:
        action = self._action(payload)
        check_run = payload.get("check_run", {})
        name = check_run.get("name", "未知")
        conclusion = check_run.get("conclusion", "pending")
        status = check_run.get("status", "")
        return (
            f"**✅ Check Run**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"🔍 名称：{name}\n"
            f"📊 状态：{status} / {conclusion}\n"
            f"📋 动作：`{action}`"
        )

    def _evt_check_suite(self, payload: dict) -> str:
        action = self._action(payload)
        suite = payload.get("check_suite", {})
        conclusion = suite.get("conclusion", "pending")
        return (
            f"**✅ Check Suite**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"📊 结论：{conclusion}\n"
            f"📋 动作：`{action}`"
        )

    # ---------- 安全扫描 ----------

    def _evt_code_scanning_alert(self, payload: dict) -> str:
        action = self._action(payload)
        alert = payload.get("alert", {})
        rule = alert.get("rule", {}).get("id", "未知规则")
        severity = alert.get("rule", {}).get("severity", "未知")
        return (
            f"**🔍 代码扫描告警**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"📏 规则：{rule}\n"
            f"⚠️ 严重程度：{severity}\n"
            f"📋 动作：`{action}`"
        )

    def _evt_dependabot_alert(self, payload: dict) -> str:
        action = self._action(payload)
        alert = payload.get("alert", {})
        pkg = alert.get("dependency", {}).get("package", {}).get("name", "未知包")
        severity = alert.get("security_vulnerability", {}).get("severity", "未知")
        return (
            f"**🤖 Dependabot 告警**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"📦 依赖包：{pkg}\n"
            f"⚠️ 严重程度：{severity}\n"
            f"📋 动作：`{action}`"
        )

    def _evt_secret_scanning_alert(self, payload: dict) -> str:
        action = self._action(payload)
        alert = payload.get("alert", {})
        secret_type = alert.get("secret_type", "未知类型")
        return (
            f"**🔑 密钥扫描告警**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"🔐 密钥类型：{secret_type}\n"
            f"📋 动作：`{action}`"
        )

    def _evt_secret_scanning_alert_location(self, payload: dict) -> str:
        action = self._action(payload)
        return (
            f"**🔑 密钥扫描位置**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"📋 动作：`{action}`"
        )

    def _evt_secret_scanning_scan(self, payload: dict) -> str:
        return (
            f"**🔑 密钥扫描完成**\n"
            f"📦 仓库：{self._repo_name(payload)}"
        )

    def _evt_repository_vulnerability_alert(self, payload: dict) -> str:
        action = self._action(payload)
        alert = payload.get("alert", {})
        pkg = alert.get("affected_package_name", "未知包")
        return (
            f"**⚠️ 仓库漏洞告警**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"📦 受影响包：{pkg}\n"
            f"📋 动作：`{action}`"
        )

    # ---------- 提交评论 ----------

    def _evt_commit_comment(self, payload: dict) -> str:
        action = self._action(payload)
        comment = payload.get("comment", {})
        body = comment.get("body", "")[:200]
        return (
            f"**💬 提交评论**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"👤 {self._sender_login(payload)}\n"
            f"📝 内容：{body}\n"
            f"📋 动作：`{action}`"
        )

    # ---------- 创建/删除 ----------

    def _evt_create(self, payload: dict) -> str:
        ref = payload.get("ref", "")
        ref_type = payload.get("ref_type", "")
        return (
            f"**➕ 创建引用**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"👤 {self._sender_login(payload)}\n"
            f"🔀 类型：{ref_type}\n"
            f"📍 引用：`{ref}`"
        )

    def _evt_delete(self, payload: dict) -> str:
        ref = payload.get("ref", "")
        ref_type = payload.get("ref_type", "")
        return (
            f"**➖ 删除引用**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"👤 {self._sender_login(payload)}\n"
            f"🔀 类型：{ref_type}\n"
            f"📍 引用：`{ref}`"
        )

    # ---------- 自定义属性 ----------

    def _evt_custom_property(self, payload: dict) -> str:
        action = self._action(payload)
        prop = payload.get("property", {})
        name = prop.get("property_name", "未知属性")
        return (
            f"**🏷️ 自定义属性**\n"
            f"👤 操作人：{self._sender_login(payload)}\n"
            f"📏 属性名：{name}\n"
            f"📋 动作：`{action}`"
        )

    def _evt_custom_property_values(self, payload: dict) -> str:
        action = self._action(payload)
        repo = payload.get("repository", {}).get("full_name", "未知仓库")
        return (
            f"**🏷️ 自定义属性值**\n"
            f"📦 仓库：{repo}\n"
            f"📋 动作：`{action}`"
        )

    # ---------- 部署 ----------

    def _evt_deploy_key(self, payload: dict) -> str:
        action = self._action(payload)
        key = payload.get("key", {})
        title = key.get("title", "未知")
        return (
            f"**🔑 部署密钥**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"📝 标题：{title}\n"
            f"📋 动作：`{action}`"
        )

    def _evt_deployment(self, payload: dict) -> str:
        deployment = payload.get("deployment", {})
        ref = deployment.get("ref", "")
        env = deployment.get("environment", "")
        return (
            f"**🚀 部署**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"👤 {self._sender_login(payload)}\n"
            f"🌿 分支：`{ref}`\n"
            f"🌍 环境：{env}"
        )

    def _evt_deployment_status(self, payload: dict) -> str:
        status = payload.get("deployment_status", {})
        state = status.get("state", "")
        env = payload.get("deployment", {}).get("environment", "")
        return (
            f"**🚀 部署状态**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"🌍 环境：{env}\n"
            f"📊 状态：{state}"
        )

    def _evt_deployment_protection_rule(self, payload: dict) -> str:
        action = self._action(payload)
        return (
            f"**🛡️ 部署保护规则**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"📋 动作：`{action}`"
        )

    def _evt_deployment_review(self, payload: dict) -> str:
        action = self._action(payload)
        return (
            f"**🛡️ 部署审批**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"👤 {self._sender_login(payload)}\n"
            f"📋 动作：`{action}`"
        )

    # ---------- Discussion ----------

    def _evt_discussion(self, payload: dict) -> str:
        action = self._action(payload)
        discussion = payload.get("discussion", {})
        title = discussion.get("title", "无标题")
        return (
            f"**💬 Discussion**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"👤 {self._sender_login(payload)}\n"
            f"📝 标题：{title}\n"
            f"📋 动作：`{action}`"
        )

    def _evt_discussion_comment(self, payload: dict) -> str:
        action = self._action(payload)
        comment = payload.get("comment", {})
        body = comment.get("body", "")[:200]
        return (
            f"**💬 Discussion 评论**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"👤 {self._sender_login(payload)}\n"
            f"📝 内容：{body}\n"
            f"📋 动作：`{action}`"
        )

    # ---------- Fork / Star / Watch / Public ----------

    def _evt_fork(self, payload: dict) -> str:
        forkee = payload.get("forkee", {})
        full_name = forkee.get("full_name", "未知")
        return (
            f"**🍴 Fork**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"👤 {self._sender_login(payload)} fork 到：{full_name}"
        )

    def _evt_star(self, payload: dict) -> str:
        action = self._action(payload)
        return (
            f"**⭐ Star**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"👤 {self._sender_login(payload)}\n"
            f"📋 动作：`{action}`"
        )

    def _evt_watch(self, payload: dict) -> str:
        action = self._action(payload)
        return (
            f"**👀 Watch**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"👤 {self._sender_login(payload)}\n"
            f"📋 动作：`{action}`"
        )

    def _evt_public(self, payload: dict) -> str:
        return (
            f"**🌍 仓库公开**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"👤 {self._sender_login(payload)} 将仓库转为公开"
        )

    # ---------- GitHub App ----------

    def _evt_github_app_authorization(self, payload: dict) -> str:
        action = self._action(payload)
        return (
            f"**🔌 GitHub App 授权**\n"
            f"👤 {self._sender_login(payload)}\n"
            f"📋 动作：`{action}`"
        )

    def _evt_installation(self, payload: dict) -> str:
        action = self._action(payload)
        installation = payload.get("installation", {})
        account = installation.get("account", {}).get("login", "未知")
        return (
            f"**🔌 App 安装**\n"
            f"👤 账户：{account}\n"
            f"📋 动作：`{action}`"
        )

    def _evt_installation_repositories(self, payload: dict) -> str:
        action = self._action(payload)
        return (
            f"**🔌 App 仓库变更**\n"
            f"👤 {self._sender_login(payload)}\n"
            f"📋 动作：`{action}`"
        )

    def _evt_installation_target(self, payload: dict) -> str:
        action = self._action(payload)
        return (
            f"**🔌 App 安装目标**\n"
            f"👤 {self._sender_login(payload)}\n"
            f"📋 动作：`{action}`"
        )

    # ---------- Wiki ----------

    def _evt_gollum(self, payload: dict) -> str:
        pages = payload.get("pages", [])
        page_info = "\n".join(
            f"  - {p.get('page_name', '')} ({p.get('action', '')})" for p in pages[:5]
        )
        return (
            f"**📚 Wiki 更新**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"👤 {self._sender_login(payload)}\n"
            f"📄 页面：\n{page_info}"
        )

    # ---------- Issue ----------

    def _evt_issues(self, payload: dict) -> str:
        action = self._action(payload)
        issue = payload.get("issue", {})
        number = issue.get("number", "")
        title = issue.get("title", "无标题")
        url = issue.get("html_url", "")
        return (
            f"**🐛 Issue**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"👤 {self._sender_login(payload)}\n"
            f"📝 #{number} {title}\n"
            f"📋 动作：`{action}`\n"
            f"🔗 {url}"
        )

    def _evt_issue_comment(self, payload: dict) -> str:
        action = self._action(payload)
        issue = payload.get("issue", {})
        comment = payload.get("comment", {})
        number = issue.get("number", "")
        title = issue.get("title", "无标题")
        body = comment.get("body", "")[:200]
        return (
            f"**💬 Issue 评论**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"👤 {self._sender_login(payload)}\n"
            f"📝 #{number} {title}\n"
            f"📝 评论：{body}\n"
            f"📋 动作：`{action}`"
        )

    def _evt_issue_dependencies(self, payload: dict) -> str:
        action = self._action(payload)
        return (
            f"**🔗 Issue 依赖**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"📋 动作：`{action}`"
        )

    def _evt_sub_issues(self, payload: dict) -> str:
        action = self._action(payload)
        return (
            f"**🔗 子 Issue**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"📋 动作：`{action}`"
        )

    # ---------- Label / Milestone ----------

    def _evt_label(self, payload: dict) -> str:
        action = self._action(payload)
        label = payload.get("label", {})
        name = label.get("name", "未知")
        return (
            f"**🏷️ 标签**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"📏 标签：{name}\n"
            f"📋 动作：`{action}`"
        )

    def _evt_milestone(self, payload: dict) -> str:
        action = self._action(payload)
        milestone = payload.get("milestone", {})
        title = milestone.get("title", "无标题")
        return (
            f"**🎯 里程碑**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"📝 标题：{title}\n"
            f"📋 动作：`{action}`"
        )

    # ---------- Marketplace ----------

    def _evt_marketplace_purchase(self, payload: dict) -> str:
        action = self._action(payload)
        return (
            f"**🛒 Marketplace 购买**\n"
            f"👤 {self._sender_login(payload)}\n"
            f"📋 动作：`{action}`"
        )

    # ---------- 成员 ----------

    def _evt_member(self, payload: dict) -> str:
        action = self._action(payload)
        member = payload.get("member", {})
        login = member.get("login", "未知")
        return (
            f"**👥 仓库成员**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"👤 成员：{login}\n"
            f"📋 动作：`{action}`"
        )

    def _evt_membership(self, payload: dict) -> str:
        action = self._action(payload)
        member = payload.get("member", {})
        team = payload.get("team", {})
        login = member.get("login", "未知")
        team_name = team.get("name", "未知")
        return (
            f"**👥 团队成员**\n"
            f"👤 成员：{login}\n"
            f"👥 团队：{team_name}\n"
            f"📋 动作：`{action}`"
        )

    def _evt_merge_group(self, payload: dict) -> str:
        action = self._action(payload)
        merge_group = payload.get("merge_group", {})
        return (
            f"**🔀 合并组**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"📋 动作：`{action}`"
        )

    # ---------- Meta ----------

    def _evt_meta(self, payload: dict) -> str:
        return (
            f"**⚙️ Webhook 配置变更**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"👤 {self._sender_login(payload)}"
        )

    # ---------- 组织 ----------

    def _evt_org_block(self, payload: dict) -> str:
        action = self._action(payload)
        org = payload.get("organization", {}).get("login", "未知组织")
        blocked = payload.get("blocked_user", {}).get("login", "未知用户")
        return (
            f"**🚫 组织屏蔽**\n"
            f"🏢 组织：{org}\n"
            f"👤 被屏蔽：{blocked}\n"
            f"📋 动作：`{action}`"
        )

    def _evt_organization(self, payload: dict) -> str:
        action = self._action(payload)
        org = payload.get("organization", {}).get("login", "未知组织")
        return (
            f"**🏢 组织**\n"
            f"🏢 组织：{org}\n"
            f"👤 {self._sender_login(payload)}\n"
            f"📋 动作：`{action}`"
        )

    def _evt_team(self, payload: dict) -> str:
        action = self._action(payload)
        team = payload.get("team", {})
        name = team.get("name", "未知")
        return (
            f"**👥 团队**\n"
            f"🏢 组织：{payload.get('organization', {}).get('login', '')}\n"
            f"📝 团队：{name}\n"
            f"📋 动作：`{action}`"
        )

    def _evt_team_add(self, payload: dict) -> str:
        team = payload.get("team", {})
        name = team.get("name", "未知")
        return (
            f"**👥 团队添加到仓库**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"👥 团队：{name}"
        )

    def _evt_personal_access_token_request(self, payload: dict) -> str:
        action = self._action(payload)
        return (
            f"**🔑 PAT 请求**\n"
            f"🏢 组织：{payload.get('organization', {}).get('login', '')}\n"
            f"📋 动作：`{action}`"
        )

    # ---------- 包 ----------

    def _evt_package(self, payload: dict) -> str:
        action = self._action(payload)
        package = payload.get("package", {})
        name = package.get("name", "未知")
        return (
            f"**📦 包**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"📝 包名：{name}\n"
            f"📋 动作：`{action}`"
        )

    def _evt_registry_package(self, payload: dict) -> str:
        action = self._action(payload)
        package = payload.get("registry_package", {})
        name = package.get("name", "未知")
        return (
            f"**📦 注册表包**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"📝 包名：{name}\n"
            f"📋 动作：`{action}`"
        )

    # ---------- Pages ----------

    def _evt_page_build(self, payload: dict) -> str:
        build = payload.get("build", {})
        status = build.get("status", "未知")
        return (
            f"**📄 Pages 构建**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"📊 状态：{status}"
        )

    # ---------- Ping ----------

    def _evt_ping(self, payload: dict) -> str:
        zen = payload.get("zen", "")
        return (
            f"**🏓 Ping**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"💡 {zen}"
        )

    # ---------- Project ----------

    def _evt_project(self, payload: dict) -> str:
        action = self._action(payload)
        project = payload.get("project", {})
        name = project.get("name", "未知")
        return (
            f"**📋 Project**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"📝 名称：{name}\n"
            f"📋 动作：`{action}`"
        )

    def _evt_project_card(self, payload: dict) -> str:
        action = self._action(payload)
        return (
            f"**📋 Project 卡片**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"📋 动作：`{action}`"
        )

    def _evt_project_column(self, payload: dict) -> str:
        action = self._action(payload)
        return (
            f"**📋 Project 列**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"📋 动作：`{action}`"
        )

    def _evt_projects_v2(self, payload: dict) -> str:
        action = self._action(payload)
        projects_v2 = payload.get("projects_v2", {})
        title = projects_v2.get("title", "未知")
        return (
            f"**📋 Projects v2**\n"
            f"📝 标题：{title}\n"
            f"📋 动作：`{action}`"
        )

    def _evt_projects_v2_item(self, payload: dict) -> str:
        action = self._action(payload)
        return (
            f"**📋 Projects v2 项**\n"
            f"📋 动作：`{action}`"
        )

    def _evt_projects_v2_status_update(self, payload: dict) -> str:
        return (
            f"**📋 Projects v2 状态更新**\n"
            f"📦 仓库：{self._repo_name(payload)}"
        )

    # ---------- Pull Request ----------

    def _evt_pull_request(self, payload: dict) -> str:
        action = self._action(payload)
        pr = payload.get("pull_request", {})
        number = pr.get("number", "")
        title = pr.get("title", "无标题")
        url = pr.get("html_url", "")
        merged = pr.get("merged", False)
        merged_str = "（已合并）" if merged else ""
        return (
            f"**🔀 Pull Request**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"👤 {self._sender_login(payload)}\n"
            f"📝 #{number} {title}{merged_str}\n"
            f"📋 动作：`{action}`\n"
            f"🔗 {url}"
        )

    def _evt_pull_request_review(self, payload: dict) -> str:
        action = self._action(payload)
        pr = payload.get("pull_request", {})
        review = payload.get("review", {})
        number = pr.get("number", "")
        state = review.get("state", "")
        return (
            f"**👀 PR 审查**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"👤 {self._sender_login(payload)}\n"
            f"📝 PR #{number}\n"
            f"📊 状态：{state}\n"
            f"📋 动作：`{action}`"
        )

    def _evt_pull_request_review_comment(self, payload: dict) -> str:
        action = self._action(payload)
        pr = payload.get("pull_request", {})
        comment = payload.get("comment", {})
        number = pr.get("number", "")
        body = comment.get("body", "")[:200]
        return (
            f"**💬 PR 评审评论**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"👤 {self._sender_login(payload)}\n"
            f"📝 PR #{number}\n"
            f"📝 评论：{body}\n"
            f"📋 动作：`{action}`"
        )

    def _evt_pull_request_review_thread(self, payload: dict) -> str:
        action = self._action(payload)
        return (
            f"**💬 PR 评审线程**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"📋 动作：`{action}`"
        )

    # ---------- Push ----------

    def _evt_push(self, payload: dict) -> str:
        ref = payload.get("ref", "")
        pusher = payload.get("pusher", {}).get("name", "未知")
        commits = payload.get("commits", [])
        commit_count = len(commits)
        commit_msgs = "\n".join(
            f"  - `{c.get('id', '')[:8]}` {c.get('message', '').split(chr(10))[0]}"
            for c in commits[:5]
        )
        compare = payload.get("compare", "")
        return (
            f"**📥 Push**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"👤 推送者：{pusher}\n"
            f"🔀 分支：`{ref}`\n"
            f"📊 提交数：{commit_count}\n"
            f"📝 提交：\n{commit_msgs}\n"
            f"🔗 {compare}"
        )

    # ---------- Release ----------

    def _evt_release(self, payload: dict) -> str:
        action = self._action(payload)
        release = payload.get("release", {})
        tag = release.get("tag_name", "")
        name = release.get("name", tag)
        url = release.get("html_url", "")
        return (
            f"**🎉 Release**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"👤 {self._sender_login(payload)}\n"
            f"🏷️ 版本：{name} (`{tag}`)\n"
            f"📋 动作：`{action}`\n"
            f"🔗 {url}"
        )

    # ---------- Repository ----------

    def _evt_repository(self, payload: dict) -> str:
        action = self._action(payload)
        repo = payload.get("repository", {})
        name = repo.get("full_name", "未知")
        return (
            f"**📦 仓库**\n"
            f"📝 名称：{name}\n"
            f"👤 {self._sender_login(payload)}\n"
            f"📋 动作：`{action}`"
        )

    def _evt_repository_advisory(self, payload: dict) -> str:
        action = self._action(payload)
        advisory = payload.get("repository_advisory", {})
        summary = advisory.get("summary", "")[:200]
        return (
            f"**⚠️ 仓库安全通告**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"📝 摘要：{summary}\n"
            f"📋 动作：`{action}`"
        )

    def _evt_repository_dispatch(self, payload: dict) -> str:
        event_type = payload.get("event_type", "未知")
        return (
            f"**📤 仓库自定义事件**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"👤 {self._sender_login(payload)}\n"
            f"📝 事件类型：`{event_type}`"
        )

    def _evt_repository_import(self, payload: dict) -> str:
        status = payload.get("status", "未知")
        return (
            f"**📥 仓库导入**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"📊 状态：{status}"
        )

    def _evt_repository_ruleset(self, payload: dict) -> str:
        action = self._action(payload)
        ruleset = payload.get("repository_ruleset", {})
        name = ruleset.get("name", "未知")
        return (
            f"**📏 仓库规则集**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"📝 名称：{name}\n"
            f"📋 动作：`{action}`"
        )

    # ---------- Security ----------

    def _evt_security_advisory(self, payload: dict) -> str:
        action = self._action(payload)
        advisory = payload.get("security_advisory", {})
        summary = advisory.get("summary", "")[:200]
        return (
            f"**🛡️ 安全通告**\n"
            f"📝 摘要：{summary}\n"
            f"📋 动作：`{action}`"
        )

    def _evt_security_and_analysis(self, payload: dict) -> str:
        return (
            f"**🔒 安全与分析设置**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"👤 {self._sender_login(payload)}"
        )

    # ---------- Sponsorship ----------

    def _evt_sponsorship(self, payload: dict) -> str:
        action = self._action(payload)
        sponsorship = payload.get("sponsorship", {})
        sponsor = sponsorship.get("sponsor", {}).get("login", "未知")
        return (
            f"**💖 赞助**\n"
            f"👤 赞助者：{sponsor}\n"
            f"📋 动作：`{action}`"
        )

    # ---------- Status ----------

    def _evt_status(self, payload: dict) -> str:
        state = payload.get("state", "未知")
        sha = payload.get("sha", "")[:8]
        context = payload.get("context", "")
        return (
            f"**📊 提交状态**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"🔀 SHA：`{sha}`\n"
            f"📏 上下文：{context}\n"
            f"📊 状态：{state}"
        )

    # ---------- Workflow ----------

    def _evt_workflow_dispatch(self, payload: dict) -> str:
        workflow = payload.get("workflow", {})
        name = workflow.get("name", "未知")
        return (
            f"**⚙️ Workflow 手动触发**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"👤 {self._sender_login(payload)}\n"
            f"📝 工作流：{name}"
        )

    def _evt_workflow_job(self, payload: dict) -> str:
        action = self._action(payload)
        job = payload.get("workflow_job", {})
        name = job.get("name", "未知")
        conclusion = job.get("conclusion", "pending")
        return (
            f"**⚙️ Workflow Job**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"📝 Job：{name}\n"
            f"📊 结论：{conclusion}\n"
            f"📋 动作：`{action}`"
        )

    def _evt_workflow_run(self, payload: dict) -> str:
        action = self._action(payload)
        run = payload.get("workflow_run", {})
        name = run.get("name", "未知")
        conclusion = run.get("conclusion", "pending")
        branch = run.get("head_branch", "")
        return (
            f"**⚙️ Workflow Run**\n"
            f"📦 仓库：{self._repo_name(payload)}\n"
            f"📝 工作流：{name}\n"
            f"🌿 分支：`{branch}`\n"
            f"📊 结论：{conclusion}\n"
            f"📋 动作：`{action}`"
        )


class _RateLimiter:
    """基于滑动窗口的速率限制器"""

    def __init__(self, max_requests: int, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: deque = deque()
        self._lock = asyncio.Lock()

    async def is_allowed(self) -> tuple[bool, int]:
        """检查请求是否允许，返回 (是否允许, 重试等待秒数)"""
        if self.max_requests <= 0:
            return True, 0

        current_time = time.time()
        async with self._lock:
            # 移除窗口外的时间戳
            while self._requests and self._requests[0] < current_time - self.window_seconds:
                self._requests.popleft()

            if len(self._requests) < self.max_requests:
                self._requests.append(current_time)
                return True, 0
            else:
                oldest = self._requests[0]
                retry_after = int(oldest + self.window_seconds - current_time)
                return False, max(retry_after, 1)

    def get_usage(self) -> tuple[int, int]:
        """获取当前用量 (当前请求数, 最大请求数)"""
        current_time = time.time()
        while self._requests and self._requests[0] < current_time - self.window_seconds:
            self._requests.popleft()
        return len(self._requests), self.max_requests
