"""飞书交互卡片 + 多渠道群发的回归测试。

HTTP 全部打桩，不联网、不读真实 Secret。
"""
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import qoder_daily as daily

BARE_KEY = "00000000-1111-2222-3333-444455556666"
FULL_HOOK = daily.FEISHU_HOOK_PREFIX + BARE_KEY
PUSH_ENV = ("PUSHPLUS_TOKEN", "BARK_URL", "WECOM_WEBHOOK", "DINGTALK_WEBHOOK",
            "FEISHU_WEBHOOK", "QL_URL", "QL_TOKEN")
HANDLERS = ("notify_pushplus", "notify_bark", "notify_wecom",
            "notify_dingtalk", "notify_feishu", "notify_ql")


def push_env(**values):
    """把所有推送变量先置空（空串 == 未配置），再覆盖指定项。"""
    blank = {name: "" for name in PUSH_ENV}
    blank.update(values)
    return patch.dict(os.environ, blank, clear=False)


def fake_response(payload):
    response = Mock(status_code=200)
    response.json.return_value = payload
    return response


class FeishuCardTests(unittest.TestCase):
    def setUp(self):
        self.logs = []
        log_patch = patch.object(daily, "log", side_effect=self.logs.append)
        log_patch.start()
        self.addCleanup(log_patch.stop)

    def send(self, content, payload=None, hook=BARE_KEY, title="🧭 Qoder 签到报告"):
        answer = payload if payload is not None else {"code": 0}
        with push_env(FEISHU_WEBHOOK=hook), patch.object(
                daily, "post_json", return_value=fake_response(answer)) as post:
            result = daily.notify_feishu(title, content)
        return result, post

    def card(self, post):
        return post.call_args.args[1]

    def test_unconfigured_returns_false_without_http(self):
        with push_env(FEISHU_WEBHOOK=""), patch.object(daily, "post_json") as post:
            self.assertFalse(daily.notify_feishu("t", "c"))
        post.assert_not_called()

    def test_bare_key_expands_to_default_prefix(self):
        ok, post = self.send("账号1 主号: ✅ 今日签到成功，+100 credits")
        self.assertTrue(ok)
        self.assertEqual(post.call_args.args[0], FULL_HOOK)

    def test_card_shape_and_green_template(self):
        body = "账号1 主号: ✅ 今日签到成功，+100 credits"
        ok, post = self.send(body)
        self.assertTrue(ok)
        payload = self.card(post)
        self.assertEqual(payload["msg_type"], "interactive")
        card = payload["card"]
        self.assertTrue(card["config"]["wide_screen_mode"])
        self.assertEqual(card["header"]["template"], "green")
        self.assertEqual(card["header"]["title"],
                         {"tag": "plain_text", "content": "🧭 Qoder 签到报告"})
        self.assertEqual(card["elements"][0]["tag"], "div")
        self.assertEqual(card["elements"][0]["text"], {"tag": "lark_md", "content": body})

    def test_red_wins_when_any_account_fails(self):
        ok, post = self.send(
            "账号1 主号: ✅ 今日签到成功，+100 credits\n账号2 备用: ❌ 异常: HTTP 401")
        self.assertTrue(ok)
        self.assertEqual(self.card(post)["card"]["header"]["template"], "red")

    def test_neutral_only_uses_blue(self):
        ok, post = self.send("账号1 主号: ℹ️ Pro 升级包今日已领取")
        self.assertTrue(ok)
        self.assertEqual(self.card(post)["card"]["header"]["template"], "blue")

    def test_long_body_is_truncated_with_hint(self):
        body = "x" * (daily.FEISHU_MAX_BODY + 500)
        ok, post = self.send(body)
        text = self.card(post)["card"]["elements"][0]["text"]["content"]
        self.assertTrue(ok)
        self.assertTrue(text.startswith("x" * 200))
        self.assertLessEqual(len(text), daily.FEISHU_MAX_BODY + 60)
        self.assertIn("已截断", text)
        self.assertIn(str(len(body)), text)

    def test_business_error_code_returns_false(self):
        ok, _ = self.send("账号1: ✅ ok", payload={"code": 19021, "msg": "sign match fail"})
        self.assertFalse(ok)

    def test_legacy_status_code_zero_is_success(self):
        ok, _ = self.send("账号1: ✅ ok", payload={"StatusCode": 0, "StatusMessage": "success"})
        self.assertTrue(ok)

    def test_transport_exception_returns_false(self):
        with push_env(FEISHU_WEBHOOK=BARE_KEY), patch.object(
                daily, "post_json", side_effect=RuntimeError("boom")):
            self.assertFalse(daily.notify_feishu("t", "c"))


class NotifyAllFanoutTests(unittest.TestCase):
    def setUp(self):
        self.logs = []
        log_patch = patch.object(daily, "log", side_effect=self.logs.append)
        log_patch.start()
        self.addCleanup(log_patch.stop)
        panel_patch = patch.object(daily, "_panel_notify_ready", return_value=False)
        panel_patch.start()
        self.addCleanup(panel_patch.stop)

    def mock_handlers(self, **overrides):
        mocks = {}
        for name in HANDLERS:
            value = overrides.get(name, True)
            if isinstance(value, BaseException):
                patcher = patch.object(daily, name, side_effect=value)
            else:
                patcher = patch.object(daily, name, return_value=value)
            mocks[name] = patcher.start()
            self.addCleanup(patcher.stop)
        return mocks

    def test_every_configured_channel_is_called_once(self):
        mocks = self.mock_handlers()
        with push_env(PUSHPLUS_TOKEN="t", BARK_URL="https://bark.example/push",
                      WECOM_WEBHOOK="key", DINGTALK_WEBHOOK="https://oapi.dingtalk.com/robot",
                      FEISHU_WEBHOOK=BARE_KEY, QL_URL="https://ql.example", QL_TOKEN="qt"):
            result = daily.notify_all("🧭 Qoder 签到报告", "账号1 主号: ✅ ok")
        for name, mock in mocks.items():
            self.assertEqual(mock.call_count, 1, name)
        self.assertEqual(result["failed"], [])
        self.assertEqual(len(result["sent"]), 6)
        self.assertTrue(any("飞书" in line and "成功" in line for line in self.logs))

    def test_unconfigured_channels_are_skipped(self):
        mocks = self.mock_handlers()
        with push_env(WECOM_WEBHOOK="key"):
            result = daily.notify_all("t", "c")
        self.assertEqual(result, {"sent": ["企业微信"], "failed": []})
        self.assertEqual(mocks["notify_feishu"].call_count, 0)
        self.assertEqual(mocks["notify_bark"].call_count, 0)

    def test_nothing_configured_logs_single_hint(self):
        mocks = self.mock_handlers()
        with push_env():
            result = daily.notify_all("t", "c")
        self.assertEqual(result, {"sent": [], "failed": []})
        for mock in mocks.values():
            mock.assert_not_called()
        self.assertEqual(self.logs, ["（未配置推送渠道，本次只记录日志）"])

    def test_failed_channel_is_reported(self):
        self.mock_handlers(notify_feishu=False)
        with push_env(FEISHU_WEBHOOK=BARE_KEY):
            result = daily.notify_all("t", "c")
        self.assertEqual(result, {"sent": [], "failed": ["飞书"]})
        self.assertTrue(any("飞书" in line and "失败" in line for line in self.logs))

    def test_handler_exception_does_not_block_others(self):
        self.mock_handlers(notify_wecom=RuntimeError("kaboom"))
        with push_env(WECOM_WEBHOOK="key", FEISHU_WEBHOOK=BARE_KEY):
            result = daily.notify_all("t", "c")
        self.assertEqual(result["failed"], ["企业微信"])
        self.assertEqual(result["sent"], ["飞书"])
        self.assertTrue(any("异常" in line for line in self.logs))


if __name__ == "__main__":
    unittest.main()
