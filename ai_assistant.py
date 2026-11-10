# -*- coding: utf-8 -*-
"""
ai_assistant.py - 兼容 OpenAI 接口的大模型助手 (SiliconFlow / Ollama / OpenAI / DeepSeek ...)
两大功能:
  1. suggest_scan    : 把自然语言描述 ("刚被打了一下，血少了") 转换成下一步扫描操作
  2. rank_candidates : 根据行为追踪数据，判断哪个候选地址最可能是目标数值
"""
import os
import re
import json
import urllib.request
import urllib.error

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
DEFAULT_CONFIG = {
    "base_url": "https://api.siliconflow.cn/v1",
    "api_key": "",
    "model": "deepseek-ai/DeepSeek-V3",
    "temperature": 0.2,
    "timeout": 120,
    "max_track_candidates": 2000,
}
PRESETS = {
    "SiliconFlow": {"base_url": "https://api.siliconflow.cn/v1", "model": "deepseek-ai/DeepSeek-V3"},
    "Ollama (本地)": {"base_url": "http://localhost:11434/v1", "model": "qwen2.5:7b", "api_key": "ollama"},
    "OpenAI": {"base_url": "https://api.openai.com/v1", "model": "gpt-4o-mini"},
    "DeepSeek": {"base_url": "https://api.deepseek.com/v1", "model": "deepseek-chat"},
}


def load_config():
    cfg = dict(DEFAULT_CONFIG)
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                cfg.update(json.load(f))
        except Exception:
            pass
    return cfg


def save_config(cfg):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


def extract_json(text):
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S).strip()
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, flags=re.S)
    if m:
        text = m.group(1)
    else:
        s, e = text.find("{"), text.rfind("}")
        if s >= 0 and e > s:
            text = text[s:e + 1]
    return json.loads(text)


SCAN_SYSTEM_PROMPT = """你是一个内存扫描助手（类似 Cheat Engine），帮助用户在单机程序/游戏中定位某个数值（生命值、金币、弹药等）。
用户会用自然语言描述程序里刚刚发生了什么，你要结合【当前扫描状态】给出下一步扫描操作。

可用 data_type: byte, int16, int32, int64, float, double
首次扫描 scan_type: exact, bigger, smaller, between, unknown
再次扫描 scan_type: exact, bigger, smaller, between, increased, decreased, increased_by, decreased_by, changed, unchanged
action.type: first_scan, next_scan, reset, start_tracking, none
（next_scan 必须沿用当前 data_type；换类型必须 first_scan）

经验策略：
- 知道屏幕显示的确切数字 → first_scan exact，类型优先 int32；值变化后 next_scan exact 新值。
- 只能看到血条/进度条、不知道数字 → first_scan unknown，之后用 decreased / increased / unchanged 交替过滤。
- 用户说"什么都没做/没变" → next_scan unchanged，可以大量剔除噪声。
- 知道变化量（例如少了 15）→ decreased_by 15。
- 精确扫描结果为 0 → 很可能是 float/double，或显示值被缩放（×10、×100、÷100、百分比），或显示值做了四舍五入：建议换 float 或用 between 范围扫描，或改用 unknown。
- 候选数量仍很多（>2000）→ 引导用户制造变化 + unchanged 交替过滤。
- 候选数量 ≤ 2000 但仍难区分 → action.type=start_tracking，并提示用户在游戏中做相关动作后点击"标记事件"(或按 F8)，再用 AI 分析。
- 若怀疑数值被加密(XOR)、校验或每次重新分配地址，要如实告知限制。

只输出一个 JSON，不要输出其他文字：
{"reply": "给用户的中文说明（简短，说明为什么这么扫、下一步用户要在游戏里做什么）",
 "action": {"type": "...", "scan_type": "...", "data_type": "...", "value1": 数字或null, "value2": 数字或null}}"""


RANK_SYSTEM_PROMPT = """你是内存分析专家。用户想找到代表【目标】的内存地址。程序已对候选地址进行了一段时间的采样，用户在游戏中做动作时标记了事件。
你会收到：目标描述、事件列表（时间/名称）、候选地址统计：
- total_changes 总变化次数；changes_without_event 无事件时的变化次数（噪声）
- events_followed_by_change 有多少个事件后该值发生了变化
- event_deltas 每个事件前后该值的变化量；recent_changes 最近的 [时间, 新值]
- heuristic_score 本地启发式得分（仅供参考）

判断依据：
1. 事件语义与变化方向一致（受伤→减少，回血/捡金币→增加，花钱→减少，开枪→弹药减1）。
2. 同类事件的变化量是否一致、合理。
3. 无事件时应基本不变（计时器、坐标、动画帧等会持续变化，应排除）。
4. 数值范围是否合理（血量通常 0~几万，不会是巨大或负数）。
5. 多个地址同步变化时，可能存在"显示副本"和"真实值"，建议用户都加入地址列表并逐个修改测试，修改后游戏实际生效的是真实值。

只输出 JSON：
{"ranking": [{"address": "0x...", "confidence": 0~1, "reason": "中文理由"}],  (最多 5 个，按可能性排序)
 "advice": "给用户的下一步建议（中文，简短）"}"""


class AIAssistant:
    def __init__(self, cfg):
        self.cfg = cfg
        self.history = []

    def update(self, cfg):
        self.cfg = cfg

    def chat(self, messages):
        url = self.cfg["base_url"].rstrip("/") + "/chat/completions"
        body = {"model": self.cfg["model"], "messages": messages,
                "temperature": float(self.cfg.get("temperature", 0.2)), "stream": False}
        req = urllib.request.Request(
            url, data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {self.cfg.get('api_key') or 'none'}"})
        try:
            with urllib.request.urlopen(req, timeout=int(self.cfg.get("timeout", 120))) as r:
                data = json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"HTTP {e.code}: {e.read().decode('utf-8', 'ignore')[:300]}")
        return data["choices"][0]["message"]["content"]

    def suggest_scan(self, user_text, state):
        user_msg = f"【当前扫描状态】\n{json.dumps(state, ensure_ascii=False)}\n\n【用户描述】\n{user_text}"
        msgs = [{"role": "system", "content": SCAN_SYSTEM_PROMPT}] + self.history[-8:] + \
               [{"role": "user", "content": user_msg}]
        content = self.chat(msgs)
        try:
            result = extract_json(content)
        except Exception:
            result = {"reply": content, "action": {"type": "none"}}
        self.history += [{"role": "user", "content": user_text},
                         {"role": "assistant", "content": json.dumps(result, ensure_ascii=False)}]
        return result

    def rank_candidates(self, goal, events, candidates, data_type):
        payload = {"goal": goal or "(用户未说明)", "data_type": data_type,
                   "events": events, "candidates": candidates}
        msgs = [{"role": "system", "content": RANK_SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(payload, ensure_ascii=False)}]
        return extract_json(self.chat(msgs))

    def reset(self):
        self.history = []
