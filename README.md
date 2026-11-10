# AI Memory Scanner

A Python tool that does Cheat Engine's core job (scan → filter → modify / freeze values) and adds AI help for values that are hard to locate.
**Use it only on offline programs, or for debugging and learning with software you wrote. Do not use it on online games.** Doing so breaks their terms of service, and anti-cheat will get your account banned.

## Requirements
- Windows 10/11 and **64-bit Python 3.9+**. You don't need admin rights: `run.bat` installs numpy with `pip install --user`.
- The scanner can only attach to processes running at the same privilege level as itself. If the target runs as administrator, run this tool as administrator too.

## Files
| File | Purpose |
|---|---|
| `app.py` | GUI (tkinter) |
| `winmem.py` | Windows API calls: process list, memory region listing, memory read/write |
| `scanner.py` | Scan engine (vectorised with numpy; aligned and unaligned scans) |
| `tracker.py` | Records candidate values over time and scores them locally |
| `ai_assistant.py` | AI client for any OpenAI-compatible API (SiliconFlow / Ollama / DeepSeek / OpenAI) |
| `config.json` | AI settings (you can also change these under "AI Settings" in the app) |

## Basic usage (same as Cheat Engine)
1. Click "Select Process" and double-click the target process.
2. If you know the value: set the type to "4 Bytes" and the scan type to "Exact Value", enter 100, then click "First Scan".
3. Make the value change in the game (e.g. 100 → 90). Enter 90 and click "Next Scan". Repeat until only a few results remain.
4. Double-click a result to add it to the address list. In the list, double-click an entry to change its value, or use "Freeze/Unfreeze" to lock it.

Scan types:
- **First scan**: Exact, Bigger Than, Smaller Than, Between, Unknown Initial Value.
- **Next scan**: Increased, Decreased, Increased By X, Decreased By X, Changed, Unchanged. You can also use Exact, Bigger Than, Smaller Than or Between again.

## AI features

### 1. Natural-language scan assistant
In the right-hand panel, describe what you see. The AI reads the current scan state and suggests the next step. Click "Execute AI Suggestion" to run it, or tick "Auto Execute". Examples:
- "My gold is 1250" → First Scan, Exact Value, int32, 1250
- "The health bar shows no number" → Unknown Initial Value scan
- "I just got hit" → Decreased
- "I did nothing" → Unchanged
- "Exact scan finds nothing" → the AI suggests trying float/double, checking whether the value is scaled (×10 / ×100), or using a Between scan

### 2. Behaviour tracking + AI ranking (when dozens or hundreds of candidates are left)
1. When 2,000 candidates or fewer remain, click "Start Tracking". The app records every candidate's value in the background every 0.2 s.
2. Fill in "Target Description" (e.g. Health) and "Event Name" (e.g. Took damage).
3. Go back to the game and do the action. **Press F8 right after each action.** F8 is a global hotkey, so it works while the game is in front. You can change the event name between actions, e.g. to "Drank potion".
4. Leave some stretches where you do nothing. This lets the tool rule out values that change all the time, such as timers and coordinates.
5. Click "AI Analyze Candidates":
   - The app first works out locally whether each value changed after events, how often it changed with no event, and how much it changed at each event.
   - The AI then judges by what each event means (damage → decrease, potion → increase), whether the changes are consistent, and whether the value range is plausible.
   - The top 3 are added to the address list. Change each one and see which actually takes effect in the game. This tells you the real value apart from any display-only copy.

Only statistics (addresses, values and changes) are sent to the AI, never raw memory contents.
To run offline on your own machine, use Ollama: go to "AI Settings" and choose the "Ollama (Local)" preset.

## Known limitations
- An "Unknown Initial Value" scan copies all writable memory, so large games can use several GB of RAM. Untick "Include mapped memory" first.
- There's no pointer scanning, code injection or debugger breakpoints, so you can't find out what writes to an address.
- If the value is encrypted (e.g. XOR) or moves to a new address each session, you have to scan again each time.


# AI Memory Scanner

复刻 Cheat Engine 核心功能（扫描 → 过滤 → 修改 / 冻结），并加入 AI 辅助定位难找的数值。
**仅用于单机程序、自己开发的程序调试或学习。不要用于联网游戏**（违反服务条款，且会被反作弊封号）。

## 环境
- Windows 10/11，**64 位 Python 3.9+**（不需要管理员权限，`run.bat` 会用 `pip install --user numpy`）
- 只能附加与本程序同权限级别的进程；目标以管理员运行时，本程序也要以管理员运行

## 文件
| 文件 | 作用 |
|---|---|
| `app.py` | 图形界面（tkinter） |
| `winmem.py` | Windows API：进程列表、内存区域枚举、读写内存 |
| `scanner.py` | 扫描引擎（numpy 向量化，支持对齐/非对齐） |
| `tracker.py` | 候选地址行为追踪 + 本地启发式评分 |
| `ai_assistant.py` | 兼容 OpenAI 接口的 AI（SiliconFlow / Ollama / DeepSeek / OpenAI） |
| `config.json` | AI 配置（也可在界面「AI 设置」中修改） |

## 基本用法（与 CE 相同）
1. 「选择进程」→ 双击目标进程
2. 已知数值：类型选「4 字节」，扫描方式「精确数值」，输入 100 →「首次扫描」
3. 回游戏让数值变化（如 100 → 90），输入 90 →「再次扫描」，重复直到剩下几个
4. 双击结果加入地址列表 → 双击修改值，或「冻结/解冻」锁定数值

支持的扫描方式：精确 / 大于 / 小于 / 区间 / 未知初始值 / 增加了 / 减少了 / 增加了X / 减少了X / 变动了 / 未变动。

## AI 功能

### 1. 自然语言扫描助手
在右侧输入你看到的情况，AI 结合当前扫描状态给出下一步操作，点「执行 AI 建议」（或勾选「自动执行」）：
- “我的金币是 1250” → 首次精确扫描 int32 1250
- “血条看不到数字” → 未知初始值扫描
- “刚被打了一下” → 数值减少了
- “什么都没做” → 数值未变动
- “精确扫描找不到” → 建议改 float/double、缩放值（×10/×100）、区间扫描

### 2. 行为追踪 + AI 判定（解决“剩下几十上百个分不清”）
1. 候选数 ≤ 2000 时点「开始追踪」，后台每 0.2 秒采样所有候选
2. 填写「目标描述」（如 生命值）和「事件名称」（如 受到伤害）
3. 回游戏做动作，**做完立刻按 F8**（全局热键，游戏窗口在前台也可用）；可换事件名，如“喝药”
4. 中间留一段什么都不做的时间，用来排除计时器、坐标等持续变化的噪声
5. 点「AI 分析候选」：
   - 本地先算：事件后是否变化、无事件时的噪声、每次事件的变化量
   - AI 再根据事件语义判断（受伤→减少、喝药→增加，变化量是否一致、范围是否合理）
   - 前 3 名自动加入地址列表，逐个修改验证哪个真正生效（排除“显示副本”）

AI 只接收统计数据（地址、数值、变化量），不会发送内存原始内容。
本地离线可用 Ollama：「AI 设置」→ 预设「Ollama (本地)」。

## 已知限制
- “未知初始值”会把可写内存全部复制一份，大型游戏可能占用数 GB 内存，建议先关闭“包含映射内存”
- 不支持指针扫描 / 代码注入 / 调试器断点（“找出是什么改写了这个地址”）
- 数值被加密（XOR）、或每局重新分配地址时，需要每次重新扫描
