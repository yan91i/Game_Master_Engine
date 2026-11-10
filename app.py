# -*- coding: utf-8 -*-
"""
AI Memory Scanner - 复刻 Cheat Engine 基本功能 + AI 辅助定位
仅用于单机程序 / 自己开发的程序调试。请勿用于在线游戏。
"""
import sys
import time
import json
import queue
import ctypes
import threading
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, scrolledtext

import winmem
from scanner import (Scanner, TYPES, TYPE_LABELS, FIRST_SCAN_TYPES, NEXT_SCAN_TYPES, SCAN_LABELS,
                     NEEDS_V1, NEEDS_V2, read_value, write_value, fmt_value, parse_value)
from tracker import Tracker
from ai_assistant import AIAssistant, load_config, save_config, PRESETS

MAX_SHOW = 500
LABEL2TYPE = {v: k for k, v in TYPE_LABELS.items()}
LABEL2SCAN = {v: k for k, v in SCAN_LABELS.items()}


class App:
    def __init__(self, root):
        self.root = root
        root.title("AI Memory Scanner")
        root.geometry("1360x820")
        self.proc, self.proc_name = None, ""
        self.scanner, self.tracker = None, None
        self.cfg = load_config()
        self.ai = AIAssistant(self.cfg)
        self.q = queue.Queue()
        self.busy = False
        self.cancel_evt = threading.Event()
        self.pending_action = None
        self.addr_list = []           # [{iid, desc, addr, type, frozen, fval}]
        self.lock = threading.Lock()
        self._iid = 0
        self._build()
        self._poll()
        self._refresh_loop()
        threading.Thread(target=self._freeze_loop, daemon=True).start()
        threading.Thread(target=self._hotkey_thread, daemon=True).start()

    # ================= UI =================
    def _build(self):
        top = ttk.Frame(self.root, padding=4)
        top.pack(fill="x")
        ttk.Button(top, text="选择进程", command=self.choose_process).pack(side="left")
        self.proc_var = tk.StringVar(value="未附加进程")
        ttk.Label(top, textvariable=self.proc_var, foreground="#0a6").pack(side="left", padx=8)
        ttk.Button(top, text="AI 设置", command=self.ai_settings).pack(side="right")

        paned = ttk.PanedWindow(self.root, orient="horizontal")
        paned.pack(fill="both", expand=True)
        left = ttk.PanedWindow(paned, orient="vertical")
        right = ttk.Frame(paned, padding=4)
        paned.add(left, weight=3)
        paned.add(right, weight=2)

        upper = ttk.Frame(left, padding=4)
        lower = ttk.Frame(left, padding=4)
        left.add(upper, weight=3)
        left.add(lower, weight=2)

        # ---- 扫描区 ----
        sf = ttk.LabelFrame(upper, text="扫描", padding=4)
        sf.pack(fill="x")
        self.v1, self.v2 = tk.StringVar(), tk.StringVar()
        ttk.Label(sf, text="数值").grid(row=0, column=0, sticky="w")
        ttk.Entry(sf, textvariable=self.v1, width=16).grid(row=0, column=1, sticky="w")
        ttk.Label(sf, text="数值2 (区间上限)").grid(row=0, column=2, sticky="w", padx=(10, 0))
        ttk.Entry(sf, textvariable=self.v2, width=16).grid(row=0, column=3, sticky="w")

        ttk.Label(sf, text="数据类型").grid(row=1, column=0, sticky="w")
        self.dtype_cb = ttk.Combobox(sf, state="readonly", width=14, values=[TYPE_LABELS[k] for k in TYPES])
        self.dtype_cb.set(TYPE_LABELS["int32"])
        self.dtype_cb.grid(row=1, column=1, sticky="w")
        ttk.Label(sf, text="扫描方式").grid(row=1, column=2, sticky="w", padx=(10, 0))
        self.st_cb = ttk.Combobox(sf, state="readonly", width=16)
        self.st_cb.grid(row=1, column=3, sticky="w")

        self.aligned_var = tk.BooleanVar(value=True)
        self.mapped_var = tk.BooleanVar(value=False)
        self.tol_var = tk.StringVar(value="0.01")
        ttk.Checkbutton(sf, text="对齐扫描(快)", variable=self.aligned_var).grid(row=2, column=0, columnspan=2, sticky="w")
        ttk.Checkbutton(sf, text="包含映射内存", variable=self.mapped_var).grid(row=2, column=1, sticky="e")
        ttk.Label(sf, text="浮点容差").grid(row=2, column=2, sticky="w", padx=(10, 0))
        ttk.Entry(sf, textvariable=self.tol_var, width=8).grid(row=2, column=3, sticky="w")

        bf = ttk.Frame(sf)
        bf.grid(row=3, column=0, columnspan=4, sticky="w", pady=4)
        ttk.Button(bf, text="首次扫描", command=lambda: self.ui_scan(True)).pack(side="left")
        ttk.Button(bf, text="再次扫描", command=lambda: self.ui_scan(False)).pack(side="left", padx=4)
        ttk.Button(bf, text="重置", command=self.reset_scan).pack(side="left")
        ttk.Button(bf, text="取消", command=self.cancel_evt.set).pack(side="left", padx=4)

        self.prog_var = tk.DoubleVar()
        ttk.Progressbar(sf, variable=self.prog_var, maximum=100).grid(row=4, column=0, columnspan=4, sticky="ew")
        self.status = tk.StringVar(value="就绪")
        ttk.Label(sf, textvariable=self.status).grid(row=5, column=0, columnspan=4, sticky="w")
        sf.columnconfigure(3, weight=1)
        self._update_scan_types()

        # ---- 结果 ----
        self.count_var = tk.StringVar(value="结果: 0")
        ttk.Label(upper, textvariable=self.count_var).pack(anchor="w", pady=(6, 0))
        rf = ttk.Frame(upper)
        rf.pack(fill="both", expand=True)
        self.res_tree = ttk.Treeview(rf, columns=("addr", "val", "prev"), show="headings", selectmode="extended")
        for c, t, w in (("addr", "地址", 160), ("val", "当前值", 120), ("prev", "上次扫描值", 120)):
            self.res_tree.heading(c, text=t)
            self.res_tree.column(c, width=w)
        sb = ttk.Scrollbar(rf, command=self.res_tree.yview)
        self.res_tree.configure(yscrollcommand=sb.set)
        self.res_tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.res_tree.bind("<Double-1>", lambda e: self.add_selected_results())

        # ---- 地址列表 ----
        af = ttk.LabelFrame(lower, text="地址列表 (双击修改值)", padding=4)
        af.pack(fill="both", expand=True)
        abf = ttk.Frame(af)
        abf.pack(fill="x")
        for txt, cmd in (("添加选中结果", self.add_selected_results), ("手动添加", self.add_manual),
                         ("修改值", self.modify_value), ("冻结/解冻", self.toggle_freeze),
                         ("修改描述", self.edit_desc), ("删除", self.delete_entry)):
            ttk.Button(abf, text=txt, command=cmd).pack(side="left", padx=2)
        self.addr_tree = ttk.Treeview(af, columns=("frz", "desc", "addr", "type", "val"), show="headings")
        for c, t, w in (("frz", "冻结", 50), ("desc", "描述", 200), ("addr", "地址", 150),
                        ("type", "类型", 100), ("val", "值", 120)):
            self.addr_tree.heading(c, text=t)
            self.addr_tree.column(c, width=w)
        self.addr_tree.pack(fill="both", expand=True)
        self.addr_tree.bind("<Double-1>", lambda e: self.modify_value())

        # ---- AI 区 ----
        cf = ttk.LabelFrame(right, text="AI 扫描助手（用自然语言描述发生了什么）", padding=4)
        cf.pack(fill="both", expand=True)
        self.chat_box = scrolledtext.ScrolledText(cf, wrap="word", height=18, state="disabled")
        self.chat_box.pack(fill="both", expand=True)
        ef = ttk.Frame(cf)
        ef.pack(fill="x", pady=4)
        self.chat_var = tk.StringVar()
        ent = ttk.Entry(ef, textvariable=self.chat_var)
        ent.pack(side="left", fill="x", expand=True)
        ent.bind("<Return>", lambda e: self.send_chat())
        ttk.Button(ef, text="发送", command=self.send_chat).pack(side="left", padx=2)
        xf = ttk.Frame(cf)
        xf.pack(fill="x")
        ttk.Button(xf, text="执行 AI 建议", command=self.exec_suggestion).pack(side="left")
        self.auto_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(xf, text="自动执行", variable=self.auto_var).pack(side="left", padx=6)
        ttk.Button(xf, text="清空对话", command=self.clear_chat).pack(side="right")

        tf = ttk.LabelFrame(right, text="行为追踪 + AI 判定（候选难以区分时使用）", padding=4)
        tf.pack(fill="x", pady=(6, 0))
        ttk.Label(tf, text="目标描述").grid(row=0, column=0, sticky="w")
        self.goal_var = tk.StringVar(value="生命值")
        ttk.Entry(tf, textvariable=self.goal_var, width=28).grid(row=0, column=1, columnspan=2, sticky="ew")
        ttk.Label(tf, text="事件名称").grid(row=1, column=0, sticky="w")
        self.evt_var = tk.StringVar(value="受到伤害")
        ee = ttk.Entry(tf, textvariable=self.evt_var, width=28)
        ee.grid(row=1, column=1, columnspan=2, sticky="ew")
        ee.bind("<Return>", lambda e: self.mark_event())
        b2 = ttk.Frame(tf)
        b2.grid(row=2, column=0, columnspan=3, sticky="w", pady=4)
        ttk.Button(b2, text="开始追踪", command=self.start_track).pack(side="left")
        ttk.Button(b2, text="停止追踪", command=self.stop_track).pack(side="left", padx=2)
        ttk.Button(b2, text="标记事件 (F8)", command=self.mark_event).pack(side="left", padx=2)
        ttk.Button(b2, text="AI 分析候选", command=self.ai_analyze).pack(side="left", padx=2)
        self.track_var = tk.StringVar(value="未追踪。全局热键 F8 = 标记事件（游戏窗口中也可用）")
        ttk.Label(tf, textvariable=self.track_var, wraplength=480).grid(row=3, column=0, columnspan=3, sticky="w")
        tf.columnconfigure(1, weight=1)

        self.say("system", "流程：选择进程 → 首次扫描 → 在游戏里改变数值 → 再次扫描。\n"
                           "不知道怎么扫？直接告诉 AI，例如：\"我的金币是 1250\"、\"血条看不到数字，刚被打了一下\"、"
                           "\"什么都没做\"、\"精确扫描找不到\"。")

    # ================= 线程 / 队列 =================
    def _poll(self):
        try:
            while True:
                self.q.get_nowait()()
        except queue.Empty:
            pass
        self.root.after(50, self._poll)

    def ui(self, fn):
        self.q.put(fn)

    def say(self, who, text):
        tag = {"user": "你", "ai": "AI", "system": "系统"}.get(who, who)
        self.chat_box.configure(state="normal")
        self.chat_box.insert("end", f"【{tag}】{text}\n\n")
        self.chat_box.see("end")
        self.chat_box.configure(state="disabled")

    def clear_chat(self):
        self.chat_box.configure(state="normal")
        self.chat_box.delete("1.0", "end")
        self.chat_box.configure(state="disabled")
        self.ai.reset()

    # ================= 进程 =================
    def choose_process(self):
        win = tk.Toplevel(self.root)
        win.title("选择进程")
        win.geometry("420x520")
        fv = tk.StringVar()
        ttk.Entry(win, textvariable=fv).pack(fill="x", padx=4, pady=4)
        lb = tk.Listbox(win)
        lb.pack(fill="both", expand=True, padx=4)
        procs = winmem.list_processes()

        def refill(*_):
            lb.delete(0, "end")
            key = fv.get().lower()
            for pid, name in procs:
                if key in name.lower() or key == str(pid):
                    lb.insert("end", f"{pid:>7}  {name}")
        fv.trace_add("write", refill)
        refill()

        def ok(*_):
            sel = lb.curselection()
            if not sel:
                return
            text = lb.get(sel[0]).strip()
            pid, name = text.split(None, 1)
            win.destroy()
            self.attach(int(pid), name)
        lb.bind("<Double-1>", ok)
        ttk.Button(win, text="附加", command=ok).pack(pady=4)

    def attach(self, pid, name):
        try:
            p = winmem.Process(pid)
        except OSError as e:
            messagebox.showerror("错误", str(e))
            return
        if self.proc:
            self.proc.close()
        self.stop_track()
        self.proc, self.proc_name = p, name
        self.scanner = None
        self.proc_var.set(f"已附加: {name} (PID {pid})")
        self.show_results()
        self._update_scan_types()

    # ================= 扫描 =================
    def tkey(self):
        return LABEL2TYPE[self.dtype_cb.get()]

    def _update_scan_types(self):
        nxt = self.scanner is not None and self.scanner.scan_count > 0
        vals = [SCAN_LABELS[k] for k in (NEXT_SCAN_TYPES if nxt else FIRST_SCAN_TYPES)]
        cur = self.st_cb.get()
        self.st_cb.configure(values=vals)
        self.st_cb.set(cur if cur in vals else vals[0])
        self.dtype_cb.configure(state="disabled" if nxt else "readonly")

    def ui_scan(self, first):
        st = LABEL2SCAN[self.st_cb.get()]
        tk_ = self.tkey() if first or not self.scanner else self.scanner.tkey
        try:
            v1, v2 = parse_value(self.v1.get(), tk_), parse_value(self.v2.get(), tk_)
        except ValueError:
            messagebox.showerror("错误", "数值格式不正确")
            return
        self.start_scan(first, st, v1, v2)

    def start_scan(self, first, st, v1, v2):
        if not self.proc:
            messagebox.showwarning("提示", "请先选择进程")
            return
        if self.busy:
            return
        if st in NEEDS_V1 and v1 is None or st in NEEDS_V2 and v2 is None:
            messagebox.showwarning("提示", f"「{SCAN_LABELS[st]}」需要填写数值")
            return
        try:
            tol = float(self.tol_var.get())
        except ValueError:
            tol = 0.01
        if first:
            self.stop_track()
            self.scanner = Scanner(self.proc, self.tkey(), aligned=self.aligned_var.get(),
                                   tol=tol, include_mapped=self.mapped_var.get())
        elif not self.scanner or self.scanner.scan_count == 0:
            messagebox.showwarning("提示", "请先进行首次扫描")
            return
        sc = self.scanner
        sc.tol = tol
        self.busy = True
        self.cancel_evt.clear()
        self.status.set("扫描中…")
        self.prog_var.set(0)

        def prog(p):
            self.ui(lambda: self.prog_var.set(p * 100))

        def work():
            t0 = time.time()
            err = None
            try:
                (sc.first_scan if first else sc.next_scan)(st, v1, v2, progress=prog, cancel=self.cancel_evt)
            except Exception as e:
                err = e
            self.ui(lambda: self._scan_done(err, time.time() - t0))
        threading.Thread(target=work, daemon=True).start()

    def _scan_done(self, err, dt):
        self.busy = False
        if err:
            messagebox.showerror("扫描错误", str(err))
        n = self.scanner.count() if self.scanner else 0
        self.status.set(f"完成，用时 {dt:.2f}s，结果 {n:,}")
        self.prog_var.set(100)
        self.show_results()
        self._update_scan_types()

    def reset_scan(self):
        if self.busy:
            return
        self.stop_track()
        self.scanner = None
        self.show_results()
        self._update_scan_types()
        self.status.set("已重置")

    def show_results(self):
        self.res_tree.delete(*self.res_tree.get_children())
        sc = self.scanner
        n = sc.count() if sc else 0
        self.count_var.set(f"结果: {n:,}" + (f"（仅显示前 {MAX_SHOW} 个）" if n > MAX_SHOW else ""))
        if not sc:
            return
        for a, v in sc.top(MAX_SHOW):
            s = fmt_value(v, sc.tkey)
            self.res_tree.insert("", "end", iid=str(a), values=(f"{a:016X}", s, s))

    # ================= 地址列表 =================
    def _add_entry(self, addr, tkey, desc="无描述"):
        self._iid += 1
        e = {"iid": f"e{self._iid}", "desc": desc, "addr": addr, "type": tkey, "frozen": False, "fval": None}
        with self.lock:
            self.addr_list.append(e)
        self.addr_tree.insert("", "end", iid=e["iid"], values=("", desc, f"{addr:016X}", TYPE_LABELS[tkey], ""))

    def add_selected_results(self):
        if not self.scanner:
            return
        for iid in self.res_tree.selection():
            self._add_entry(int(iid), self.scanner.tkey)

    def add_manual(self):
        s = simpledialog.askstring("手动添加", "地址 (16 进制):", parent=self.root)
        if not s:
            return
        try:
            self._add_entry(int(s, 16), self.tkey())
        except ValueError:
            messagebox.showerror("错误", "地址格式不正确")

    def _sel_entries(self):
        sel = set(self.addr_tree.selection())
        return [e for e in self.addr_list if e["iid"] in sel]

    def modify_value(self):
        es = self._sel_entries()
        if not es or not self.proc:
            return
        s = simpledialog.askstring("修改值", "新数值:", parent=self.root)
        if s is None:
            return
        for e in es:
            try:
                v = parse_value(s, e["type"])
                if not write_value(self.proc, e["addr"], e["type"], v):
                    messagebox.showerror("错误", f"写入失败 {e['addr']:X}")
                if e["frozen"]:
                    e["fval"] = v
            except (ValueError, OverflowError) as ex:
                messagebox.showerror("错误", str(ex))

    def toggle_freeze(self):
        for e in self._sel_entries():
            if e["frozen"]:
                e["frozen"] = False
            else:
                v = read_value(self.proc, e["addr"], e["type"]) if self.proc else None
                if v is None:
                    continue
                e["fval"], e["frozen"] = v, True
            self.addr_tree.set(e["iid"], "frz", "✔" if e["frozen"] else "")

    def edit_desc(self):
        for e in self._sel_entries():
            s = simpledialog.askstring("描述", "描述:", initialvalue=e["desc"], parent=self.root)
            if s is not None:
                e["desc"] = s
                self.addr_tree.set(e["iid"], "desc", s)

    def delete_entry(self):
        es = self._sel_entries()
        with self.lock:
            for e in es:
                self.addr_list.remove(e)
                self.addr_tree.delete(e["iid"])

    def _refresh_loop(self):
        try:
            if self.proc:
                if self.scanner and not self.busy:
                    tk_ = self.scanner.tkey
                    for iid in self.res_tree.get_children()[:MAX_SHOW]:
                        self.res_tree.set(iid, "val", fmt_value(read_value(self.proc, int(iid), tk_), tk_))
                for e in list(self.addr_list):
                    if self.addr_tree.exists(e["iid"]):
                        v = read_value(self.proc, e["addr"], e["type"])
                        self.addr_tree.set(e["iid"], "val", fmt_value(v, e["type"]))
            if self.tracker:
                n, ev = self.tracker.stats()
                state = "追踪中" if self.tracker.running else "已停止"
                self.track_var.set(f"{state}：{len(self.tracker.addrs)} 个候选，采样 {n} 次，事件 {ev} 个")
        except Exception:
            pass
        self.root.after(700, self._refresh_loop)

    def _freeze_loop(self):
        while True:
            if self.proc:
                with self.lock:
                    items = [(e["addr"], e["type"], e["fval"]) for e in self.addr_list if e["frozen"]]
                for a, t, v in items:
                    try:
                        write_value(self.proc, a, t, v)
                    except Exception:
                        pass
            time.sleep(0.1)

    # ================= AI 对话 =================
    def _ai_state(self):
        sc = self.scanner
        return {
            "attached_process": self.proc_name or None,
            "current_data_type": sc.tkey if sc and sc.scan_count else self.tkey(),
            "aligned": self.aligned_var.get(),
            "scan_count": sc.scan_count if sc else 0,
            "candidate_count": sc.count() if sc else 0,
            "scan_history": sc.history[-10:] if sc else [],
            "sample_candidates": [{"addr": hex(a), "value": fmt_value(v, sc.tkey)} for a, v in sc.top(10)] if sc else [],
            "tracking": bool(self.tracker and self.tracker.running),
        }

    def send_chat(self):
        text = self.chat_var.get().strip()
        if not text:
            return
        self.chat_var.set("")
        self.say("user", text)
        state = self._ai_state()

        def work():
            try:
                r = self.ai.suggest_scan(text, state)
                self.ui(lambda: self._on_suggestion(r))
            except Exception as e:
                self.ui(lambda: self.say("system", f"AI 调用失败：{e}"))
        threading.Thread(target=work, daemon=True).start()

    def _on_suggestion(self, r):
        act = r.get("action") or {"type": "none"}
        desc = ""
        if act.get("type") in ("first_scan", "next_scan"):
            desc = (f"\n→ 建议：{'首次' if act['type'] == 'first_scan' else '再次'}扫描 | "
                    f"{SCAN_LABELS.get(act.get('scan_type'), act.get('scan_type'))} | "
                    f"{act.get('data_type') or ''} | {act.get('value1')} {act.get('value2') or ''}")
        elif act.get("type") in ("reset", "start_tracking"):
            desc = f"\n→ 建议：{'重置扫描' if act['type'] == 'reset' else '开始行为追踪'}"
        self.say("ai", (r.get("reply") or "") + desc)
        self.pending_action = act if act.get("type") not in (None, "none") else None
        if self.pending_action and self.auto_var.get():
            self.exec_suggestion()

    def exec_suggestion(self):
        act = self.pending_action
        if not act:
            self.say("system", "当前没有可执行的 AI 建议")
            return
        self.pending_action = None
        t = act.get("type")
        try:
            if t == "reset":
                self.reset_scan()
                return
            if t == "start_tracking":
                self.start_track()
                return
            st = act.get("scan_type")
            dt = act.get("data_type")
            first = t == "first_scan"
            if first:
                if dt in TYPES:
                    self.dtype_cb.configure(state="readonly")
                    self.dtype_cb.set(TYPE_LABELS[dt])
                tkey = self.tkey()
                valid = FIRST_SCAN_TYPES
            else:
                if not self.scanner:
                    self.say("system", "还没有首次扫描，无法执行再次扫描")
                    return
                tkey = self.scanner.tkey
                valid = NEXT_SCAN_TYPES
            if st not in valid:
                self.say("system", f"AI 给出的扫描方式无效：{st}")
                return
            self.st_cb.set(SCAN_LABELS[st])
            v1 = act.get("value1")
            v2 = act.get("value2")
            v1 = None if v1 is None else (float(v1) if TYPES[tkey][1] else int(float(v1)))
            v2 = None if v2 is None else (float(v2) if TYPES[tkey][1] else int(float(v2)))
            self.v1.set("" if v1 is None else str(v1))
            self.v2.set("" if v2 is None else str(v2))
            self.start_scan(first, st, v1, v2)
        except Exception as e:
            self.say("system", f"执行建议失败：{e}")

    # ================= 行为追踪 =================
    def start_track(self):
        if not self.scanner or not self.proc:
            self.say("system", "请先完成扫描，得到候选地址")
            return
        limit = int(self.cfg.get("max_track_candidates", 2000))
        addrs = self.scanner.all_addresses(limit)
        if addrs is None:
            self.say("system", f"候选 {self.scanner.count():,} 个，超过 {limit}。请先再扫描几次缩小范围。")
            return
        if not addrs:
            self.say("system", "没有候选地址")
            return
        self.stop_track()
        self.tracker = Tracker(self.proc, addrs, self.scanner.tkey, interval=0.2)
        self.tracker.start()
        self.say("system", f"开始追踪 {len(addrs)} 个候选。请在游戏中做与目标相关的动作，每次做完立刻按 F8 "
                           f"或点击「标记事件」（事件名称可随时修改，如“受到伤害”“喝药”）。"
                           f"也建议有一段时间什么都不做，以便排除持续变化的噪声。完成后点「AI 分析候选」。")

    def stop_track(self):
        if self.tracker and self.tracker.running:
            self.tracker.stop()

    def mark_event(self):
        if not self.tracker or not self.tracker.running:
            self.say("system", "未在追踪中，请先点击「开始追踪」")
            return
        label = self.evt_var.get().strip() or "事件"
        t = self.tracker.mark(label)
        self.say("system", f"已标记事件「{label}」@ {t:.1f}s")

    def ai_analyze(self):
        if not self.tracker:
            self.say("system", "没有追踪数据")
            return
        tr = self.tracker
        goal = self.goal_var.get()
        self.say("system", "正在分析…")

        def work():
            cands = tr.analyze(top=30)
            if not cands:
                self.ui(lambda: self.say("system", "采样数据不足，请多追踪一会儿"))
                return
            lines = [f"{c['address']}  值={c['current_value']}  得分={c['heuristic_score']}  "
                     f"事件命中={c['events_followed_by_change']}  噪声={c['changes_without_event']}"
                     for c in cands[:8]]
            self.ui(lambda: self.say("system", "本地启发式排名（前 8）：\n" + "\n".join(lines)))
            try:
                r = self.ai.rank_candidates(goal, tr.event_list(), cands, tr.tkey)
                self.ui(lambda: self._on_rank(r, tr.tkey))
            except Exception as e:
                self.ui(lambda: self.say("system", f"AI 分析失败（可使用上面的本地排名）：{e}"))
        threading.Thread(target=work, daemon=True).start()

    def _on_rank(self, r, tkey):
        rk = r.get("ranking") or []
        lines = [f"#{i + 1} {x.get('address')}  置信度 {x.get('confidence')}\n   {x.get('reason')}"
                 for i, x in enumerate(rk)]
        self.say("ai", "候选判定：\n" + "\n".join(lines) + f"\n\n建议：{r.get('advice', '')}")
        for i, x in enumerate(rk[:3]):
            try:
                self._add_entry(int(str(x["address"]), 16), tkey,
                                f"AI#{i + 1} {self.goal_var.get()} ({x.get('confidence')})")
            except (KeyError, ValueError):
                pass
        if rk:
            self.say("system", "已将 AI 前 3 名加入地址列表。可逐个修改数值，看游戏中是否真正生效。")

    # ================= 全局热键 F8 =================
    def _hotkey_thread(self):
        if not winmem.IS_WINDOWS:
            return
        import ctypes.wintypes as wt
        user32 = ctypes.windll.user32
        if not user32.RegisterHotKey(None, 1, 0, 0x77):   # VK_F8
            self.ui(lambda: self.say("system", "F8 热键注册失败（可能已被占用），请使用按钮标记事件"))
            return
        msg = wt.MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) != 0:
            if msg.message == 0x0312:                     # WM_HOTKEY
                self.ui(self.mark_event)

    # ================= AI 设置 =================
    def ai_settings(self):
        win = tk.Toplevel(self.root)
        win.title("AI 设置（兼容 OpenAI 接口）")
        vars_ = {}
        for i, (k, label) in enumerate((("base_url", "Base URL"), ("api_key", "API Key"),
                                        ("model", "模型"), ("temperature", "Temperature"),
                                        ("max_track_candidates", "追踪最大候选数"))):
            ttk.Label(win, text=label).grid(row=i, column=0, sticky="w", padx=4, pady=2)
            v = tk.StringVar(value=str(self.cfg.get(k, "")))
            ttk.Entry(win, textvariable=v, width=48, show="*" if k == "api_key" else "").grid(row=i, column=1, padx=4)
            vars_[k] = v
        pf = ttk.Frame(win)
        pf.grid(row=5, column=0, columnspan=2, pady=4)
        ttk.Label(pf, text="预设:").pack(side="left")
        for name, p in PRESETS.items():
            def apply(p=p):
                for k, val in p.items():
                    vars_[k].set(val)
            ttk.Button(pf, text=name, command=apply).pack(side="left", padx=2)

        def collect():
            cfg = dict(self.cfg)
            for k, v in vars_.items():
                cfg[k] = v.get().strip()
            cfg["temperature"] = float(cfg["temperature"] or 0.2)
            cfg["max_track_candidates"] = int(cfg["max_track_candidates"] or 2000)
            return cfg

        def save():
            try:
                self.cfg = collect()
            except ValueError:
                messagebox.showerror("错误", "数值格式不正确", parent=win)
                return
            save_config(self.cfg)
            self.ai.update(self.cfg)
            win.destroy()

        def test():
            try:
                tmp = AIAssistant(collect())
                r = tmp.chat([{"role": "user", "content": "回复 OK"}])
                messagebox.showinfo("连接成功", r[:200], parent=win)
            except Exception as e:
                messagebox.showerror("连接失败", str(e), parent=win)
        bf = ttk.Frame(win)
        bf.grid(row=6, column=0, columnspan=2, pady=6)
        ttk.Button(bf, text="测试连接", command=test).pack(side="left", padx=4)
        ttk.Button(bf, text="保存", command=save).pack(side="left", padx=4)


def main():
    if not winmem.IS_WINDOWS:
        print("本程序仅支持 Windows")
        sys.exit(1)
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
