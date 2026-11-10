# -*- coding: utf-8 -*-
"""
tracker.py - 候选地址行为追踪
在后台周期性采样候选地址的值，用户在游戏中做动作时"标记事件"，
然后根据 "事件发生后是否变化 / 变化方向 / 无事件时的噪声" 给候选打分，
并生成精简的统计数据交给 AI 做最终判断。
"""
import time
import threading
import numpy as np
from scanner import read_value, TYPES


class Tracker:
    def __init__(self, proc, addresses, tkey, interval=0.2):
        self.proc = proc
        self.addrs = list(addresses)
        self.tkey = tkey
        self.interval = interval
        self.t0 = time.time()
        self.times, self.samples, self.events = [], [], []
        self.lock = threading.Lock()
        self._stop = threading.Event()
        self.thread = None

    @property
    def running(self):
        return self.thread is not None and self.thread.is_alive()

    def start(self):
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def stop(self):
        self._stop.set()

    def mark(self, label):
        t = time.time() - self.t0
        with self.lock:
            self.events.append((t, label))
        return t

    def _run(self):
        last = np.full(len(self.addrs), np.nan)
        while not self._stop.is_set():
            row = last.copy()
            for i, a in enumerate(self.addrs):
                v = read_value(self.proc, a, self.tkey)
                if v is not None:
                    row[i] = v
            last = row
            with self.lock:
                self.times.append(time.time() - self.t0)
                self.samples.append(row)
            self._stop.wait(self.interval)

    def stats(self):
        with self.lock:
            return len(self.times), len(self.events)

    # ---------- 分析 ----------
    def analyze(self, top=30, before=1.5, after=1.0):
        # 用户通常是"先做动作、再按 F8"，所以窗口偏向事件之前
        with self.lock:
            T = np.array(self.times)
            V = np.array(self.samples) if self.samples else None
            events = list(self.events)
        if V is None or len(T) < 3:
            return []
        V = np.nan_to_num(V, nan=0.0)
        N = V.shape[1]
        ch = np.diff(V, axis=0) != 0          # (T-1, N)
        ct = T[1:]
        n_changes = ch.sum(0)
        hits = np.zeros(N)
        in_any = np.zeros(len(ct), dtype=bool)
        ev_deltas = []
        for t, _ in events:
            w = (ct >= t - before) & (ct <= t + after)
            in_any |= w
            if w.any():
                hits += ch[w].any(0)
            i0 = max(int(np.searchsorted(T, t - before)) - 1, 0)
            i1 = min(max(int(np.searchsorted(T, t + after)) - 1, 0), len(T) - 1)
            ev_deltas.append(V[i1] - V[i0])
        aligned = ch[in_any].sum(0)
        noise = n_changes - aligned
        E = len(events)
        if E:
            score = (hits / E) * (aligned + 1) / (n_changes + 1)
        else:
            score = np.where(n_changes > 0, 1.0 / (1 + n_changes), 0.0)

        order = np.argsort(-score, kind="stable")[:top]
        out = []
        for j in order:
            idx = np.flatnonzero(ch[:, j])[-15:]
            log = [[round(float(ct[k]), 2), _num(V[k + 1, j], self.tkey)] for k in idx]
            out.append({
                "address": hex(self.addrs[j]),
                "first_value": _num(V[0, j], self.tkey),
                "current_value": _num(V[-1, j], self.tkey),
                "total_changes": int(n_changes[j]),
                "changes_without_event": int(noise[j]),
                "events_followed_by_change": int(hits[j]),
                "heuristic_score": round(float(score[j]), 4),
                "event_deltas": [{"event": events[e][1], "t": round(events[e][0], 2),
                                  "delta": _num(ev_deltas[e][j], self.tkey)} for e in range(E)][-20:],
                "recent_changes": log,
            })
        return out

    def event_list(self):
        with self.lock:
            return [{"t": round(t, 2), "label": l} for t, l in self.events]


def _num(v, tkey):
    return round(float(v), 4) if TYPES[tkey][1] else int(v)
