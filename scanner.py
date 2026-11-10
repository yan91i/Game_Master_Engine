# -*- coding: utf-8 -*-
"""
scanner.py - 内存扫描引擎 (numpy 向量化)
支持: 精确值 / 大于 / 小于 / 区间 / 未知初始值 / 增加 / 减少 / 增加了X / 减少了X / 变动 / 未变动
"""
import numpy as np

TYPES = {               # key: (numpy dtype, 是否浮点)
    "byte":   (np.dtype("<u1"), False),
    "int16":  (np.dtype("<i2"), False),
    "int32":  (np.dtype("<i4"), False),
    "int64":  (np.dtype("<i8"), False),
    "float":  (np.dtype("<f4"), True),
    "double": (np.dtype("<f8"), True),
}
TYPE_LABELS = {
    "byte": "字节 (1B)", "int16": "2 字节", "int32": "4 字节",
    "int64": "8 字节", "float": "单浮点 float", "double": "双浮点 double",
}
FIRST_SCAN_TYPES = ["exact", "bigger", "smaller", "between", "unknown"]
NEXT_SCAN_TYPES = ["exact", "bigger", "smaller", "between", "increased", "decreased",
                   "increased_by", "decreased_by", "changed", "unchanged"]
SCAN_LABELS = {
    "exact": "精确数值", "bigger": "大于", "smaller": "小于", "between": "介于两值之间",
    "unknown": "未知初始值", "increased": "数值增加了", "decreased": "数值减少了",
    "increased_by": "增加了指定值", "decreased_by": "减少了指定值",
    "changed": "数值变动了", "unchanged": "数值未变动",
}
NEEDS_V1 = {"exact", "bigger", "smaller", "between", "increased_by", "decreased_by"}
NEEDS_V2 = {"between"}


def read_value(proc, addr, tkey):
    dt, _ = TYPES[tkey]
    data = proc.read(addr, dt.itemsize)
    if not data or len(data) < dt.itemsize:
        return None
    return np.frombuffer(data, dtype=dt, count=1)[0].item()


def write_value(proc, addr, tkey, value):
    dt, isf = TYPES[tkey]
    value = float(value) if isf else int(value)
    return proc.write(addr, np.array([value], dtype=dt).tobytes())


def fmt_value(v, tkey):
    if v is None:
        return "??"
    return f"{v:.6g}" if TYPES[tkey][1] else str(int(v))


def parse_value(s, tkey):
    s = (s or "").strip()
    if not s:
        return None
    if TYPES[tkey][1]:
        return float(s)
    if s.lower().startswith("0x"):
        return int(s, 16)
    return int(float(s)) if "." in s else int(s)


class RegionResult:
    __slots__ = ("base", "size", "offsets", "values")

    def __init__(self, base, size, offsets, values):
        self.base = base          # 区域基址
        self.size = size          # 区域大小
        self.offsets = offsets    # np.uint32 偏移；None 表示整块(未知初始值快照)
        self.values = values      # 上次扫描时的值


class Scanner:
    def __init__(self, proc, tkey="int32", aligned=True, tol=0.01, include_mapped=False):
        self.proc = proc
        self.tkey = tkey
        self.dtype, self.is_float = TYPES[tkey]
        self.size = self.dtype.itemsize
        self.aligned = aligned
        self.tol = tol
        self.include_mapped = include_mapped
        self.results = []
        self.scan_count = 0
        self.history = []

    # ---------- 条件判断 ----------
    def _cond(self, cur, old, st, v1, v2):
        f = np.float64 if self.is_float else np.int64
        c = cur.astype(f)
        o = old.astype(f) if old is not None else None
        tol = self.tol if self.is_float else 0
        if st == "exact":
            return np.abs(c - v1) <= tol if self.is_float else c == v1
        if st == "bigger":
            return c > v1
        if st == "smaller":
            return c < v1
        if st == "between":
            lo, hi = sorted((v1, v2))
            return (c >= lo - tol) & (c <= hi + tol)
        if st == "increased":
            return c > o
        if st == "decreased":
            return c < o
        if st == "changed":
            return np.abs(c - o) > tol if self.is_float else c != o
        if st == "unchanged":
            return np.abs(c - o) <= tol if self.is_float else c == o
        if st == "increased_by":
            return np.abs((c - o) - v1) <= tol if self.is_float else (c - o) == v1
        if st == "decreased_by":
            return np.abs((o - c) - v1) <= tol if self.is_float else (o - c) == v1
        raise ValueError(f"未知扫描方式: {st}")

    def _gather(self, buf, offsets):
        if self.aligned:
            full = np.frombuffer(buf, dtype=self.dtype, count=len(buf) // self.size)
            return full[offsets // self.size]
        raw = np.frombuffer(buf, dtype=np.uint8)
        out = np.empty(len(offsets), dtype=self.dtype)
        ar = np.arange(self.size)
        step = 1 << 20
        for i in range(0, len(offsets), step):
            o = offsets[i:i + step].astype(np.int64)
            out[i:i + step] = np.ascontiguousarray(raw[o[:, None] + ar]).view(self.dtype).ravel()
        return out

    # ---------- 扫描 ----------
    def first_scan(self, st, v1=None, v2=None, progress=None, cancel=None):
        if st not in FIRST_SCAN_TYPES:
            raise ValueError("首次扫描不支持该方式")
        if st == "unknown":
            self.aligned = True
        regions = self.proc.regions(include_mapped=self.include_mapped)
        total = sum(s for _, s in regions) or 1
        done, results = 0, []
        for base, size in regions:
            if cancel is not None and cancel.is_set():
                break
            buf = self.proc.read(base, size)
            done += size
            if progress:
                progress(done / total)
            if not buf or len(buf) < self.size:
                continue
            if st == "unknown":
                n = len(buf) // self.size
                vals = np.frombuffer(buf, dtype=self.dtype, count=n).copy()
                results.append(RegionResult(base, len(buf), None, vals))
                continue
            offs_l, vals_l = [], []
            for off in ([0] if self.aligned else range(self.size)):
                n = (len(buf) - off) // self.size
                if n <= 0:
                    continue
                arr = np.frombuffer(buf, dtype=self.dtype, count=n, offset=off)
                idx = np.flatnonzero(self._cond(arr, None, st, v1, v2))
                if idx.size:
                    offs_l.append((idx * self.size + off).astype(np.uint32))
                    vals_l.append(arr[idx])
            if offs_l:
                offs, vals = np.concatenate(offs_l), np.concatenate(vals_l)
                if len(offs_l) > 1:
                    order = np.argsort(offs, kind="stable")
                    offs, vals = offs[order], vals[order]
                results.append(RegionResult(base, len(buf), offs, vals))
        self.results = results
        self.scan_count = 1
        self.history = [self._hist("first", st, v1, v2)]

    def next_scan(self, st, v1=None, v2=None, progress=None, cancel=None):
        if self.scan_count == 0:
            raise RuntimeError("请先进行首次扫描")
        if st not in NEXT_SCAN_TYPES:
            raise ValueError("再次扫描不支持该方式")
        total = len(self.results) or 1
        new = []
        for i, r in enumerate(self.results):
            if cancel is not None and cancel.is_set():
                return  # 取消则保持原结果
            if progress:
                progress((i + 1) / total)
            buf = self.proc.read(r.base, r.size)
            if not buf or len(buf) < r.size:
                continue
            if r.offsets is None:
                cur = np.frombuffer(buf, dtype=self.dtype, count=len(r.values))
                idx = np.flatnonzero(self._cond(cur, r.values, st, v1, v2))
                if idx.size:
                    new.append(RegionResult(r.base, r.size, (idx * self.size).astype(np.uint32), cur[idx]))
            else:
                cur = self._gather(buf, r.offsets)
                m = self._cond(cur, r.values, st, v1, v2)
                if m.any():
                    new.append(RegionResult(r.base, r.size, r.offsets[m], cur[m].copy()))
        self.results = new
        self.scan_count += 1
        self.history.append(self._hist("next", st, v1, v2))

    def _hist(self, kind, st, v1, v2):
        return {"scan": kind, "scan_type": st, "value1": v1, "value2": v2,
                "data_type": self.tkey, "result_count": self.count()}

    # ---------- 结果访问 ----------
    def count(self):
        return int(sum(len(r.values) for r in self.results))

    def top(self, limit=500):
        out = []
        for r in self.results:
            k = limit - len(out)
            if k <= 0:
                break
            if r.offsets is None:
                for i in range(min(k, len(r.values))):
                    out.append((r.base + i * self.size, r.values[i].item()))
            else:
                for o, v in zip(r.offsets[:k], r.values[:k]):
                    out.append((r.base + int(o), v.item()))
        return out

    def all_addresses(self, max_n):
        if self.count() > max_n:
            return None
        return [a for a, _ in self.top(max_n)]
