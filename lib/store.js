import { mkdir, readFile, rename, rm, open } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";

// 进程内互斥队列：所有读改写事务串行化，保证并发激活/轮换/撤销只有一个赢家。
class Mutex {
  #chain = Promise.resolve();
  run(task) {
    const run = this.#chain.then(() => task());
    // 单个任务失败不能毒化整条链。
    this.#chain = run.then(() => {}, () => {});
    return run;
  }
}

// JSON 文件存储：内存状态 + 原子落盘（同目录临时文件 fsync 后 rename）。
// mutate 回调对状态的修改只有在落盘成功后才提交；落盘失败整体回滚，
// 因此不会出现“内存里生效、磁盘上没有”或写一半的记录。
export class JsonStore {
  constructor(file, seed = {}, { clock = () => Date.now() } = {}) {
    this.file = file;
    this.seed = seed;
    this.clock = clock;
    this.mutex = new Mutex();
    this.state = null;
    // 测试用故障注入：设为整数后，下一次落盘在 rename 前抛错，随后计数递减。
    this.failNextWrites = 0;
  }

  async load() {
    if (this.state) return this.state;
    if (!existsSync(this.file)) {
      await mkdir(dirname(this.file), { recursive: true });
      this.state = mergeSeed(undefined, this.seed);
      await this.#flush(true);
      return this.state;
    }
    const raw = await readFile(this.file, "utf8");
    this.state = mergeSeed(raw.trim() ? JSON.parse(raw) : {}, this.seed);
    return this.state;
  }

  // 只读快照（事务外读到的是最近一次成功提交的状态）。
  async read() {
    return this.load();
  }

  // 读改写事务：同一进程内串行；写失败时回调内的全部修改回滚。
  async mutate(fn) {
    return this.mutex.run(async () => {
      const current = await this.load();
      const snapshot = structuredClone(current);
      const result = await fn(current);
      try {
        await this.#flush();
      } catch (error) {
        this.state = snapshot; // 回滚到事务前状态，绝不留半条记录
        throw error;
      }
      return result;
    });
  }

  async #flush(allowRetry = false) {
    const tmp = `${this.file}.tmp-${process.pid}-${this.clock().toString(36)}`;
    const payload = JSON.stringify(this.state, null, 2);
    // 先写临时文件并 fsync，再原子 rename：任何时刻正式文件要么是旧版要么是新版。
    const handle = await open(tmp, "w");
    try {
      await handle.writeFile(payload, "utf8");
      await handle.sync();
    } finally {
      await handle.close();
    }
    if (this.failNextWrites > 0) {
      this.failNextWrites -= 1;
      await rm(tmp, { force: true });
      throw new Error("injected_disk_failure");
    }
    await rename(tmp, this.file);
    // 目录项变更也 fsync 一下，尽量保证崩溃后 rename 已持久化。
    try {
      const dir = await open(dirname(this.file), "r");
      try { await dir.sync(); } finally { await dir.close(); }
    } catch { /* 某些文件系统不支持目录 fsync，忽略 */ }
    if (allowRetry) { /* 首次初始化路径，无额外处理 */ }
  }

  // ---- 测试/故障恢复用 ----
  injectWriteFailure(times = 1) { this.failNextWrites = times; }

  // 模拟重启：丢弃内存状态，下一次访问从磁盘重新加载。
  async simulateRestart() {
    this.state = null;
    this.failNextWrites = 0;
    return this.load();
  }
}

function mergeSeed(loaded, seed) {
  const out = structuredClone(seed);
  if (loaded) {
    for (const [key, value] of Object.entries(loaded)) {
      if (Array.isArray(seed[key]) && Array.isArray(value)) {
        out[key] = value;
      } else if (isObject(seed[key]) && isObject(value)) {
        out[key] = { ...seed[key], ...value };
      } else {
        out[key] = value;
      }
    }
  }
  return out;
}

function isObject(value) { return value && typeof value === "object" && !Array.isArray(value); }
