// "局域网直连"里连接过的电脑的列表操作（纯函数）。四个连接参数由 Rust 端加密写进 config.toml 的
// [[lanDevice]]（见 src-tauri/src/lan_devices.rs）；这里的状态只放 IP/端口明文和账号/密码的遮罩。
import type { QualitySettings, SavedLanDevice } from "./api";

/** 最多保存多少台（与 Rust 端 lan_devices::MAX 相同） */
export const MAX_LAN_DEVICES = 50;

/** 遮罩：和 Rust 端 lan_devices::mask 保持一致，明文不进列表状态 */
export const MASKED = "••••••";

/** 列表标题：自己起的名字 > 对方的设备名 > IP:端口 */
export const lanTitle = (d: SavedLanDevice) => d.alias?.trim() || d.name.trim() || lanAddr(d);
export const lanAddr = (d: SavedLanDevice) => `${d.addr}:${d.port}`;

/** 最近连过的在前面 */
export const sortLanDevices = (list: SavedLanDevice[]) => [...list].sort((a, b) => b.lastUsed - a.lastUsed);

/**
 * `IP:端口` 的 128 位散列，与 Rust 端 `lan_devices::id_for` 一致（两个 FNV-1a）。
 * 文件里不存明文地址；这里只用来给刚连上的电脑排列表，真正保存时后端还会再算一遍。
 */
export function lanDeviceId(addr: string, port: string): string {
  const key = `${addr.trim()}:${port.trim()}`;
  const mask = (1n << 64n) - 1n;
  let a = 0xcbf29ce484222325n;
  let b = 0x9ae16a3b2f90404fn;
  for (const byte of new TextEncoder().encode(key)) {
    const c = BigInt(byte);
    a = ((a ^ c) * 0x100000001b3n) & mask;
    b = (((b ^ c) * 0x100000001b3n) & mask);
    b = ((b << 13n) | (b >> 51n)) & mask;
  }
  return a.toString(16).padStart(16, "0") + b.toString(16).padStart(16, "0");
}

/** 连上了：记下（或更新）这台电脑。账号/密码只存遮罩，明文由 actions.ts 交给后端加密保存 */
export function rememberLan(
  list: SavedLanDevice[],
  seen: {
    id: string;
    addr: string;
    port: string;
    name: string;
    os: string;
    quality: QualitySettings | null;
  },
  now: number,
): SavedLanDevice[] {
  const old = list.find((d) => d.id === seen.id);
  const d: SavedLanDevice = {
    id: seen.id,
    addr: seen.addr.trim(),
    port: seen.port.trim(),
    accountMasked: MASKED,
    passwordMasked: MASKED,
    alias: old?.alias ?? null,
    name: seen.name.trim() || old?.name || "",
    os: seen.os.trim() || old?.os || "",
    lastUsed: now,
    quality: seen.quality ?? old?.quality ?? null,
  };
  return sortLanDevices([d, ...list.filter((x) => x.id !== seen.id)]).slice(0, MAX_LAN_DEVICES);
}

/** 更新名字或画质（列表里没有就什么也不变） */
export function patchLanDevice(
  list: SavedLanDevice[],
  id: string,
  patch: Partial<Pick<SavedLanDevice, "alias" | "quality">>,
) {
  if (!list.some((d) => d.id === id)) return list;
  return list.map((d) => (d.id === id ? { ...d, ...patch } : d));
}

/** 重命名：和对方的设备名一样、或者清空，就是不另起名字 */
export function renameLanDevice(list: SavedLanDevice[], id: string, name: string) {
  const d = list.find((x) => x.id === id);
  if (!d) return list;
  const n = name.trim();
  return patchLanDevice(list, id, { alias: n && n !== d.name ? n : null });
}

export const forgetLanDevice = (list: SavedLanDevice[], id: string) => list.filter((d) => d.id !== id);

/** 撤销移除：放回原来的位置（按最后连接时间） */
export const restoreLanDevice = (list: SavedLanDevice[], d: SavedLanDevice) =>
  sortLanDevices([d, ...list.filter((x) => x.id !== d.id)]).slice(0, MAX_LAN_DEVICES);

/** 搜索：名字、IP、端口 */
export function matchLanDevice(d: SavedLanDevice, query: string): boolean {
  const q = query.trim().toLowerCase();
  return !q || lanTitle(d).toLowerCase().includes(q) || lanAddr(d).includes(q) || d.port.includes(q);
}
