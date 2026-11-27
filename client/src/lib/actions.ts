// 跨组件的操作：连接、我的设备、重新打开关闭的会话、关闭控制台 / 切换为被控端（先确认）、全屏。
import {
  api,
  toProblem,
  type QualitySettings,
  type SavedDevice,
  type SavedLanDevice,
  type SavedLanDeviceInput,
} from "./api";
import * as devices from "./devices";
import * as lanDevices from "./lan-devices";
import { OS } from "./platform";
import { RemoteSession } from "./session";
import { emptyDraft, store } from "./store";

export { fmtCode } from "./devices";

/** 新建连接标签里正在连的会话（关掉这个标签就放弃） */
let pending: RemoteSession | null = null;

/**
 * 怎么连：配对码（对方要求配对时；对方的身份变了、用户确认是重装之后也是重新配对，
 * 配对码认的就是对方，记着的旧公钥不作数，见 airhand_proto::handshake 的"身份"）
 */
export interface OpenOptions {
  pairing?: string | null;
}

/**
 * 连接控制码为 `code` 的电脑，在新建连接标签里显示进度和错误，连上后这个标签变成会话标签。
 * 已经有这台电脑的标签：切过去（断开了就重新连接）。
 */
export async function openSession(code: string, settings: QualitySettings, opts: OpenOptions = {}): Promise<void> {
  const st = store.get();
  const dup = st.sessions.find((s) => s.code === code);
  if (dup) {
    if (st.view === "new") store.closeDraft();
    store.setView(dup.id);
    if (dup.state === "closed") {
      if (opts.pairing) dup.pairWith(opts.pairing);
      else dup.reconnect();
    }
    return;
  }
  if (!st.draft) store.newTab();
  if (store.get().draft?.busy) return;
  store.patchDraft({ digits: code.split(""), busy: true, error: null });
  // 我的设备里有：带着上次的重连凭证连（对方不在线时等它上线，而不是报错），连上之前就显示它的名字；
  // 只认记着的对方公钥（带着配对码时认配对码，连上之后记下对方现在的公钥）
  const saved = st.devices.find((d) => d.code === code);
  const s = new RemoteSession(code, settings, saved, opts.pairing);
  pending = s;
  try {
    await s.open();
    if (pending !== s) {
      // 等待期间关掉了新建连接标签
      s.dispose();
      return;
    }
    store.add(s);
    // 连上了就记进我的设备（在等对方上线的，等连上时再记）；之后每次重连、改画质也更新
    if (s.sid !== null) rememberSession(s);
    s.onConnected = rememberSession;
    s.onSettingsChange = rememberQuality;
    s.onInputSettingsChange = rememberInputSettings;
  } catch (e) {
    s.dispose();
    if (pending === s) store.patchDraft({ busy: false, error: toProblem(e) });
  } finally {
    if (pending === s) pending = null;
  }
}

/** 等待用户回答"要不要保存这台 LAN 电脑"的连接：明文凭证只放在这里，不进 store */
const lanSavePending = new Map<
  string,
  { ip: string; port: string; account: string; password: string; s: RemoteSession }
>();
/** 已经问过（保存或不保存）的会话：断线重连不再问第二次 */
const lanSaveDone = new Set<string>();

/** 连接局域网直连的被控端（不经过中转服务器），在新建连接标签里显示进度和错误，连上后这个标签变成会话标签。 */
export async function openLanSession(
  addr: string,
  account: string,
  password: string,
  settings: QualitySettings,
): Promise<void> {
  const st = store.get();
  if (!st.draft) store.newTab();
  if (store.get().draft?.busy) return;
  // 局域网直连没有控制码、也不进"我的设备"：code 用一个占位（界面用 hostName / 账号显示标题）
  store.patchDraft({ digits: Array(6).fill(""), busy: true, error: null });
  const cut = addr.lastIndexOf(":");
  const ip = cut < 0 ? addr : addr.slice(0, cut);
  const port = cut < 0 ? "" : addr.slice(cut + 1);
  const s = new RemoteSession(account, settings, undefined, null, { addr, account, password });
  pending = s;
  const id = lanDevices.lanDeviceId(ip, port);
  // 已经在列表里的：只刷新最近使用时间等信息，不再问；新电脑：连上后问一次要不要保存
  const onLanConnected = () => {
    if (store.get().lanDevices.some((d) => d.id === id)) {
      rememberLanSession(ip, port, account, password, s);
      return;
    }
    askLanSave(ip, port, account, password, s);
  };
  try {
    await s.open();
    if (pending !== s) {
      s.dispose();
      return;
    }
    store.add(s);
    if (s.sid !== null) onLanConnected();
    s.onConnected = onLanConnected;
    s.onSettingsChange = () =>
      setLanDevices(lanDevices.patchLanDevice(store.get().lanDevices, id, { quality: s.settings }));
    s.onInputSettingsChange = () => {};
  } catch (e) {
    s.dispose();
    if (pending === s) store.patchDraft({ busy: false, error: toProblem(e) });
  } finally {
    if (pending === s) pending = null;
  }
}

/** 连上了一台新电脑：弹窗问用户，选"不保存"就什么都不写 */
function askLanSave(ip: string, port: string, account: string, password: string, s: RemoteSession) {
  // 同一个会话断线重连不再重复问；用户拒绝了就是拒绝了
  if (lanSaveDone.has(s.id) || lanSavePending.has(s.id)) return;
  lanSavePending.set(s.id, { ip, port, account, password, s });
  store.setConfirm({ kind: "lanSave", token: s.id, addr: `${ip}:${port}` });
}

/** 用户点了"保存"：这才把四个连接参数交给 Rust 加密保存 */
export function confirmLanSave() {
  const c = store.get().confirm;
  if (c?.kind !== "lanSave") return;
  store.setConfirm(null);
  lanSaveDone.add(c.token);
  const req = lanSavePending.get(c.token);
  lanSavePending.delete(c.token);
  if (req) rememberLanSession(req.ip, req.port, req.account, req.password, req.s);
}

/** 用户点了"不保存"、按 Esc 或点了遮罩：丢掉暂存的明文，不写盘 */
export function dismissLanSave() {
  const c = store.get().confirm;
  if (c?.kind === "lanSave") {
    lanSaveDone.add(c.token);
    lanSavePending.delete(c.token);
  }
  store.setConfirm(null);
}

/**
 * 点"局域网直连"列表里的一台：只取回这一台的明文连接参数（账号密码不进列表状态），然后照常连接。
 */
export async function openSavedLanDevice(d: SavedLanDevice, settings: QualitySettings): Promise<void> {
  if (!store.get().draft) store.newTab();
  if (store.get().draft?.busy) return;
  store.patchDraft({ mode: "lan", error: null });
  try {
    const c = await api.lanDeviceCredentials(d.id);
    if (store.get().draft?.busy) return;
    // 明文只交给会话和加密保存，不回填到输入框（界面上账号密码始终是遮罩）
    await openLanSession(`${c.addr.trim()}:${c.port.trim()}`, c.account, c.password, d.quality ?? settings);
  } catch (e) {
    store.patchDraft({ busy: false, error: toProblem(e) });
  }
}

/** 关闭新建连接标签（正在连接就放弃） */
export function closeDraft() {
  const st = store.get();
  if (!st.draft || st.sessions.length === 0) return;
  pending = null;
  store.closeDraft();
}

/** 关闭标签：会话标签 = 断开连接，新建连接标签 = 放弃输入 */
export function closeTab(view: string) {
  if (view === "new") closeDraft();
  else if (view !== "grid") store.remove(view);
}

/** 重新打开最近关闭的会话（Ctrl+Shift+T） */
export function reopenLast() {
  const r = store.get().recent[0];
  if (!r) return;
  store.newTab();
  void openSession(r.code, r.settings);
}

// ── 我的设备 ──

/** 读出保存的设备（打开控制台时） */
export async function loadDevices() {
  const list = await api.loadDevices().catch((e) => {
    console.warn("can't load the saved devices", e);
    return null;
  });
  // 读的时候控制台里可能已经记下了新连上的（很少见）：合在一起
  const now = store.get().devices;
  const merged = list ? devices.sortDevices([...now, ...list.filter((d) => !now.some((x) => x.code === d.code))]) : now;
  store.setDevices(merged.slice(0, devices.MAX_DEVICES), list !== null);
  if (list && now.length > 0) scheduleSave("devices");
}

/** 读出保存的 LAN 电脑（打开控制台时） */
export async function loadLanDevices() {
  const list = await api.loadLanDevices().catch((e) => {
    console.warn("can't load the saved LAN computers", e);
    return null;
  });
  const now = store.get().lanDevices;
  const merged = list
    ? lanDevices.sortLanDevices([...now, ...list.filter((d) => !now.some((x) => x.id === d.id))])
    : now;
  store.setLanDevices(merged.slice(0, lanDevices.MAX_LAN_DEVICES), list !== null);
  if (list && now.length > 0) scheduleSave("lan");
}

/** 保存：一次只存一份，存的时候取最新的列表（连续几次变化只存最后一次，也不会旧的盖掉新的） */
let saving: Promise<void> = Promise.resolve();
let dirtyDevices = false;
let dirtyLan = false;
/** 还没存完的次数 */
let unsaved = 0;
/** 刚连上的电脑的明文账号密码：只在内存里待到 Rust 加密写盘为止，不进 React 状态 */
const pendingLanSecrets = new Map<string, { account: string; password: string }>();

function scheduleSave(which: "devices" | "lan") {
  if (which === "devices" && !store.get().devicesSaved) return;
  if (which === "lan" && !store.get().lanDevicesSaved) return;
  if (which === "devices") dirtyDevices = true;
  else dirtyLan = true;
  unsaved++;
  saving = saving.then(async () => {
    try {
      if (dirtyDevices) {
        dirtyDevices = false;
        await api.saveDevices(store.get().devices).catch((e) => console.warn("can't save the devices", e));
      }
      if (dirtyLan) {
        dirtyLan = false;
        const inputs: SavedLanDeviceInput[] = store.get().lanDevices.map((d) => ({
          id: d.id,
          addr: d.addr,
          port: d.port,
          // 空串 = 沿用文件里已加密保存的值（列表里只有遮罩）
          account: pendingLanSecrets.get(d.id)?.account ?? "",
          password: pendingLanSecrets.get(d.id)?.password ?? "",
          alias: d.alias,
          name: d.name,
          os: d.os,
          lastUsed: d.lastUsed,
          quality: d.quality,
        }));
        const sent = inputs.filter((d) => d.account || d.password).map((d) => d.id);
        let ok = true;
        await api
          .saveLanDevices(inputs)
          .catch((e) => {
            ok = false;
            console.warn("can't save the LAN computers", e);
          });
        if (ok) for (const id of sent) pendingLanSecrets.delete(id);
      }
    } finally {
      unsaved--;
    }
  });
}

function setDevices(list: SavedDevice[]) {
  if (list === store.get().devices) return;
  store.setDevices(list);
  scheduleSave("devices");
}

function setLanDevices(list: SavedLanDevice[]) {
  if (list === store.get().lanDevices) return;
  store.setLanDevices(list);
  scheduleSave("lan");
}

/** 连上 LAN 电脑：记到"局域网直连"页最下面，四个连接参数交给 Rust 加密保存 */
function rememberLanSession(
  ip: string,
  port: string,
  account: string,
  password: string,
  s: RemoteSession,
) {
  const id = lanDevices.lanDeviceId(ip, port);
  pendingLanSecrets.set(id, { account, password });
  setLanDevices(
    lanDevices.rememberLan(
      store.get().lanDevices,
      { id, addr: ip, port, name: s.hostName, os: s.hostOs, quality: s.settings },
      Date.now(),
    ),
  );
}

/** 连上了：记下这台电脑（名字、系统、重连凭证、画质、鼠标模式、时间） */
export function rememberSession(s: RemoteSession) {
  const seen = {
    code: s.code,
    name: s.hostName,
    os: s.hostOs,
    resume: s.resumeToken,
    quality: s.settings,
    hostKey: s.hostKey,
    mouse: s.mouseMode,
    swapCtrlCommand: s.swapCtrlCommand,
  };
  setDevices(devices.remember(store.get().devices, seen, Date.now()));
}

/** 画质改了：下次用同样的画质连（只更新已经记下的） */
function rememberQuality(s: RemoteSession) {
  setDevices(devices.patchDevice(store.get().devices, s.code, { quality: s.settings }));
}

/** 输入偏好按设备记住（只更新已经记下的） */
function rememberInputSettings(s: RemoteSession) {
  setDevices(devices.patchDevice(store.get().devices, s.code, { mouse: s.mouseMode, swapCtrlCommand: s.swapCtrlCommand }));
}

export const renameDevice = (code: string, name: string) =>
  setDevices(devices.renameDevice(store.get().devices, code, name));
export const forgetDevice = (code: string) => setDevices(devices.forgetDevice(store.get().devices, code));
export const restoreDevice = (d: SavedDevice) => setDevices(devices.restoreDevice(store.get().devices, d));

export const renameLanDevice = (id: string, name: string) =>
  setLanDevices(lanDevices.renameLanDevice(store.get().lanDevices, id, name));
export const forgetLanDevice = (id: string) => setLanDevices(lanDevices.forgetLanDevice(store.get().lanDevices, id));
export const restoreLanDevice = (d: SavedLanDevice) =>
  setLanDevices(lanDevices.restoreLanDevice(store.get().lanDevices, d));

/** 等正在保存的存完（关闭控制台之前） */
const devicesSaved = () => Promise.race([saving, new Promise((r) => setTimeout(r, 1500))]);

/** 键盘回到当前会话的远程画面（关掉主菜单之后等） */
export function focusActive() {
  const st = store.get();
  st.sessions.find((s) => s.id === st.view)?.focus();
}

/** 新建连接标签：清空输入 */
export function resetDraft() {
  store.patchDraft(emptyDraft());
}

// ── 关闭控制台 / 切换为被控端 ──

/** 还连着（或者在等、在重连）的会话数：为 0 时关闭控制台不会丢掉什么，不用问 */
const activeSessions = () => store.get().sessions.filter((s) => s.state !== "closed").length;

/**
 * 窗口要关闭了（标题栏的关闭按钮、任务栏、Alt+F4、macOS 的红灯，见 App 里的 onCloseRequested）：
 * 关闭控制台 = 断开所有会话、回到被控端模式，有会话时先问一下。返回 true 表示直接关
 */
export function allowClose(): boolean {
  const n = activeSessions();
  if (n > 0) {
    // 上一个"要不要保存 LAN 电脑"的询问作废，明文凭证也一起丢掉
    dismissLanSave();
    store.setConfirm({ kind: "close", sessions: n });
    return false;
  }
  // 我的设备还没存完：存完再关
  if (unsaved > 0) {
    void devicesSaved().then(() => api.frame?.destroy());
    return false;
  }
  return true;
}

/** 切换为被控端（关闭控制台）。有会话时先问一下 */
export function requestToHost() {
  const n = activeSessions();
  if (n === 0) return void quit("toHost");
  dismissLanSave();
  store.setConfirm({ kind: "toHost", sessions: n });
}

/** 用户确认之后 */
export async function quit(kind: "close" | "toHost") {
  store.setConfirm(null);
  await devicesSaved();
  if (kind === "toHost" || !api.frame) await api.switchToHost();
  else await api.frame.destroy();
}

// ── 全屏 ──

// Keyboard Lock API：全屏时捕获 Win、Alt+Tab 等系统快捷键并发送给远端
type KeyboardLock = { lock?: (codes?: string[]) => Promise<void>; unlock?: () => void };
const keyboardApi = () => (navigator as Navigator & { keyboard?: KeyboardLock }).keyboard;

// macOS 桌面版只用窗口全屏：WKWebView 不支持键盘锁定，网页全屏没有用处，
// 而且 WebKit 会把网页挪进它自己的全屏窗口，再加上窗口全屏就成了两个全屏空间
const WEB_FULLSCREEN = !(api.frame && OS === "mac");

/** 进入 / 退出全屏（网页全屏 + 键盘锁定 + 窗口全屏）。可以重复调用 */
export async function applyFullscreen(on: boolean) {
  if (WEB_FULLSCREEN && on) {
    // 先进入网页全屏（Keyboard Lock 的前提），再让窗口全屏
    if (!document.fullscreenElement) await document.documentElement.requestFullscreen?.().catch(() => {});
    await keyboardApi()?.lock?.().catch(() => {});
  } else if (WEB_FULLSCREEN) {
    keyboardApi()?.unlock?.();
    if (document.fullscreenElement) await document.exitFullscreen().catch(() => {});
  }
  await api.setWindowFullscreen(on).catch(() => {});
}

export async function toggleFullscreen() {
  const next = !store.get().immersive;
  store.setImmersive(next);
  await applyFullscreen(next);
}

