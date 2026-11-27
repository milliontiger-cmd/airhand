// "局域网直连"里保存过的电脑：id 与 Rust 端对齐，列表只存遮罩后的账号密码
import assert from "node:assert/strict";
import { test } from "node:test";
import type { SavedLanDevice } from "../src/lib/api.ts";
import {
  MASKED,
  forgetLanDevice,
  lanAddr,
  lanDeviceId,
  lanTitle,
  matchLanDevice,
  rememberLan,
  renameLanDevice,
  restoreLanDevice,
} from "../src/lib/lan-devices.ts";

const q = { fps: 60, bitrateKbps: 8000, maxShort: 1080, adaptive: true, codec: "h264" as const };
const seen = (ip: string, port: string, name: string) => ({
  id: lanDeviceId(ip, port),
  addr: ip,
  port,
  name,
  os: "Windows 11",
  quality: q,
});

test("id 与 Rust 端 lan_devices::id_for 一致，且不泄露明文地址", () => {
  const id = lanDeviceId("192.168.1.10", "4900");
  assert.equal(id, "96d05ae74e8e6f59971e1738648663e7");
  assert.equal(id, lanDeviceId("192.168.1.10", "4900"));
  assert.notEqual(id, lanDeviceId("192.168.1.11", "4900"));
  assert.equal(id.includes("192.168"), false);
});

test("连上就记下；账号密码只有遮罩，重复连接保留自定义名字并按时间排序", () => {
  const a = seen("192.168.1.10", "4900", "DESIGN-WS");
  const b = seen("192.168.1.11", "4900", "NAS");
  let list: SavedLanDevice[] = [];
  list = rememberLan(list, a, 1000);
  list = rememberLan(list, b, 2000);
  assert.deepEqual(
    list.map((d) => lanAddr(d)),
    ["192.168.1.11:4900", "192.168.1.10:4900"],
  );
  assert.equal(list[0].accountMasked, MASKED);
  assert.equal(list[0].passwordMasked, MASKED);
  assert.equal(JSON.stringify(list).includes("s3cret"), false);

  list = renameLanDevice(list, a.id, "书房");
  list = rememberLan(list, { ...a, name: "NEW-NAME" }, 3000);
  assert.equal(list[0].id, a.id);
  assert.equal(list[0].alias, "书房");
  assert.equal(list[0].name, "NEW-NAME");
  assert.equal(lanTitle(list[0]), "书房");
  assert.equal(list.length, 2);
});

test("移除/撤销/搜索按 IP 或端口", () => {
  const a = seen("192.168.1.10", "4900", "DESIGN-WS");
  const list = rememberLan([], a, 1000);
  assert.equal(matchLanDevice(list[0], "1.10"), true);
  assert.equal(matchLanDevice(list[0], "4900"), true);
  assert.equal(matchLanDevice(list[0], "nope"), false);
  const gone = forgetLanDevice(list, a.id);
  assert.equal(gone.length, 0);
  assert.deepEqual(restoreLanDevice(gone, list[0]), list);
});
