// 局域网直连设置窗口（桌面版托盘菜单"局域网直连设置…"打开，见 src-tauri/src/lib.rs 的 open_lan_settings）。
//
// 和无边框窗口一样：顶部是拖动区 + 标题，下面是表单，关闭按钮由界面画（见 api.frame.close）。
// 保存时调 api.lanSettingsSave，密码只在本地派生 PSK，不存密码、不上线；保存成功后关闭窗口。
import { useEffect, useState } from "react";
import { api } from "../lib/api";
import { useT } from "../lib/i18n";
import { NATIVE_WINDOW_BUTTONS } from "../lib/platform";
import { IconWarn, IconWinClose } from "./Icons";

export function LanSettingsView() {
  const t = useT();
  const [enabled, setEnabled] = useState(true);
  const [listen, setListen] = useState("0.0.0.0:4900");
  const [account, setAccount] = useState("admin");
  const [password, setPassword] = useState("");
  const [loaded, setLoaded] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void api.lanSettingsLoad().then((s) => {
      setEnabled(s.enabled);
      setListen(s.listen);
      setAccount(s.account);
      setLoaded(true);
    });
    // Esc 关闭窗口
    const esc = (e: KeyboardEvent) => {
      if (e.key === "Escape") void api.frame?.close();
    };
    window.addEventListener("keydown", esc);
    return () => window.removeEventListener("keydown", esc);
  }, []);

  const save = async () => {
    if (saving) return;
    setError(null);
    // 端口合法性在 Rust 端再校验一遍；这里先做基本的空值检查
    if (!account.trim()) {
      setError(t("lanSettings.accountEmpty"));
      return;
    }
    if (!listen.trim()) {
      setError(t("lanSettings.listenEmpty"));
      return;
    }
    setSaving(true);
    try {
      await api.lanSettingsSave({
        enabled,
        listen: listen.trim(),
        account: account.trim(),
        password,
      });
      // 保存成功后关闭窗口。窗口关闭有权限或异步失败时，按钮也不能一直停在"保存中"。
      api.frame?.close().catch(() => {});
      setSaving(false);
    } catch (e) {
      setError(String(e));
      setSaving(false);
    }
  };

  return (
    <div className="lan-settings" data-tauri-drag-region="deep">
      <header className={`lan-settings-titlebar ${NATIVE_WINDOW_BUTTONS ? "native-buttons" : ""}`} data-tauri-drag-region="deep">
        <span className="lan-settings-title" data-tauri-drag-region="deep">
          {t("lanSettings.title")}
        </span>
        {api.frame && !NATIVE_WINDOW_BUTTONS && (
          <button
            className="win-btn"
            title={t("lanSettings.close")}
            onClick={() => void api.frame?.close()}
          >
            <IconWinClose />
          </button>
        )}
      </header>

      <div className="lan-settings-body">
        <label className="lan-settings-row">
          <span className="lan-settings-label">{t("lanSettings.enabled")}</span>
          <input
            type="checkbox"
            checked={enabled}
            disabled={!loaded}
            onChange={(e) => setEnabled(e.target.checked)}
          />
        </label>

        <div className="lan-settings-field">
          <span className="lan-settings-label">{t("lanSettings.listen")}</span>
          <input
            value={listen}
            autoComplete="off"
            spellCheck={false}
            placeholder="0.0.0.0:4900"
            disabled={!loaded || saving}
            aria-label={t("lanSettings.listen")}
            onChange={(e) => setListen(e.target.value)}
          />
          <div className="preset-desc muted small">{t("lanSettings.listenHint")}</div>
        </div>

        <div className="lan-settings-field">
          <span className="lan-settings-label">{t("lanSettings.account")}</span>
          <input
            value={account}
            autoComplete="off"
            spellCheck={false}
            disabled={!loaded || saving}
            aria-label={t("lanSettings.account")}
            onChange={(e) => setAccount(e.target.value)}
          />
        </div>

        <div className="lan-settings-field">
          <span className="lan-settings-label">{t("lanSettings.password")}</span>
          <input
            type="password"
            value={password}
            autoComplete="new-password"
            disabled={!loaded || saving}
            aria-label={t("lanSettings.password")}
            onChange={(e) => setPassword(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") void save();
            }}
          />
          <div className="preset-desc muted small">{t("lanSettings.passwordHint")}</div>
        </div>

        {error && (
          <div className="error-box" role="alert">
            <IconWarn size={15} />
            <span>{error}</span>
          </div>
        )}

        <div className="lan-settings-actions">
          <button className="ghost-btn" onClick={() => void api.frame?.close()} disabled={saving}>
            {t("lanSettings.cancel")}
          </button>
          <button className="primary-btn" onClick={() => void save()} disabled={!loaded || saving}>
            {saving ? t("lanSettings.saving") : t("lanSettings.save")}
          </button>
        </div>
      </div>
    </div>
  );
}
