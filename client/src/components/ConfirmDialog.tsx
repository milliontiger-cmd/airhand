// 确认弹窗：关闭控制台 / 切换为被控端（会断开所有会话）；LAN 连上后问要不要保存这台电脑。
import { useEffect, type PointerEvent as ReactPointerEvent } from "react";
import { confirmLanSave, dismissLanSave, quit } from "../lib/actions";
import { useT } from "../lib/i18n";
import { store, useStore } from "../lib/store";
import { IconPlus, IconPower } from "./Icons";

/** 点取消 / Esc / 遮罩：LAN 保存默认不保存，别的确认就是取消 */
function cancelConfirm() {
  const c = store.get().confirm;
  if (c?.kind === "lanSave") dismissLanSave();
  else store.setConfirm(null);
}

export function ConfirmDialog() {
  const t = useT();
  const c = useStore((s) => s.confirm);

  useEffect(() => {
    if (!c) return;
    const esc = (e: KeyboardEvent) => {
      if (e.key === "Escape") cancelConfirm();
    };
    window.addEventListener("keydown", esc);
    return () => window.removeEventListener("keydown", esc);
  }, [c]);

  if (!c) return null;
  const backdrop = {
    className: "modal-backdrop",
    "data-tauri-drag-region": "false",
    onPointerDown: (e: ReactPointerEvent<HTMLDivElement>) => e.target === e.currentTarget && cancelConfirm(),
  };

  if (c.kind === "lanSave") {
    return (
      <div {...backdrop}>
        <div className="modal" role="alertdialog" aria-modal="true" aria-labelledby="confirm-title">
          <div className="modal-icon save-icon">
            <IconPlus size={20} />
          </div>
          <h3 id="confirm-title">{t("confirm.lanSave.title")}</h3>
          <p>{t("confirm.lanSave.body", { addr: c.addr })}</p>
          <div className="modal-actions">
            {/* 默认焦点在"保存"上：Enter 保存，Esc / 点别处不保存 */}
            <button className="ghost-btn" onClick={cancelConfirm}>
              {t("confirm.lanSave.no")}
            </button>
            <button className="primary-btn" autoFocus onClick={confirmLanSave}>
              {t("confirm.lanSave.ok")}
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div {...backdrop}>
      <div className="modal" role="alertdialog" aria-modal="true" aria-labelledby="confirm-title">
        <div className="modal-icon">
          <IconPower size={20} />
        </div>
        <h3 id="confirm-title">{t(`confirm.${c.kind}.title`)}</h3>
        <p>{t(`confirm.${c.kind}.body`, { n: c.sessions })}</p>
        <div className="modal-actions">
          <button className="ghost-btn" onClick={cancelConfirm}>
            {t("confirm.cancel")}
          </button>
          <button className="danger-btn" autoFocus onClick={() => void quit(c.kind)}>
            {t(`confirm.${c.kind}.ok`)}
          </button>
        </div>
      </div>
    </div>
  );
}
