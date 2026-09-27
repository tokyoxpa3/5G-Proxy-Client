package com.tokyoxpa3.socksclient

/**
 * 「同機共存」（5G Proxy Pro 與 5G Proxy Client 跑在同一支手機）的純決策邏輯。
 * 不依賴 Android，可用 JVM 單元測試。
 *
 * ## 為什麼一定要把 Pro 留在隧道外
 *
 * Pro 必須把 socket 綁到蜂巢式出口（`Network.bindSocket`）才能走 5G。一旦被本 App 的
 * 隧道接管，這一步會被系統以 `EPERM` 拒絕 —— Pro 不是「變慢」，是**根本起不來**。
 *
 * ## 不變式：Pro 不得進隧道
 *
 * 共存的判準不是「有沒有勾 Pro」，而是「**Pro 有沒有被隧道接管**」。同一個勾選動作在
 * 不同模式下語意相反，所以「共存」對應的操作也不同：
 *
 * | 模式 | 勾選的語意 | 共存成立時 Pro 的狀態 | 能否關閉 |
 * |---|---|---|---|
 * | 排除勾選的 App | 勾選 = 走本機網路 | **勾選** Pro | 可（取消勾選 Pro） |
 * | 指定 App（白名單） | 勾選 = 走隧道 | **不勾** Pro | **不可** —— 見下 |
 * | 全局 | 清單完全不生效 | 無法表達 | 不可 |
 *
 * 指定 App 模式下要「關閉共存」，唯一的手段就是把 Pro 勾進白名單（＝主動送它進隧道），
 * 而那正是要避免的事。因此該模式下共存是**自動成立且鎖定**的（[isLocked]），UI 會把
 * 開關與 Pro 那一列一起鎖住，並用 [sanitize] 把 Pro 擋在勾選清單之外。
 *
 * ## 開關是衍生值，不是第二份狀態
 *
 * 開關狀態完全由 (隧道模式, 勾選清單) 決定，不另存 SharedPreferences 鍵 ——
 * 因此不存在「開關說開了、清單卻沒勾」的不一致。
 */
object Coexist {

    /** 5G Proxy Pro（伺服器端）的套件名。 */
    const val PRO_PACKAGE = "com.tokyoxpa3.androidproxy"

    /** (隧道模式, 勾選清單) 的一組狀態。 */
    data class State(val mode: Int, val selected: Set<String>)

    /** 共存是否成立：Pro 不在隧道內。 */
    fun isOn(mode: Int, selected: Set<String>): Boolean = when (mode) {
        Config.MODE_EXCLUDE -> selected.contains(PRO_PACKAGE)
        Config.MODE_ALLOWLIST -> !selected.contains(PRO_PACKAGE)
        else -> false
    }

    /**
     * 該模式下共存是否「強制成立、不可由使用者關閉」。
     * 僅指定 App 模式如此：關掉它的唯一方式是勾選 Pro，而那等同主動破壞共存。
     */
    fun isLocked(mode: Int): Boolean = mode == Config.MODE_ALLOWLIST

    /**
     * 打開共存。
     *
     * 全局模式表達不了「排除某個 App」（`PerAppMode.compute` 對 GLOBAL 回空 Plan），
     * 因此連帶把模式切到「排除勾選的 App」——UI 上電台按鈕會同步跳過去，是可見行為。
     */
    fun turnOn(mode: Int, selected: Set<String>): State = when (mode) {
        Config.MODE_ALLOWLIST -> State(mode, selected - PRO_PACKAGE)
        else -> State(Config.MODE_EXCLUDE, selected + PRO_PACKAGE)
    }

    /**
     * 關閉共存：只對排除模式有效（其餘模式不可關閉，回傳原狀態）。
     *
     * 注意：排除模式下關閉等於讓 Pro 被隧道接管 —— Pro 會因 `EPERM` 起不來。
     * 這是使用者的明確選擇，UI 以提示（而非默默修正）回應。
     */
    fun turnOff(mode: Int, selected: Set<String>): State = when (mode) {
        Config.MODE_EXCLUDE -> State(mode, selected - PRO_PACKAGE)
        else -> State(mode, selected)
    }

    /**
     * 把「Pro 不得進隧道」的不變式套用到勾選清單。
     *
     * 指定 App 模式下勾了 Pro 等於主動要求把它送進隧道 → 移除。
     * 排除模式交由開關決定，不在此強制（否則使用者就無法關閉共用了）。
     */
    fun sanitize(mode: Int, selected: Set<String>): Set<String> =
        if (mode == Config.MODE_ALLOWLIST) selected - PRO_PACKAGE else selected
}
