package com.tokyoxpa3.socksclient

/**
 * Per-App 模式的純決策邏輯（不依賴 Android，可用 JVM 單元測試）。
 *
 * 三種模式語意（與 TunSocksService.applyPerAppMode 原本一致）：
 *  - MODE_GLOBAL   ：所有流量走隧道，不加任何限制
 *  - MODE_ALLOWLIST：僅勾選的 App 走隧道；其餘走本機網路
 *  - MODE_EXCLUDE  ：勾選的 App 走本機網路；其餘走隧道
 *
 * 決策結果以「要套用到 VpnService.Builder 的兩個集合」表達：
 *  - [Plan.disallowed]：走本機網路（addDisallowedApplication）
 *  - [Plan.allowed]   ：走隧道（addAllowedApplication，API 30+ 才有）
 *
 * 抽離動機：applyPerAppMode 內含 API 26-29 / 30+ 的分支與 package 差集，
 * 是服務層最容易回歸卻零測試的部分；抽成純函式後可覆蓋全部分支。
 */
object PerAppMode {

    // addAllowedApplication 自 API 30（Android 11）起才可用
    const val API_ADD_ALLOWED = 30

    /** 決策結果：分別列出要走本機網路 / 走隧道的 package。 */
    data class Plan(
        val disallowed: Set<String> = emptySet(),
        val allowed: Set<String> = emptySet()
    )

    /**
     * 判斷是否為「僅允許模式但尚未勾選任何 App」——此狀態下隧道不會涵蓋任何 App，
     * 應在啟動前由 UI 層攔截提示，避免使用者啟動後誤以為已連線。
     */
    fun isEmptyAllowlist(mode: Int, selected: Set<String>): Boolean =
        mode == Config.MODE_ALLOWLIST && selected.isEmpty()

    /**
     * @param mode              Config.MODE_GLOBAL / MODE_ALLOWLIST / MODE_EXCLUDE
     * @param selected          已勾選的 package（空白已由呼叫端過濾）
     * @param installedPackages 完整已安裝 package 清單（僅 ALLOWLIST + API<30 需要，
     *                          用來把「未勾選者」全部設為繞過隧道）
     * @param apiLevel          Build.VERSION.SDK_INT
     */
    fun compute(
        mode: Int,
        selected: Set<String>,
        installedPackages: Collection<String>,
        apiLevel: Int
    ): Plan = when (mode) {
        Config.MODE_EXCLUDE -> Plan(disallowed = selected)

        Config.MODE_ALLOWLIST -> if (apiLevel >= API_ADD_ALLOWED) {
            Plan(allowed = selected)
        } else {
            // API 26-29 無 addAllowedApplication：將「未勾選」的 App 全部設為繞過隧道
            Plan(disallowed = installedPackages.toSet() - selected)
        }

        else -> Plan() // GLOBAL：不加任何限制
    }
}
