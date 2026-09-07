package com.tokyoxpa3.socksclient

/**
 * 連線參數校驗的純邏輯（不依賴 Android，可用 JVM 單元測試）。
 * MainActivity 的表單驗證與 TunSocksService 的啟動前檢查共用同一套規則，
 * 避免同一數值範圍散落兩處而分叉。
 */
object ConfigValidator {

    /** 伺服器參數是否有效：host 非空且 port 在 1..65535。port 為 null（無法解析）視為無效。 */
    fun isServerValid(host: String, port: Int?): Boolean =
        host.isNotEmpty() && port != null && port in 1..65535

    /** 單一 DNS 欄位是否有效：空白視為有效（不填則用預設）；非空白須為數字 IP。 */
    fun isDnsValid(dns: String): Boolean =
        dns.isBlank() || Config.isLiteralIp(dns)
}
