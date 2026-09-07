package com.tokyoxpa3.socksclient

import org.junit.Assert.assertEquals
import org.junit.Test

class AppListFilterTest {

    private val apps = listOf(
        AppListFilter.Entry("com.example.app", "Example App", system = false),
        AppListFilter.Entry("com.android.settings", "Settings", system = true),
        AppListFilter.Entry("com.example.games", "Example Games", system = false),
        AppListFilter.Entry("com.android.systemui", "System UI", system = true)
    )

    @Test
    fun blankQueryShowsAllWhenShowSystem() {
        assertEquals(apps, AppListFilter.filter(apps, "", showSystem = true))
    }

    @Test
    fun blankQueryHidesSystemWhenDisabled() {
        assertEquals(listOf(apps[0], apps[2]), AppListFilter.filter(apps, "", showSystem = false))
    }

    @Test
    fun queryMatchesLabelOrPkg() {
        val byLabel = AppListFilter.filter(apps, "example", showSystem = true)
        assertEquals(listOf(apps[0], apps[2]), byLabel)

        val byPkg = AppListFilter.filter(apps, "systemui", showSystem = true)
        assertEquals(listOf(apps[3]), byPkg)
    }

    @Test
    fun queryIsCaseInsensitive() {
        assertEquals(listOf(apps[0], apps[2]), AppListFilter.filter(apps, "EXAMPLE", showSystem = true))
    }

    @Test
    fun queryExcludingSystemAppsReturnsNothingWhenOnlySystemMatches() {
        // "system" 只命中系統 App（System UI / com.android.systemui），showSystem=false 時全部被排除
        assertEquals(emptyList<AppListFilter.Entry>(), AppListFilter.filter(apps, "system", showSystem = false))
    }
}
