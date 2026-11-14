/**
 * ============================================================================
 * AdShield - تطبيق مانع إعلانات متكامل للأندرويد (بآلية AdGuard + فلاتر تجميلية)
 * ============================================================================
 *
 * متطلبات الإعداد في مشروع Android Studio (ملف app/build.gradle.kts):
 * ----------------------------------------------------------------------------
 * dependencies {
 *     implementation("androidx.core:core-ktx:1.13.1")
 *     implementation("androidx.activity:activity-compose:1.9.2")
 *     implementation(platform("androidx.compose:compose-bom:2024.09.00"))
 *     implementation("androidx.compose.ui:ui")
 *     implementation("androidx.compose.material3:material3")
 *     implementation("androidx.compose.material:material-icons-extended")
 *     implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
 * }
 *
 * متطلبات ملف AndroidManifest.xml:
 * ----------------------------------------------------------------------------
 * <uses-permission android:name="android.permission.INTERNET" />
 * <uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
 * <uses-permission android:name="android.permission.FOREGROUND_SERVICE_SPECIAL_USE" />
 * <uses-permission android:name="android.permission.QUERY_ALL_PACKAGES" />
 *
 * داخل وسم <application>:
 * <service
 *     android:name=".AdShieldVpnService"
 *     android:permission="android.permission.BIND_VPN_SERVICE"
 *     android:foregroundServiceType="specialUse"
 *     android:exported="false">
 *     <intent-filter>
 *         <action android:name="android.net.VpnService" />
 *     </intent-filter>
 * </service>
 * ============================================================================
 */

package com.adshield.app

import android.app.Activity
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.ProxyInfo
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.ParcelFileDescriptor
import android.security.KeyChain
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import org.json.JSONArray
import org.json.JSONObject
import java.io.*
import java.math.BigInteger
import java.net.*
import java.nio.ByteBuffer
import java.security.KeyPairGenerator
import java.security.Signature
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import javax.net.ssl.SSLSocketFactory

// ============================================================================
// 1. نماذج البيانات الأساسية (Data Models)
// ============================================================================

/**
 * يمثل قائمة فلتر واحدة (افتراضية أو مخصصة أضافها المستخدم عبر رابط)
 */
data class FilterListItem(
    val id: String,
    val name: String,
    val description: String,
    val url: String,
    val isDefault: Boolean = false,
    val enabled: Boolean = true,
    val rulesCount: Int = 0,
    val blockedCount: Long = 0L,
    val colorHex: Long = 0xFF10B981
)

/**
 * يمثل تطبيقاً مثبتاً على هاتف المستخدم مع إعدادات التوجيه وفلترة HTTPS المستقلة
 */
data class ManagedAppItem(
    val packageName: String,
    val appName: String,
    val isPopularBrowser: Boolean,
    val routeThroughVpn: Boolean = true,
    val httpsFilteringEnabled: Boolean = isPopularBrowser
)

/**
 * الحالة اللحظية العامة للتطبيق والخدمة
 */
data class AdShieldUiState(
    val isVpnActive: Boolean = false,
    val isUpdatingFilters: Boolean = false,
    val lastUpdateText: String = "لم يتم التحديث بعد",
    val lastBlockedDomain: String = "في انتظار حركة الشبكة...",
    val lastBlockedFilterName: String = "",
    val cosmeticElementsHidden: Long = 0L,
    val certificateInstalled: Boolean = false,
    val filters: List<FilterListItem> = emptyList(),
    val apps: List<ManagedAppItem> = emptyList()
)

// ============================================================================
// 2. قائمة المتصفحات الشهيرة المعتمدة لتفعيل HTTPS تلقائياً
// ============================================================================

object BrowserRegistry {
    /**
     * أسماء الحزم (Package Names) لأشهر متصفحات الأندرويد.
     * يتم تفعيل فلترة HTTPS التجميلية لها تلقائياً، بينما تظل مغلقة افتراضياً
     * لباقي التطبيقات لحماية التطبيقات التي تستخدم SSL Pinning (مثل البنوك).
     */
    val POPULAR_BROWSERS: Set<String> = setOf(
        "com.android.chrome",              // Google Chrome
        "com.chrome.beta",                 // Chrome Beta
        "com.chrome.dev",                  // Chrome Dev
        "org.mozilla.firefox",             // Mozilla Firefox
        "org.mozilla.firefox_beta",        // Firefox Beta
        "org.mozilla.fenix",               // Firefox Nightly
        "com.opera.browser",               // Opera Browser
        "com.opera.mini.native",           // Opera Mini
        "com.opera.gx",                    // Opera GX
        "com.sec.android.app.sbrowser",    // Samsung Internet
        "com.brave.browser",               // Brave Browser
        "com.microsoft.emmx",              // Microsoft Edge
        "com.duckduckgo.mobile.android",   // DuckDuckGo Browser
        "com.vivaldi.browser",             // Vivaldi Browser
        "com.kiwibrowser.browser",         // Kiwi Browser
        "org.chromium.webview_shell"       // Chromium
    )

    fun isBrowser(packageName: String): Boolean = POPULAR_BROWSERS.contains(packageName)
}

// ============================================================================
// 3. مستودع البيانات وإدارة الحالة والتخزين المحلي (Repository)
// ============================================================================

object AdShieldRepository {
    private const val PREFS_NAME = "adshield_prefs_v1"
    private const val KEY_FILTERS = "saved_filters"
    private const val KEY_APP_OVERRIDES = "app_overrides"
    private const val KEY_COSMETIC_COUNT = "cosmetic_count"
    private const val KEY_LAST_UPDATE = "last_update"
    private const val KEY_CERT_INSTALLED = "cert_installed"

    private val _uiState = MutableStateFlow(AdShieldUiState())
    val uiState: StateFlow<AdShieldUiState> = _uiState.asStateFlow()

    private var appContext: Context? = null

    /**
     * الفلاتر الثلاثة الأساسية الفعالة افتراضياً كما حددها المستخدم
     */
    private fun defaultFilters(): List<FilterListItem> = listOf(
        FilterListItem(
            id = "easylist",
            name = "EasyList",
            description = "الفلتر الأساسي لحجب الإعلانات المرئية والنوافذ المنبثقة",
            url = "https://easylist.to/easylist/easylist.txt",
            isDefault = true,
            enabled = true,
            colorHex = 0xFF10B981 // Emerald
        ),
        FilterListItem(
            id = "easyprivacy",
            name = "EasyPrivacy",
            description = "منع سكريبتات التتبع وجمع البيانات الخفية",
            url = "https://easylist.to/easylist/easyprivacy.txt",
            isDefault = true,
            enabled = true,
            colorHex = 0xFF0EA5E9 // Sky Blue
        ),
        FilterListItem(
            id = "fanboy_annoyance",
            name = "Fanboy's Annoyance Filter",
            description = "إزالة إشعارات الكوكيز والنوافذ المزعجة تجميلياً",
            url = "https://secure.fanboy.co.nz/fanboy-annoyance.txt",
            isDefault = true,
            enabled = true,
            colorHex = 0xFFF59E0B // Amber
        )
    )

    /**
     * تهيئة المستودع وتحميل الفلاتر والتطبيقات المثبتة على الجهاز
     */
    fun initialize(context: Context) {
        if (appContext != null) return
        appContext = context.applicationContext
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

        val loadedFilters = loadFiltersFromPrefs(prefs)
        val cosmeticCount = prefs.getLong(KEY_COSMETIC_COUNT, 0L)
        val lastUpdate = prefs.getString(KEY_LAST_UPDATE, "جاهز للتحديث") ?: "جاهز للتحديث"
        val certInstalled = prefs.getBoolean(KEY_CERT_INSTALLED, false)

        _uiState.update {
            it.copy(
                filters = loadedFilters,
                cosmeticElementsHidden = cosmeticCount,
                lastUpdateText = lastUpdate,
                certificateInstalled = certInstalled
            )
        }

        // تحميل القواعد المخزنة محلياً في المحرك
        FilterEngine.reloadCachedRules(context, loadedFilters)

        // فحص التطبيقات المثبتة على الهاتف في الخلفية
        CoroutineScope(Dispatchers.IO).launch {
            val installedApps = scanInstalledApps(context, prefs)
            _uiState.update { it.copy(apps = installedApps) }
        }
    }

    /**
     * فحص جميع التطبيقات المثبتة وتطبيق القاعدة الذكية:
     * - تمرير البيانات (VPN): مفعل للجميع افتراضياً
     * - فلترة HTTPS: مفعلة للمتصفحات الشهيرة فقط، ومغلقة لباقي التطبيقات افتراضياً
     */
    private fun scanInstalledApps(context: Context, prefs: android.content.SharedPreferences): List<ManagedAppItem> {
        val pm = context.packageManager
        val overridesJson = JSONObject(prefs.getString(KEY_APP_OVERRIDES, "{}") ?: "{}")
        val packages = try {
            pm.getInstalledApplications(PackageManager.GET_META_DATA)
        } catch (e: Exception) {
            emptyList()
        }

        return packages
            .filter { appInfo ->
                // استثناء تطبيقنا نفسه وإظهار التطبيقات التي لها واجهة أو المتصفحات
                appInfo.packageName != context.packageName &&
                    (pm.getLaunchIntentForPackage(appInfo.packageName) != null ||
                        BrowserRegistry.isBrowser(appInfo.packageName) ||
                        (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) == 0)
            }
            .map { appInfo ->
                val pkg = appInfo.packageName
                val label = try {
                    pm.getApplicationLabel(appInfo).toString()
                } catch (e: Exception) {
                    pkg
                }
                val isBrowser = BrowserRegistry.isBrowser(pkg)
                val savedObj = overridesJson.optJSONObject(pkg)

                val routeVpn = savedObj?.optBoolean("vpn", true) ?: true
                val httpsEnabled = savedObj?.optBoolean("https", isBrowser) ?: isBrowser

                ManagedAppItem(
                    packageName = pkg,
                    appName = label,
                    isPopularBrowser = isBrowser,
                    routeThroughVpn = routeVpn,
                    httpsFilteringEnabled = httpsEnabled
                )
            }
            .sortedWith(
                compareByDescending<ManagedAppItem> { it.isPopularBrowser }
                    .thenBy { it.appName.lowercase(Locale.getDefault()) }
            )
    }

    fun setVpnActive(active: Boolean) {
        _uiState.update { it.copy(isVpnActive = active) }
    }

    fun setCertificateInstalled(installed: Boolean) {
        _uiState.update { it.copy(certificateInstalled = installed) }
        appContext?.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            ?.edit()?.putBoolean(KEY_CERT_INSTALLED, installed)?.apply()
    }

    /**
     * تحديث وتنزيل كافة الفلاتر النشطة من روابطها المباشرة
     */
    suspend fun updateAllActiveFilters() {
        val ctx = appContext ?: return
        if (_uiState.value.isUpdatingFilters) return

        _uiState.update { it.copy(isUpdatingFilters = true) }
        withContext(Dispatchers.IO) {
            val updatedList = _uiState.value.filters.map { filter ->
                if (filter.enabled) {
                    val count = FilterEngine.downloadAndParseFilter(ctx, filter)
                    if (count > 0) filter.copy(rulesCount = count) else filter
                } else {
                    filter
                }
            }

            FilterEngine.reloadCachedRules(ctx, updatedList)
            val timeStr = SimpleDateFormat("hh:mm a", Locale.getDefault()).format(Date())

            _uiState.update {
                it.copy(
                    isUpdatingFilters = false,
                    filters = updatedList,
                    lastUpdateText = "آخر تحديث: $timeStr"
                )
            }
            saveFiltersToPrefs(updatedList)
            ctx.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit().putString(KEY_LAST_UPDATE, "آخر تحديث: $timeStr").apply()
        }
    }

    /**
     * إضافة فلتر مخصص جديد عبر رابط يكتبه المستخدم
     */
    fun addCustomFilter(name: String, url: String) {
        val ctx = appContext ?: return
        val cleanName = name.trim()
        val cleanUrl = url.trim()
        if (cleanName.isEmpty() || cleanUrl.isEmpty()) return

        val colors = listOf(0xFF8B5CF6, 0xFFEC4899, 0xFF14B8A6, 0xFFF97316)
        val newFilter = FilterListItem(
            id = "custom_${System.currentTimeMillis()}",
            name = cleanName,
            description = "فلتر مخصص أضيف عبر رابط خارجي",
            url = cleanUrl,
            isDefault = false,
            enabled = true,
            colorHex = colors[_uiState.value.filters.size % colors.size]
        )

        val newList = _uiState.value.filters + newFilter
        _uiState.update { it.copy(filters = newList) }
        saveFiltersToPrefs(newList)

        // تحميل الفلتر الجديد مباشرة في الخلفية
        CoroutineScope(Dispatchers.IO).launch {
            updateAllActiveFilters()
        }
    }

    fun toggleFilter(filterId: String) {
        val ctx = appContext ?: return
        val newList = _uiState.value.filters.map {
            if (it.id == filterId) it.copy(enabled = !it.enabled) else it
        }
        _uiState.update { it.copy(filters = newList) }
        saveFiltersToPrefs(newList)
        CoroutineScope(Dispatchers.IO).launch {
            FilterEngine.reloadCachedRules(ctx, newList)
        }
    }

    fun deleteCustomFilter(filterId: String) {
        val ctx = appContext ?: return
        val newList = _uiState.value.filters.filterNot { it.id == filterId && !it.isDefault }
        _uiState.update { it.copy(filters = newList) }
        saveFiltersToPrefs(newList)
        File(ctx.filesDir, "filter_$filterId.txt").delete()
        CoroutineScope(Dispatchers.IO).launch {
            FilterEngine.reloadCachedRules(ctx, newList)
        }
    }

    /**
     * تعديل إعداد توجيه البيانات أو فلترة HTTPS لتطبيق معين
     */
    fun updateAppSetting(packageName: String, routeVpn: Boolean, httpsFiltering: Boolean) {
        val finalHttps = if (!routeVpn) false else httpsFiltering
        val newApps = _uiState.value.apps.map { app ->
            if (app.packageName == packageName) {
                app.copy(routeThroughVpn = routeVpn, httpsFilteringEnabled = finalHttps)
            } else {
                app
            }
        }
        _uiState.update { it.copy(apps = newApps) }
        saveAppOverrides(newApps)
    }

    /**
     * تسجيل عملية حظر جديدة وزيادة العداد الخاص بالفلتر الذي قام بالحظر
     */
    fun recordBlockedHit(filterId: String, domain: String, isCosmetic: Boolean = false) {
        var matchedFilterName = ""
        val updatedFilters = _uiState.value.filters.map { filter ->
            if (filter.id == filterId) {
                matchedFilterName = filter.name
                filter.copy(blockedCount = filter.blockedCount + 1)
            } else {
                filter
            }
        }

        val newCosmetic = if (isCosmetic) {
            _uiState.value.cosmeticElementsHidden + 1
        } else {
            _uiState.value.cosmeticElementsHidden
        }

        _uiState.update {
            it.copy(
                filters = updatedFilters,
                cosmeticElementsHidden = newCosmetic,
                lastBlockedDomain = domain,
                lastBlockedFilterName = matchedFilterName
            )
        }
        saveFiltersToPrefs(updatedFilters)
    }

    private fun saveFiltersToPrefs(list: List<FilterListItem>) {
        val ctx = appContext ?: return
        val arr = JSONArray()
        list.forEach { f ->
            arr.put(JSONObject().apply {
                put("id", f.id)
                put("name", f.name)
                put("description", f.description)
                put("url", f.url)
                put("isDefault", f.isDefault)
                put("enabled", f.enabled)
                put("rulesCount", f.rulesCount)
                put("blockedCount", f.blockedCount)
                put("colorHex", f.colorHex)
            })
        }
        ctx.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_FILTERS, arr.toString())
            .putLong(KEY_COSMETIC_COUNT, _uiState.value.cosmeticElementsHidden)
            .apply()
    }

    private fun loadFiltersFromPrefs(prefs: android.content.SharedPreferences): List<FilterListItem> {
        val raw = prefs.getString(KEY_FILTERS, null) ?: return defaultFilters()
        return try {
            val arr = JSONArray(raw)
            val result = mutableListOf<FilterListItem>()
            for (i in 0 until arr.length()) {
                val obj = arr.getJSONObject(i)
                result.add(
                    FilterListItem(
                        id = obj.getString("id"),
                        name = obj.getString("name"),
                        description = obj.optString("description", ""),
                        url = obj.getString("url"),
                        isDefault = obj.optBoolean("isDefault", false),
                        enabled = obj.optBoolean("enabled", true),
                        rulesCount = obj.optInt("rulesCount", 0),
                        blockedCount = obj.optLong("blockedCount", 0L),
                        colorHex = obj.optLong("colorHex", 0xFF10B981)
                    )
                )
            }
            if (result.isEmpty())
