package com.checkphone.scanner

import android.accessibilityservice.AccessibilityServiceInfo
import android.app.ActivityManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.TrafficStats
import android.os.BatteryManager
import android.view.accessibility.AccessibilityManager
import com.checkphone.model.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class PhoneScanner(private val context: Context) {

    suspend fun runFullScan(onProgress: (Int, String) -> Unit): ScanResult = withContext(Dispatchers.IO) {
        val threats = mutableListOf<Threat>()

        onProgress(10, "فحص برامج التجسس المعروفة...")
        threats.addAll(scanForSpyware())

        onProgress(22, "فحص الصلاحيات الخطيرة...")
        threats.addAll(scanDangerousPermissions())

        onProgress(38, "فحص خدمات إمكانية الوصول...")
        threats.addAll(scanAccessibilityServices())

        onProgress(52, "فحص تطبيقات إدارة الجهاز...")
        threats.addAll(scanDeviceAdminApps())

        onProgress(64, "فحص الشبكة والاتصالات...")
        threats.addAll(scanNetwork())

        onProgress(76, "فحص التطبيقات من مصادر مجهولة...")
        threats.addAll(scanUnknownSources())

        onProgress(88, "فحص التطبيقات المخفية...")
        threats.addAll(scanHiddenApps())

        onProgress(95, "فحص استهلاك البطارية...")
        threats.addAll(scanBatteryAbuse())

        onProgress(100, "اكتمل الفحص")
        ScanResult(threats = threats)
    }

    // ─── 1. Known Spyware ────────────────────────────────────────────────────
    private fun scanForSpyware(): List<Threat> {
        val threats = mutableListOf<Threat>()
        val pm = context.packageManager
        val packages = pm.getInstalledPackages(0)
        for (pkg in packages) {
            if (pkg.packageName in KNOWN_SPYWARE_PACKAGES) {
                threats.add(Threat(
                    title = "⚫ برنامج تجسس معروف!",
                    description = "تم اكتشاف تطبيق تجسس معروف مثبت على جهازك",
                    details = "اسم التطبيق: ${getAppName(pm, pkg.packageName)}\nالحزمة: ${pkg.packageName}\n\nهذا التطبيق معروف بسرقة البيانات الشخصية والتجسس على المستخدمين. احذفه فوراً.",
                    level = ThreatLevel.CRITICAL,
                    category = ThreatCategory.SPYWARE,
                    fixable = true,
                    fixAction = pkg.packageName
                ))
            }
        }
        return threats
    }

    // ─── 2. Dangerous Permissions (مع Whitelist) ─────────────────────────────
    private fun scanDangerousPermissions(): List<Threat> {
        val threats = mutableListOf<Threat>()
        val pm = context.packageManager
        val packages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)

        for (pkg in packages) {
            // تجاهل: تطبيقات النظام، تطبيقنا، والتطبيقات المعروفة
            if (isSystemApp(pkg)) continue
            if (pkg.packageName == context.packageName) continue
            if (pkg.packageName in WHITELIST_PACKAGES) continue
            if (isKnownSafeByPrefix(pkg.packageName)) continue

            val grantedPerms = pkg.requestedPermissions
                ?.filterIndexed { i, _ ->
                    pkg.requestedPermissionsFlags?.get(i)
                        ?.and(PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
                } ?: continue

            for ((permCombo, description, level) in SUSPICIOUS_PERMISSION_COMBOS) {
                if (grantedPerms.containsAll(permCombo)) {
                    val appName = getAppName(pm, pkg.packageName)
                    // تحقق إضافي: لو التطبيق من Play Store وعنده اسم واضح، خفف الخطورة
                    val adjustedLevel = if (isFromPlayStore(pkg.packageName) && level == ThreatLevel.CRITICAL)
                        ThreatLevel.DANGER else level

                    threats.add(Threat(
                        title = "صلاحيات مشبوهة — $appName",
                        description = description,
                        details = "التطبيق: $appName\nالحزمة: ${pkg.packageName}\n\nالصلاحيات المشبوهة:\n${permCombo.joinToString("\n") { "• ${formatPermission(it)}" }}\n\nمصدر التثبيت: ${getInstallSource(pkg.packageName)}",
                        level = adjustedLevel,
                        category = ThreatCategory.PERMISSIONS
                    ))
                    break
                }
            }
        }
        return threats
    }

    // ─── 3. Accessibility Services ───────────────────────────────────────────
    private fun scanAccessibilityServices(): List<Threat> {
        val threats = mutableListOf<Threat>()
        val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as AccessibilityManager
        val enabledServices = am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)

        for (service in enabledServices) {
            val pkgName = service.resolveInfo.serviceInfo.packageName
            if (pkgName == context.packageName) continue
            if (isKnownSafeAccessibility(pkgName)) continue
            if (pkgName in WHITELIST_PACKAGES) continue

            val appName = getAppName(context.packageManager, pkgName)
            val isSystemPkg = try {
                val info = context.packageManager.getApplicationInfo(pkgName, 0)
                info.flags and ApplicationInfo.FLAG_SYSTEM != 0
            } catch (e: Exception) { false }

            if (isSystemPkg) continue

            threats.add(Threat(
                title = "خدمة وصول مشبوهة — $appName",
                description = "تطبيق يستطيع رؤية كل ما تكتبه وتفعله على الشاشة",
                details = "التطبيق: $appName\nالحزمة: $pkgName\n\n⚠️ خدمات إمكانية الوصول تستطيع:\n• تسجيل كلمات المرور\n• قراءة الرسائل\n• رؤية كل ضغطة على الكيبورد\n\nإذا لم تكن أنت من فعّل هذه الخدمة، فهذا خطر كبير.",
                level = ThreatLevel.DANGER,
                category = ThreatCategory.ACCESSIBILITY
            ))
        }
        return threats
    }

    // ─── 4. Device Admin Apps ────────────────────────────────────────────────
    private fun scanDeviceAdminApps(): List<Threat> {
        val threats = mutableListOf<Threat>()
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val adminApps = dpm.activeAdmins ?: return threats

        for (admin in adminApps) {
            val pkgName = admin.packageName
            if (pkgName == context.packageName) continue
            if (isKnownSafeAdmin(pkgName)) continue
            if (pkgName in WHITELIST_PACKAGES) continue

            val appName = getAppName(context.packageManager, pkgName)
            threats.add(Threat(
                title = "تطبيق إدارة جهاز مجهول — $appName",
                description = "تطبيق يملك صلاحية التحكم الكامل في جهازك",
                details = "التطبيق: $appName\nالحزمة: $pkgName\n\n⚠️ تطبيقات Device Admin تستطيع:\n• مسح جهازك بالكامل\n• منع إلغاء تثبيتها\n• التحكم في إعدادات الجهاز\n• قفل الشاشة\n\nإذا لم تكن أنت من منحت هذه الصلاحية، فهذا خطر شديد.",
                level = ThreatLevel.CRITICAL,
                category = ThreatCategory.DEVICE_ADMIN,
                fixable = true
            ))
        }
        return threats
    }

    // ─── 5. Network ──────────────────────────────────────────────────────────
    private fun scanNetwork(): List<Threat> {
        val threats = mutableListOf<Threat>()
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val caps = cm.getNetworkCapabilities(cm.activeNetwork)

        if (caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
            threats.add(Threat(
                title = "VPN نشط",
                description = "كل بيانات الإنترنت بتاعتك بتمر عبر سيرفر تاني",
                details = "VPN نشط على جهازك حالياً.\n\nإذا كنت أنت من فعّله: لا مشكلة.\nإذا لم تفعله: قد يكون تطبيق يراقب اتصالاتك.\n\nتحقق من: الإعدادات ← الشبكة ← VPN",
                level = ThreatLevel.WARNING,
                category = ThreatCategory.NETWORK
            ))
        }

        // فحص رفع البيانات
        val totalTx = TrafficStats.getTotalTxBytes()
        if (totalTx > 1_000_000_000L) { // 1GB رفع
            threats.add(Threat(
                title = "استهلاك داتا رفع مرتفع",
                description = "جهازك رفع كمية كبيرة جداً من البيانات",
                details = "إجمالي البيانات المرفوعة: ${totalTx / 1_000_000} MB\n\nهذا قد يكون طبيعياً لو بتستخدم يوتيوب أو السوشيال ميديا كتير.\nلكن قد يعني أيضاً أن تطبيقاً ما يرفع بياناتك في الخلفية.",
                level = ThreatLevel.WARNING,
                category = ThreatCategory.NETWORK
            ))
        }

        return threats
    }

    // ─── 6. Unknown Sources ──────────────────────────────────────────────────
    private fun scanUnknownSources(): List<Threat> {
        val threats = mutableListOf<Threat>()
        val pm = context.packageManager
        val packages = pm.getInstalledPackages(0)
        val suspiciousApps = mutableListOf<Pair<String, String>>()

        for (pkg in packages) {
            if (isSystemApp(pkg)) continue
            if (pkg.packageName == context.packageName) continue
            if (pkg.packageName in WHITELIST_PACKAGES) continue
            if (isKnownSafeByPrefix(pkg.packageName)) continue

            try {
                val installer = pm.getInstallerPackageName(pkg.packageName)
                val knownStores = setOf(
                    "com.android.vending",
                    "com.amazon.venezia",
                    "com.huawei.appmarket",
                    "com.samsung.android.packageinstaller",
                    "com.xiaomi.mipush.sdk",
                    "com.oppo.market",
                    "com.vivo.appstore"
                )
                if (installer == null || installer !in knownStores) {
                    val appName = getAppName(pm, pkg.packageName)
                    suspiciousApps.add(Pair(appName, pkg.packageName))
                }
            } catch (e: Exception) { }
        }

        if (suspiciousApps.isNotEmpty()) {
            val appList = suspiciousApps.joinToString("\n") { "• ${it.first} (${it.second})" }
            threats.add(Threat(
                title = "تطبيقات من مصادر غير رسمية (${suspiciousApps.size})",
                description = "تطبيقات غير مثبتة من متجر Google Play",
                details = "التطبيقات:\n$appList\n\nهذه التطبيقات لم تخضع لفحص Google.\nبعضها قد يكون آمناً (APK من مصادر موثوقة)، لكن البعض الآخر قد يكون خطيراً.",
                level = ThreatLevel.WARNING,
                category = ThreatCategory.UNKNOWN_APP
            ))
        }
        return threats
    }

    // ─── 7. Hidden Apps ──────────────────────────────────────────────────────
    private fun scanHiddenApps(): List<Threat> {
        val threats = mutableListOf<Threat>()
        val pm = context.packageManager
        val packages = pm.getInstalledPackages(0)
        val hiddenApps = mutableListOf<String>()

        for (pkg in packages) {
            if (isSystemApp(pkg)) continue
            if (pkg.packageName == context.packageName) continue
            if (pkg.packageName in WHITELIST_PACKAGES) continue

            try {
                val appInfo = pm.getApplicationInfo(pkg.packageName, 0)
                // تطبيق بدون أيقونة launcher = مخفي محتمل
                val hasLauncher = pm.getLaunchIntentForPackage(pkg.packageName) != null
                val isEnabled = appInfo.enabled

                // تطبيق مفعّل وليس له أيقونة ظاهرة = مشبوه
                if (!hasLauncher && isEnabled && !isKnownSafeByPrefix(pkg.packageName)) {
                    val appName = getAppName(pm, pkg.packageName)
                    // استثني تطبيقات الخدمات المعروفة
                    if (!appName.contains("service", true) &&
                        !appName.contains("provider", true) &&
                        !appName.contains("manager", true) &&
                        !pkg.packageName.contains("google", true) &&
                        !pkg.packageName.contains("samsung", true) &&
                        !pkg.packageName.contains("huawei", true) &&
                        !pkg.packageName.contains("xiaomi", true) &&
                        !pkg.packageName.contains("oppo", true)) {
                        hiddenApps.add("$appName (${pkg.packageName})")
                    }
                }
            } catch (e: Exception) { }
        }

        if (hiddenApps.size in 1..10) { // لو أكتر من 10 غالباً تطبيقات نظام
            threats.add(Threat(
                title = "تطبيقات مخفية (${hiddenApps.size})",
                description = "تطبيقات مثبتة على جهازك لكن مش ظاهرة في الشاشة الرئيسية",
                details = "التطبيقات:\n${hiddenApps.joinToString("\n") { "• $it" }}\n\nالتطبيقات المخفية قد تكون:\n- خدمات خلفية عادية\n- أو تطبيقات تجسس تخفي نفسها",
                level = ThreatLevel.WARNING,
                category = ThreatCategory.UNKNOWN_APP
            ))
        }
        return threats
    }

    // ─── 8. Battery Abuse ────────────────────────────────────────────────────
    private fun scanBatteryAbuse(): List<Threat> {
        val threats = mutableListOf<Threat>()
        val bm = context.getSystemService(Context.BATTERY_SERVICE) as BatteryManager
        val batteryLevel = bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY)
        val isCharging = bm.isCharging

        // لو البطارية بتنزل بسرعة وهو مش شغال
        val currentNow = bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CURRENT_NOW)
        if (!isCharging && currentNow < -800000) { // استهلاك عالي جداً في الخلفية
            threats.add(Threat(
                title = "استهلاك بطارية مرتفع في الخلفية",
                description = "في تطبيق أو أكتر بيستهلك بطاريتك بشكل غير طبيعي",
                details = "معدل استهلاك البطارية الحالي مرتفع جداً.\n\nهذا قد يعني:\n• تطبيق يعمل في الخلفية باستمرار\n• تطبيق تجسس يرفع بيانات باستمرار\n• مشكلة في بطارية الجهاز\n\nتحقق من: الإعدادات ← البطارية ← استخدام البطارية",
                level = ThreatLevel.WARNING,
                category = ThreatCategory.BATTERY
            ))
        }
        return threats
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────
    private fun getAppName(pm: PackageManager, packageName: String): String {
        return try { pm.getApplicationLabel(pm.getApplicationInfo(packageName, 0)).toString() }
        catch (e: Exception) { packageName }
    }

    private fun isSystemApp(pkg: PackageInfo): Boolean {
        return pkg.applicationInfo.flags and ApplicationInfo.FLAG_SYSTEM != 0
    }

    private fun isFromPlayStore(packageName: String): Boolean {
        return try {
            context.packageManager.getInstallerPackageName(packageName) == "com.android.vending"
        } catch (e: Exception) { false }
    }

    private fun getInstallSource(packageName: String): String {
        return try {
            when (context.packageManager.getInstallerPackageName(packageName)) {
                "com.android.vending" -> "Google Play ✅"
                null -> "مصدر مجهول ⚠️"
                else -> "متجر آخر"
            }
        } catch (e: Exception) { "غير معروف" }
    }

    private fun formatPermission(perm: String) = when (perm) {
        "android.permission.RECORD_AUDIO"           -> "تسجيل الصوت 🎙️"
        "android.permission.CAMERA"                 -> "الكاميرا 📷"
        "android.permission.READ_SMS"               -> "قراءة الرسائل 💬"
        "android.permission.READ_CONTACTS"          -> "جهات الاتصال 👥"
        "android.permission.ACCESS_FINE_LOCATION"   -> "الموقع الدقيق 📍"
        "android.permission.READ_CALL_LOG"          -> "سجل المكالمات 📞"
        "android.permission.INTERNET"               -> "الإنترنت 🌐"
        "android.permission.RECEIVE_BOOT_COMPLETED" -> "بدء تلقائي مع الجهاز 🔄"
        "android.permission.HIDE_OVERLAY_WINDOWS"   -> "إخفاء النوافذ 👁️"
        else -> perm.substringAfterLast(".")
    }

    private fun isKnownSafeByPrefix(pkg: String): Boolean {
        val safePrefixes = listOf(
            "com.google.", "com.android.", "android.",
            "com.samsung.", "com.huawei.", "com.xiaomi.",
            "com.oppo.", "com.vivo.", "com.oneplus.",
            "com.miui.", "com.coloros.", "com.realme."
        )
        return safePrefixes.any { pkg.startsWith(it) }
    }

    private fun isKnownSafeAccessibility(pkg: String): Boolean {
        val safe = setOf(
            "com.google.android.marvin.talkback",
            "com.samsung.accessibility",
            "com.android.talkback",
            "com.google.android.accessibility"
        )
        return safe.any { pkg.startsWith(it) }
    }

    private fun isKnownSafeAdmin(pkg: String): Boolean {
        val safe = setOf(
            "com.google.android.apps.work",
            "com.samsung.android.mdm",
            "com.android.managedprovisioning",
            "com.google.android.gms"
        )
        return safe.any { pkg.startsWith(it) }
    }
}
