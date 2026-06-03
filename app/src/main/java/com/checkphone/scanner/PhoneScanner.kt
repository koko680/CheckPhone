package com.checkphone.scanner

import android.accessibilityservice.AccessibilityServiceInfo
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.TrafficStats
import android.net.VpnService
import android.view.accessibility.AccessibilityManager
import com.checkphone.model.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class PhoneScanner(private val context: Context) {

    suspend fun runFullScan(onProgress: (Int, String) -> Unit): ScanResult = withContext(Dispatchers.IO) {
        val threats = mutableListOf<Threat>()

        onProgress(10, "جاري فحص التطبيقات المثبتة...")
        threats.addAll(scanForSpyware())

        onProgress(25, "جاري فحص الصلاحيات الخطيرة...")
        threats.addAll(scanDangerousPermissions())

        onProgress(45, "جاري فحص خدمات إمكانية الوصول...")
        threats.addAll(scanAccessibilityServices())

        onProgress(60, "جاري فحص تطبيقات إدارة الجهاز...")
        threats.addAll(scanDeviceAdminApps())

        onProgress(75, "جاري فحص الشبكة...")
        threats.addAll(scanNetwork())

        onProgress(90, "جاري فحص التطبيقات المجهولة...")
        threats.addAll(scanUnknownSources())

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
                threats.add(
                    Threat(
                        title = "برنامج تجسس معروف",
                        description = "تم اكتشاف تطبيق تجسس معروف على جهازك",
                        details = "اسم التطبيق: ${getAppName(pm, pkg.packageName)}\nالحزمة: ${pkg.packageName}",
                        level = ThreatLevel.CRITICAL,
                        category = ThreatCategory.SPYWARE,
                        fixable = true,
                        fixAction = pkg.packageName
                    )
                )
            }
        }
        return threats
    }

    // ─── 2. Dangerous Permissions ────────────────────────────────────────────
    private fun scanDangerousPermissions(): List<Threat> {
        val threats = mutableListOf<Threat>()
        val pm = context.packageManager
        val packages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)

        for (pkg in packages) {
            if (isSystemApp(pkg) || pkg.packageName == context.packageName) continue

            val grantedPerms = pkg.requestedPermissions
                ?.filterIndexed { i, _ ->
                    pkg.requestedPermissionsFlags?.get(i)
                        ?.and(PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
                } ?: continue

            for ((permCombo, description, level) in DANGEROUS_PERMISSION_COMBOS) {
                if (grantedPerms.containsAll(permCombo)) {
                    val appName = getAppName(pm, pkg.packageName)
                    threats.add(
                        Threat(
                            title = "صلاحيات خطيرة — $appName",
                            description = description,
                            details = "التطبيق: $appName\nالصلاحيات المشبوهة:\n${permCombo.joinToString("\n") { "• ${formatPermission(it)}" }}",
                            level = level,
                            category = ThreatCategory.PERMISSIONS
                        )
                    )
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

            val appName = getAppName(context.packageManager, pkgName)
            threats.add(
                Threat(
                    title = "خدمة وصول مشبوهة — $appName",
                    description = "تطبيق بيشوف كل اللي بتكتبه وبتعمله على الشاشة",
                    details = "التطبيق: $appName\nالحزمة: $pkgName\n\nخدمات إمكانية الوصول تقدر تسجل كلمات السر والرسايل وكل ضغطة على الكيبورد.",
                    level = ThreatLevel.DANGER,
                    category = ThreatCategory.ACCESSIBILITY
                )
            )
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

            val appName = getAppName(context.packageManager, pkgName)
            threats.add(
                Threat(
                    title = "تطبيق إدارة جهاز مجهول — $appName",
                    description = "تطبيق عنده صلاحية التحكم الكامل في جهازك",
                    details = "التطبيق: $appName\nالحزمة: $pkgName\n\nتطبيقات Device Admin تقدر تمسح جهازك، تمنع الإلغاء، وتتحكم في الإعدادات.",
                    level = ThreatLevel.CRITICAL,
                    category = ThreatCategory.DEVICE_ADMIN,
                    fixable = true
                )
            )
        }
        return threats
    }

    // ─── 5. Network Scan ─────────────────────────────────────────────────────
    private fun scanNetwork(): List<Threat> {
        val threats = mutableListOf<Threat>()
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val network = cm.activeNetwork
        val caps = cm.getNetworkCapabilities(network)

        // VPN Detection
        if (caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
            threats.add(
                Threat(
                    title = "VPN نشط — مجهول المصدر",
                    description = "في حاجة بتحول كل داتا الإنترنت بتاعتك على سيرفر تاني",
                    details = "ده ممكن يكون VPN عادي أنت نزّلته، أو ممكن يكون تطبيق بيراقب اتصالاتك.\nتأكد إنك أنت اللي فعّلت الـ VPN ده.",
                    level = ThreatLevel.WARNING,
                    category = ThreatCategory.NETWORK
                )
            )
        }

        // High data usage check
        val totalRx = TrafficStats.getTotalRxBytes()
        val totalTx = TrafficStats.getTotalTxBytes()
        val suspiciousUpload = totalTx > 500_000_000L // 500MB uploaded
        if (suspiciousUpload) {
            threats.add(
                Threat(
                    title = "استهلاك داتا رفع عالي",
                    description = "جهازك رفع كمية كبيرة من البيانات",
                    details = "تم رفع ${totalTx / 1_000_000} MB\nده ممكن يكون طبيعي أو ممكن يعني في تطبيق بيرفع بياناتك.",
                    level = ThreatLevel.WARNING,
                    category = ThreatCategory.NETWORK
                )
            )
        }

        return threats
    }

    // ─── 6. Unknown Sources ──────────────────────────────────────────────────
    private fun scanUnknownSources(): List<Threat> {
        val threats = mutableListOf<Threat>()
        val pm = context.packageManager
        val packages = pm.getInstalledPackages(0)

        val suspiciousApps = mutableListOf<String>()

        for (pkg in packages) {
            if (isSystemApp(pkg)) continue
            if (pkg.packageName == context.packageName) continue

            // Check if installed from unknown source
            try {
                val installer = pm.getInstallerPackageName(pkg.packageName)
                val knownStores = setOf(
                    "com.android.vending",         // Google Play
                    "com.amazon.venezia",           // Amazon
                    "com.huawei.appmarket",         // Huawei
                    "com.samsung.android.packageinstaller"
                )
                if (installer == null || installer !in knownStores) {
                    val appName = getAppName(pm, pkg.packageName)
                    // Skip if it's a well-known app by name check
                    if (!isWellKnownApp(pkg.packageName)) {
                        suspiciousApps.add(appName)
                    }
                }
            } catch (e: Exception) {
                // ignore
            }
        }

        if (suspiciousApps.isNotEmpty()) {
            threats.add(
                Threat(
                    title = "تطبيقات من مصادر مجهولة (${suspiciousApps.size})",
                    description = "في تطبيقات مش متنزّلة من متجر رسمي",
                    details = "التطبيقات:\n${suspiciousApps.joinToString("\n") { "• $it" }}\n\nالتطبيقات دي ممكن تكون خطيرة لأنها مش اتفحصت من Google Play.",
                    level = ThreatLevel.WARNING,
                    category = ThreatCategory.UNKNOWN_APP
                )
            )
        }

        return threats
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────
    private fun getAppName(pm: PackageManager, packageName: String): String {
        return try {
            pm.getApplicationLabel(pm.getApplicationInfo(packageName, 0)).toString()
        } catch (e: Exception) {
            packageName
        }
    }

    private fun isSystemApp(pkg: PackageInfo): Boolean {
        return pkg.applicationInfo.flags and ApplicationInfo.FLAG_SYSTEM != 0
    }

    private fun formatPermission(perm: String): String {
        return when (perm) {
            "android.permission.RECORD_AUDIO"    -> "تسجيل الصوت"
            "android.permission.CAMERA"          -> "الكاميرا"
            "android.permission.READ_SMS"        -> "قراءة الرسايل"
            "android.permission.READ_CONTACTS"   -> "جهات الاتصال"
            "android.permission.ACCESS_FINE_LOCATION" -> "الموقع الدقيق"
            "android.permission.READ_CALL_LOG"   -> "سجل المكالمات"
            "android.permission.INTERNET"        -> "الإنترنت"
            "android.permission.RECEIVE_BOOT_COMPLETED" -> "بدء تلقائي مع الجهاز"
            else -> perm.substringAfterLast(".")
        }
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
            "com.android.managedprovisioning"
        )
        return safe.any { pkg.startsWith(it) }
    }

    private fun isWellKnownApp(pkg: String): Boolean {
        val known = setOf(
            "com.whatsapp", "com.facebook", "com.instagram",
            "com.telegram", "org.telegram", "com.twitter",
            "com.google", "com.microsoft", "com.amazon",
            "com.netflix", "com.spotify", "com.tiktok",
            "com.snapchat", "com.viber", "com.skype"
        )
        return known.any { pkg.startsWith(it) }
    }
}
