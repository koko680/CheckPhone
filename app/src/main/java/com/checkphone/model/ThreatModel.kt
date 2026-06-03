package com.checkphone.model

enum class ThreatLevel {
    SAFE,       // 🟢
    WARNING,    // 🟡
    DANGER,     // 🔴
    CRITICAL    // ⚫
}

enum class ThreatCategory {
    SPYWARE,
    PERMISSIONS,
    NETWORK,
    DEVICE_ADMIN,
    ACCESSIBILITY,
    UNKNOWN_APP,
    SYSTEM
}

data class Threat(
    val title: String,
    val description: String,
    val details: String,
    val level: ThreatLevel,
    val category: ThreatCategory,
    val fixable: Boolean = false,
    val fixAction: String? = null
)

data class ScanResult(
    val threats: List<Threat>,
    val scanTime: Long = System.currentTimeMillis(),
    val overallLevel: ThreatLevel = calculateOverall(threats),
    val summary: String = buildSummary(threats)
) {
    companion object {
        fun calculateOverall(threats: List<Threat>): ThreatLevel {
            return when {
                threats.any { it.level == ThreatLevel.CRITICAL } -> ThreatLevel.CRITICAL
                threats.any { it.level == ThreatLevel.DANGER }   -> ThreatLevel.DANGER
                threats.any { it.level == ThreatLevel.WARNING }  -> ThreatLevel.WARNING
                else -> ThreatLevel.SAFE
            }
        }

        fun buildSummary(threats: List<Threat>): String {
            if (threats.isEmpty()) return "جهازك آمن — لم يتم اكتشاف أي تهديدات"
            val critical = threats.count { it.level == ThreatLevel.CRITICAL }
            val danger   = threats.count { it.level == ThreatLevel.DANGER }
            val warning  = threats.count { it.level == ThreatLevel.WARNING }
            return buildString {
                if (critical > 0) append("$critical مشكلة خطيرة جداً  ")
                if (danger > 0)   append("$danger مشكلة خطيرة  ")
                if (warning > 0)  append("$warning تحذير")
            }.trim()
        }
    }
}

// Known spyware package names
val KNOWN_SPYWARE_PACKAGES = setOf(
    "com.flexispy",
    "com.mspy",
    "com.mobilespy",
    "com.android.spyware",
    "org.stalker",
    "com.spy.phone",
    "com.hoverwatch",
    "com.spyera",
    "com.familyorbit",
    "com.finfisher",
    "com.ahmyth.mine",
    "com.droidjack"
)

// Dangerous permission combinations
val DANGEROUS_PERMISSION_COMBOS = listOf(
    Triple(
        listOf("android.permission.RECORD_AUDIO", "android.permission.READ_CONTACTS"),
        "تطبيق بيسجل صوتك ويقرأ جهات اتصالك",
        ThreatLevel.DANGER
    ),
    Triple(
        listOf("android.permission.CAMERA", "android.permission.INTERNET", "android.permission.READ_CALL_LOG"),
        "تطبيق بيستخدم الكاميرا ويرفع بياناتك على الإنترنت",
        ThreatLevel.CRITICAL
    ),
    Triple(
        listOf("android.permission.READ_SMS", "android.permission.INTERNET"),
        "تطبيق بيقرأ رسايلك ويرسلها للإنترنت",
        ThreatLevel.CRITICAL
    ),
    Triple(
        listOf("android.permission.ACCESS_FINE_LOCATION", "android.permission.INTERNET", "android.permission.RECEIVE_BOOT_COMPLETED"),
        "تطبيق بيتبع موقعك ويبدأ تلقائي مع الجهاز",
        ThreatLevel.DANGER
    )
)
