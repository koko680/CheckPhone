package com.checkphone.model

enum class ThreatLevel {
    SAFE, WARNING, DANGER, CRITICAL
}

enum class ThreatCategory {
    SPYWARE, PERMISSIONS, NETWORK, DEVICE_ADMIN, ACCESSIBILITY, UNKNOWN_APP, SYSTEM, BATTERY
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

val KNOWN_SPYWARE_PACKAGES = setOf(
    "com.flexispy", "com.mspy", "com.mobilespy", "com.android.spyware",
    "org.stalker", "com.spy.phone", "com.hoverwatch", "com.spyera",
    "com.familyorbit", "com.finfisher", "com.ahmyth.mine", "com.droidjack",
    "com.thetruthspy", "com.copy9", "com.ispyoo", "com.android.callrecorder.spy"
)

// تطبيقات معروفة وآمنة - لا يتم الإبلاغ عنها
val WHITELIST_PACKAGES = setOf(
    "com.whatsapp", "com.whatsapp.w4b",
    "com.facebook.katana", "com.facebook.lite", "com.facebook.orca",
    "com.instagram.android",
    "org.telegram.messenger", "org.telegram.messenger.web", "com.telegram.messenger",
    "com.twitter.android", "com.twitter.android.lite",
    "com.google.android.gm", "com.google.android.apps.maps",
    "com.google.android.youtube", "com.google.android.apps.photos",
    "com.google.android.apps.docs", "com.google.android.keep",
    "com.microsoft.teams", "com.microsoft.office.word",
    "com.netflix.mediaclient", "com.spotify.music",
    "com.snapchat.android", "com.viber.voip", "com.skype.raider",
    "com.tiktok", "com.zhiliaoapp.musically",
    "com.amazon.mShop.android.shopping",
    "com.ubercab", "com.careem",
    // تطبيقات مصرية وإقليمية معروفة
    "com.indriver.app", "com.indrive",
    "com.waffarx", "com.waffarha",
    "com.orange.egyptapp", "com.orange.android",
    "com.vodafone.egypt", "com.etisalat.egypt",
    "com.we.egyptapp",
    "com.talabat", "com.otlob",
    "com.instashop", "com.noon.buyerapp",
    "com.souq.android",
    "com.fawry.merchant", "com.fawry.customer",
    "com.aman.wallet",
    "com.banque.misr", "com.cib.egypt", "com.qnb.egypt",
    "com.nbe.mobilebanking",
    "air.com.gamedevltd.modernstrike",
    "com.bigo.live", "sg.bigo.live",
    "com.likee", "video.like",
    "com.kwai.video", "com.snack.video",
    // AI Apps
    "com.openai.chatgpt",
    "com.anthropic.claude",
    // Caller ID
    "com.truecaller",
    "com.hiya.star",
    // Productivity
    "com.adobe.reader",
    "com.dropbox.android",
    "com.evernote",
    "com.todoist",
    // Egyptian Apps extra
    "com.etisalat.my",
    "com.vodafone.vfgroup",
    "com.ncb.mobilebanking",
    "com.alexbank",
    "com.aaib.mobilebanking",
    "com.swvl.android",
    "com.cartona.app",
    "com.maxab.app"
)

// صلاحيات خطيرة - بس لو التطبيق مجهول
val SUSPICIOUS_PERMISSION_COMBOS = listOf(
    Triple(
        listOf("android.permission.RECORD_AUDIO", "android.permission.READ_CONTACTS", "android.permission.INTERNET"),
        "تطبيق مجهول بيسجل صوتك ويرفع جهات اتصالك",
        ThreatLevel.CRITICAL
    ),
    Triple(
        listOf("android.permission.CAMERA", "android.permission.RECORD_AUDIO", "android.permission.INTERNET", "android.permission.RECEIVE_BOOT_COMPLETED"),
        "تطبيق مجهول بيستخدم الكاميرا والميكروفون ويرفع البيانات",
        ThreatLevel.CRITICAL
    ),
    Triple(
        listOf("android.permission.READ_SMS", "android.permission.INTERNET"),
        "تطبيق بيقرأ رسايلك ويرسلها للإنترنت",
        ThreatLevel.CRITICAL
    ),
    Triple(
        listOf("android.permission.READ_CALL_LOG", "android.permission.INTERNET", "android.permission.RECEIVE_BOOT_COMPLETED"),
        "تطبيق بيسجل مكالماتك ويرفعها تلقائياً",
        ThreatLevel.DANGER
    ),
    Triple(
        listOf("android.permission.ACCESS_FINE_LOCATION", "android.permission.INTERNET", "android.permission.RECEIVE_BOOT_COMPLETED", "android.permission.HIDE_OVERLAY_WINDOWS"),
        "تطبيق بيتبع موقعك ومخفي عن الشاشة",
        ThreatLevel.DANGER
    ),
    Triple(
        listOf("android.permission.READ_CONTACTS", "android.permission.READ_CALL_LOG", "android.permission.READ_SMS"),
        "تطبيق بيقرأ كل بياناتك الشخصية",
        ThreatLevel.DANGER
    )
)
