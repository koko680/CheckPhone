package com.checkphone.ui

import android.content.Intent
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.cardview.widget.CardView
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.checkphone.R
import com.checkphone.databinding.ActivityResultBinding
import com.checkphone.model.ThreatLevel
import java.text.SimpleDateFormat
import java.util.*

class ResultActivity : AppCompatActivity() {

    private lateinit var binding: ActivityResultBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityResultBinding.inflate(layoutInflater)
        setContentView(binding.root)

        val threatCount  = intent.getIntExtra("threat_count", 0)
        val overallLevel = intent.getStringExtra("overall_level") ?: "SAFE"
        val summary      = intent.getStringExtra("summary") ?: ""
        val scanTime     = intent.getLongExtra("scan_time", System.currentTimeMillis())

        val titles   = intent.getStringArrayExtra("threat_titles")   ?: emptyArray()
        val descs    = intent.getStringArrayExtra("threat_descs")    ?: emptyArray()
        val details  = intent.getStringArrayExtra("threat_details")  ?: emptyArray()
        val levels   = intent.getStringArrayExtra("threat_levels")   ?: emptyArray()
        val fixable  = intent.getBooleanArrayExtra("threat_fixable") ?: BooleanArray(0)

        // Overall status card
        val level = ThreatLevel.valueOf(overallLevel)
        binding.tvOverallStatus.text = getLevelEmoji(level) + "  " + getLevelText(level)
        binding.tvSummary.text = summary
        binding.cardOverall.setCardBackgroundColor(getLevelColor(level))

        // Scan time
        val sdf = SimpleDateFormat("dd/MM/yyyy HH:mm", Locale.getDefault())
        binding.tvScanTime.text = "وقت الفحص: ${sdf.format(Date(scanTime))}"

        // Threats list
        if (threatCount == 0) {
            binding.tvNoThreats.visibility = View.VISIBLE
            binding.rvThreats.visibility = View.GONE
        } else {
            binding.tvNoThreats.visibility = View.GONE
            binding.rvThreats.visibility = View.VISIBLE

            val threats = (0 until threatCount).map { i ->
                ThreatItem(
                    title   = titles.getOrElse(i) { "" },
                    desc    = descs.getOrElse(i) { "" },
                    details = details.getOrElse(i) { "" },
                    level   = levels.getOrElse(i) { "WARNING" },
                    fixable = fixable.getOrElse(i) { false }
                )
            }

            binding.rvThreats.layoutManager = LinearLayoutManager(this)
            binding.rvThreats.adapter = ThreatAdapter(threats)
        }

        binding.btnScanAgain.setOnClickListener {
            startActivity(Intent(this, ScanActivity::class.java))
            finish()
        }

        binding.btnHome.setOnClickListener {
            startActivity(Intent(this, MainActivity::class.java))
            finishAffinity()
        }
    }

    private fun getLevelEmoji(level: ThreatLevel) = when (level) {
        ThreatLevel.SAFE     -> "🟢"
        ThreatLevel.WARNING  -> "🟡"
        ThreatLevel.DANGER   -> "🔴"
        ThreatLevel.CRITICAL -> "⚫"
    }

    private fun getLevelText(level: ThreatLevel) = when (level) {
        ThreatLevel.SAFE     -> "جهازك آمن"
        ThreatLevel.WARNING  -> "يوجد تحذيرات"
        ThreatLevel.DANGER   -> "يوجد مشاكل خطيرة"
        ThreatLevel.CRITICAL -> "جهازك في خطر!"
    }

    private fun getLevelColor(level: ThreatLevel) = when (level) {
        ThreatLevel.SAFE     -> 0xFF2E7D32.toInt()
        ThreatLevel.WARNING  -> 0xFFF57F17.toInt()
        ThreatLevel.DANGER   -> 0xFFC62828.toInt()
        ThreatLevel.CRITICAL -> 0xFF212121.toInt()
    }
}

data class ThreatItem(
    val title: String,
    val desc: String,
    val details: String,
    val level: String,
    val fixable: Boolean
)

class ThreatAdapter(private val items: List<ThreatItem>) :
    RecyclerView.Adapter<ThreatAdapter.VH>() {

    inner class VH(view: View) : RecyclerView.ViewHolder(view) {
        val card: CardView   = view.findViewById(R.id.cardThreat)
        val tvLevel: TextView  = view.findViewById(R.id.tvThreatLevel)
        val tvTitle: TextView  = view.findViewById(R.id.tvThreatTitle)
        val tvDesc: TextView   = view.findViewById(R.id.tvThreatDesc)
        val tvDetails: TextView = view.findViewById(R.id.tvThreatDetails)
        val btnExpand: TextView = view.findViewById(R.id.btnExpand)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        val v = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_threat, parent, false)
        return VH(v)
    }

    override fun getItemCount() = items.size

    override fun onBindViewHolder(holder: VH, position: Int) {
        val item = items[position]
        val level = ThreatLevel.valueOf(item.level)

        holder.tvLevel.text = when (level) {
            ThreatLevel.SAFE     -> "🟢 آمن"
            ThreatLevel.WARNING  -> "🟡 تحذير"
            ThreatLevel.DANGER   -> "🔴 خطر"
            ThreatLevel.CRITICAL -> "⚫ خطر شديد"
        }

        holder.card.setCardBackgroundColor(when (level) {
            ThreatLevel.SAFE     -> 0xFFE8F5E9.toInt()
            ThreatLevel.WARNING  -> 0xFFFFF8E1.toInt()
            ThreatLevel.DANGER   -> 0xFFFFEBEE.toInt()
            ThreatLevel.CRITICAL -> 0xFF263238.toInt()
        })

        if (level == ThreatLevel.CRITICAL) {
            holder.tvTitle.setTextColor(0xFFFFFFFF.toInt())
            holder.tvDesc.setTextColor(0xFFEEEEEE.toInt())
            holder.tvDetails.setTextColor(0xFFCCCCCC.toInt())
            holder.tvLevel.setTextColor(0xFFFFFFFF.toInt())
            holder.btnExpand.setTextColor(0xFFAAAAAA.toInt())
        }

        holder.tvTitle.text = item.title
        holder.tvDesc.text = item.desc
        holder.tvDetails.text = item.details
        holder.tvDetails.visibility = View.GONE

        holder.btnExpand.setOnClickListener {
            if (holder.tvDetails.visibility == View.GONE) {
                holder.tvDetails.visibility = View.VISIBLE
                holder.btnExpand.text = "إخفاء التفاصيل ▲"
            } else {
                holder.tvDetails.visibility = View.GONE
                holder.btnExpand.text = "عرض التفاصيل ▼"
            }
        }
    }
}
