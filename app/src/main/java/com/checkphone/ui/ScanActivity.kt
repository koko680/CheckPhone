package com.checkphone.ui

import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.checkphone.databinding.ActivityScanBinding
import com.checkphone.model.ScanResult
import com.checkphone.scanner.PhoneScanner
import kotlinx.coroutines.launch

class ScanActivity : AppCompatActivity() {

    private lateinit var binding: ActivityScanBinding
    private val scanner by lazy { PhoneScanner(this) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityScanBinding.inflate(layoutInflater)
        setContentView(binding.root)

        startScan()
    }

    private fun startScan() {
        lifecycleScope.launch {
            try {
                val result = scanner.runFullScan { progress, message ->
                    runOnUiThread {
                        binding.progressBar.progress = progress
                        binding.tvStatus.text = message
                        binding.tvPercent.text = "$progress%"
                    }
                }
                navigateToResult(result)
            } catch (e: Exception) {
                runOnUiThread {
                    binding.tvStatus.text = "حدث خطأ: ${e.message}"
                }
            }
        }
    }

    private fun navigateToResult(result: ScanResult) {
        val intent = Intent(this, ResultActivity::class.java).apply {
            putExtra("threat_count", result.threats.size)
            putExtra("overall_level", result.overallLevel.name)
            putExtra("summary", result.summary)
            putExtra("scan_time", result.scanTime)

            // Pass threats as serializable data
            val threatTitles = result.threats.map { it.title }.toTypedArray()
            val threatDescs = result.threats.map { it.description }.toTypedArray()
            val threatDetails = result.threats.map { it.details }.toTypedArray()
            val threatLevels = result.threats.map { it.level.name }.toTypedArray()
            val threatFixable = result.threats.map { it.fixable }.toBooleanArray()

            putExtra("threat_titles", threatTitles)
            putExtra("threat_descs", threatDescs)
            putExtra("threat_details", threatDetails)
            putExtra("threat_levels", threatLevels)
            putExtra("threat_fixable", threatFixable)
        }
        startActivity(intent)
        finish()
    }
}
