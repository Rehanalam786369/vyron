package com.vyron.networkcontrol

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.view.View
import android.widget.*
import org.json.JSONObject
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import kotlin.concurrent.thread

class BlockedOverlayActivity : Activity() {

    private lateinit var policyStore: PolicyStore
    private var targetType: String = "app"
    private var packageName: String = ""
    private var appName: String = ""
    private var blockReason: String = ""
    private var activeWaiverId: Int? = null
    private val handler = Handler(Looper.getMainLooper())
    private var pollRunnable: Runnable? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        policyStore = PolicyStore(this)
        loadExtras(intent)
        buildView()
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        if (intent != null) {
            setIntent(intent)
            loadExtras(intent)
            buildView()
        }
    }

    private fun loadExtras(intent: Intent) {
        targetType = intent.getStringExtra("EXTRA_TARGET_TYPE") ?: "app"
        packageName = intent.getStringExtra("EXTRA_PACKAGE_NAME") ?: ""
        appName = intent.getStringExtra("EXTRA_APP_NAME") ?: packageName
        blockReason = intent.getStringExtra("EXTRA_REASON") ?: "Restricted by VYRON policy"
    }

    private fun buildView() {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor("#070a12"))
            gravity = Gravity.CENTER
            setPadding(64, 64, 64, 64)
        }

        // Shield Icon Badge
        val iconText = TextView(this).apply {
            text = "🛡️"
            textSize = 54f
            gravity = Gravity.CENTER
            setPadding(0, 0, 0, 24)
        }
        root.addView(iconText)

        // Title
        val title = TextView(this).apply {
            text = "VYRON Guided Pause"
            textSize = 24f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.WHITE)
            gravity = Gravity.CENTER
            setPadding(0, 0, 0, 8)
        }
        root.addView(title)

        // Subtitle / App Target
        val targetText = TextView(this).apply {
            text = appName
            textSize = 18f
            setTextColor(Color.parseColor("#38bdf8"))
            typeface = Typeface.MONOSPACE
            gravity = Gravity.CENTER
            setPadding(0, 0, 0, 16)
        }
        root.addView(targetText)

        // Reason Card
        val reasonCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            val bg = GradientDrawable().apply {
                setColor(Color.parseColor("#0f172a"))
                setStroke(2, Color.parseColor("#f43f5e"))
                cornerRadius = 16f
            }
            background = bg
            setPadding(32, 24, 32, 24)
            gravity = Gravity.CENTER
        }

        val reasonLabel = TextView(this).apply {
            text = "REASON"
            textSize = 11f
            setTextColor(Color.parseColor("#fb7185"))
            typeface = Typeface.DEFAULT_BOLD
            gravity = Gravity.CENTER
        }
        val reasonDesc = TextView(this).apply {
            text = blockReason
            textSize = 14f
            setTextColor(Color.parseColor("#f1f5f9"))
            gravity = Gravity.CENTER
            setPadding(0, 8, 0, 0)
        }
        reasonCard.addView(reasonLabel)
        reasonCard.addView(reasonDesc)
        root.addView(reasonCard)

        // Optional Note Input
        val noteInput = EditText(this).apply {
            hint = "Optional: Add a note for parent..."
            setHintTextColor(Color.parseColor("#64748b"))
            setTextColor(Color.WHITE)
            textSize = 13f
            val bg = GradientDrawable().apply {
                setColor(Color.parseColor("#0b1120"))
                setStroke(1, Color.parseColor("#334155"))
                cornerRadius = 12f
            }
            background = bg
            setPadding(28, 20, 28, 20)
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(0, 36, 0, 20) }
        }
        root.addView(noteInput)

        // Status Feedback Area
        val statusFeedback = TextView(this).apply {
            text = ""
            textSize = 12f
            setTextColor(Color.parseColor("#f59e0b"))
            gravity = Gravity.CENTER
            visibility = View.GONE
            setPadding(0, 0, 0, 16)
        }
        root.addView(statusFeedback)

        // Request Waiver Button
        val waiverBtn = Button(this).apply {
            text = "Request Emergency Waiver (10 min)"
            textSize = 13f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.WHITE)
            val bg = GradientDrawable().apply {
                setColor(Color.parseColor("#7e22ce"))
                cornerRadius = 12f
            }
            background = bg
            setPadding(24, 24, 24, 24)
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            )
            setOnClickListener {
                val reason = noteInput.text.toString().trim().ifEmpty { "Emergency access requested" }
                isEnabled = false
                statusFeedback.text = "Sending request to supervisor..."
                statusFeedback.visibility = View.VISIBLE
                sendWaiverRequest(reason, statusFeedback, this)
            }
        }
        root.addView(waiverBtn)

        // Return Home Button
        val homeBtn = Button(this).apply {
            text = "Return to Home Screen"
            textSize = 13f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.parseColor("#94a3b8"))
            val bg = GradientDrawable().apply {
                setColor(Color.parseColor("#1e293b"))
                cornerRadius = 12f
            }
            background = bg
            setPadding(24, 24, 24, 24)
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(0, 16, 0, 0) }
            setOnClickListener {
                goHome()
            }
        }
        root.addView(homeBtn)

        setContentView(root)
    }

    private fun sendWaiverRequest(reason: String, feedbackView: TextView, button: Button) {
        val serverUrl = policyStore.serverUrl.trimEnd('/')
        val token = policyStore.deviceToken

        thread {
            try {
                val url = URL("$serverUrl/api/device/waivers/request")
                val conn = url.openConnection() as HttpURLConnection
                conn.requestMethod = "POST"
                conn.setRequestProperty("Content-Type", "application/json")
                conn.setRequestProperty("X-VYRON-TOKEN", token)
                conn.doOutput = true
                conn.connectTimeout = 35000
                conn.readTimeout = 35000

                val payload = JSONObject().apply {
                    put("target_type", targetType)
                    put("target", packageName)
                    put("display_name", appName)
                    put("duration_minutes", 10)
                    put("reason", reason)
                }

                OutputStreamWriter(conn.outputStream).use { it.write(payload.toString()) }

                val code = conn.responseCode
                if (code == 201) {
                    val respStr = conn.inputStream.bufferedReader().use { it.readText() }
                    val json = JSONObject(respStr)
                    val waiverId = json.optInt("waiver_id")
                    activeWaiverId = waiverId

                    handler.post {
                        feedbackView.text = "Waiver requested! Waiting for supervisor approval..."
                        startPollingWaiver(waiverId, feedbackView)
                    }
                } else {
                    handler.post {
                        feedbackView.text = "Request failed. Server returned code $code"
                        button.isEnabled = true
                    }
                }
            } catch (e: Exception) {
                handler.post {
                    feedbackView.text = "Could not reach server: ${e.message}"
                    button.isEnabled = true
                }
            }
        }
    }

    private fun startPollingWaiver(waiverId: Int, feedbackView: TextView) {
        val serverUrl = policyStore.serverUrl.trimEnd('/')
        val token = policyStore.deviceToken

        pollRunnable = object : Runnable {
            override fun run() {
                thread {
                    try {
                        val url = URL("$serverUrl/api/device/waivers/$waiverId")
                        val conn = url.openConnection() as HttpURLConnection
                        conn.requestMethod = "GET"
                        conn.setRequestProperty("X-VYRON-TOKEN", token)
                        conn.connectTimeout = 20000
                        conn.readTimeout = 20000

                        if (conn.responseCode == 200) {
                            val resp = conn.inputStream.bufferedReader().use { it.readText() }
                            val json = JSONObject(resp)
                            val status = json.optString("status")

                            if (status == "APPROVED") {
                                // Sync latest policy cleanly through shared sync manager
                                VyronPolicySyncManager.performSyncBlocking(this@BlockedOverlayActivity)
                                handler.post {
                                    feedbackView.setTextColor(Color.parseColor("#34d399"))
                                    feedbackView.text = "Waiver Approved! Resuming application..."
                                    handler.postDelayed({ finish() }, 1000)
                                }
                                return@thread
                            } else if (status == "DENIED") {
                                handler.post {
                                    feedbackView.setTextColor(Color.parseColor("#fb7185"))
                                    feedbackView.text = "Supervisor denied the emergency waiver request."
                                }
                                return@thread
                            }
                        }
                    } catch (e: Exception) {
                        // ignore network hiccup during poll
                    }
                    handler.postDelayed(pollRunnable!!, 2000)
                }
            }
        }
        handler.postDelayed(pollRunnable!!, 2000)
    }

    private fun goHome() {
        val homeIntent = Intent(Intent.ACTION_MAIN).apply {
            addCategory(Intent.CATEGORY_HOME)
            flags = Intent.FLAG_ACTIVITY_NEW_TASK
        }
        startActivity(homeIntent)
        finish()
    }

    override fun onBackPressed() {
        goHome()
    }

    override fun onDestroy() {
        super.onDestroy()
        pollRunnable?.let { handler.removeCallbacks(it) }
    }
}
