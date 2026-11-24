package com.vyron.networkcontrol

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Bundle
import android.text.TextUtils
import android.view.Gravity
import android.view.KeyEvent
import android.view.View
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputMethodManager
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import java.io.ByteArrayInputStream
import java.net.URLEncoder

/**
 * Built-in VYRON Safe Browser.
 * Registers as a system Android browser (http/https) so users can set VYRON
 * as their Default Browser for Zero-VPN-Icon domain filtering (online & offline).
 */
class VyronBrowserActivity : Activity() {

    private lateinit var policyStore: PolicyStore
    private lateinit var webView: WebView
    private lateinit var urlInput: EditText
    private lateinit var progressBar: ProgressBar
    private val defaultHomeUrl = "https://www.google.com"

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        policyStore = PolicyStore(this)
        VyronPolicySyncManager.syncIfDueAsync(this, 15000L)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor("#070A12"))
        }

        // Top Shield Strip
        val statusBar = TextView(this).apply {
            text = "🛡️ VYRON ON-DEVICE DNS BROWSER • ZERO VPN ICON"
            textSize = 10f
            setTypeface(Typeface.MONOSPACE, Typeface.BOLD)
            setTextColor(Color.parseColor("#34D399"))
            setBackgroundColor(Color.parseColor("#0B132B"))
            gravity = Gravity.CENTER
            setPadding(16, 10, 16, 10)
        }
        root.addView(statusBar)

        // Navigation Toolbar
        val toolbar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setBackgroundColor(Color.parseColor("#0F172A"))
            setPadding(12, 12, 12, 12)
        }

        fun navBtn(label: String, onClick: () -> Unit): Button {
            return Button(this).apply {
                text = label
                textSize = 15f
                setTextColor(Color.WHITE)
                setBackgroundColor(Color.TRANSPARENT)
                minWidth = 0
                minimumWidth = 0
                setPadding(18, 8, 18, 8)
                setOnClickListener { onClick() }
            }
        }

        toolbar.addView(navBtn("←") { if (webView.canGoBack()) webView.goBack() })
        toolbar.addView(navBtn("↻") { webView.reload() })

        urlInput = EditText(this).apply {
            hint = "Search or enter URL..."
            setHintTextColor(Color.parseColor("#64748B"))
            setTextColor(Color.WHITE)
            textSize = 13f
            isSingleLine = true
            imeOptions = EditorInfo.IME_ACTION_GO
            setPadding(24, 14, 24, 14)
            background = GradientDrawable().apply {
                setColor(Color.parseColor("#070A12"))
                cornerRadius = 18f
                setStroke(2, Color.parseColor("#1E293B"))
            }
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply {
                setMargins(8, 0, 8, 0)
            }
            setOnEditorActionListener { _, actionId, event ->
                if (actionId == EditorInfo.IME_ACTION_GO ||
                    (event != null && event.keyCode == KeyEvent.KEYCODE_ENTER && event.action == KeyEvent.ACTION_DOWN)
                ) {
                    navigateToInput(text.toString())
                    true
                } else {
                    false
                }
            }
        }
        toolbar.addView(urlInput)

        toolbar.addView(navBtn("⚙") {
            startActivity(Intent(this, MainActivity::class.java))
        })

        root.addView(toolbar)

        progressBar = ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal).apply {
            max = 100
            visibility = View.GONE
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 6)
        }
        root.addView(progressBar)

        webView = WebView(this).apply {
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f)
            settings.apply {
                javaScriptEnabled = true
                domStorageEnabled = true
                useWideViewPort = true
                loadWithOverviewMode = true
                builtInZoomControls = true
                displayZoomControls = false
                mixedContentMode = WebSettings.MIXED_CONTENT_COMPATIBILITY_MODE
            }

            webChromeClient = object : WebChromeClient() {
                override fun onProgressChanged(view: WebView?, newProgress: Int) {
                    if (newProgress in 1..99) {
                        progressBar.visibility = View.VISIBLE
                        progressBar.progress = newProgress
                    } else {
                        progressBar.visibility = View.GONE
                    }
                }
            }

            webViewClient = object : WebViewClient() {
                override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
                    val uri = request?.url ?: return false
                    val host = uri.host?.lowercase() ?: ""
                    if (host.isNotEmpty() && policyStore.isDomainBlockedWithWaiver(host)) {
                        VyronPolicySyncManager.queueLog(
                            "domain",
                            host,
                            "BLOCKED",
                            "Blocked in VYRON Default Browser ($host)"
                        )
                        showBlockedHtml(host)
                        return true
                    }
                    return false
                }

                override fun onPageFinished(view: WebView?, url: String?) {
                    super.onPageFinished(view, url)
                    if (!url.isNullOrEmpty() && !url.startsWith("data:")) {
                        urlInput.setText(url)
                    }
                }

                override fun shouldInterceptRequest(
                    view: WebView?,
                    request: WebResourceRequest?
                ): WebResourceResponse? {
                    val host = request?.url?.host?.lowercase() ?: ""
                    if (host.isNotEmpty() && policyStore.isDomainBlockedWithWaiver(host)) {
                        return WebResourceResponse(
                            "text/plain",
                            "utf-8",
                            403,
                            "Blocked by VYRON",
                            emptyMap(),
                            ByteArrayInputStream(ByteArray(0))
                        )
                    }
                    return super.shouldInterceptRequest(view, request)
                }
            }
        }
        root.addView(webView)
        setContentView(root)

        handleIncomingIntent(intent)
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIncomingIntent(intent)
    }

    override fun onResume() {
        super.onResume()
        VyronPolicySyncManager.syncIfDueAsync(this, 30000L)
    }

    private fun handleIncomingIntent(intent: Intent?) {
        val dataUrl = intent?.dataString
        if (!dataUrl.isNullOrBlank()) {
            navigateToInput(dataUrl)
        } else {
            navigateToInput(defaultHomeUrl)
        }
    }

    private fun navigateToInput(rawInput: String) {
        val trimmed = rawInput.trim()
        if (trimmed.isEmpty()) return

        // Hide soft keyboard
        try {
            val imm = getSystemService(INPUT_METHOD_SERVICE) as? InputMethodManager
            imm?.hideSoftInputFromWindow(urlInput.windowToken, 0)
        } catch (_: Exception) {
        }

        val targetUrl = when {
            trimmed.startsWith("http://", ignoreCase = true) ||
                trimmed.startsWith("https://", ignoreCase = true) -> trimmed
            trimmed.contains(".") && !trimmed.contains(" ") -> "https://$trimmed"
            else -> "https://www.google.com/search?q=${URLEncoder.encode(trimmed, "UTF-8")}"
        }

        val host = Uri.parse(targetUrl).host?.lowercase() ?: ""
        if (host.isNotEmpty() && policyStore.isDomainBlockedWithWaiver(host)) {
            VyronPolicySyncManager.queueLog("domain", host, "BLOCKED", "Blocked in VYRON Default Browser ($host)")
            urlInput.setText(targetUrl)
            showBlockedHtml(host)
            return
        }

        urlInput.setText(targetUrl)
        webView.loadUrl(targetUrl)
    }

    private fun showBlockedHtml(host: String) {
        val safeHost = TextUtils.htmlEncode(host)
        val html = """
            <!DOCTYPE html>
            <html>
            <head>
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <style>
                body { background:#070a12; color:#f8fafc; font-family:sans-serif; display:flex; align-items:center; justify-content:center; min-height:90vh; margin:0; padding:24px; text-align:center; }
                .card { background:#0f172a; border:1px solid #e11d48; border-radius:16px; padding:28px; max-width:380px; }
                .badge { color:#fb7185; font-size:12px; font-weight:700; letter-spacing:1px; margin-bottom:10px; }
                h2 { margin:0 0 10px 0; font-size:20px; }
                p { color:#94a3b8; font-size:14px; line-height:1.5; }
                .host { font-family:monospace; color:#38bdf8; background:#070a12; padding:6px 12px; border-radius:8px; display:inline-block; margin:10px 0; }
                a { display:inline-block; margin-top:16px; background:#0284c7; color:white; text-decoration:none; padding:10px 18px; border-radius:8px; font-weight:bold; font-size:13px; }
              </style>
            </head>
            <body>
              <div class="card">
                <div class="badge">🛡️ VYRON ON-DEVICE SHIELD</div>
                <h2>Website Restricted</h2>
                <div class="host">$safeHost</div>
                <p>Blocked immediately by your on-device VYRON policy (0ms local lookup, online & offline).</p>
                <a href="https://www.google.com">Return to Safe Search</a>
              </div>
            </body>
            </html>
        """.trimIndent()
        webView.loadDataWithBaseURL(null, html, "text/html", "UTF-8", null)
    }

    @Deprecated("Deprecated in Java")
    @Suppress("DEPRECATION")
    override fun onBackPressed() {
        if (webView.canGoBack()) {
            webView.goBack()
        } else {
            super.onBackPressed()
        }
    }
}
