package com.ctf.app

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.text.InputType
import android.view.View
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputMethodManager
import android.widget.*
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import com.chaquo.python.Python
import com.chaquo.python.android.AndroidPlatform
import kotlinx.coroutines.*
import org.json.JSONException
import org.json.JSONObject

class MainActivity : AppCompatActivity() {

    private lateinit var queryInput: EditText
    private lateinit var runButton: Button
    private lateinit var copyButton: Button
    private lateinit var settingsButton: ImageButton
    private lateinit var outputView: TextView
    private lateinit var scrollView: ScrollView
    private lateinit var progressBar: ProgressBar
    private lateinit var statusLabel: TextView

    private var lastResult: String = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        queryInput     = findViewById(R.id.queryInput)
        runButton      = findViewById(R.id.runButton)
        copyButton     = findViewById(R.id.copyButton)
        settingsButton = findViewById(R.id.settingsButton)
        outputView     = findViewById(R.id.outputView)
        scrollView     = findViewById(R.id.scrollView)
        progressBar    = findViewById(R.id.progressBar)
        statusLabel    = findViewById(R.id.statusLabel)

        progressBar.visibility = View.GONE
        copyButton.visibility  = View.GONE

        if (!Python.isStarted()) {
            Python.start(AndroidPlatform(this))
        }

        runButton.setOnClickListener { startInvestigation() }
        copyButton.setOnClickListener { copyToClipboard() }
        settingsButton.setOnClickListener { showSettingsDialog() }

        queryInput.setOnEditorActionListener { _, actionId, _ ->
            if (actionId == EditorInfo.IME_ACTION_DONE) {
                startInvestigation()
                true
            } else false
        }
    }

    /**
     * Module 4 (reverse infrastructure mapping) can use a GitHub personal
     * access token and a HaveIBeenPwned API key to raise its GitHub rate
     * limit and enable breach lookups. Both are optional - the module
     * degrades gracefully without them. Stored locally in the app's
     * private SharedPreferences, never sent anywhere except as the
     * Authorization header on the respective API's own request.
     */
    private fun showSettingsDialog() {
        val prefs = getSharedPreferences("ctf_settings", Context.MODE_PRIVATE)

        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 32, 48, 0)
        }

        val githubLabel = TextView(this).apply { text = "GitHub personal access token (optional)" }
        val githubInput = EditText(this).apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            setText(prefs.getString("github_token", ""))
        }
        val hibpLabel = TextView(this).apply {
            text = "HaveIBeenPwned API key (optional)"
            setPadding(0, 32, 0, 0)
        }
        val hibpInput = EditText(this).apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            setText(prefs.getString("hibp_key", ""))
        }

        container.addView(githubLabel)
        container.addView(githubInput)
        container.addView(hibpLabel)
        container.addView(hibpInput)

        AlertDialog.Builder(this)
            .setTitle("Module 4 API Keys")
            .setView(container)
            .setPositiveButton("Save") { _, _ ->
                prefs.edit()
                    .putString("github_token", githubInput.text.toString().trim().ifEmpty { null })
                    .putString("hibp_key", hibpInput.text.toString().trim().ifEmpty { null })
                    .apply()
                Toast.makeText(this, "Saved", Toast.LENGTH_SHORT).show()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun startInvestigation() {
        val query = queryInput.text.toString().trim()
        if (query.isEmpty()) {
            outputView.text = "Enter a target first."
            return
        }

        // Dismiss keyboard
        (getSystemService(Context.INPUT_METHOD_SERVICE) as InputMethodManager)
            .hideSoftInputFromWindow(queryInput.windowToken, 0)

        runButton.isEnabled    = false
        copyButton.visibility  = View.GONE
        progressBar.visibility = View.VISIBLE
        statusLabel.text       = "Running: $query"
        outputView.text        = ""

        CoroutineScope(Dispatchers.Main).launch {
            val raw = withContext(Dispatchers.IO) { callPython(query) }
            displayResult(raw)
            runButton.isEnabled    = true
            progressBar.visibility = View.GONE
        }
    }

    private fun callPython(query: String): String {
        return try {
            val py     = Python.getInstance()
            val bridge = py.getModule("ctf_bridge")
            // filesDir is the app's private, writable storage - Chaquopy's
            // process cwd is not writable, so the evidence journal needs an
            // explicit path or every investigation fails before it starts.
            val prefs = getSharedPreferences("ctf_settings", Context.MODE_PRIVATE)
            val githubToken = prefs.getString("github_token", null)
            val hibpKey = prefs.getString("hibp_key", null)
            bridge.callAttr(
                "run_investigation",
                query,
                filesDir.absolutePath,
                githubToken,
                hibpKey
            ).toString()
        } catch (e: Exception) {
            """{"error": "${e.message}", "error_type": "${e.javaClass.simpleName}"}"""
        }
    }

    private fun displayResult(raw: String) {
        lastResult = raw
        val sb = StringBuilder()

        try {
            val j = JSONObject(raw)

            // Narration log (the print() output from modules)
            val log = j.optString("log", "").trim()
            if (log.isNotEmpty()) {
                sb.appendLine("── INVESTIGATION LOG ──────────────────")
                sb.appendLine(log)
            }

            // Error
            val err = j.optString("error", "")
            if (err.isNotEmpty()) {
                sb.appendLine("── ERROR ───────────────────────────────")
                sb.appendLine("${j.optString("error_type")}: $err")
                statusLabel.text = "Error"
            } else {
                // Structured results
                val results = j.optJSONObject("results")
                if (results != null) {
                    sb.appendLine("\n── STRUCTURED RESULTS ──────────────────")
                    sb.appendLine(results.toString(2))
                }

                // Report engine output (law enforcement handoff + court report)
                val leReport = j.optString("le_report", "").trim()
                if (leReport.isNotEmpty()) {
                    sb.appendLine("\n── LAW ENFORCEMENT HANDOFF ─────────────")
                    sb.appendLine(leReport)
                }
                val courtReport = j.optString("court_report", "").trim()
                if (courtReport.isNotEmpty()) {
                    sb.appendLine("\n── COURT-ADMISSIBLE REPORT ─────────────")
                    sb.appendLine(courtReport)
                }

                statusLabel.text = "Complete"
            }
        } catch (_: JSONException) {
            sb.appendLine(raw)
            statusLabel.text = "Done"
        }

        outputView.text = sb.toString()
        copyButton.visibility = View.VISIBLE
        scrollView.post { scrollView.fullScroll(View.FOCUS_DOWN) }
    }

    private fun copyToClipboard() {
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("CTF Results", lastResult))
        Toast.makeText(this, "Copied to clipboard", Toast.LENGTH_SHORT).show()
    }
}
