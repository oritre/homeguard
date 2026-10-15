package com.oritre.homeguard

import android.app.RemoteInput
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Buttons on the timer notification. */
class ActionReceiver : BroadcastReceiver() {
    companion object {
        const val MORE = "com.oritre.homeguard.MORE"
        const val DONE = "com.oritre.homeguard.DONE"
        const val SITE = "com.oritre.homeguard.SITE"
        const val KEY_SITE = "site"
    }

    override fun onReceive(context: Context, intent: Intent) {
        val svc = GuardService.instance ?: return
        when (intent.action) {
            MORE -> svc.askMore()
            DONE -> svc.done()
            SITE -> {
                val site = RemoteInput.getResultsFromIntent(intent)?.getCharSequence(KEY_SITE)?.toString()?.trim()
                if (!site.isNullOrEmpty()) svc.requestSite(site)
                svc.pollOnceAsync()
            }
        }
    }
}
