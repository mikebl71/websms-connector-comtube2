package com.mikebl71.android.websms.connector.comtube2;

import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.preference.Preference;
import android.preference.PreferenceActivity;
import android.preference.PreferenceManager;
import android.view.View;
import android.widget.EditText;

/**
 * Preferences.
 */
@SuppressWarnings("deprecation")
public final class Preferences extends PreferenceActivity {

    /** Preference key: enabled */
    public static final String PREFS_ENABLED = "enable_connector";
    /** Preference key: username */
    public static final String PREFS_USERNAME = "username";
    /** Preference key: password */
    public static final String PREFS_PASSWORD = "password";
    /** Preference key: sender name */
    public static final String PREFS_SENDER = "sender_name";

    @Override
    protected void onCreate(final Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        addPreferencesFromResource(R.xml.prefs);
    }

}
