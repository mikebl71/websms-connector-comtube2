package com.mikebl71.android.websms.connector.comtube2;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.entity.StringEntity;
import org.apache.http.message.BasicHeader;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Handler;
import android.os.Looper;
import android.preference.PreferenceManager;
import android.text.TextUtils;
import android.widget.Toast;

import de.ub0r.android.websms.connector.common.Connector;
import de.ub0r.android.websms.connector.common.ConnectorCommand;
import de.ub0r.android.websms.connector.common.ConnectorSpec;
import de.ub0r.android.websms.connector.common.ConnectorSpec.SubConnectorSpec;
import de.ub0r.android.websms.connector.common.Log;
import de.ub0r.android.websms.connector.common.Utils;
import de.ub0r.android.websms.connector.common.WebSMSException;
import de.ub0r.android.websms.connector.common.WebSMSNoNetworkException;

/**
 * Main class for Comtube2 Connector.
 * Receives commands from WebSMS and acts upon them.
 */
public class Comtube2Connector extends Connector {

    // Logging tag
    private static final String TAG = "comtube2";

    private static final String SERVICE_URL = "https://api.comtube.ru/scripts/api/sms.php";
    private static final String ENCODING = "UTF-8";

    // Delay between status checks
    private static final long STATUS_CHECK_DELAY_MS  = 10000;
    // Max number of status checks
    private static final int STATUS_CHECK_MAXCNT = 3;

    private static final String SMS_STATUS_SENT      = "10";
    private static final String SMS_STATUS_DELIVERED = "12";
    private static final String SMS_STATUS_ENQUEUED  = "20";
    private static final String SMS_STATUS_FAILED    = "0";

    /**
     * Initializes {@link ConnectorSpec}. This is only run once.
     * Changing properties are set in updateSpec().
     */
    @Override
    public ConnectorSpec initSpec(Context context) {
        ConnectorSpec c = new ConnectorSpec(context.getString(R.string.connector_comtube2_name));
        c.setAuthor(context.getString(R.string.connector_comtube2_author));
        c.setBalance(null);
        c.setCapabilities(ConnectorSpec.CAPABILITIES_SEND
                | ConnectorSpec.CAPABILITIES_PREFS);

        c.addSubConnector(TAG, c.getName(), SubConnectorSpec.FEATURE_NONE);

        return c;
    }

    /**
     * Updates connector's status.
     */
    @Override
    public ConnectorSpec updateSpec(Context context, ConnectorSpec connectorSpec) {
        final SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        if (prefs.getBoolean(Preferences.PREFS_ENABLED, false)) {
            connectorSpec.setReady();
        } else {
            connectorSpec.setStatus(ConnectorSpec.STATUS_INACTIVE);
        }
        return connectorSpec;
    }

    /**
     * Called to send the actual message.
     */
    @Override
    protected void doSend(Context context, Intent intent) throws IOException {
        if (!Utils.isNetworkAvailable(context)) {
            throw new WebSMSNoNetworkException(context);
        }

        String msgUID = sendMessage(context, new ConnectorCommand(intent));

        // retrieve status
        String status = "";
        for (int tryCnt = 0; tryCnt < STATUS_CHECK_MAXCNT; tryCnt++) {

            sleep(STATUS_CHECK_DELAY_MS);

            status = checkMessageStatus(context, msgUID);

            if (status.equals(SMS_STATUS_DELIVERED)) {
                break;

            } else if (status.equals(SMS_STATUS_FAILED)) {
                Log.e(TAG, "Message status: FAILED");
                throw new WebSMSException(context, R.string.error_sms_failed);
            }
            // else continue
        }

        if (status.equals(SMS_STATUS_ENQUEUED)) {
            showToast(context, R.string.toast_sms_enqueued);
        } else if (status.equals(SMS_STATUS_SENT)) {
            showToast(context, R.string.toast_sms_sent);
        } else if (status.equals(SMS_STATUS_DELIVERED)) {
            showToast(context, R.string.toast_sms_delivered);
        }
    }

    private String sendMessage(Context context, ConnectorCommand command) throws IOException {
        final SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);

        String username = prefs.getString(Preferences.PREFS_USERNAME, "");
        String password = prefs.getString(Preferences.PREFS_PASSWORD, "");
        String senderId = prefs.getString(Preferences.PREFS_SENDER, "");

        Map<String,String> postData = new HashMap<String,String>();
        postData.put("action", "send");
        postData.put("charset", "utf-8");
        postData.put("message", command.getText());
        postData.put("number", Utils.joinRecipientsNumbers(command.getRecipients(), ",", false /*oldFormat*/));
        postData.put("senderid", senderId);
        postData.put("type", "xml");
        postData.put("username", username);

        HttpResponse response = executeHttp(context, SERVICE_URL, postData, password);

        String responseText = Utils.stream2str(response.getEntity().getContent());

        String code = getStringBetween(responseText, "<code>", "</code>");
        String desc = getStringBetween(responseText, "<desc>", "</desc>");
        if (!"200".equals(code)) {
            Log.e(TAG, "Unexpected send response: " + responseText);
            throw new WebSMSException(context, R.string.error_send, desc);
        }

        String msgUID = getStringBetween(responseText, "<uid>", "</uid>");
        if (TextUtils.isEmpty(msgUID)) {
            Log.e(TAG, "Unexpected send response: " + responseText);
            throw new WebSMSException(context, R.string.error_send, "UID");
        }
        Log.d(TAG, "Message unique key: " + msgUID);
        return msgUID;
    }

    private String checkMessageStatus(Context context, String msgUID) throws IOException {
        final SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);

        String username = prefs.getString(Preferences.PREFS_USERNAME, "");
        String password = prefs.getString(Preferences.PREFS_PASSWORD, "");

        Map<String,String> postData = new HashMap<String,String>();
        postData.put("action", "state");
        postData.put("uid", msgUID);
        postData.put("charset", "utf-8");
        postData.put("type", "xml");
        postData.put("username", username);

        HttpResponse response = executeHttp(context, SERVICE_URL, postData, password);

        String responseText = Utils.stream2str(response.getEntity().getContent());

        String status = getStringBetween(responseText, "<status>", "</status>");
        String desc = getStringBetween(responseText, "<desc>", "</desc>");
        if (TextUtils.isEmpty(status)) {
            Log.e(TAG, "Unexpected status response: " + responseText);
            throw new WebSMSException(context, R.string.error_status, desc);
        }
        return status;
    }

    private HttpResponse executeHttp(Context context, String url, Map<String, String> params, String password)
            throws IOException {
        Utils.HttpOptions options = new Utils.HttpOptions(ENCODING);
        options.url = url;
        options.trustAll = true;

        if (options.headers == null) {
            options.headers = new ArrayList<Header>();
        }
        options.headers.add(new BasicHeader("Content-Type", "application/x-www-form-urlencoded"));

        options.postData = new StringEntity(buildUrlParamsWithSignature(params, password), ENCODING);

        //java.util.logging.Logger.getLogger("org.apache.http.wire").setLevel(java.util.logging.Level.FINEST);
        // adb shell setprop log.tag.org.apache.http.wire VERBOSE

        HttpResponse response = Utils.getHttpClient(options);

        if (response.getStatusLine().getStatusCode() != HttpURLConnection.HTTP_OK) {
            throw new WebSMSException(context,
                    R.string.error_http,
                    response.getStatusLine().getReasonPhrase());
        }

        if (response.getEntity() == null) {
            throw new WebSMSException(context, R.string.error_empty_response);
        }

        return response;
    }

    private String buildUrlParamsWithSignature(Map<String, String> params, String password) {
        StringBuilder urlParams  = new StringBuilder();
        Set<String> sortedKeys = new TreeSet<String>(params.keySet());

        try {
            for (String key : sortedKeys) {
                if (params.get(key) != null) {
                    String value = URLEncoder.encode(params.get(key), "UTF-8");

                    // Java bug workaround.
                    value = value.replace("*", "%2A");
                    value = value.replace("~", "%7E");

                    urlParams.append(key).append('=').append(value).append('&');
                }
            }

            MessageDigest md5 = MessageDigest.getInstance("MD5");

            md5.reset();
            md5.update((urlParams.toString() + "&password=" + URLEncoder.encode(password, "UTF8")).getBytes());

            urlParams.append("signature=").append(convertToHex(md5.digest()).toLowerCase());

        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("MD5 algorithm not found");

        } catch (java.io.UnsupportedEncodingException e) {
            throw new IllegalStateException("UTF-8 charset not found");
        }
        return urlParams.toString();
    }

    private String convertToHex(byte[] data) {
        StringBuilder buf = new StringBuilder();
        for (byte aData : data) {
            int halfByte = (aData >>> 4) & 0x0F;
            int twoHalfs = 0;
            do {
                if ((0 <= halfByte) && (halfByte <= 9)) {
                    buf.append((char) ('0' + halfByte));
                } else {
                    buf.append((char) ('a' + (halfByte - 10)));
                }
                halfByte = aData & 0x0F;
            } while (twoHalfs++ < 1);
        }
        return buf.toString();
    }

    private String getStringBetween(String src, String from, String to) {
        String sub = src;
        if (sub != null) {
            int fromIdx = sub.indexOf(from);
            if (fromIdx >= 0) {
                sub = sub.substring(fromIdx + from.length());
                int toIdx = sub.indexOf(to);
                if (toIdx >= 0) {
                    sub = sub.substring(0, toIdx);
                    return sub;
                }
            }
        }
        return "";
    }

    private void showToast(final Context ctx, final int stringRes) {
        new Handler(Looper.getMainLooper()).post(new Runnable() {
            public void run() {
                Toast.makeText(ctx, ctx.getString(stringRes), Toast.LENGTH_SHORT).show();
            }
        });
    }

    private void sleep(long delayMs) {
        try {
            Thread.sleep(delayMs);
        } catch (Exception ex) {
        }
    }

}
