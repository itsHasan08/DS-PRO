package com.dspro.guard;

import android.app.Activity;
import android.app.Application;
import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.database.Cursor;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Debug;
import android.os.Process;
import android.view.WindowManager;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.NetworkInterface;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Runtime protection guard compiled into ds_pro_guard.dex and injected into protected APKs.
 * Executes inside ContentProvider.onCreate() before Application.onCreate().
 */
public final class DsProGuardProvider extends ContentProvider {

    private static final String CONFIG_ASSET = "ds_pro_security_config.json";
    private static final String INTEGRITY_ASSET = "ds_pro_integrity.sha256";

    @Override
    public boolean onCreate() {
        final Context context = getContext();
        if (context == null) {
            return true;
        }

        final JSONObject config = readConfig(context);
        if (config == null) {
            return true;
        }

        enforceChecks(context, config);

        final boolean antiScreenshot = config.optBoolean("antiScreenshot", false);
        final boolean detectVpn = config.optBoolean("detectVpn", false);
        final boolean detectDebugger = config.optBoolean("detectDebugger", false);

        if (antiScreenshot || detectVpn || detectDebugger) {
            final Context appCtx = context.getApplicationContext();
            if (appCtx instanceof Application) {
                ((Application) appCtx).registerActivityLifecycleCallbacks(
                    new Application.ActivityLifecycleCallbacks() {
                        @Override
                        public void onActivityCreated(Activity activity, Bundle savedInstanceState) {
                            if (antiScreenshot && activity.getWindow() != null) {
                                activity.getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
                            }
                        }

                        @Override
                        public void onActivityStarted(Activity activity) {
                        }

                        @Override
                        public void onActivityResumed(Activity activity) {
                            if (antiScreenshot && activity.getWindow() != null) {
                                activity.getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
                            }
                            if (detectDebugger && isDebuggerAttached(activity)) {
                                terminate("Debugger detected");
                            }
                            if (detectVpn && isVpnActive(activity)) {
                                terminate("VPN connection detected");
                            }
                        }

                        @Override
                        public void onActivityPaused(Activity activity) {
                        }

                        @Override
                        public void onActivityStopped(Activity activity) {
                        }

                        @Override
                        public void onActivitySaveInstanceState(Activity activity, Bundle outState) {
                        }

                        @Override
                        public void onActivityDestroyed(Activity activity) {
                        }
                    }
                );
            }
        }

        return true;
    }

    private static void enforceChecks(Context context, JSONObject config) {
        if (config.optBoolean("detectDebugger", false) && isDebuggerAttached(context)) {
            terminate("Debugger detected");
        }
        if (config.optBoolean("detectRoot", false) && isDeviceRooted()) {
            terminate("Root environment detected");
        }
        if (config.optBoolean("detectEmulator", false) && isEmulator()) {
            terminate("Emulator environment detected");
        }
        if (config.optBoolean("detectVpn", false) && isVpnActive(context)) {
            terminate("VPN connection detected");
        }
        if (config.optBoolean("detectXposed", false) && isHookingFrameworkPresent()) {
            terminate("Hooking framework detected");
        }
        if (config.optBoolean("antiTampering", false) && !verifyApkIntegrity(context)) {
            terminate("APK integrity verification failed");
        }
        if (config.optBoolean("signaturePinning", false)) {
            final String expectedCert = config.optString("pinnedCertSha256", "");
            if (!expectedCert.isEmpty() && !"UNSIGNED".equalsIgnoreCase(expectedCert)) {
                if (!verifySigningCert(context, expectedCert)) {
                    terminate("APK signature mismatch");
                }
            }
        }
    }

    private static JSONObject readConfig(Context context) {
        try (InputStream in = context.getAssets().open(CONFIG_ASSET)) {
            byte[] buf = new byte[4096];
            StringBuilder sb = new StringBuilder();
            int n;
            while ((n = in.read(buf)) != -1) {
                sb.append(new String(buf, 0, n, StandardCharsets.UTF_8));
            }
            return new JSONObject(sb.toString());
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static boolean isDeviceRooted() {
        String tags = Build.TAGS;
        if (tags != null && tags.contains("test-keys")) {
            return true;
        }
        String[] paths = {
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/su/bin/su",
            "/vendor/bin/su",
            "/magisk/.core/bin/su"
        };
        for (String path : paths) {
            if (new File(path).exists()) {
                return true;
            }
        }
        String pathEnv = System.getenv("PATH");
        if (pathEnv != null) {
            for (String dir : pathEnv.split(":")) {
                if (new File(dir, "su").exists() || new File(dir, "magisk").exists()) {
                    return true;
                }
            }
        }
        return containsInFile("/proc/mounts", "magisk", "kernelsu", "apatch");
    }

    private static boolean isEmulator() {
        String fp = safeLower(Build.FINGERPRINT);
        String model = safeLower(Build.MODEL);
        String manufacturer = safeLower(Build.MANUFACTURER);
        String brand = safeLower(Build.BRAND);
        String device = safeLower(Build.DEVICE);
        String product = safeLower(Build.PRODUCT);
        String hardware = safeLower(Build.HARDWARE);

        if (fp.startsWith("generic")
            || fp.startsWith("unknown")
            || fp.contains("emulator")
            || fp.contains("sdk_gphone")
            || model.contains("google_sdk")
            || model.contains("emulator")
            || model.contains("android sdk built for")
            || manufacturer.contains("genymotion")
            || (brand.startsWith("generic") && device.startsWith("generic"))
            || "google_sdk".equals(product)
            || product.contains("sdk_gphone")
            || product.contains("vbox86p")
            || hardware.contains("goldfish")
            || hardware.contains("ranchu")
            || hardware.contains("vbox86")
            || hardware.contains("nox")) {
            return true;
        }

        return new File("/dev/socket/qemud").exists()
            || new File("/dev/qemu_pipe").exists()
            || new File("/system/lib/libc_malloc_debug_qemu.so").exists();
    }

    private static boolean isVpnActive(Context context) {
        try {
            ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm != null) {
                Network[] networks = cm.getAllNetworks();
                if (networks != null) {
                    for (Network net : networks) {
                        NetworkCapabilities caps = cm.getNetworkCapabilities(net);
                        if (caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                            return true;
                        }
                    }
                }
            }
        } catch (Throwable ignored) {
        }

        try {
            Enumeration<NetworkInterface> ifaces = NetworkInterface.getNetworkInterfaces();
            if (ifaces != null) {
                for (NetworkInterface nif : Collections.list(ifaces)) {
                    if (!nif.isUp() || nif.isLoopback()) {
                        continue;
                    }
                    String name = safeLower(nif.getName());
                    if (name.startsWith("tun") || name.startsWith("ppp") || name.startsWith("wg") || name.startsWith("pptp")) {
                        return true;
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    private static boolean isHookingFrameworkPresent() {
        try {
            Class.forName("de.robv.android.xposed.XposedBridge");
            return true;
        } catch (Throwable ignored) {
        }

        for (StackTraceElement el : Thread.currentThread().getStackTrace()) {
            String cls = safeLower(el.getClassName());
            if (cls.contains("xposed") || cls.contains("lsposed") || cls.contains("substrate") || cls.contains("frida")) {
                return true;
            }
        }

        return containsInFile("/proc/self/maps", "xposed", "lsposed", "edxposed", "frida-agent", "frida-gadget", "libsubstrate");
    }

    private static boolean isDebuggerAttached(Context context) {
        if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) {
            return true;
        }
        if ((context.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
            return true;
        }
        try (BufferedReader reader = new BufferedReader(new FileReader("/proc/self/status"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("TracerPid:")) {
                    String val = line.substring("TracerPid:".length()).trim();
                    if (!"0".equals(val) && !val.isEmpty()) {
                        return true;
                    }
                    break;
                }
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    private static boolean verifyApkIntegrity(Context context) {
        try (BufferedReader manifestReader = new BufferedReader(
            new InputStreamReader(context.getAssets().open(INTEGRITY_ASSET), StandardCharsets.UTF_8)
        );
             ZipFile apkZip = new ZipFile(context.getPackageCodePath())) {

            String line;
            int verified = 0;
            while ((line = manifestReader.readLine()) != null) {
                String trimmed = line.trim();
                if (trimmed.isEmpty()) {
                    continue;
                }
                int sep = trimmed.indexOf("  ");
                if (sep <= 0) {
                    return false;
                }
                String expectedHex = trimmed.substring(0, sep).trim().toLowerCase(Locale.US);
                String entryName = trimmed.substring(sep + 2).trim();
                ZipEntry entry = apkZip.getEntry(entryName);
                if (entry == null) {
                    return false;
                }
                String actualHex = sha256Entry(apkZip, entry);
                if (!expectedHex.equals(actualHex)) {
                    return false;
                }
                verified++;
            }
            return verified > 0;
        } catch (Throwable t) {
            return false;
        }
    }

    @SuppressWarnings("deprecation")
    private static boolean verifySigningCert(Context context, String expectedColonHex) {
        try {
            PackageManager pm = context.getPackageManager();
            String pkg = context.getPackageName();
            byte[] certBytes = null;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                PackageInfo info = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES);
                SigningInfo si = info.signingInfo;
                if (si != null) {
                    Signature[] sigs = si.hasMultipleSigners() ? si.getApkContentsSigners() : si.getSigningCertificateHistory();
                    if (sigs != null && sigs.length > 0) {
                        certBytes = sigs[0].toByteArray();
                    }
                }
            } else {
                PackageInfo info = pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES);
                if (info.signatures != null && info.signatures.length > 0) {
                    certBytes = info.signatures[0].toByteArray();
                }
            }
            if (certBytes == null) {
                return false;
            }
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(certBytes);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < digest.length; i++) {
                if (i > 0) sb.append(':');
                sb.append(String.format(Locale.US, "%02X", digest[i] & 0xFF));
            }
            return sb.toString().equalsIgnoreCase(expectedColonHex);
        } catch (Throwable t) {
            return false;
        }
    }

    private static String sha256Entry(ZipFile zip, ZipEntry entry) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try (InputStream in = zip.getInputStream(entry)) {
            byte[] buf = new byte[16 * 1024];
            int n;
            while ((n = in.read(buf)) != -1) {
                md.update(buf, 0, n);
            }
        }
        byte[] digest = md.digest();
        StringBuilder sb = new StringBuilder(digest.length * 2);
        for (byte b : digest) {
            sb.append(String.format(Locale.US, "%02x", b & 0xFF));
        }
        return sb.toString();
    }

    private static boolean containsInFile(String filePath, String... needles) {
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String lower = line.toLowerCase(Locale.US);
                for (String needle : needles) {
                    if (lower.contains(needle)) {
                        return true;
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    private static String safeLower(String s) {
        return s == null ? "" : s.toLowerCase(Locale.US);
    }

    private static void terminate(String reason) {
        Process.killProcess(Process.myPid());
        System.exit(10);
        throw new SecurityException("DS PRO: " + reason);
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        return null;
    }

    @Override
    public String getType(Uri uri) {
        return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        return null;
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        return 0;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        return 0;
    }
}
