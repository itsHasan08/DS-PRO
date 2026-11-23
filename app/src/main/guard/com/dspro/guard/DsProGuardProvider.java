package com.dspro.guard;

import android.app.Activity;
import android.app.Application;
import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Debug;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.WindowManager;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Runtime protection guard compiled into ds_pro_guard.dex and injected into protected APKs.
 * Reads encrypted binary security configuration from assets/dspro_guard.bin, wipes keys immediately,
 * enforces checks at startup/Activity resume, and runs a live anti-dump watchdog thread.
 */
public final class DsProGuardProvider extends ContentProvider {

    private static final String TAG = "DsProGuard";

    private static final int FLAG_DETECT_ROOT = 1;
    private static final int FLAG_DETECT_EMULATOR = 1 << 1;
    private static final int FLAG_DETECT_XPOSED = 1 << 3;
    private static final int FLAG_DETECT_DEBUGGER = 1 << 4;
    private static final int FLAG_ANTI_SCREENSHOT = 1 << 5;
    private static final int FLAG_ANTI_TAMPERING = 1 << 6;
    private static final int FLAG_SIGNATURE_PINNING = 1 << 7;
    private static final int FLAG_ANTI_DUMP = 1 << 8;

    private static final String POLICY_ASSET = "dspro_guard.bin";
    private static volatile boolean watchdogStarted = false;

    private static final class GuardPolicy {
        final int flags;
        final String pinnedCertSha256;
        final List<String> integrityEntries;

        GuardPolicy(int flags, String pinnedCertSha256, List<String> integrityEntries) {
            this.flags = flags;
            this.pinnedCertSha256 = pinnedCertSha256;
            this.integrityEntries = integrityEntries;
        }

        boolean has(int flag) {
            return (flags & flag) != 0;
        }
    }

    @Override
    public boolean onCreate() {
        final Context context = getContext();
        if (context == null) {
            return true;
        }

        final GuardPolicy policy = readEncryptedPolicy(context);
        if (policy == null) {
            return true;
        }

        enforceChecks(context, policy);

        final boolean antiScreenshot = policy.has(FLAG_ANTI_SCREENSHOT);
        final boolean detectDebugger = policy.has(FLAG_DETECT_DEBUGGER);
        final boolean antiDump = policy.has(FLAG_ANTI_DUMP);
        final boolean detectXposed = policy.has(FLAG_DETECT_XPOSED);
        final boolean antiTampering = policy.has(FLAG_ANTI_TAMPERING);

        if (antiScreenshot || detectDebugger || antiDump || detectXposed) {
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
                            if (detectDebugger && isDebuggerAttached()) {
                                crashWithReason("Debugger detected");
                            }
                            if (detectXposed && isHookingClassPresent()) {
                                crashWithReason("Xposed / Frida hooking detected");
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

        if (antiDump || detectXposed || detectDebugger || antiTampering) {
            startLiveWatchdog(context.getApplicationContext(), policy);
        }

        return true;
    }

    private static void enforceChecks(Context context, GuardPolicy policy) {
        if (policy.has(FLAG_DETECT_DEBUGGER) && isDebuggerAttached()) {
            crashWithReason("Debugger detected");
        }
        if (policy.has(FLAG_ANTI_DUMP) && isMemoryDumpDetected()) {
            crashWithReason("Memory / APK dumper detected");
        }
        if (policy.has(FLAG_DETECT_ROOT) && isDeviceRooted()) {
            crashWithReason("Root detected");
        }
        if (policy.has(FLAG_DETECT_EMULATOR) && isEmulator()) {
            crashWithReason("Emulator detected");
        }
        if (policy.has(FLAG_DETECT_XPOSED) && isHookingFrameworkPresent()) {
            crashWithReason("Xposed / Frida hooking detected");
        }
        if (policy.has(FLAG_ANTI_TAMPERING) && !verifyCriticalApkIntegrity(context, policy.integrityEntries)) {
            crashWithReason("APK tampering detected");
        }
        if (policy.has(FLAG_SIGNATURE_PINNING)) {
            final String expectedCert = policy.pinnedCertSha256;
            if (!expectedCert.isEmpty() && !"UNSIGNED".equalsIgnoreCase(expectedCert)) {
                if (!verifySigningCert(context, expectedCert)) {
                    crashWithReason("APK signature mismatch");
                }
            }
        }
    }

    private static synchronized void startLiveWatchdog(final Context appContext, final GuardPolicy policy) {
        if (watchdogStarted || appContext == null) {
            return;
        }
        watchdogStarted = true;
        final Handler mainHandler = new Handler(Looper.getMainLooper());
        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                int cycle = 0;
                while (true) {
                    if (cycle > 0) {
                        try {
                            Thread.sleep(2500L);
                        } catch (InterruptedException ignored) {
                            return;
                        }
                    }
                    try {
                        if (policy.has(FLAG_DETECT_DEBUGGER) && isDebuggerAttached()) {
                            triggerMainCrash(mainHandler, "Debugger attached at runtime");
                            return;
                        }
                        if (policy.has(FLAG_ANTI_DUMP) && isMemoryDumpDetected()) {
                            triggerMainCrash(mainHandler, "Runtime memory / DEX dump blocked");
                            return;
                        }
                        if (policy.has(FLAG_DETECT_XPOSED) && isHookingFrameworkPresent()) {
                            triggerMainCrash(mainHandler, "Runtime hooking framework detected");
                            return;
                        }
                        if (policy.has(FLAG_ANTI_TAMPERING) && (cycle % 8 == 0)) {
                            if (!verifyApkIntegrity(appContext, policy.integrityEntries)) {
                                triggerMainCrash(mainHandler, "APK tampering detected");
                                return;
                            }
                        }
                    } catch (SecurityException se) {
                        triggerMainCrash(mainHandler, se.getMessage() != null ? se.getMessage() : "Security violation");
                        return;
                    } catch (Throwable ignored) {
                    }
                    cycle++;
                }
            }
        }, "dspro-guard-mon");
        t.setDaemon(true);
        t.start();
    }

    private static void triggerMainCrash(Handler mainHandler, final String reason) {
        final String fullMsg = reason.startsWith("DS PRO Protection:") ? reason : "DS PRO Protection: " + reason;
        Log.e(TAG, fullMsg);
        mainHandler.postAtFrontOfQueue(new Runnable() {
            @Override
            public void run() {
                throw new SecurityException(fullMsg);
            }
        });
    }

    private static GuardPolicy readEncryptedPolicy(Context context) {
        final String pkg = context.getPackageName();

        byte[] blob = null;
        byte[] salt = null;
        byte[] keyBytes = null;
        byte[] plain = null;
        try (InputStream in = context.getAssets().open(POLICY_ASSET)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream(1024);
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) != -1) {
                out.write(buf, 0, n);
            }
            blob = out.toByteArray();
        } catch (Throwable ignored) {
            return null;
        }

        if (blob.length <= 28) {
            crashWithReason("Security policy tampered");
            return null;
        }

        try {
            salt = new byte[16];
            byte[] iv = new byte[12];
            System.arraycopy(blob, 0, salt, 0, 16);
            System.arraycopy(blob, 16, iv, 0, 12);
            String saltHex = toLowerHex(salt);
            keyBytes = MessageDigest.getInstance("SHA-256").digest(
                (pkg + ":DSPRO_GCFG_KEY:" + saltHex).getBytes(StandardCharsets.UTF_8)
            );
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(
                Cipher.DECRYPT_MODE,
                new SecretKeySpec(keyBytes, "AES"),
                new GCMParameterSpec(128, iv)
            );
            plain = cipher.doFinal(blob, 28, blob.length - 28);
            String text = new String(plain, StandardCharsets.UTF_8);
            String[] lines = text.split("\n");
            if (lines.length < 3) {
                crashWithReason("Security policy tampered");
                return null;
            }
            int flags = Integer.parseInt(lines[0].trim());
            String pinnedCert = lines[1].trim();
            int integrityCount = Integer.parseInt(lines[2].trim());
            List<String> integrityEntries = new ArrayList<>(Math.max(0, integrityCount));
            for (int i = 0; i < integrityCount && (3 + i) < lines.length; i++) {
                String row = lines[3 + i].trim();
                if (!row.isEmpty()) {
                    integrityEntries.add(row);
                }
            }
            return new GuardPolicy(flags, pinnedCert, Collections.unmodifiableList(integrityEntries));
        } catch (SecurityException se) {
            throw se;
        } catch (Throwable t) {
            crashWithReason("Security policy tampered");
            return null;
        } finally {
            wipe(blob);
            wipe(salt);
            wipe(keyBytes);
            wipe(plain);
        }
    }

    private static void wipe(byte[] bytes) {
        if (bytes != null) {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    private static String toLowerHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format(Locale.US, "%02x", b & 0xFF));
        }
        return sb.toString();
    }

    private static boolean isMemoryDumpDetected() {
        if (isDebuggerAttached()) {
            return true;
        }
        if (containsInFile(
            "/proc/self/maps",
            "blackdex",
            "dumpdex",
            "fupk3",
            "libfart",
            "fart_art",
            "youpk",
            "dexdump",
            "drizzledumper",
            "frida-agent",
            "frida-gadget",
            "linjector",
            "sandhook",
            "libpine",
            "libepic",
            "libwhale",
            "libdobby",
            "libsubstrate",
            "lspd",
            "lsposed",
            "edxposed",
            "libriru"
        )) {
            return true;
        }
        if (hasSuspiciousThreadNames(
            "gum-js-loop",
            "pool-frida",
            "linjector",
            "blackdex",
            "fupk3"
        )) {
            return true;
        }
        // Check Frida listening ports 27042 (0x69A2) and 27043 (0x69A3) in /proc/net/tcp*
        if (containsFridaListeningPort("/proc/net/tcp")
            || containsFridaListeningPort("/proc/net/tcp6")
            || containsInFile("/proc/net/unix", "frida", "linjector", "blackdex")) {
            return true;
        }
        for (StackTraceElement el : Thread.currentThread().getStackTrace()) {
            String cls = safeLower(el.getClassName());
            if (cls.contains("blackdex")
                || cls.contains("dumpdex")
                || cls.contains("fupk")
                || cls.contains("libfart")
                || cls.contains("fart_art")
                || cls.contains("cn.mik.fart")
                || cls.contains("youpk")
                || cls.contains("dexdump")
                || cls.contains("frida")) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasSuspiciousThreadNames(String... needles) {
        try {
            File taskDir = new File("/proc/self/task");
            File[] tasks = taskDir.listFiles();
            if (tasks == null) {
                return false;
            }
            for (File task : tasks) {
                File commFile = new File(task, "comm");
                if (!commFile.isFile()) continue;
                try (BufferedReader br = new BufferedReader(new FileReader(commFile))) {
                    String line = br.readLine();
                    if (line != null) {
                        String lower = line.trim().toLowerCase(Locale.US);
                        for (String needle : needles) {
                            if (lower.contains(needle)) {
                                return true;
                            }
                        }
                    }
                } catch (Throwable ignored) {
                }
            }
        } catch (Throwable ignored) {
        }
        return false;
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

    private static boolean isHookingClassPresent() {
        try {
            Class.forName("de.robv.android.xposed.XposedBridge");
            return true;
        } catch (Throwable ignored) {
        }
        return false;
    }

    private static boolean isHookingFrameworkPresent() {
        if (isHookingClassPresent()) {
            return true;
        }

        for (StackTraceElement el : Thread.currentThread().getStackTrace()) {
            String cls = safeLower(el.getClassName());
            if (cls.contains("xposed") || cls.contains("lsposed") || cls.contains("substrate") || cls.contains("frida")) {
                return true;
            }
        }

        return containsInFile("/proc/self/maps", "xposed", "lsposed", "edxposed", "frida-agent", "frida-gadget", "linjector", "libsubstrate")
            || hasSuspiciousThreadNames("gum-js-loop", "pool-frida", "linjector");
    }

    private static boolean isDebuggerAttached() {
        if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) {
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

    private static boolean verifyCriticalApkIntegrity(Context context, List<String> entries) {
        if (entries == null || entries.isEmpty()) {
            return false;
        }
        try (ZipFile apkZip = new ZipFile(context.getPackageCodePath())) {
            int verified = 0;
            for (String row : entries) {
                int sep = row.indexOf('|');
                if (sep <= 0) {
                    return false;
                }
                String expectedHex = row.substring(0, sep).trim().toLowerCase(Locale.US);
                String entryName = row.substring(sep + 1).trim();
                ZipEntry entry = apkZip.getEntry(entryName);
                if (entry == null) {
                    return false;
                }
                boolean isCriticalFast = "AndroidManifest.xml".equals(entryName)
                    || entryName.endsWith(".dex")
                    || entryName.startsWith("assets/dspro_");
                if (isCriticalFast) {
                    String actualHex = sha256Entry(apkZip, entry);
                    if (!expectedHex.equals(actualHex)) {
                        return false;
                    }
                }
                verified++;
            }
            return verified > 0;
        } catch (Throwable t) {
            return false;
        }
    }

    private static boolean verifyApkIntegrity(Context context, List<String> entries) {
        if (entries == null || entries.isEmpty()) {
            return false;
        }
        try (ZipFile apkZip = new ZipFile(context.getPackageCodePath())) {
            int verified = 0;
            for (String row : entries) {
                int sep = row.indexOf('|');
                if (sep <= 0) {
                    return false;
                }
                String expectedHex = row.substring(0, sep).trim().toLowerCase(Locale.US);
                String entryName = row.substring(sep + 1).trim();
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
        return toLowerHex(md.digest());
    }

    private static boolean containsFridaListeningPort(String tcpPath) {
        try (BufferedReader reader = new BufferedReader(new FileReader(tcpPath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String lower = line.toLowerCase(Locale.US);
                if ((lower.contains(":69a2 ") || lower.contains(":69a3 ")) && lower.contains(" 0a ")) {
                    return true;
                }
            }
        } catch (Throwable ignored) {
        }
        return false;
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

    private static void crashWithReason(String reason) {
        final String message = "DS PRO Protection: " + reason;
        Log.e(TAG, message);
        throw new SecurityException(message);
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
