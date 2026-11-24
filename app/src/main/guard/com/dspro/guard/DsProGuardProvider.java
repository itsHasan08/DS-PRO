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
import android.os.Process;
import android.util.Log;
import android.view.WindowManager;

import dalvik.system.BaseDexClassLoader;
import dalvik.system.InMemoryDexClassLoader;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.zip.Inflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Runtime protection guard compiled into ds_pro_guard.dex and injected into protected APKs.
 * Reads encrypted binary security configuration from assets/dspro_guard.bin, wipes keys immediately,
 * enforces checks at startup/Activity resume, and runs a burst-polling anti-dump watchdog thread.
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

    private static final String POLICY_ASSET = /*O*/"dspro_guard.bin"/*O*/;
    private static volatile boolean watchdogStarted = false;

    static String _xs(int seed, byte[] data) {
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            out[i] = (byte) ((data[i] & 0xFF) ^ ((seed + i * 31) & 0xFF));
        }
        return new String(out, StandardCharsets.UTF_8);
    }

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
                                crashWithReason(/*O*/"Debugger detected"/*O*/);
                            }
                            if (detectXposed && isHookingClassPresent()) {
                                crashWithReason(/*O*/"Xposed / Frida hooking detected"/*O*/);
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
            crashWithReason(/*O*/"Debugger detected"/*O*/);
        }
        if (policy.has(FLAG_ANTI_DUMP) && isMemoryDumpDetected(context, true)) {
            crashWithReason(/*O*/"Memory / APK dumper detected"/*O*/);
        }
        if (policy.has(FLAG_DETECT_ROOT) && isDeviceRooted()) {
            crashWithReason(/*O*/"Root detected"/*O*/);
        }
        if (policy.has(FLAG_DETECT_EMULATOR) && isEmulator()) {
            crashWithReason(/*O*/"Emulator detected"/*O*/);
        }
        if (policy.has(FLAG_DETECT_XPOSED) && isHookingFrameworkPresent()) {
            crashWithReason(/*O*/"Xposed / Frida hooking detected"/*O*/);
        }
        if (policy.has(FLAG_ANTI_TAMPERING) && !verifyCriticalApkIntegrity(context, policy.integrityEntries)) {
            crashWithReason(/*O*/"APK tampering detected"/*O*/);
        }
        if (policy.has(FLAG_SIGNATURE_PINNING)) {
            final String expectedCert = policy.pinnedCertSha256;
            if (!expectedCert.isEmpty() && !"UNSIGNED".equalsIgnoreCase(expectedCert)) {
                if (!verifySigningCert(context, expectedCert)) {
                    crashWithReason(/*O*/"APK signature mismatch"/*O*/);
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
                            long sleepMs = (cycle < 20) ? 150L : 600L;
                            Thread.sleep(sleepMs);
                        } catch (InterruptedException ignored) {
                            return;
                        }
                    }
                    try {
                        boolean deepScan = (cycle % 4 == 0);
                        if (policy.has(FLAG_DETECT_DEBUGGER) && isDebuggerAttached()) {
                            triggerMainCrash(mainHandler, /*O*/"Debugger attached at runtime"/*O*/);
                            return;
                        }
                        if (policy.has(FLAG_ANTI_DUMP) && isMemoryDumpDetected(appContext, deepScan)) {
                            triggerMainCrash(mainHandler, /*O*/"Runtime memory / DEX dump blocked"/*O*/);
                            return;
                        }
                        if (policy.has(FLAG_DETECT_XPOSED) && (deepScan ? isHookingFrameworkPresent() : (isHookingClassPresent() || hasHookedSystemMethods()))) {
                            triggerMainCrash(mainHandler, /*O*/"Runtime hooking framework detected"/*O*/);
                            return;
                        }
                        if (policy.has(FLAG_ANTI_TAMPERING) && (cycle % 24 == 0)) {
                            if (!verifyApkIntegrity(appContext, policy.integrityEntries)) {
                                triggerMainCrash(mainHandler, /*O*/"APK tampering detected"/*O*/);
                                return;
                            }
                        }
                    } catch (SecurityException se) {
                        triggerMainCrash(mainHandler, se.getMessage() != null ? se.getMessage() : /*O*/"Security violation"/*O*/);
                        return;
                    } catch (Throwable ignored) {
                    }
                    cycle++;
                }
            }
        }, /*O*/"dspro-guard-mon"/*O*/);
        t.setDaemon(true);
        t.start();
    }

    private static void triggerMainCrash(Handler mainHandler, final String reason) {
        final String fullMsg = reason.startsWith(/*O*/"DS PRO Protection:"/*O*/)
            ? reason
            : /*O*/"DS PRO Protection: "/*O*/ + reason;
        Log.e(TAG, fullMsg);
        mainHandler.postAtFrontOfQueue(new Runnable() {
            @Override
            public void run() {
                throw new SecurityException(fullMsg);
            }
        });
        try {
            Thread.sleep(100L);
        } catch (InterruptedException ignored) {
        }
        Process.killProcess(Process.myPid());
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
            crashWithReason(/*O*/"Security policy tampered"/*O*/);
            return null;
        }

        try {
            salt = new byte[16];
            byte[] iv = new byte[12];
            System.arraycopy(blob, 0, salt, 0, 16);
            System.arraycopy(blob, 16, iv, 0, 12);
            String saltHex = toLowerHex(salt);
            keyBytes = MessageDigest.getInstance("SHA-256").digest(
                (pkg + /*O*/":DSPRO_GCFG_KEY:"/*O*/ + saltHex).getBytes(StandardCharsets.UTF_8)
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
                crashWithReason(/*O*/"Security policy tampered"/*O*/);
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
            crashWithReason(/*O*/"Security policy tampered"/*O*/);
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

    private static boolean isMemoryDumpDetected(Context context, boolean deepScan) {
        if (isDebuggerAttached() || hasHookedSystemMethods() || hasSuspiciousOpenFds()) {
            return true;
        }
        if (hasSuspiciousThreadNames(
            /*O*/"gum-js-loop"/*O*/,
            /*O*/"pool-frida"/*O*/,
            /*O*/"linjector"/*O*/,
            /*O*/"blackdex"/*O*/,
            /*O*/"fupk3"/*O*/,
            /*O*/"dumpdex"/*O*/
        )) {
            return true;
        }
        if (!deepScan) {
            return false;
        }
        if (context != null) {
            String apkPath = safeLower(context.getPackageCodePath());
            if (apkPath.contains(/*O*/"/data/data/"/*O*/)
                || apkPath.contains(/*O*/"/data/user/"/*O*/)
                || apkPath.contains(/*O*/"/sdcard/"/*O*/)
                || apkPath.contains(/*O*/"/storage/emulated/"/*O*/)
                || apkPath.contains(/*O*/"/virtual/"/*O*/)
                || apkPath.contains(/*O*/"blackbox"/*O*/)
                || apkPath.contains(/*O*/"blackdex"/*O*/)
                || apkPath.contains(/*O*/"sandvxposed"/*O*/)
                || apkPath.contains(/*O*/"dualspace"/*O*/)
                || apkPath.contains(/*O*/"virtualapp"/*O*/)
                || apkPath.contains(/*O*/"cloneapp"/*O*/)) {
                return true;
            }
            try {
                String filesDir = safeLower(context.getFilesDir().getAbsolutePath());
                if (filesDir.contains(/*O*/"/virtual/"/*O*/)
                    || filesDir.contains(/*O*/"blackbox"/*O*/)
                    || filesDir.contains(/*O*/"blackdex"/*O*/)
                    || filesDir.contains(/*O*/"sandvxposed"/*O*/)
                    || filesDir.contains(/*O*/"dualspace"/*O*/)
                    || filesDir.contains(/*O*/"virtualapp"/*O*/)
                    || filesDir.contains(/*O*/"parallel"/*O*/)
                    || filesDir.contains(/*O*/"cloneapp"/*O*/)) {
                    return true;
                }
            } catch (Throwable ignored) {
            }
            if (!Process.isIsolated()) {
                String cmdline = readCmdline();
                if (!cmdline.isEmpty()) {
                    String lowerCmd = cmdline.toLowerCase(Locale.US);
                    if (lowerCmd.contains(/*O*/"blackdex"/*O*/)
                        || lowerCmd.contains(/*O*/"blackbox"/*O*/)
                        || lowerCmd.contains(/*O*/"virtualapp"/*O*/)
                        || lowerCmd.contains(/*O*/"io.va."/*O*/)
                        || lowerCmd.contains(/*O*/"com.lody"/*O*/)
                        || lowerCmd.contains(/*O*/"sandvxposed"/*O*/)
                        || lowerCmd.contains(/*O*/"dualspace"/*O*/)
                        || lowerCmd.contains(/*O*/"parallel"/*O*/)
                        || lowerCmd.contains(/*O*/"cloneapp"/*O*/)) {
                        return true;
                    }
                    String pkg = context.getPackageName();
                    if (pkg != null && !pkg.isEmpty() && !cmdline.startsWith(pkg)) {
                        if (!mapsContainsPackageApk(pkg)) {
                            return true;
                        }
                    }
                }
            }
        }
        if (hasHookedInstrumentation()) {
            return true;
        }
        if (hasDumperInMaps()) {
            return true;
        }
        if (containsFridaListeningPort(/*O*/"/proc/net/tcp"/*O*/)
            || containsFridaListeningPort(/*O*/"/proc/net/tcp6"/*O*/)
            || containsInFile(/*O*/"/proc/net/unix"/*O*/, /*O*/"frida"/*O*/, /*O*/"linjector"/*O*/, /*O*/"hluda"/*O*/, /*O*/"florida"/*O*/, /*O*/"blackdex"/*O*/)) {
            return true;
        }
        try {
            Map<Thread, StackTraceElement[]> all = Thread.getAllStackTraces();
            for (StackTraceElement[] frames : all.values()) {
                if (hasDumperFrames(frames)) {
                    return true;
                }
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    private static boolean hasDumperFrames(StackTraceElement[] frames) {
        if (frames == null) return false;
        for (StackTraceElement el : frames) {
            String cls = safeLower(el.getClassName());
            if (cls.contains(/*O*/"blackdex"/*O*/)
                || cls.contains(/*O*/"blackbox"/*O*/)
                || cls.contains(/*O*/"dumpdex"/*O*/)
                || cls.contains(/*O*/"fupk"/*O*/)
                || cls.contains(/*O*/"libfart"/*O*/)
                || cls.contains(/*O*/"fart_art"/*O*/)
                || cls.contains(/*O*/"cn.mik.fart"/*O*/)
                || cls.contains(/*O*/"youpk"/*O*/)
                || cls.contains(/*O*/"dexdump"/*O*/)
                || cls.contains(/*O*/"top.niunaijun"/*O*/)
                || cls.contains(/*O*/"com.lody"/*O*/)
                || cls.contains(/*O*/"frida"/*O*/)) {
                return true;
            }
        }
        return false;
    }

    private static String readCmdline() {
        try (InputStream in = new FileInputStream(/*O*/"/proc/self/cmdline"/*O*/)) {
            byte[] buf = new byte[256];
            int n = in.read(buf);
            if (n <= 0) return "";
            int end = 0;
            while (end < n && buf[end] != 0) end++;
            return new String(buf, 0, end, StandardCharsets.UTF_8).trim();
        } catch (Throwable ignored) {
            return "";
        }
    }

    private static boolean mapsContainsPackageApk(String packageName) {
        String lowerPkg = packageName.toLowerCase(Locale.US);
        try (BufferedReader reader = new BufferedReader(new FileReader(/*O*/"/proc/self/maps"/*O*/))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String lower = line.toLowerCase(Locale.US);
                if (lower.contains(lowerPkg) && lower.contains(".apk")) {
                    return true;
                }
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    private static boolean hasHookedInstrumentation() {
        try {
            Class<?> atCls = Class.forName(/*O*/"android.app.ActivityThread"/*O*/);
            Method curAt = atCls.getDeclaredMethod(/*O*/"currentActivityThread"/*O*/);
            Object at = curAt.invoke(null);
            if (at != null) {
                Field f = atCls.getDeclaredField("mInstrumentation");
                f.setAccessible(true);
                Object inst = f.get(at);
                if (inst != null) {
                    String cls = safeLower(inst.getClass().getName());
                    if (cls.contains(/*O*/"blackbox"/*O*/)
                        || cls.contains(/*O*/"blackdex"/*O*/)
                        || cls.contains(/*O*/"virtual"/*O*/)
                        || cls.contains(/*O*/"lody"/*O*/)
                        || cls.contains(/*O*/"sandhook"/*O*/)
                        || cls.contains(/*O*/"xposed"/*O*/)
                        || cls.contains(/*O*/"lsposed"/*O*/)
                        || cls.contains(/*O*/"dualspace"/*O*/)
                        || cls.contains(/*O*/"clone"/*O*/)) {
                        return true;
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    private static boolean hasDumperInMaps() {
        try (BufferedReader reader = new BufferedReader(new FileReader(/*O*/"/proc/self/maps"/*O*/))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String lower = line.toLowerCase(Locale.US);
                if (lower.contains(/*O*/"blackdex"/*O*/)
                    || lower.contains(/*O*/"blackbox"/*O*/)
                    || lower.contains(/*O*/"libnmmvm"/*O*/)
                    || lower.contains(/*O*/"dumpdex"/*O*/)
                    || lower.contains(/*O*/"fupk3"/*O*/)
                    || lower.contains(/*O*/"libfart"/*O*/)
                    || lower.contains(/*O*/"fart_art"/*O*/)
                    || lower.contains(/*O*/"youpk"/*O*/)
                    || lower.contains(/*O*/"dexdump"/*O*/)
                    || lower.contains(/*O*/"drizzledumper"/*O*/)
                    || lower.contains(/*O*/"dexextractor"/*O*/)
                    || lower.contains(/*O*/"frida-agent"/*O*/)
                    || lower.contains(/*O*/"frida-gadget"/*O*/)
                    || lower.contains(/*O*/"re.frida"/*O*/)
                    || lower.contains(/*O*/"memfd:frida"/*O*/)
                    || lower.contains(/*O*/"hluda"/*O*/)
                    || lower.contains(/*O*/"florida"/*O*/)
                    || lower.contains(/*O*/"linjector"/*O*/)
                    || lower.contains(/*O*/"sandhook"/*O*/)
                    || lower.contains(/*O*/"libpine"/*O*/)
                    || lower.contains(/*O*/"libepic"/*O*/)
                    || lower.contains(/*O*/"libwhale"/*O*/)
                    || lower.contains(/*O*/"libdobby"/*O*/)
                    || lower.contains(/*O*/"libsubstrate"/*O*/)
                    || lower.contains(/*O*/"zygisk"/*O*/)
                    || lower.contains(/*O*/"shamiko"/*O*/)
                    || lower.contains(/*O*/"lspd"/*O*/)
                    || lower.contains(/*O*/"lsposed"/*O*/)
                    || lower.contains(/*O*/"edxposed"/*O*/)
                    || lower.contains(/*O*/"libriru"/*O*/)
                    || (lower.contains(/*O*/"/data/local/tmp/"/*O*/) && lower.contains(".so"))) {
                    return true;
                }
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    private static boolean hasHookedSystemMethods() {
        try {
            Method doFinalMethod = Cipher.class.getDeclaredMethod("doFinal", byte[].class);
            if (Modifier.isNative(doFinalMethod.getModifiers())) {
                return true;
            }
            Method digestMethod = MessageDigest.class.getDeclaredMethod("digest", byte[].class);
            if (Modifier.isNative(digestMethod.getModifiers())) {
                return true;
            }
            Method loadClassMethod = ClassLoader.class.getDeclaredMethod("loadClass", String.class);
            if (Modifier.isNative(loadClassMethod.getModifiers())) {
                return true;
            }
            Method findClassMethod = BaseDexClassLoader.class.getDeclaredMethod("findClass", String.class);
            if (Modifier.isNative(findClassMethod.getModifiers())) {
                return true;
            }
            Method inflateMethod = Inflater.class.getDeclaredMethod("inflate", byte[].class);
            if (Modifier.isNative(inflateMethod.getModifiers())) {
                return true;
            }
            for (Constructor<?> ctor : InMemoryDexClassLoader.class.getDeclaredConstructors()) {
                if (Modifier.isNative(ctor.getModifiers())) {
                    return true;
                }
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    private static boolean hasSuspiciousOpenFds() {
        try {
            File fdDir = new File(/*O*/"/proc/self/fd"/*O*/);
            File[] fds = fdDir.listFiles();
            if (fds == null) {
                return false;
            }
            for (File fd : fds) {
                String path = safeLower(fd.getCanonicalPath());
                if (path.contains(/*O*/"frida"/*O*/)
                    || path.contains(/*O*/"hluda"/*O*/)
                    || path.contains(/*O*/"florida"/*O*/)
                    || path.contains(/*O*/"blackdex"/*O*/)
                    || path.contains(/*O*/"blackbox"/*O*/)
                    || path.contains(/*O*/"dumpdex"/*O*/)
                    || path.contains(/*O*/"fupk"/*O*/)
                    || path.contains(/*O*/"libfart"/*O*/)
                    || path.contains(/*O*/"youpk"/*O*/)
                    || path.contains(/*O*/"drizzledumper"/*O*/)) {
                    return true;
                }
                if (path.endsWith(".dex")
                    && (path.contains(/*O*/"/sdcard/"/*O*/)
                        || path.contains(/*O*/"/storage/emulated/"/*O*/)
                        || path.contains(/*O*/"/data/local/tmp/"/*O*/)
                        || path.contains(/*O*/"/dump"/*O*/))) {
                    return true;
                }
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    private static boolean hasSuspiciousThreadNames(String... needles) {
        try {
            File taskDir = new File(/*O*/"/proc/self/task"/*O*/);
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
            /*O*/"/system/app/Superuser.apk"/*O*/,
            /*O*/"/sbin/su"/*O*/,
            /*O*/"/system/bin/su"/*O*/,
            /*O*/"/system/xbin/su"/*O*/,
            /*O*/"/data/local/xbin/su"/*O*/,
            /*O*/"/data/local/bin/su"/*O*/,
            /*O*/"/system/sd/xbin/su"/*O*/,
            /*O*/"/system/bin/failsafe/su"/*O*/,
            /*O*/"/data/local/su"/*O*/,
            /*O*/"/su/bin/su"/*O*/,
            /*O*/"/vendor/bin/su"/*O*/,
            /*O*/"/magisk/.core/bin/su"/*O*/
        };
        for (String path : paths) {
            if (new File(path).exists()) {
                return true;
            }
        }
        String pathEnv = System.getenv("PATH");
        if (pathEnv != null) {
            for (String dir : pathEnv.split(":")) {
                if (new File(dir, "su").exists() || new File(dir, /*O*/"magisk"/*O*/).exists()) {
                    return true;
                }
            }
        }
        return containsInFile(/*O*/"/proc/mounts"/*O*/, /*O*/"magisk"/*O*/, /*O*/"kernelsu"/*O*/, /*O*/"apatch"/*O*/);
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

        return new File(/*O*/"/dev/socket/qemud"/*O*/).exists()
            || new File(/*O*/"/dev/qemu_pipe"/*O*/).exists()
            || new File(/*O*/"/system/lib/libc_malloc_debug_qemu.so"/*O*/).exists();
    }

    private static boolean isHookingClassPresent() {
        try {
            Class.forName(/*O*/"de.robv.android.xposed.XposedBridge"/*O*/);
            return true;
        } catch (Throwable ignored) {
        }
        return false;
    }

    private static boolean isHookingFrameworkPresent() {
        if (isHookingClassPresent() || hasHookedSystemMethods()) {
            return true;
        }

        for (StackTraceElement el : Thread.currentThread().getStackTrace()) {
            String cls = safeLower(el.getClassName());
            if (cls.contains(/*O*/"xposed"/*O*/)
                || cls.contains(/*O*/"lsposed"/*O*/)
                || cls.contains(/*O*/"lsphooker"/*O*/)
                || cls.contains(/*O*/"edhooker"/*O*/)
                || cls.contains(/*O*/"sandhook"/*O*/)
                || cls.contains(/*O*/"substrate"/*O*/)
                || cls.contains(/*O*/"frida"/*O*/)) {
                return true;
            }
        }

        return containsInFile(
            /*O*/"/proc/self/maps"/*O*/,
            /*O*/"xposed"/*O*/,
            /*O*/"lsposed"/*O*/,
            /*O*/"lspd"/*O*/,
            /*O*/"edxposed"/*O*/,
            /*O*/"frida-agent"/*O*/,
            /*O*/"frida-gadget"/*O*/,
            /*O*/"re.frida"/*O*/,
            /*O*/"memfd:frida"/*O*/,
            /*O*/"hluda"/*O*/,
            /*O*/"florida"/*O*/,
            /*O*/"linjector"/*O*/,
            /*O*/"libsubstrate"/*O*/,
            /*O*/"zygisk"/*O*/
        ) || hasSuspiciousThreadNames(/*O*/"gum-js-loop"/*O*/, /*O*/"pool-frida"/*O*/, /*O*/"linjector"/*O*/);
    }

    private static boolean isDebuggerAttached() {
        if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) {
            return true;
        }
        try (BufferedReader reader = new BufferedReader(new FileReader(/*O*/"/proc/self/status"/*O*/))) {
            String line;
            String prefix = /*O*/"TracerPid:"/*O*/;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith(prefix)) {
                    String val = line.substring(prefix.length()).trim();
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
        final String message = /*O*/"DS PRO Protection: "/*O*/ + reason;
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
