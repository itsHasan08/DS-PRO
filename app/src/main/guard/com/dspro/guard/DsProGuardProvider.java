package com.dspro.guard;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Application;
import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.res.AssetManager;
import android.content.res.Resources;
import android.content.res.loader.ResourcesLoader;
import android.content.res.loader.ResourcesProvider;
import android.database.Cursor;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.ProxyInfo;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Debug;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.os.Process;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;
import android.view.WindowManager;
import android.widget.Toast;

import dalvik.system.BaseDexClassLoader;
import dalvik.system.InMemoryDexClassLoader;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.lang.ref.WeakReference;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.zip.Adler32;
import java.util.zip.Inflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

/**
 * Runtime protection guard compiled into ds_pro_guard.dex and injected into protected APKs.
 * Reads encrypted binary security configuration from assets/dspro_guard.bin, wipes keys immediately,
 * dynamically mounts encrypted assets from assets/dspro_res.bin when present, enforces DEX Integrity,
 * Device Certificate & runtime security checks, and runs a low-overhead background watchdog.
 */
public final class DsProGuardProvider extends ContentProvider {

    private static final String TAG = "DsProGuard";

    private static final int FLAG_DETECT_ROOT = 1;
    private static final int FLAG_DETECT_DEBUGGER = 1 << 4;
    private static final int FLAG_ANTI_SCREENSHOT = 1 << 5;
    private static final int FLAG_ANTI_TAMPERING = 1 << 6;
    private static final int FLAG_ANTI_DUMP = 1 << 8;
    private static final int FLAG_DEX_INTEGRITY = 1 << 9;
    private static final int FLAG_DEVICE_CERTIFICATE = 1 << 10;

    private static final String POLICY_ASSET = /*O*/"dspro_guard.bin"/*O*/;
    private static final String RESOURCE_VAULT_ASSET = /*O*/"assets/dspro_res.bin"/*O*/;
    private static final String CORE_LOADER_CLASS = "com.dspro.core.DsProCoreLoader";
    private static volatile boolean watchdogStarted = false;
    private static volatile String pendingWarningTitle = null;
    private static volatile String pendingWarningMessage = null;
    private static volatile boolean warningCrashScheduled = false;
    private static volatile WeakReference<Activity> foregroundActivityRef = new WeakReference<>(null);
    private static volatile WeakReference<Activity> shownWarningDialogActivityRef = new WeakReference<>(null);
    private static volatile ProxySelector originalProxySelector = null;
    private static volatile boolean captureNetworkGuardInstalled = false;
    private static volatile String cachedInstalledCaptureTool = null;
    private static volatile long cachedCaptureToolCheckedAt = 0L;

    private static volatile boolean resourcesMounted = false;
    private static volatile Object cachedResourcesLoader = null;
    private static volatile String cachedLegacyAssetPath = null;
    private static final Map<Resources, Boolean> attachedResourcesMap =
        Collections.synchronizedMap(new WeakHashMap<Resources, Boolean>());
    private static final Map<AssetManager, Boolean> attachedAssetsMap =
        Collections.synchronizedMap(new WeakHashMap<AssetManager, Boolean>());

    static String _xs(int seed, byte[] data) {
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            out[i] = (byte) ((data[i] & 0xFF) ^ ((seed + i * 31) & 0xFF));
        }
        return new String(out, StandardCharsets.UTF_8);
    }

    private static final class GuardPolicy {
        final int flags;
        final List<String> integrityEntries;
        final List<String> dexIntegrityEntries;

        GuardPolicy(
            int flags,
            List<String> integrityEntries,
            List<String> dexIntegrityEntries
        ) {
            this.flags = flags;
            this.integrityEntries = integrityEntries;
            this.dexIntegrityEntries = dexIntegrityEntries;
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
        if (policy != null) {
            enforceChecks(context, policy);
        }

        mountEncryptedResourcesIfNeeded(context);

        final Context appCtx = context.getApplicationContext();
        if (appCtx != null) {
            attachResourcesIfMounted(appCtx);
        }

        final boolean antiScreenshot = policy != null && policy.has(FLAG_ANTI_SCREENSHOT);
        final boolean detectDebugger = policy != null && policy.has(FLAG_DETECT_DEBUGGER);
        final boolean antiDump = policy != null && policy.has(FLAG_ANTI_DUMP);
        final boolean antiTampering = policy != null && policy.has(FLAG_ANTI_TAMPERING);
        final boolean dexIntegrity = policy != null && policy.has(FLAG_DEX_INTEGRITY);
        final boolean deviceCertificate = policy != null && policy.has(FLAG_DEVICE_CERTIFICATE);

        if (appCtx instanceof Application) {
            ((Application) appCtx).registerActivityLifecycleCallbacks(
                new Application.ActivityLifecycleCallbacks() {
                    @Override
                    public void onActivityPreCreated(Activity activity, Bundle savedInstanceState) {
                        if (antiTampering) {
                            ensureCaptureNetworkGuardIntact(activity);
                            String captureFailure = checkNetworkCaptureFailure(activity, false);
                            if (captureFailure != null) {
                                hardKillOnThreat(captureFailure);
                            }
                        }
                        attachResourcesIfMounted(activity);
                    }

                    @Override
                    public void onActivityCreated(Activity activity, Bundle savedInstanceState) {
                        if (antiTampering) {
                            ensureCaptureNetworkGuardIntact(activity);
                            String captureFailure = checkNetworkCaptureFailure(activity, false);
                            if (captureFailure != null) {
                                hardKillOnThreat(captureFailure);
                            }
                        }
                        attachResourcesIfMounted(activity);
                        if (antiScreenshot && activity.getWindow() != null) {
                            activity.getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
                        }
                        if (pendingWarningMessage != null) {
                            showWarningDialog(activity, pendingWarningTitle, pendingWarningMessage);
                        }
                    }

                    @Override
                    public void onActivityStarted(Activity activity) {
                        if (antiTampering) {
                            ensureCaptureNetworkGuardIntact(activity);
                            String captureFailure = checkNetworkCaptureFailure(activity, false);
                            if (captureFailure != null) {
                                hardKillOnThreat(captureFailure);
                            }
                        }
                    }

                    @Override
                    public void onActivityResumed(Activity activity) {
                        foregroundActivityRef = new WeakReference<>(activity);
                        if (antiScreenshot && activity.getWindow() != null) {
                            activity.getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
                        }
                        if (pendingWarningMessage != null) {
                            showWarningDialog(activity, pendingWarningTitle, pendingWarningMessage);
                        }
                        if (antiTampering) {
                            ensureCaptureNetworkGuardIntact(activity);
                            String captureFailure = checkNetworkCaptureFailure(activity, true);
                            if (captureFailure != null) {
                                hardKillOnThreat(captureFailure);
                            }
                        }
                        if (detectDebugger && isDebuggerAttached()) {
                            crashWithReason(/*O*/"Debugger detected"/*O*/);
                        }
                    }

                    @Override
                    public void onActivityPaused(Activity activity) {
                        if (foregroundActivityRef.get() == activity) {
                            foregroundActivityRef = new WeakReference<>(null);
                        }
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

        if (policy != null && (antiDump || detectDebugger || antiTampering || dexIntegrity || deviceCertificate)) {
            startLiveWatchdog(appCtx != null ? appCtx : context, policy);
        }

        return true;
    }

    private static synchronized void mountEncryptedResourcesIfNeeded(Context context) {
        if (context == null || Process.isIsolated()) {
            return;
        }
        // Delegate to DsProCoreLoader when Core DEX is already present so assets decrypt only once.
        try {
            Class<?> coreCls = Class.forName(CORE_LOADER_CLASS, false, context.getClassLoader());
            Method mountMethod = coreCls.getDeclaredMethod("mountEncryptedResources", Context.class);
            mountMethod.setAccessible(true);
            mountMethod.invoke(null, context);
            return;
        } catch (ClassNotFoundException ignored) {
        } catch (Throwable t) {
            if (t.getCause() instanceof SecurityException) {
                throw (SecurityException) t.getCause();
            }
        }

        if (resourcesMounted) {
            attachResourcesIfMounted(context);
            return;
        }

        String apkPath;
        String pkg;
        try {
            apkPath = context.getPackageCodePath();
            pkg = context.getPackageName();
        } catch (Throwable ignored) {
            return;
        }
        if (apkPath == null || apkPath.isEmpty() || pkg == null || pkg.isEmpty()) {
            return;
        }

        byte[] blob = null;
        byte[] salt = null;
        byte[] key = null;
        byte[] plainZip = null;
        try (ZipFile zip = new ZipFile(apkPath)) {
            ZipEntry entry = zip.getEntry(RESOURCE_VAULT_ASSET);
            if (entry == null) {
                return;
            }
            try (InputStream in = zip.getInputStream(entry)) {
                ByteArrayOutputStream out = new ByteArrayOutputStream((int) Math.max(4096L, entry.getSize()));
                byte[] buf = new byte[16384];
                int n;
                while ((n = in.read(buf)) != -1) {
                    out.write(buf, 0, n);
                }
                blob = out.toByteArray();
            }
            if (blob.length <= 28) {
                crashWithReason(/*O*/"Encrypted resource vault tampered"/*O*/);
                return;
            }
            salt = new byte[16];
            byte[] iv = new byte[12];
            System.arraycopy(blob, 0, salt, 0, 16);
            System.arraycopy(blob, 16, iv, 0, 12);
            String saltHex = toLowerHex(salt);
            key = MessageDigest.getInstance("SHA-256").digest(
                (pkg + /*O*/":DSPRO_RES_V1:"/*O*/ + saltHex).getBytes(StandardCharsets.UTF_8)
            );
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
            plainZip = cipher.doFinal(blob, 28, blob.length - 28);

            File cacheDir = context.getCodeCacheDir();
            if (cacheDir == null) {
                cacheDir = context.getCacheDir();
            }
            if (cacheDir != null && !cacheDir.exists()) {
                cacheDir.mkdirs();
            }

            if (Build.VERSION.SDK_INT >= 30) {
                File tmp = File.createTempFile(/*O*/".dspro_rv_"/*O*/, ".apk", cacheDir);
                ParcelFileDescriptor pfd = null;
                try {
                    try (FileOutputStream fos = new FileOutputStream(tmp)) {
                        fos.write(plainZip);
                        fos.flush();
                    }
                    pfd = ParcelFileDescriptor.open(tmp, ParcelFileDescriptor.MODE_READ_ONLY);
                    ResourcesLoader loader = new ResourcesLoader();
                    loader.addProvider(ResourcesProvider.loadFromApk(pfd));
                    cachedResourcesLoader = loader;
                } finally {
                    if (pfd != null) {
                        try {
                            pfd.close();
                        } catch (Throwable ignored) {
                        }
                    }
                    tmp.delete();
                }
            } else {
                File vaultFile = new File(cacheDir, /*O*/".dspro_rv_"/*O*/ + Integer.toHexString(apkPath.hashCode()) + ".apk");
                if (vaultFile.exists()) {
                    vaultFile.setWritable(true);
                    vaultFile.delete();
                }
                try (FileOutputStream fos = new FileOutputStream(vaultFile)) {
                    fos.write(plainZip);
                    fos.flush();
                }
                vaultFile.setReadOnly();
                vaultFile.deleteOnExit();
                cachedLegacyAssetPath = vaultFile.getAbsolutePath();
            }
            resourcesMounted = true;
            attachResourcesIfMounted(context);
        } catch (SecurityException se) {
            throw se;
        } catch (Throwable t) {
            crashWithReason(/*O*/"Encrypted resource vault verification failed"/*O*/);
        } finally {
            wipe(blob);
            wipe(salt);
            wipe(key);
            wipe(plainZip);
        }
    }

    private static void attachResourcesIfMounted(Context context) {
        if (context == null) {
            return;
        }
        try {
            Class<?> coreCls = Class.forName(CORE_LOADER_CLASS, false, context.getClassLoader());
            Method attachMethod = coreCls.getDeclaredMethod("attachResourcesIfMounted", Context.class);
            attachMethod.setAccessible(true);
            attachMethod.invoke(null, context);
            return;
        } catch (ClassNotFoundException ignored) {
        } catch (Throwable ignored) {
        }

        if (!resourcesMounted) {
            return;
        }
        try {
            Resources res = context.getResources();
            if (res == null) {
                return;
            }
            if (Build.VERSION.SDK_INT >= 30 && cachedResourcesLoader instanceof ResourcesLoader) {
                synchronized (attachedResourcesMap) {
                    if (!Boolean.TRUE.equals(attachedResourcesMap.get(res))) {
                        res.addLoaders((ResourcesLoader) cachedResourcesLoader);
                        attachedResourcesMap.put(res, Boolean.TRUE);
                    }
                }
            } else if (cachedLegacyAssetPath != null) {
                AssetManager am = res.getAssets();
                if (am != null) {
                    synchronized (attachedAssetsMap) {
                        if (!Boolean.TRUE.equals(attachedAssetsMap.get(am))) {
                            Method addAssetPath = AssetManager.class.getDeclaredMethod("addAssetPath", String.class);
                            addAssetPath.setAccessible(true);
                            addAssetPath.invoke(am, cachedLegacyAssetPath);
                            attachedAssetsMap.put(am, Boolean.TRUE);
                        }
                    }
                }
            }
        } catch (Throwable ignored) {
        }
    }

    private static void enforceChecks(Context context, GuardPolicy policy) {
        final boolean coreInitialized = isCoreInitialized(context);
        int state = 0x107;
        while (state != 0) {
            switch (state) {
                case 0x107:
                    if (policy.has(FLAG_DETECT_DEBUGGER) && isDebuggerAttached()) {
                        crashWithReason(/*O*/"Debugger detected"/*O*/);
                    }
                    state = 0x219;
                    break;
                case 0x219:
                    if (policy.has(FLAG_ANTI_DUMP) && !coreInitialized && isMemoryDumpDetected(context, false)) {
                        crashWithReason(/*O*/"Memory / APK dumper detected"/*O*/);
                    }
                    state = 0x34A;
                    break;
                case 0x34A:
                    if (policy.has(FLAG_DETECT_ROOT) && isDeviceRooted()) {
                        crashWithReason(/*O*/"Root detected"/*O*/);
                    }
                    state = 0x3E8;
                    break;
                case 0x3E8:
                    if (policy.has(FLAG_DEVICE_CERTIFICATE)) {
                        String certFailure = checkDeviceCertificateFailure(context, false);
                        if (certFailure != null) {
                            warnAndScheduleCrash(context, /*O*/"Device Certificate Warning"/*O*/, certFailure);
                        }
                    }
                    state = 0x47C;
                    break;
                case 0x47C:
                    if (policy.has(FLAG_DEX_INTEGRITY)) {
                        boolean dexOk = coreInitialized
                            ? verifyDexIntegrity(context, policy.dexIntegrityEntries)
                            : verifyDexStructureQuick(context, policy.dexIntegrityEntries);
                        if (!dexOk) {
                            crashWithReason(/*O*/"DEX integrity violation detected"/*O*/);
                        }
                    }
                    state = 0x591;
                    break;
                case 0x591:
                    if (policy.has(FLAG_ANTI_TAMPERING)) {
                        installCaptureResistantNetworkGuard(context);
                        String captureFailure = checkNetworkCaptureFailure(context, true);
                        if (captureFailure != null) {
                            hardKillOnThreat(captureFailure);
                        } else if (!verifyCriticalApkIntegrity(context, policy.integrityEntries, coreInitialized)) {
                            hardKillOnThreat(/*O*/"APK tampering detected"/*O*/);
                        }
                    }
                    state = 0;
                    break;
                default:
                    state = 0;
                    break;
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
                boolean attestedOnce = false;
                boolean fullIntegrityChecked = false;
                boolean fullDexChecked = false;
                while (true) {
                    if (cycle > 0) {
                        try {
                            long sleepMs = policy.has(FLAG_ANTI_TAMPERING)
                                ? 350L
                                : ((cycle < 5) ? 800L : 5000L);
                            Thread.sleep(sleepMs);
                        } catch (InterruptedException ignored) {
                            return;
                        }
                    }
                    try {
                        if (policy.has(FLAG_ANTI_TAMPERING)) {
                            ensureCaptureNetworkGuardIntact(appContext);
                            String captureFailure = checkNetworkCaptureFailure(appContext, (cycle % 8 == 0));
                            if (captureFailure != null) {
                                hardKillOnThreat(captureFailure);
                                return;
                            }
                            if (!fullIntegrityChecked) {
                                fullIntegrityChecked = true;
                                if (!verifyApkIntegrity(appContext, policy.integrityEntries)) {
                                    hardKillOnThreat(/*O*/"APK tampering detected"/*O*/);
                                    return;
                                }
                            } else if (cycle % 170 == 0 && !verifyCriticalApkIntegrity(appContext, policy.integrityEntries, isCoreInitialized(appContext))) {
                                hardKillOnThreat(/*O*/"APK tampering detected"/*O*/);
                                return;
                            }
                        }
                        if (policy.has(FLAG_DEVICE_CERTIFICATE)) {
                            boolean runAttestation = !attestedOnce;
                            attestedOnce = true;
                            if (runAttestation || (cycle % 12 == 0)) {
                                String certFailure = checkDeviceCertificateFailure(appContext, runAttestation);
                                if (certFailure != null) {
                                    warnAndScheduleCrash(appContext, /*O*/"Device Certificate Warning"/*O*/, certFailure);
                                    return;
                                }
                            }
                        }
                        if (policy.has(FLAG_DETECT_DEBUGGER) && isDebuggerAttached()) {
                            triggerMainCrash(mainHandler, /*O*/"Debugger attached at runtime"/*O*/);
                            return;
                        }
                        boolean coreMonActive = isCoreWatchdogRunning(appContext);
                        if (policy.has(FLAG_ANTI_DUMP) && !coreMonActive) {
                            boolean deepScan = (cycle % 12 == 0);
                            if (isMemoryDumpDetected(appContext, deepScan)) {
                                triggerMainCrash(mainHandler, /*O*/"Runtime memory / DEX dump blocked"/*O*/);
                                return;
                            }
                        }
                        if (policy.has(FLAG_DEX_INTEGRITY)) {
                            if (!fullDexChecked) {
                                fullDexChecked = true;
                                if (!verifyDexIntegrity(appContext, policy.dexIntegrityEntries)) {
                                    triggerMainCrash(mainHandler, /*O*/"DEX integrity violation detected"/*O*/);
                                    return;
                                }
                            } else if (cycle % 12 == 0 && !verifyDexStructureQuick(appContext, policy.dexIntegrityEntries)) {
                                triggerMainCrash(mainHandler, /*O*/"DEX integrity violation detected"/*O*/);
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
        t.setPriority(Thread.MIN_PRIORITY);
        t.setDaemon(true);
        t.start();
    }

    private static boolean isCoreInitialized(Context context) {
        if (context == null) {
            return false;
        }
        try {
            Class<?> coreCls = Class.forName(CORE_LOADER_CLASS, false, context.getClassLoader());
            Method m = coreCls.getDeclaredMethod("isInitialized");
            m.setAccessible(true);
            return Boolean.TRUE.equals(m.invoke(null));
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static boolean isCoreWatchdogRunning(Context context) {
        if (context == null) {
            return false;
        }
        try {
            Class<?> coreCls = Class.forName(CORE_LOADER_CLASS, false, context.getClassLoader());
            Method m = coreCls.getDeclaredMethod("isCoreWatchdogStarted");
            m.setAccessible(true);
            return Boolean.TRUE.equals(m.invoke(null));
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static synchronized void warnAndScheduleCrash(
        final Context context,
        final String title,
        final String reason
    ) {
        final String fullMsg = reason.startsWith(/*O*/"DS PRO Protection:"/*O*/)
            ? reason
            : /*O*/"DS PRO Protection: "/*O*/ + reason;
        final String dialogTitle = (title != null && !title.isEmpty())
            ? title
            : /*O*/"DS PRO Security Warning"/*O*/;
        pendingWarningTitle = dialogTitle;
        pendingWarningMessage = fullMsg;
        if (warningCrashScheduled) {
            return;
        }
        warningCrashScheduled = true;
        Log.e(TAG, fullMsg);
        final Context appOrCtx = (context != null && context.getApplicationContext() != null)
            ? context.getApplicationContext()
            : context;
        final Handler mainHandler = new Handler(Looper.getMainLooper());
        mainHandler.post(new Runnable() {
            @Override
            public void run() {
                try {
                    if (appOrCtx != null) {
                        Toast.makeText(appOrCtx, fullMsg, Toast.LENGTH_LONG).show();
                    }
                } catch (Throwable ignored) {
                }
                Activity act = foregroundActivityRef.get();
                if (act != null && !act.isFinishing() && !act.isDestroyed()) {
                    showWarningDialog(act, dialogTitle, fullMsg);
                }
            }
        });
        mainHandler.postDelayed(new Runnable() {
            @Override
            public void run() {
                try {
                    throw new SecurityException(fullMsg);
                } finally {
                    Process.killProcess(Process.myPid());
                }
            }
        }, 1600L);
    }

    private static void showWarningDialog(
        final Activity activity,
        final String title,
        final String message
    ) {
        if (activity == null || activity.isFinishing() || activity.isDestroyed()) {
            return;
        }
        if (shownWarningDialogActivityRef.get() == activity) {
            return;
        }
        shownWarningDialogActivityRef = new WeakReference<>(activity);
        try {
            new AlertDialog.Builder(activity)
                .setTitle(title != null && !title.isEmpty() ? title : /*O*/"DS PRO Security Warning"/*O*/)
                .setMessage(message)
                .setCancelable(false)
                .show();
        } catch (Throwable ignored) {
        }
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
            String[] lines = text.split("\n", -1);
            if (lines.length < 3) {
                crashWithReason(/*O*/"Security policy tampered"/*O*/);
                return null;
            }
            int flags = Integer.parseInt(lines[0].trim());
            // lines[1] reserved header slot
            int integrityCount = Integer.parseInt(lines[2].trim());
            List<String> integrityEntries = new ArrayList<>(Math.max(0, integrityCount));
            for (int i = 0; i < integrityCount && (3 + i) < lines.length; i++) {
                String row = lines[3 + i].trim();
                if (!row.isEmpty()) {
                    integrityEntries.add(row);
                }
            }
            int dexCountIdx = 3 + integrityCount;
            List<String> dexIntegrityEntries = Collections.emptyList();
            if (dexCountIdx < lines.length && !lines[dexCountIdx].trim().isEmpty()) {
                int dexIntegrityCount = Integer.parseInt(lines[dexCountIdx].trim());
                List<String> parsedDex = new ArrayList<>(Math.max(0, dexIntegrityCount));
                for (int i = 0; i < dexIntegrityCount && (dexCountIdx + 1 + i) < lines.length; i++) {
                    String row = lines[dexCountIdx + 1 + i].trim();
                    if (!row.isEmpty()) {
                        parsedDex.add(row);
                    }
                }
                dexIntegrityEntries = Collections.unmodifiableList(parsedDex);
            }
            return new GuardPolicy(
                flags,
                Collections.unmodifiableList(integrityEntries),
                dexIntegrityEntries
            );
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

    private static boolean verifyDexStructureQuick(Context context, List<String> expectedEntries) {
        if (context == null || expectedEntries == null || expectedEntries.isEmpty()) {
            return false;
        }
        try (ZipFile apkZip = new ZipFile(context.getPackageCodePath())) {
            Map<String, Integer> expectedSizes = new HashMap<>(expectedEntries.size());
            for (String row : expectedEntries) {
                String[] parts = row.split("\\|", 4);
                if (parts.length != 4) {
                    return false;
                }
                expectedSizes.put(parts[3].trim(), Integer.parseInt(parts[2].trim()));
            }
            int apkDexCount = 0;
            Enumeration<? extends ZipEntry> entries = apkZip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry e = entries.nextElement();
                String name = e.getName();
                if (isRootClassesDex(name)) {
                    apkDexCount++;
                    Integer expectedSize = expectedSizes.get(name);
                    if (expectedSize == null || e.getSize() != expectedSize.longValue()) {
                        return false;
                    }
                }
            }
            return apkDexCount == expectedSizes.size();
        } catch (Throwable t) {
            return false;
        }
    }

    private static boolean verifyDexIntegrity(Context context, List<String> expectedEntries) {
        if (context == null || expectedEntries == null || expectedEntries.isEmpty()) {
            return false;
        }
        try (ZipFile apkZip = new ZipFile(context.getPackageCodePath())) {
            Map<String, String> expectedByName = new HashMap<>(expectedEntries.size());
            for (String row : expectedEntries) {
                String[] parts = row.split("\\|", 4);
                if (parts.length != 4) {
                    return false;
                }
                expectedByName.put(parts[3].trim(), row);
            }

            // Ensure no extra/untracked classes*.dex was injected into the APK root
            int apkDexCount = 0;
            Enumeration<? extends ZipEntry> entries = apkZip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry e = entries.nextElement();
                String name = e.getName();
                if (isRootClassesDex(name)) {
                    apkDexCount++;
                    if (!expectedByName.containsKey(name)) {
                        return false;
                    }
                }
            }
            if (apkDexCount != expectedByName.size()) {
                return false;
            }

            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            for (Map.Entry<String, String> target : expectedByName.entrySet()) {
                String entryName = target.getKey();
                String[] parts = target.getValue().split("\\|", 4);
                String expectedSha256 = parts[0].trim().toLowerCase(Locale.US);
                long expectedAdler = Long.parseLong(parts[1].trim());
                int expectedSize = Integer.parseInt(parts[2].trim());

                ZipEntry entry = apkZip.getEntry(entryName);
                if (entry == null) {
                    return false;
                }
                byte[] dexBytes;
                try (InputStream in = apkZip.getInputStream(entry)) {
                    ByteArrayOutputStream out = new ByteArrayOutputStream(Math.max(1024, expectedSize));
                    byte[] buf = new byte[32768];
                    int n;
                    while ((n = in.read(buf)) != -1) {
                        out.write(buf, 0, n);
                    }
                    dexBytes = out.toByteArray();
                }

                if (dexBytes.length != expectedSize || dexBytes.length < 0x70) {
                    return false;
                }
                if (dexBytes[0] != 'd' || dexBytes[1] != 'e' || dexBytes[2] != 'x' || dexBytes[3] != '\n') {
                    return false;
                }
                ByteBuffer hdr = ByteBuffer.wrap(dexBytes, 0, 0x70).order(ByteOrder.LITTLE_ENDIAN);
                if (hdr.getInt(32) != dexBytes.length || hdr.getInt(36) != 0x70 || hdr.getInt(40) != 0x12345678) {
                    return false;
                }

                long headerAdler = hdr.getInt(8) & 0xFFFFFFFFL;
                Adler32 adler = new Adler32();
                adler.update(dexBytes, 12, dexBytes.length - 12);
                if (headerAdler != expectedAdler || adler.getValue() != headerAdler) {
                    return false;
                }

                sha1.reset();
                sha1.update(dexBytes, 32, dexBytes.length - 32);
                byte[] actualSha1 = sha1.digest();
                for (int i = 0; i < 20; i++) {
                    if (actualSha1[i] != dexBytes[12 + i]) {
                        return false;
                    }
                }

                sha256.reset();
                sha256.update(dexBytes);
                if (!expectedSha256.equals(toLowerHex(sha256.digest()))) {
                    return false;
                }
            }
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    private static boolean isRootClassesDex(String name) {
        if (name == null || !name.startsWith("classes") || !name.endsWith(".dex") || name.indexOf('/') >= 0) {
            return false;
        }
        String middle = name.substring("classes".length(), name.length() - ".dex".length());
        if (middle.isEmpty()) {
            return true;
        }
        for (int i = 0; i < middle.length(); i++) {
            char c = middle.charAt(i);
            if (c < '0' || c > '9') {
                return false;
            }
        }
        return true;
    }

    private static void wipe(byte[] bytes) {
        if (bytes != null) {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();

    private static String toLowerHex(byte[] bytes) {
        char[] chars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            chars[i * 2] = HEX_CHARS[v >>> 4];
            chars[i * 2 + 1] = HEX_CHARS[v & 0x0F];
        }
        return new String(chars);
    }

    private static boolean isMemoryDumpDetected(Context context, boolean deepScan) {
        if (isDebuggerAttached() || hasSuspiciousJavaThreadNames() || hasHookedInstrumentation() || hasVirtualContainerHints(context)) {
            return true;
        }
        if (!deepScan) {
            return false;
        }
        if (hasHookedSystemMethods() || hasSuspiciousProcThreadNames() || hasSuspiciousOpenFds()) {
            return true;
        }
        boolean checkPkgInMaps = false;
        if (context != null && !Process.isIsolated()) {
            String cmdline = readCmdline();
            if (!cmdline.isEmpty()) {
                String pkg = context.getPackageName();
                if (pkg != null && !pkg.isEmpty() && !cmdline.startsWith(pkg)) {
                    checkPkgInMaps = true;
                }
            }
        }
        if (scanProcMaps(context != null ? context.getPackageName() : null, checkPkgInMaps)) {
            return true;
        }
        if (containsFridaListeningPort(/*O*/"/proc/net/tcp"/*O*/)
            || containsFridaListeningPort(/*O*/"/proc/net/tcp6"/*O*/)
            || containsInFile(/*O*/"/proc/net/unix"/*O*/, /*O*/"frida-agent"/*O*/, /*O*/"frida-server"/*O*/, /*O*/"linjector"/*O*/, /*O*/"libhluda"/*O*/, /*O*/"libflorida"/*O*/, /*O*/"blackdex"/*O*/)) {
            return true;
        }
        return false;
    }

    private static boolean hasVirtualContainerHints(Context context) {
        if (context == null) {
            return false;
        }
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
                || filesDir.contains(/*O*/"com.lbe.parallel"/*O*/)
                || filesDir.contains(/*O*/"parallel.space"/*O*/)
                || filesDir.contains(/*O*/"parallel_intl"/*O*/)
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
                    || lowerCmd.contains(/*O*/"com.lbe.parallel"/*O*/)
                    || lowerCmd.contains(/*O*/"parallel.space"/*O*/)
                    || lowerCmd.contains(/*O*/"cloneapp"/*O*/)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean hasSuspiciousJavaThreadNames() {
        try {
            ThreadGroup root = Thread.currentThread().getThreadGroup();
            while (root != null && root.getParent() != null) {
                root = root.getParent();
            }
            if (root != null) {
                int count = root.activeCount();
                Thread[] list = new Thread[count + 16];
                int n = root.enumerate(list, true);
                for (int i = 0; i < n; i++) {
                    Thread th = list[i];
                    if (th == null) continue;
                    String lower = safeLower(th.getName());
                    if (lower.contains(/*O*/"gum-js-loop"/*O*/)
                        || lower.contains(/*O*/"pool-frida"/*O*/)
                        || lower.contains(/*O*/"linjector"/*O*/)
                        || lower.contains(/*O*/"blackdex"/*O*/)
                        || lower.contains(/*O*/"fupk3"/*O*/)
                        || lower.contains(/*O*/"dumpdex"/*O*/)) {
                        return true;
                    }
                }
            }
        } catch (Throwable ignored) {
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

    private static boolean scanProcMaps(String packageName, boolean requirePkgApk) {
        String lowerPkg = (requirePkgApk && packageName != null) ? packageName.toLowerCase(Locale.US) : null;
        boolean foundPkgApk = !requirePkgApk;
        try (BufferedReader reader = new BufferedReader(new FileReader(/*O*/"/proc/self/maps"/*O*/), 16384)) {
            String line;
            while ((line = reader.readLine()) != null) {
                String lower = line.toLowerCase(Locale.US);
                if (!foundPkgApk && lowerPkg != null && lower.contains(lowerPkg) && lower.contains(".apk")) {
                    foundPkgApk = true;
                }
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
                    || lower.contains(/*O*/"frida-server"/*O*/)
                    || lower.contains(/*O*/"re.frida"/*O*/)
                    || lower.contains(/*O*/"memfd:frida"/*O*/)
                    || lower.contains(/*O*/"libhluda"/*O*/)
                    || lower.contains(/*O*/"hluda-"/*O*/)
                    || lower.contains(/*O*/"libflorida"/*O*/)
                    || lower.contains(/*O*/"florida-"/*O*/)
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
            return false;
        }
        return requirePkgApk && !foundPkgApk;
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
                if (path.contains(/*O*/"frida-agent"/*O*/)
                    || path.contains(/*O*/"frida-gadget"/*O*/)
                    || path.contains(/*O*/"frida-server"/*O*/)
                    || path.contains(/*O*/"re.frida"/*O*/)
                    || path.contains(/*O*/"memfd:frida"/*O*/)
                    || path.contains(/*O*/"libhluda"/*O*/)
                    || path.contains(/*O*/"hluda-"/*O*/)
                    || path.contains(/*O*/"libflorida"/*O*/)
                    || path.contains(/*O*/"florida-"/*O*/)
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

    private static boolean hasSuspiciousProcThreadNames() {
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
                        if (lower.contains(/*O*/"gum-js-loop"/*O*/)
                            || lower.contains(/*O*/"pool-frida"/*O*/)
                            || lower.contains(/*O*/"linjector"/*O*/)
                            || lower.contains(/*O*/"blackdex"/*O*/)
                            || lower.contains(/*O*/"fupk3"/*O*/)
                            || lower.contains(/*O*/"dumpdex"/*O*/)) {
                            return true;
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

    private static String checkDeviceCertificateFailure(Context context, boolean includeAttestation) {
        if (context == null || Process.isIsolated()) {
            return null;
        }
        try {
            PackageManager pm = context.getPackageManager();
            if (pm != null) {
                String playErr = checkCertifiedSystemPackage(pm, /*O*/"com.android.vending"/*O*/, /*O*/"Google Play Store"/*O*/);
                if (playErr != null) {
                    return playErr;
                }
                String gmsErr = checkCertifiedSystemPackage(pm, /*O*/"com.google.android.gms"/*O*/, /*O*/"Google Play Services"/*O*/);
                if (gmsErr != null) {
                    return gmsErr;
                }
            }
        } catch (Throwable ignored) {
        }

        String tags = Build.TAGS;
        if (tags != null && tags.contains(/*O*/"test-keys"/*O*/)) {
            return /*O*/"Device certificate missing: unsigned test-keys ROM"/*O*/;
        }

        String bootState = readSystemProperty(/*O*/"ro.boot.verifiedbootstate"/*O*/).toLowerCase(Locale.US);
        if (/*O*/"orange"/*O*/.equals(bootState) || /*O*/"yellow"/*O*/.equals(bootState) || /*O*/"red"/*O*/.equals(bootState)) {
            return /*O*/"Device certificate failed: Verified Boot unlocked"/*O*/;
        }
        String flashLocked = readSystemProperty(/*O*/"ro.boot.flash.locked"/*O*/);
        if ("0".equals(flashLocked)) {
            return /*O*/"Device certificate failed: Bootloader unlocked"/*O*/;
        }
        String vbmetaState = readSystemProperty(/*O*/"ro.boot.vbmeta.device_state"/*O*/).toLowerCase(Locale.US);
        if (/*O*/"unlocked"/*O*/.equals(vbmetaState)) {
            return /*O*/"Device certificate failed: vbmeta device unlocked"/*O*/;
        }

        if (includeAttestation) {
            String attestErr = checkHardwareRootOfTrust();
            if (attestErr != null) {
                return attestErr;
            }
        }
        return null;
    }

    private static String checkCertifiedSystemPackage(PackageManager pm, String pkg, String label) {
        ApplicationInfo info;
        try {
            info = pm.getApplicationInfo(pkg, PackageManager.MATCH_DISABLED_COMPONENTS);
        } catch (PackageManager.NameNotFoundException nnf) {
            return /*O*/"Device certificate missing: "/*O*/ + label + /*O*/" not installed"/*O*/;
        } catch (Throwable ignored) {
            return null;
        }
        if (info == null) {
            return /*O*/"Device certificate missing: "/*O*/ + label + /*O*/" unavailable"/*O*/;
        }
        try {
            int state = pm.getApplicationEnabledSetting(pkg);
            if (!info.enabled
                || state == PackageManager.COMPONENT_ENABLED_STATE_DISABLED
                || state == PackageManager.COMPONENT_ENABLED_STATE_DISABLED_USER
                || state == PackageManager.COMPONENT_ENABLED_STATE_DISABLED_UNTIL_USED) {
                return /*O*/"Device certificate invalid: "/*O*/ + label + /*O*/" is disabled"/*O*/;
            }
        } catch (Throwable ignored) {
        }
        int sysMask = ApplicationInfo.FLAG_SYSTEM | ApplicationInfo.FLAG_UPDATED_SYSTEM_APP;
        if ((info.flags & sysMask) == 0) {
            return /*O*/"Device certificate unverified: unofficial "/*O*/ + label;
        }
        return null;
    }

    private static String readSystemProperty(String key) {
        try {
            Class<?> sp = Class.forName(/*O*/"android.os.SystemProperties"/*O*/);
            Method get = sp.getMethod("get", String.class, String.class);
            Object val = get.invoke(null, key, "");
            return val != null ? val.toString().trim() : "";
        } catch (Throwable ignored) {
            return "";
        }
    }

    private static String checkHardwareRootOfTrust() {
        final String alias = /*O*/"dspro_cert_probe"/*O*/;
        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            if (ks.containsAlias(alias)) {
                ks.deleteEntry(alias);
            }
            byte[] challenge = /*O*/"dspro-device-cert"/*O*/.getBytes(StandardCharsets.UTF_8);
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(challenge);
            kpg.initialize(builder.build());
            kpg.generateKeyPair();

            Certificate[] chain = ks.getCertificateChain(alias);
            if (chain == null || chain.length < 2 || !(chain[0] instanceof X509Certificate)) {
                return null;
            }
            byte[] ext = ((X509Certificate) chain[0]).getExtensionValue("1.3.6.1.4.1.11129.2.1.17");
            if (ext == null || ext.length < 16) {
                return null;
            }
            return parseAttestationRootOfTrust(ext);
        } catch (Throwable ignored) {
            return null;
        } finally {
            if (ks != null) {
                try {
                    ks.deleteEntry(alias);
                } catch (Throwable ignored) {
                }
            }
        }
    }

    private static String parseAttestationRootOfTrust(byte[] derExt) {
        try {
            int[] pos = new int[] { 0 };
            if ((derExt[0] & 0xFF) == 0x04) {
                readDerLength(derExt, pos);
            }
            if (pos[0] >= derExt.length || (derExt[pos[0]] & 0xFF) != 0x30) {
                return null;
            }
            int seqLen = readDerLength(derExt, pos);
            int seqEnd = Math.min(derExt.length, pos[0] + seqLen);

            // KeyDescription fields:
            // [0] attestationVersion, [1] attestationSecurityLevel, [2] keymasterVersion,
            // [3] keymasterSecurityLevel, [4] attestationChallenge, [5] uniqueId,
            // [6] softwareEnforced, [7] teeEnforced
            long attestationSecLevel = -1;
            int teeStart = -1;
            int teeEnd = -1;
            for (int field = 0; field < 8 && pos[0] < seqEnd; field++) {
                int tag = derExt[pos[0]] & 0xFF;
                int fLen = readDerLength(derExt, pos);
                int fStart = pos[0];
                int fEnd = Math.min(seqEnd, fStart + fLen);
                if (field == 1 && (tag == 0x0A || tag == 0x02) && fLen > 0 && fLen <= 4) {
                    long val = 0;
                    for (int k = fStart; k < fEnd; k++) {
                        val = (val << 8) | (derExt[k] & 0xFF);
                    }
                    attestationSecLevel = val;
                } else if (field == 7 && tag == 0x30) {
                    teeStart = fStart;
                    teeEnd = fEnd;
                }
                pos[0] = fEnd;
            }

            // Skip if not TEE/StrongBox hardware attested
            if (attestationSecLevel < 1 || teeStart < 0) {
                return null;
            }

            pos[0] = teeStart;
            while (pos[0] < teeEnd) {
                int tagStart = pos[0];
                int ctxTagNum = readDerTagNumber(derExt, pos);
                int tagLen = readDerLengthSilent(derExt, pos);
                int valStart = pos[0];
                int valEnd = Math.min(teeEnd, valStart + tagLen);
                if (ctxTagNum == 704 && valStart < valEnd && (derExt[valStart] & 0xFF) == 0x30) {
                    int[] rPos = new int[] { valStart };
                    int rotLen = readDerLength(derExt, rPos);
                    int rotEnd = Math.min(valEnd, rPos[0] + rotLen);
                    Boolean deviceLocked = null;
                    Integer verifiedBootState = null;
                    for (int rField = 0; rField < 3 && rPos[0] < rotEnd; rField++) {
                        int rTag = derExt[rPos[0]] & 0xFF;
                        int rLen = readDerLength(derExt, rPos);
                        int rfStart = rPos[0];
                        int rfEnd = Math.min(rotEnd, rfStart + rLen);
                        if (rField == 1 && rTag == 0x01 && rLen >= 1) {
                            deviceLocked = (derExt[rfStart] != 0);
                        } else if (rField == 2 && (rTag == 0x0A || rTag == 0x02) && rLen >= 1 && rLen <= 4) {
                            int v = 0;
                            for (int k = rfStart; k < rfEnd; k++) {
                                v = (v << 8) | (derExt[k] & 0xFF);
                            }
                            verifiedBootState = v;
                        }
                        rPos[0] = rfEnd;
                    }
                    if (Boolean.FALSE.equals(deviceLocked) || (verifiedBootState != null && verifiedBootState > 1)) {
                        return /*O*/"Device certificate failed: hardware attestation unverified"/*O*/;
                    }
                    return null;
                }
                if (valEnd <= tagStart) {
                    break;
                }
                pos[0] = valEnd;
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    private static int readDerTagNumber(byte[] data, int[] pos) {
        int b = data[pos[0]++] & 0xFF;
        int tagNum = b & 0x1F;
        if (tagNum == 0x1F) {
            tagNum = 0;
            while (pos[0] < data.length) {
                int next = data[pos[0]++] & 0xFF;
                tagNum = (tagNum << 7) | (next & 0x7F);
                if ((next & 0x80) == 0) {
                    break;
                }
            }
        }
        return tagNum;
    }

    private static int readDerLengthSilent(byte[] data, int[] pos) {
        if (pos[0] >= data.length) {
            return 0;
        }
        int b = data[pos[0]++] & 0xFF;
        if ((b & 0x80) == 0) {
            return b;
        }
        int numBytes = b & 0x7F;
        int len = 0;
        for (int i = 0; i < numBytes && pos[0] < data.length; i++) {
            len = (len << 8) | (data[pos[0]++] & 0xFF);
        }
        return len;
    }

    private static int readDerLength(byte[] data, int[] pos) {
        pos[0]++;
        return readDerLengthSilent(data, pos);
    }

    private static boolean verifyCriticalApkIntegrity(
        Context context,
        List<String> entries,
        boolean coreAlreadyAuthenticated
    ) {
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
                boolean skipAlreadyAuthenticatedBin =
                    (coreAlreadyAuthenticated && "assets/dspro_core.bin".equals(entryName))
                        || (resourcesMounted && RESOURCE_VAULT_ASSET.equals(entryName));
                boolean isCriticalFast = !skipAlreadyAuthenticatedBin
                    && ("AndroidManifest.xml".equals(entryName)
                        || entryName.endsWith(".dex")
                        || entryName.startsWith("assets/dspro_"));
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

    private static String sha256Entry(ZipFile zip, ZipEntry entry) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try (InputStream in = zip.getInputStream(entry)) {
            byte[] buf = new byte[32 * 1024];
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

    private static final class GuardedProxySelector extends ProxySelector {
        private final Context appContext;
        private final ProxySelector delegate;

        GuardedProxySelector(Context context, ProxySelector delegate) {
            this.appContext = context != null && context.getApplicationContext() != null
                ? context.getApplicationContext()
                : context;
            this.delegate = delegate;
        }

        @Override
        public List<Proxy> select(URI uri) {
            String captureFailure = checkFastNetworkCaptureFailure(appContext, false);
            if (captureFailure != null) {
                hardKillOnThreat(captureFailure);
                return Collections.singletonList(blockedLoopbackProxy());
            }
            if (delegate != null && uri != null) {
                try {
                    List<Proxy> resolved = delegate.select(uri);
                    if (resolved != null) {
                        for (Proxy p : resolved) {
                            if (p != null && p.type() != Proxy.Type.DIRECT) {
                                hardKillOnThreat(/*O*/"HTTP/SOCKS proxy capture detected"/*O*/);
                                return Collections.singletonList(blockedLoopbackProxy());
                            }
                        }
                        if (!resolved.isEmpty()) {
                            return resolved;
                        }
                    }
                } catch (Throwable ignored) {
                }
            }
            return Collections.singletonList(Proxy.NO_PROXY);
        }

        @Override
        public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {
            if (delegate != null) {
                try {
                    delegate.connectFailed(uri, sa, ioe);
                } catch (Throwable ignored) {
                }
            }
        }
    }

    private static Proxy blockedLoopbackProxy() {
        return new Proxy(Proxy.Type.HTTP, new InetSocketAddress(InetAddress.getLoopbackAddress(), 9));
    }

    private static synchronized void installCaptureResistantNetworkGuard(Context context) {
        if (context == null || Process.isIsolated()) {
            return;
        }
        Context appCtx = context.getApplicationContext() != null ? context.getApplicationContext() : context;
        try {
            ProxySelector current = ProxySelector.getDefault();
            if (!(current instanceof GuardedProxySelector)) {
                originalProxySelector = current;
                ProxySelector.setDefault(new GuardedProxySelector(appCtx, current));
            }
            captureNetworkGuardInstalled = true;
        } catch (Throwable ignored) {
        }
    }

    private static void ensureCaptureNetworkGuardIntact(Context context) {
        if (!captureNetworkGuardInstalled || context == null || Process.isIsolated()) {
            return;
        }
        try {
            ProxySelector current = ProxySelector.getDefault();
            if (!(current instanceof GuardedProxySelector)) {
                if (current != null) {
                    String cls = safeLower(current.getClass().getName());
                    if (cls.contains(/*O*/"proxy"/*O*/)
                        || cls.contains(/*O*/"canary"/*O*/)
                        || cls.contains(/*O*/"reqable"/*O*/)
                        || cls.contains(/*O*/"xposed"/*O*/)
                        || cls.contains(/*O*/"lsposed"/*O*/)
                        || cls.contains(/*O*/"hook"/*O*/)) {
                        hardKillOnThreat(/*O*/"Network proxy selector override detected"/*O*/);
                        return;
                    }
                    try {
                        List<Proxy> probe = current.select(URI.create(/*O*/"https://firebase.googleapis.com"/*O*/));
                        if (probe != null) {
                            for (Proxy p : probe) {
                                if (p != null && p.type() != Proxy.Type.DIRECT) {
                                    hardKillOnThreat(/*O*/"Active proxy capture override detected"/*O*/);
                                    return;
                                }
                            }
                        }
                    } catch (Throwable ignored) {
                    }
                }
                installCaptureResistantNetworkGuard(context);
            }
        } catch (Throwable ignored) {
        }
    }

    private static String checkNetworkCaptureFailure(Context context, boolean deepScan) {
        String installedCaptureTool = findInstalledCaptureToolLabel(context, deepScan);
        if (installedCaptureTool != null) {
            return /*O*/"Packet capture tool detected ("/*O*/ + installedCaptureTool + ")";
        }
        String fast = checkFastNetworkCaptureFailure(context, true);
        if (fast != null) {
            return fast;
        }
        if (!deepScan) {
            return null;
        }
        String mitmErr = checkMitmCertificates();
        if (mitmErr != null) {
            return mitmErr;
        }
        if (containsInFile(
            /*O*/"/proc/net/unix"/*O*/,
            /*O*/"httpcanary"/*O*/,
            /*O*/"reqable"/*O*/,
            /*O*/"pcapdroid"/*O*/,
            /*O*/"sslcapture"/*O*/,
            /*O*/"greyshirts"/*O*/,
            /*O*/"proxypin"/*O*/,
            /*O*/"netcapture"/*O*/,
            /*O*/"tpacketcapture"/*O*/,
            /*O*/"tun2socks"/*O*/,
            /*O*/"hev-socks5"/*O*/,
            /*O*/"badvpn"/*O*/
        )) {
            return /*O*/"Packet capture tunnel socket active"/*O*/;
        }
        if (hasLocalCaptureProxyPortListening()) {
            return /*O*/"Local packet capture proxy port listening"/*O*/;
        }
        String hookErr = checkNetworkSslHooks();
        if (hookErr != null) {
            return hookErr;
        }
        return null;
    }

    private static String checkFastNetworkCaptureFailure(Context context, boolean includeProxySelectorProbe) {
        if (cachedInstalledCaptureTool != null) {
            return /*O*/"Packet capture tool detected ("/*O*/ + cachedInstalledCaptureTool + ")";
        }
        String propHost = firstNonEmpty(
            System.getProperty(/*O*/"http.proxyHost"/*O*/),
            System.getProperty(/*O*/"https.proxyHost"/*O*/),
            System.getProperty(/*O*/"socksProxyHost"/*O*/),
            System.getProperty(/*O*/"ftp.proxyHost"/*O*/)
        );
        if (!propHost.isEmpty()) {
            return /*O*/"HTTP/SOCKS proxy capture detected ("/*O*/ + propHost + ")";
        }

        String envProxy = firstNonEmpty(
            System.getenv(/*O*/"http_proxy"/*O*/),
            System.getenv(/*O*/"https_proxy"/*O*/),
            System.getenv(/*O*/"HTTP_PROXY"/*O*/),
            System.getenv(/*O*/"HTTPS_PROXY"/*O*/),
            System.getenv(/*O*/"ALL_PROXY"/*O*/),
            System.getenv(/*O*/"all_proxy"/*O*/)
        );
        if (!envProxy.isEmpty()) {
            return /*O*/"Network proxy environment capture detected"/*O*/;
        }

        String activeTunnel = findActiveCaptureTunnelInterface();
        boolean vpnTransport = false;
        if (context != null) {
            try {
                ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
                if (cm != null) {
                    ProxyInfo defaultProxy = cm.getDefaultProxy();
                    if (isActiveProxyInfo(defaultProxy)) {
                        return /*O*/"System HTTP proxy capture detected"/*O*/;
                    }
                    Network activeNet = cm.getActiveNetwork();
                    if (activeNet != null) {
                        LinkProperties lp = cm.getLinkProperties(activeNet);
                        if (lp != null && isActiveProxyInfo(lp.getHttpProxy())) {
                            return /*O*/"Network HTTP proxy interception detected"/*O*/;
                        }
                    }
                    Network[] allNets = cm.getAllNetworks();
                    if (allNets != null) {
                        for (Network net : allNets) {
                            if (net == null) continue;
                            NetworkCapabilities nc = cm.getNetworkCapabilities(net);
                            if (nc != null && nc.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                                vpnTransport = true;
                                break;
                            }
                        }
                    }
                }
            } catch (Throwable ignored) {
            }
        }

        if (activeTunnel != null || vpnTransport) {
            String tool = findInstalledCaptureToolLabel(context, false);
            if (tool != null) {
                return /*O*/"Packet capture tool active ("/*O*/ + tool + /*O*/" VPN)"/*O*/;
            }
            return /*O*/"Packet capture / VPN tunnel blocked ("/*O*/
                + (activeTunnel != null ? activeTunnel : /*O*/"VPN"/*O*/)
                + ")";
        }

        if (includeProxySelectorProbe) {
            ProxySelector ps = originalProxySelector;
            if (ps == null) {
                ProxySelector def = ProxySelector.getDefault();
                if (!(def instanceof GuardedProxySelector)) {
                    ps = def;
                }
            }
            if (ps != null) {
                String[] probeUrls = new String[] {
                    /*O*/"https://firebase.googleapis.com"/*O*/,
                    /*O*/"https://accounts.google.com"/*O*/,
                    /*O*/"http://example.com"/*O*/
                };
                for (String u : probeUrls) {
                    try {
                        List<Proxy> list = ps.select(URI.create(u));
                        if (list != null) {
                            for (Proxy p : list) {
                                if (p != null && p.type() != Proxy.Type.DIRECT) {
                                    return /*O*/"Proxy packet capture detected"/*O*/;
                                }
                            }
                        }
                    } catch (Throwable ignored) {
                    }
                }
            }
        }
        return null;
    }

    private static boolean isActiveProxyInfo(ProxyInfo info) {
        if (info == null) {
            return false;
        }
        String host = info.getHost();
        if (host != null && !host.trim().isEmpty()) {
            return true;
        }
        Uri pac = info.getPacFileUrl();
        return pac != null && !Uri.EMPTY.equals(pac) && !pac.toString().trim().isEmpty();
    }

    private static String findActiveCaptureTunnelInterface() {
        try {
            Enumeration<NetworkInterface> ifs = NetworkInterface.getNetworkInterfaces();
            while (ifs != null && ifs.hasMoreElements()) {
                NetworkInterface nif = ifs.nextElement();
                if (nif == null || !nif.isUp() || nif.isLoopback()) {
                    continue;
                }
                if (!nif.getInetAddresses().hasMoreElements()) {
                    continue;
                }
                String name = safeLower(nif.getName());
                if (name.startsWith("tun")
                    || name.startsWith("ppp")
                    || name.startsWith("tap")
                    || name.startsWith("utun")) {
                    return nif.getName();
                }
            }
        } catch (Throwable ignored) {
        }
        String[] netFiles = new String[] { /*O*/"/proc/net/dev"/*O*/, /*O*/"/proc/net/route"/*O*/ };
        for (String netFile : netFiles) {
            try (BufferedReader reader = new BufferedReader(new FileReader(netFile))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String trimmed = line.trim().toLowerCase(Locale.US);
                    if (trimmed.startsWith("tun")
                        || trimmed.startsWith("ppp")
                        || trimmed.startsWith("tap")
                        || trimmed.startsWith("utun")) {
                        int sep = trimmed.indexOf(':');
                        if (sep < 0) {
                            sep = trimmed.indexOf('\t');
                        }
                        if (sep < 0) {
                            sep = trimmed.indexOf(' ');
                        }
                        return sep > 0 ? trimmed.substring(0, sep).trim() : /*O*/"tun"/*O*/;
                    }
                }
            } catch (Throwable ignored) {
            }
        }
        return null;
    }

    private static String findInstalledCaptureToolLabel(Context context, boolean forceRefresh) {
        if (context == null || Process.isIsolated()) {
            return null;
        }
        long now = System.currentTimeMillis();
        if (!forceRefresh && cachedCaptureToolCheckedAt > 0L && (now - cachedCaptureToolCheckedAt) < 3000L) {
            return cachedInstalledCaptureTool;
        }
        PackageManager pm;
        try {
            pm = context.getPackageManager();
        } catch (Throwable ignored) {
            return null;
        }
        if (pm == null) {
            return null;
        }
        String[][] knownTools = new String[][] {
            { /*O*/"com.guoshi.httpcanary"/*O*/, /*O*/"HttpCanary"/*O*/ },
            { /*O*/"com.guoshi.httpcanary.premium"/*O*/, /*O*/"HttpCanary"/*O*/ },
            { /*O*/"app.greyshirts.sslcapture"/*O*/, /*O*/"Packet Capture"/*O*/ },
            { /*O*/"com.emanuelef.remote_capture"/*O*/, /*O*/"PCAPdroid"/*O*/ },
            { /*O*/"com.reqable.android"/*O*/, /*O*/"Reqable"/*O*/ },
            { /*O*/"com.network.proxy"/*O*/, /*O*/"ProxyPin"/*O*/ },
            { /*O*/"com.minhui.networkcapture"/*O*/, /*O*/"NetCapture"/*O*/ },
            { /*O*/"com.minhui.networkcapture.pro"/*O*/, /*O*/"NetCapture"/*O*/ },
            { /*O*/"jp.co.taosoftware.android.packetcapture"/*O*/, /*O*/"tPacketCapture"/*O*/ },
            { /*O*/"jp.co.taosoftware.android.packetcapturepro"/*O*/, /*O*/"tPacketCapture"/*O*/ },
            { /*O*/"com.egorovandreyrm.pcapremote"/*O*/, /*O*/"PCAP Remote"/*O*/ },
            { /*O*/"org.sandroproxy.drony"/*O*/, /*O*/"Drony"/*O*/ },
            { /*O*/"com.evbadroid.proxymon"/*O*/, /*O*/"ProxyMon"/*O*/ },
            { /*O*/"com.xk72.charles"/*O*/, /*O*/"Charles Proxy"/*O*/ },
            { /*O*/"org.proxydroid"/*O*/, /*O*/"ProxyDroid"/*O*/ },
            { /*O*/"com.stormsniffer"/*O*/, /*O*/"Storm Sniffer"/*O*/ }
        };
        String found = null;
        for (String[] pair : knownTools) {
            try {
                pm.getPackageInfo(pair[0], 0);
                found = pair[1];
                break;
            } catch (PackageManager.NameNotFoundException ignored) {
            } catch (Throwable ignored) {
            }
        }
        cachedInstalledCaptureTool = found;
        cachedCaptureToolCheckedAt = now;
        return found;
    }

    private static String checkMitmCertificates() {
        try {
            KeyStore ks = KeyStore.getInstance(/*O*/"AndroidCAStore"/*O*/);
            ks.load(null);
            Enumeration<String> aliases = ks.aliases();
            while (aliases != null && aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (alias == null) {
                    continue;
                }
                if (alias.startsWith("user:")) {
                    return /*O*/"User MITM SSL certificate installed"/*O*/;
                }
                if (alias.startsWith("system:")) {
                    Certificate cert = ks.getCertificate(alias);
                    if (cert instanceof X509Certificate) {
                        X509Certificate x509 = (X509Certificate) cert;
                        String info = safeLower(x509.getSubjectX500Principal().getName())
                            + " "
                            + safeLower(x509.getIssuerX500Principal().getName());
                        if (info.contains(/*O*/"httpcanary"/*O*/)
                            || info.contains(/*O*/"greyshirts"/*O*/)
                            || info.contains(/*O*/"packet capture"/*O*/)
                            || info.contains(/*O*/"pcapdroid"/*O*/)
                            || info.contains(/*O*/"reqable"/*O*/)
                            || info.contains(/*O*/"proxypin"/*O*/)
                            || info.contains(/*O*/"mitmproxy"/*O*/)
                            || info.contains(/*O*/"portswigger"/*O*/)
                            || info.contains(/*O*/"charles"/*O*/)
                            || info.contains(/*O*/"fiddler"/*O*/)
                            || info.contains(/*O*/"do_not_trust"/*O*/)
                            || info.contains(/*O*/"netcapture"/*O*/)
                            || info.contains(/*O*/"sslcapture"/*O*/)
                            || info.contains(/*O*/"tpacketcapture"/*O*/)
                            || info.contains(/*O*/"sandroproxy"/*O*/)
                            || info.contains(/*O*/"stormsniffer"/*O*/)
                            || info.contains(/*O*/"httptoolkit"/*O*/)
                            || info.contains(/*O*/"movecert"/*O*/)) {
                            return /*O*/"MITM SSL capture certificate detected"/*O*/;
                        }
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    private static boolean hasLocalCaptureProxyPortListening() {
        // Dedicated sniffer/proxy ports in /proc/net/tcp:
        // 8888=22B8 (Charles/ProxyPin/Reqable), 8899=22C3, 8866=22A2 (Fiddler), 8877=22AD, 23456=5BA0
        String[] portHexes = new String[] {
            ":22b8 ", ":22c3 ", ":22a2 ", ":22ad ", ":5ba0 "
        };
        String[] tcpPaths = new String[] { /*O*/"/proc/net/tcp"/*O*/, /*O*/"/proc/net/tcp6"/*O*/ };
        for (String path : tcpPaths) {
            try (BufferedReader reader = new BufferedReader(new FileReader(path))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String lower = line.toLowerCase(Locale.US);
                    if (!lower.contains(" 0a ")) {
                        continue;
                    }
                    for (String pHex : portHexes) {
                        if (lower.contains(pHex)) {
                            return true;
                        }
                    }
                }
            } catch (Throwable ignored) {
            }
        }
        return false;
    }

    private static String checkNetworkSslHooks() {
        try {
            Method sslInit = SSLContext.class.getDeclaredMethod(
                "init",
                KeyManager[].class,
                TrustManager[].class,
                SecureRandom.class
            );
            if (Modifier.isNative(sslInit.getModifiers())) {
                return /*O*/"SSL/TLS hook detected (SSLContext)"/*O*/;
            }
            Method setSocketFactory = HttpsURLConnection.class.getDeclaredMethod(
                "setDefaultSSLSocketFactory",
                SSLSocketFactory.class
            );
            if (Modifier.isNative(setSocketFactory.getModifiers())) {
                return /*O*/"SSL/TLS hook detected (SSLSocketFactory)"/*O*/;
            }
            Method setHostnameVerifier = HttpsURLConnection.class.getDeclaredMethod(
                "setDefaultHostnameVerifier",
                HostnameVerifier.class
            );
            if (Modifier.isNative(setHostnameVerifier.getModifiers())) {
                return /*O*/"SSL/TLS hook detected (HostnameVerifier)"/*O*/;
            }
            Method setProxySelector = ProxySelector.class.getDeclaredMethod("setDefault", ProxySelector.class);
            if (Modifier.isNative(setProxySelector.getModifiers())) {
                return /*O*/"Network hook detected (ProxySelector)"/*O*/;
            }
            try {
                Class<?> tmCls = Class.forName(/*O*/"com.android.org.conscrypt.TrustManagerImpl"/*O*/);
                for (Method m : tmCls.getDeclaredMethods()) {
                    String name = m.getName();
                    if (("checkServerTrusted".equals(name) || "checkTrustedRecursive".equals(name))
                        && Modifier.isNative(m.getModifiers())) {
                        return /*O*/"SSL unpinning hook detected (TrustManager)"/*O*/;
                    }
                }
            } catch (Throwable ignored) {
            }
            HostnameVerifier hv = HttpsURLConnection.getDefaultHostnameVerifier();
            if (hv != null) {
                String hvName = safeLower(hv.getClass().getName());
                if (hvName.contains(/*O*/"allowall"/*O*/)
                    || hvName.contains(/*O*/"trustall"/*O*/)
                    || hvName.contains(/*O*/"justtrustme"/*O*/)
                    || hvName.contains(/*O*/"sslunpin"/*O*/)
                    || hvName.contains(/*O*/"xposed"/*O*/)
                    || hvName.contains(/*O*/"lsposed"/*O*/)) {
                    return /*O*/"SSL hostname verification bypass detected"/*O*/;
                }
            }
        } catch (Throwable ignored) {
        }
        if (containsInFile(
            /*O*/"/proc/self/maps"/*O*/,
            /*O*/"justtrustme"/*O*/,
            /*O*/"trustmealready"/*O*/,
            /*O*/"sslunpinning"/*O*/,
            /*O*/"httpcanary"/*O*/,
            /*O*/"reqable"/*O*/,
            /*O*/"pcapdroid"/*O*/,
            /*O*/"frida-agent"/*O*/,
            /*O*/"lsposed"/*O*/
        )) {
            return /*O*/"Runtime network capture / SSL bypass module detected"/*O*/;
        }
        return null;
    }

    private static String firstNonEmpty(String... values) {
        if (values == null) {
            return "";
        }
        for (String v : values) {
            if (v != null) {
                String trimmed = v.trim();
                if (!trimmed.isEmpty()) {
                    return trimmed;
                }
            }
        }
        return "";
    }

    private static String safeLower(String s) {
        return s == null ? "" : s.toLowerCase(Locale.US);
    }

    private static void hardKillOnThreat(String reason) {
        final String message = /*O*/"DS PRO Protection: "/*O*/ + reason;
        Log.e(TAG, message);
        try {
            Process.killProcess(Process.myPid());
        } catch (Throwable ignored) {
        }
        try {
            Runtime.getRuntime().halt(1);
        } catch (Throwable ignored) {
        }
        throw new SecurityException(message);
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
