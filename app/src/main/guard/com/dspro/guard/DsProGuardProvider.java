package com.dspro.guard;

import android.app.Activity;
import android.app.Application;
import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.content.res.AssetManager;
import android.content.res.Resources;
import android.content.res.loader.ResourcesLoader;
import android.content.res.loader.ResourcesProvider;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Debug;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.os.Process;
import android.util.Log;
import android.view.WindowManager;

import dalvik.system.BaseDexClassLoader;
import dalvik.system.InMemoryDexClassLoader;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
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

/**
 * Runtime protection guard compiled into ds_pro_guard.dex and injected into protected APKs.
 * Reads encrypted binary security configuration from assets/dspro_guard.bin, wipes keys immediately,
 * dynamically mounts encrypted assets from assets/dspro_res.bin when present, enforces DEX Integrity
 * Protection & runtime security checks via flattened control-flow dispatch, and runs a burst watchdog.
 */
public final class DsProGuardProvider extends ContentProvider {

    private static final String TAG = "DsProGuard";

    private static final int FLAG_DETECT_ROOT = 1;
    private static final int FLAG_DETECT_DEBUGGER = 1 << 4;
    private static final int FLAG_ANTI_SCREENSHOT = 1 << 5;
    private static final int FLAG_ANTI_TAMPERING = 1 << 6;
    private static final int FLAG_ANTI_DUMP = 1 << 8;
    private static final int FLAG_DEX_INTEGRITY = 1 << 9;

    private static final String POLICY_ASSET = /*O*/"dspro_guard.bin"/*O*/;
    private static final String RESOURCE_VAULT_ASSET = /*O*/"assets/dspro_res.bin"/*O*/;
    private static final String CORE_LOADER_CLASS = "com.dspro.core.DsProCoreLoader";
    private static volatile boolean watchdogStarted = false;

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

        mountEncryptedResourcesIfNeeded(context);

        final GuardPolicy policy = readEncryptedPolicy(context);
        final Context appCtx = context.getApplicationContext();
        if (appCtx != null) {
            attachResourcesIfMounted(appCtx);
        }

        if (policy != null) {
            enforceChecks(context, policy);
        }

        final boolean antiScreenshot = policy != null && policy.has(FLAG_ANTI_SCREENSHOT);
        final boolean detectDebugger = policy != null && policy.has(FLAG_DETECT_DEBUGGER);
        final boolean antiDump = policy != null && policy.has(FLAG_ANTI_DUMP);
        final boolean antiTampering = policy != null && policy.has(FLAG_ANTI_TAMPERING);
        final boolean dexIntegrity = policy != null && policy.has(FLAG_DEX_INTEGRITY);

        if (appCtx instanceof Application) {
            ((Application) appCtx).registerActivityLifecycleCallbacks(
                new Application.ActivityLifecycleCallbacks() {
                    @Override
                    public void onActivityPreCreated(Activity activity, Bundle savedInstanceState) {
                        attachResourcesIfMounted(activity);
                    }

                    @Override
                    public void onActivityCreated(Activity activity, Bundle savedInstanceState) {
                        attachResourcesIfMounted(activity);
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

        if (policy != null && (antiDump || detectDebugger || antiTampering || dexIntegrity)) {
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
                try (FileOutputStream fos = new FileOutputStream(tmp)) {
                    fos.write(plainZip);
                    fos.flush();
                }
                ParcelFileDescriptor pfd = ParcelFileDescriptor.open(tmp, ParcelFileDescriptor.MODE_READ_ONLY);
                tmp.delete();
                try {
                    ResourcesLoader loader = new ResourcesLoader();
                    loader.addProvider(ResourcesProvider.loadFromApk(pfd));
                    cachedResourcesLoader = loader;
                } finally {
                    try {
                        pfd.close();
                    } catch (Throwable ignored) {
                    }
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
                    if (policy.has(FLAG_ANTI_DUMP) && isMemoryDumpDetected(context, true)) {
                        crashWithReason(/*O*/"Memory / APK dumper detected"/*O*/);
                    }
                    state = 0x34A;
                    break;
                case 0x34A:
                    if (policy.has(FLAG_DETECT_ROOT) && isDeviceRooted()) {
                        crashWithReason(/*O*/"Root detected"/*O*/);
                    }
                    state = 0x47C;
                    break;
                case 0x47C:
                    if (policy.has(FLAG_DEX_INTEGRITY) && !verifyDexIntegrity(context, policy.dexIntegrityEntries)) {
                        crashWithReason(/*O*/"DEX integrity violation detected"/*O*/);
                    }
                    state = 0x591;
                    break;
                case 0x591:
                    if (policy.has(FLAG_ANTI_TAMPERING) && !verifyCriticalApkIntegrity(context, policy.integrityEntries)) {
                        crashWithReason(/*O*/"APK tampering detected"/*O*/);
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
                        if (policy.has(FLAG_DEX_INTEGRITY) && (cycle % 16 == 0)) {
                            if (!verifyDexIntegrity(appContext, policy.dexIntegrityEntries)) {
                                triggerMainCrash(mainHandler, /*O*/"DEX integrity violation detected"/*O*/);
                                return;
                            }
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
                    byte[] buf = new byte[16384];
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
