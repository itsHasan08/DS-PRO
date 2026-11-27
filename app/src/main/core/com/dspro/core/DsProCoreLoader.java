package com.dspro.core;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ProviderInfo;
import android.content.res.AssetManager;
import android.content.res.Resources;
import android.content.res.loader.ResourcesLoader;
import android.content.res.loader.ResourcesProvider;
import android.os.Build;
import android.os.Debug;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.os.Process;
import dalvik.system.BaseDexClassLoader;
import dalvik.system.InMemoryDexClassLoader;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.NetworkInterface;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.WeakHashMap;
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
 * Decrypts V5 self-bound AES-256-GCM encrypted DEX container in direct memory,
 * unlocks per-DEX encrypted literal string tables and verifies DEX SHA-256 integrity
 * inside wiped DirectByteBuffers, dynamically mounts encrypted asset vaults (dspro_res.bin),
 * and runs burst-polling anti-dump / anti-virtualizer / anti-capture watchdogs.
 */
final class DsProCoreLoader {

    static final class CoreMetadata {
        final int dexCount;
        final String originalAppClass;
        final String originalFactoryClass;
        final boolean requireGuard;
        final boolean antiDumpEnabled;
        final boolean stringEncryptionEnabled;
        final String[] dexPayloadDigests;
        final boolean antiTamperingEnabled;

        CoreMetadata(
            int dexCount,
            String originalAppClass,
            String originalFactoryClass,
            boolean requireGuard,
            boolean antiDumpEnabled,
            boolean stringEncryptionEnabled,
            String[] dexPayloadDigests,
            boolean antiTamperingEnabled
        ) {
            this.dexCount = dexCount;
            this.originalAppClass = originalAppClass;
            this.originalFactoryClass = originalFactoryClass;
            this.requireGuard = requireGuard;
            this.antiDumpEnabled = antiDumpEnabled;
            this.stringEncryptionEnabled = stringEncryptionEnabled;
            this.dexPayloadDigests = dexPayloadDigests != null ? dexPayloadDigests : new String[0];
            this.antiTamperingEnabled = antiTamperingEnabled;
        }
    }

    static final class DecryptedBundle {
        final ByteBuffer[] dexBuffers;
        final CoreMetadata metadata;

        DecryptedBundle(ByteBuffer[] dexBuffers, CoreMetadata metadata) {
            this.dexBuffers = dexBuffers;
            this.metadata = metadata;
        }
    }

    static String _xs(int seed, byte[] data) {
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            out[i] = (byte) ((data[i] & 0xFF) ^ ((seed + i * 31) & 0xFF));
        }
        return new String(out, StandardCharsets.UTF_8);
    }

    private static final String CONTAINER_ASSET = /*O*/"assets/dspro_core.bin"/*O*/;
    private static final String GUARD_POLICY_ASSET = /*O*/"assets/dspro_guard.bin"/*O*/;
    private static final String RESOURCE_VAULT_ASSET = /*O*/"assets/dspro_res.bin"/*O*/;
    private static final String GUARD_PROVIDER_NAME = "com.dspro.guard.DsProGuardProvider";

    private static volatile boolean initialized = false;
    private static volatile String initializedPackage = "";
    private static volatile CoreMetadata cachedMetadata = null;
    private static volatile ClassLoader activeClassLoader = null;
    private static volatile Object delegateFactory = null;
    private static volatile boolean guardProviderInstantiated = false;
    private static volatile boolean guardBindingVerified = false;
    private static volatile boolean coreWatchdogStarted = false;

    private static volatile boolean resourcesMounted = false;
    private static volatile Object cachedResourcesLoader = null;
    private static volatile String cachedLegacyAssetPath = null;
    private static final Map<Resources, Boolean> attachedResourcesMap =
        Collections.synchronizedMap(new WeakHashMap<Resources, Boolean>());
    private static final Map<AssetManager, Boolean> attachedAssetsMap =
        Collections.synchronizedMap(new WeakHashMap<AssetManager, Boolean>());

    static boolean isInitialized() {
        return initialized;
    }

    static boolean isCoreWatchdogStarted() {
        return coreWatchdogStarted;
    }

    static boolean isInitializedFor(String packageName) {
        return initialized && packageName != null && packageName.equals(initializedPackage);
    }

    static CoreMetadata getCachedMetadata() {
        return cachedMetadata;
    }

    static ClassLoader getActiveClassLoader() {
        return activeClassLoader;
    }

    static Object getDelegateFactory() {
        return delegateFactory;
    }

    static void markGuardProviderInstantiated() {
        guardProviderInstantiated = true;
    }

    static void assertGuardActiveIfRequired() {
        if (Process.isIsolated()) {
            return;
        }
        CoreMetadata meta = cachedMetadata;
        if (meta == null || !meta.requireGuard || guardProviderInstantiated) {
            return;
        }
        throw new SecurityException(/*O*/"DS PRO Protection: Guard integrity compromised"/*O*/);
    }

    static synchronized void markInitialized(
        String packageName,
        CoreMetadata metadata,
        ClassLoader loader,
        Object factory
    ) {
        initializedPackage = packageName == null ? "" : packageName;
        cachedMetadata = metadata;
        activeClassLoader = loader;
        delegateFactory = factory;
        initialized = true;
    }

    static synchronized void mountEncryptedResources(Context context) {
        if (context == null || Process.isIsolated()) {
            return;
        }
        if (resourcesMounted) {
            attachResourcesIfMounted(context);
            return;
        }

        String apkPath;
        String packageName;
        try {
            apkPath = context.getPackageCodePath();
            packageName = context.getPackageName();
        } catch (Throwable ignored) {
            return;
        }
        if (apkPath == null || apkPath.isEmpty() || packageName == null || packageName.isEmpty()) {
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
                throw new SecurityException(/*O*/"DS PRO Protection: Encrypted resource vault tampered"/*O*/);
            }

            salt = new byte[16];
            byte[] iv = new byte[12];
            System.arraycopy(blob, 0, salt, 0, 16);
            System.arraycopy(blob, 16, iv, 0, 12);
            String saltHex = toLowerHex(salt);
            key = MessageDigest.getInstance("SHA-256").digest(
                (packageName + /*O*/":DSPRO_RES_V1:"/*O*/ + saltHex).getBytes(StandardCharsets.UTF_8)
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
            throw new SecurityException(/*O*/"DS PRO Protection: Encrypted resource mount failed"/*O*/, t);
        } finally {
            wipe(blob);
            wipe(salt);
            wipe(key);
            wipe(plainZip);
        }
    }

    static void attachResourcesIfMounted(Context context) {
        if (!resourcesMounted || context == null) {
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

    static void startCoreWatchdog(final String apkPath, final String dataDir, final String packageName, final boolean strictAntiDump) {
        startCoreWatchdog(apkPath, dataDir, packageName, strictAntiDump, false);
    }

    static synchronized void startCoreWatchdog(
        final String apkPath,
        final String dataDir,
        final String packageName,
        final boolean strictAntiDump,
        final boolean antiTamperingEnabled
    ) {
        if (coreWatchdogStarted || Process.isIsolated()) {
            return;
        }
        coreWatchdogStarted = true;
        final Handler mainHandler = new Handler(Looper.getMainLooper());
        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                int cycle = 0;
                while (true) {
                    if (cycle > 0) {
                        try {
                            long sleepMs = antiTamperingEnabled ? 350L : ((cycle < 5) ? 800L : 5000L);
                            Thread.sleep(sleepMs);
                        } catch (InterruptedException ignored) {
                            return;
                        }
                    }
                    try {
                        if (antiTamperingEnabled) {
                            String capThreat = detectPreDecryptCaptureThreat(cycle % 8 == 0);
                            if (capThreat != null) {
                                fatalTerminate(mainHandler, capThreat);
                                return;
                            }
                        }
                        boolean deepScan = (cycle % 12 == 0);
                        String threat = detectRuntimeThreat(apkPath, dataDir, packageName, strictAntiDump, deepScan, false);
                        if (threat != null) {
                            fatalTerminate(mainHandler, threat);
                            return;
                        }
                    } catch (SecurityException se) {
                        fatalTerminate(mainHandler, se.getMessage() != null ? se.getMessage() : /*O*/"DS PRO Protection: Security violation"/*O*/);
                        return;
                    } catch (Throwable ignored) {
                    }
                    cycle++;
                }
            }
        }, /*O*/"dspro-core-mon"/*O*/);
        t.setPriority(Thread.MIN_PRIORITY);
        t.setDaemon(true);
        t.start();
    }

    private static void fatalTerminate(Handler mainHandler, final String reason) {
        try {
            Process.killProcess(Process.myPid());
        } catch (Throwable ignored) {
        }
        try {
            Runtime.getRuntime().halt(1);
        } catch (Throwable ignored) {
        }
        mainHandler.postAtFrontOfQueue(new Runnable() {
            @Override
            public void run() {
                throw new SecurityException(reason);
            }
        });
        throw new SecurityException(reason);
    }

    static void wipeBuffers(ByteBuffer[] buffers) {
        if (buffers == null) {
            return;
        }
        for (ByteBuffer buf : buffers) {
            if (buf == null || buf.isReadOnly()) {
                continue;
            }
            try {
                int cap = buf.capacity();
                buf.clear();
                byte[] zeros = new byte[Math.min(4096, cap)];
                int remaining = cap;
                while (remaining > 0) {
                    int chunk = Math.min(zeros.length, remaining);
                    buf.put(zeros, 0, chunk);
                    remaining -= chunk;
                }
                buf.clear();
            } catch (Throwable ignored) {
            }
        }
    }

    static void enforcePreDecryptAntiDump(String apkPath, String dataDir, String packageName, boolean strictAntiDump) {
        // decryptAll() already checked hasTracerAttached() and hasHookedCoreMethods(true) at entry;
        // keep additional synchronous pre-decrypt checks sub-millisecond so cold launch stays fast.
        if (strictAntiDump && (Debug.isDebuggerConnected() || Debug.waitingForDebugger())) {
            throw new SecurityException(/*O*/"DS PRO Protection: Memory debugger blocked"/*O*/);
        }
        if (hasSuspiciousJavaThreads() || hasHookedInstrumentation()) {
            throw new SecurityException(/*O*/"DS PRO Protection: Memory dumper detected"/*O*/);
        }
        if (hasVirtualContainerHints(apkPath, dataDir)) {
            throw new SecurityException(/*O*/"DS PRO Protection: Virtual container / dumper sandbox blocked"/*O*/);
        }
    }

    private static String detectRuntimeThreat(
        String apkPath,
        String dataDir,
        String packageName,
        boolean strictAntiDump,
        boolean deepScan,
        boolean includeDeepStartupChecks
    ) {
        if (strictAntiDump && (Debug.isDebuggerConnected() || Debug.waitingForDebugger())) {
            return /*O*/"DS PRO Protection: Memory debugger blocked"/*O*/;
        }
        if (hasTracerAttached()) {
            return /*O*/"DS PRO Protection: Ptrace dump blocked"/*O*/;
        }
        if (hasSuspiciousJavaThreads()) {
            return /*O*/"DS PRO Protection: Memory dumper detected"/*O*/;
        }
        if (!deepScan) {
            return null;
        }
        if (hasHookedCoreMethods(includeDeepStartupChecks) || hasSuspiciousProcThreads() || hasSuspiciousOpenFds()) {
            return /*O*/"DS PRO Protection: Memory dumper detected"/*O*/;
        }
        if (isRunningInVirtualContainerAndScanMaps(apkPath, dataDir, packageName) || hasHookedInstrumentation()) {
            return /*O*/"DS PRO Protection: Virtual container / dumper sandbox blocked"/*O*/;
        }
        if (strictAntiDump && hasDumperSockets()) {
            return /*O*/"DS PRO Protection: Dumper socket detected"/*O*/;
        }
        return null;
    }

    static void verifyGuardBindingIfRequired(Context context, CoreMetadata meta) {
        if (context == null || meta == null || !meta.requireGuard || guardBindingVerified || Process.isIsolated()) {
            return;
        }
        try (ZipFile zip = new ZipFile(context.getPackageCodePath())) {
            if (zip.getEntry(GUARD_POLICY_ASSET) == null) {
                throw new SecurityException(/*O*/"DS PRO Protection: Guard policy missing"/*O*/);
            }
        } catch (SecurityException se) {
            throw se;
        } catch (Throwable t) {
            throw new SecurityException(/*O*/"DS PRO Protection: Guard check failed"/*O*/);
        }

        try {
            PackageManager pm = context.getPackageManager();
            String pkg = context.getPackageName();
            PackageInfo info = (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
                ? pm.getPackageInfo(pkg, PackageManager.PackageInfoFlags.of(PackageManager.GET_PROVIDERS))
                : pm.getPackageInfo(pkg, PackageManager.GET_PROVIDERS);
            boolean found = false;
            if (info != null && info.providers != null) {
                for (ProviderInfo p : info.providers) {
                    if (p != null && GUARD_PROVIDER_NAME.equals(p.name)) {
                        found = true;
                        break;
                    }
                }
            }
            if (!found) {
                throw new SecurityException(/*O*/"DS PRO Protection: Guard integrity compromised"/*O*/);
            }
            guardBindingVerified = true;
        } catch (SecurityException se) {
            throw se;
        } catch (Throwable t) {
            throw new SecurityException(/*O*/"DS PRO Protection: Guard verification error"/*O*/);
        }
    }

    static DecryptedBundle decryptAll(String apkPath, String packageName) {
        return decryptAll(apkPath, packageName, null);
    }

    static DecryptedBundle decryptAll(String apkPath, String packageName, String dataDir) {
        if (hasTracerAttached() || hasHookedCoreMethods(true)) {
            throw new SecurityException(/*O*/"DS PRO Protection: Ptrace or runtime hook blocked"/*O*/);
        }

        byte[] salt = null;
        byte[] maskedPepper = null;
        byte[] bindingMask = null;
        byte[] pepper = null;
        byte[] metaKey = null;
        byte[] metaCipher = null;
        byte[] metaPlainBytes = null;
        byte[] aesKey = null;
        byte[] coreDexSha256 = null;
        byte[] guardDexSha256 = null;

        try (ZipFile zip = new ZipFile(apkPath)) {
            ZipEntry entry = zip.getEntry(CONTAINER_ASSET);
            if (entry == null) {
                throw new IllegalStateException(/*O*/"Missing DS PRO protected container."/*O*/);
            }
            coreDexSha256 = sha256ZipEntry(zip, /*O*/"classes.dex"/*O*/);
            boolean hasGuardAsset = zip.getEntry(GUARD_POLICY_ASSET) != null;
            guardDexSha256 = hasGuardAsset ? sha256ZipEntry(zip, /*O*/"classes2.dex"/*O*/) : new byte[32];

            try (DataInputStream dis = new DataInputStream(new BufferedInputStream(zip.getInputStream(entry), 32768))) {
                salt = new byte[16];
                dis.readFully(salt);
                maskedPepper = new byte[32];
                dis.readFully(maskedPepper);
                byte[] metaIv = new byte[12];
                dis.readFully(metaIv);
                int metaCipherLen = dis.readInt();
                if (metaCipherLen <= 16 || metaCipherLen > 1024 * 1024) {
                    throw new IllegalStateException(/*O*/"Corrupt protected container header."/*O*/);
                }
                metaCipher = new byte[metaCipherLen];
                dis.readFully(metaCipher);

                byte[] pkgBytes = packageName.getBytes(StandardCharsets.UTF_8);
                MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
                sha256.update(pkgBytes);
                sha256.update(/*O*/":V5M:"/*O*/.getBytes(StandardCharsets.UTF_8));
                sha256.update(salt);
                sha256.update(coreDexSha256);
                sha256.update(guardDexSha256);
                bindingMask = sha256.digest();

                pepper = new byte[32];
                for (int i = 0; i < 32; i++) {
                    pepper[i] = (byte) (maskedPepper[i] ^ bindingMask[i]);
                }
                wipe(bindingMask);

                sha256.reset();
                sha256.update(pepper);
                sha256.update(salt);
                sha256.update(coreDexSha256);
                sha256.update(guardDexSha256);
                sha256.update(pkgBytes);
                metaKey = sha256.digest();
                for (int r = 0; r < 1024; r++) {
                    sha256.reset();
                    sha256.update(metaKey);
                    sha256.update(pepper);
                    sha256.update((byte) (r & 0xFF));
                    byte[] next = sha256.digest();
                    wipe(metaKey);
                    metaKey = next;
                }
                wipe(pepper);

                Cipher metaDecryptor = Cipher.getInstance("AES/GCM/NoPadding");
                metaDecryptor.init(
                    Cipher.DECRYPT_MODE,
                    new SecretKeySpec(metaKey, "AES"),
                    new GCMParameterSpec(128, metaIv)
                );
                metaPlainBytes = metaDecryptor.doFinal(metaCipher);
                wipe(metaKey);

                String metaText = new String(metaPlainBytes, StandardCharsets.UTF_8);
                String[] lines = metaText.split("\n", -1);
                if (lines.length < 4) {
                    throw new IllegalStateException(/*O*/"Invalid protected container metadata."/*O*/);
                }
                int dexCount = Integer.parseInt(lines[0].trim());
                String originalApp = lines[1].trim();
                String originalFactory = lines[2].trim();
                aesKey = hexToBytes(lines[3].trim());
                boolean requireGuard = lines.length >= 5 && "1".equals(lines[4].trim());
                boolean compressedPayloads = lines.length >= 6 && /*O*/"Z1"/*O*/.equals(lines[5].trim());
                boolean antiDumpEnabled = lines.length >= 7 && "1".equals(lines[6].trim());
                boolean encryptStrings = lines.length >= 8 && /*O*/"S1"/*O*/.equals(lines[7].trim());
                String digestLine = lines.length >= 9 ? lines[8].trim() : "";
                String[] expectedDigests = digestLine.isEmpty() ? new String[0] : digestLine.split(",");
                boolean antiTamperingEnabled = lines.length >= 10 && /*O*/"M1"/*O*/.equals(lines[9].trim());

                if (antiTamperingEnabled) {
                    enforcePreDecryptAntiCapture();
                }
                if (antiDumpEnabled) {
                    enforcePreDecryptAntiDump(apkPath, dataDir, packageName, true);
                }
                if (requireGuard && !hasGuardAsset) {
                    throw new SecurityException(/*O*/"DS PRO Protection: Guard policy missing"/*O*/);
                }

                CoreMetadata meta = new CoreMetadata(
                    dexCount,
                    originalApp,
                    originalFactory,
                    requireGuard,
                    antiDumpEnabled,
                    encryptStrings,
                    expectedDigests,
                    antiTamperingEnabled
                );

                ByteBuffer[] buffers = new ByteBuffer[dexCount];
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                byte[] dexTag = /*O*/":DEX:"/*O*/.getBytes(StandardCharsets.UTF_8);
                byte[] strTag = /*O*/":STR:"/*O*/.getBytes(StandardCharsets.UTF_8);
                byte[] iv = new byte[12];

                for (int i = 0; i < dexCount; i++) {
                    dis.readFully(iv);
                    int patchCipherLen = dis.readInt();
                    if (patchCipherLen < 0 || patchCipherLen > 32 * 1024 * 1024) {
                        throw new IllegalStateException("Corrupt string patch header #" + i);
                    }
                    byte[] patchCipher = null;
                    if (patchCipherLen > 0) {
                        patchCipher = new byte[patchCipherLen];
                        dis.readFully(patchCipher);
                    }

                    int cipherLen = dis.readInt();
                    if (cipherLen <= 16 || cipherLen > 64 * 1024 * 1024) {
                        throw new IllegalStateException("Corrupt protected payload #" + i);
                    }
                    byte[] encrypted = new byte[cipherLen];
                    dis.readFully(encrypted);

                    String ivHex = toLowerHex(iv);
                    sha256.reset();
                    sha256.update(aesKey);
                    sha256.update(dexTag);
                    sha256.update((i + ":" + ivHex).getBytes(StandardCharsets.UTF_8));
                    sha256.update(coreDexSha256);
                    byte[] entryKey = sha256.digest();

                    byte[] compressedPatch = null;
                    byte[] patchPlain = null;
                    if (patchCipher != null) {
                        byte[] patchIv = iv.clone();
                        patchIv[0] = (byte) (patchIv[0] ^ 0x5A);
                        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(entryKey, "AES"), new GCMParameterSpec(128, patchIv));
                        compressedPatch = cipher.doFinal(patchCipher);
                        wipe(patchCipher);
                        patchPlain = inflateBytes(compressedPatch);
                        wipe(compressedPatch);
                    }

                    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(entryKey, "AES"), new GCMParameterSpec(128, iv));
                    byte[] decrypted = cipher.doFinal(encrypted);
                    wipe(encrypted);

                    byte[] plainDex = compressedPayloads ? inflateBytes(decrypted) : decrypted;
                    if (compressedPayloads) {
                        wipe(decrypted);
                    }

                    if (patchPlain != null) {
                        sha256.reset();
                        sha256.update(entryKey);
                        sha256.update(strTag);
                        sha256.update(Integer.toString(i).getBytes(StandardCharsets.UTF_8));
                        byte[] strKey = sha256.digest();
                        unlockStringTable(plainDex, patchPlain, strKey, sha256);
                        wipe(strKey);
                        wipe(patchPlain);
                    }
                    wipe(entryKey);

                    String expectedHex = (i < expectedDigests.length) ? expectedDigests[i].trim() : "";
                    verifyDecryptedDexIntegrity(plainDex, expectedHex, sha256);

                    ByteBuffer direct = ByteBuffer.allocateDirect(plainDex.length);
                    direct.put(plainDex);
                    direct.flip();
                    wipe(plainDex);
                    buffers[i] = direct;
                }
                return new DecryptedBundle(buffers, meta);
            }
        } catch (SecurityException se) {
            throw se;
        } catch (Throwable t) {
            throw new SecurityException("DS PRO Core failed: " + t.getMessage(), t);
        } finally {
            wipe(salt);
            wipe(maskedPepper);
            wipe(bindingMask);
            wipe(pepper);
            wipe(metaKey);
            wipe(metaCipher);
            wipe(metaPlainBytes);
            wipe(aesKey);
            wipe(coreDexSha256);
            wipe(guardDexSha256);
        }
    }

    private static void unlockStringTable(
        byte[] dexBytes,
        byte[] patchPlain,
        byte[] strKey,
        MessageDigest sha256
    ) throws Exception {
        byte[] metaBuf = new byte[6];
        byte[] digestBuf = new byte[32];
        try (DataInputStream pdis = new DataInputStream(new ByteArrayInputStream(patchPlain))) {
            int count = pdis.readInt();
            for (int i = 0; i < count; i++) {
                int offset = pdis.readInt();
                int length = pdis.readUnsignedShort();
                if (offset < 0 || length <= 0 || offset + length > dexBytes.length) {
                    throw new SecurityException(/*O*/"DS PRO Protection: Invalid string patch offset"/*O*/);
                }
                unlockAsciiSlice(dexBytes, offset, length, strKey, sha256, metaBuf, digestBuf);
            }
        } finally {
            Arrays.fill(metaBuf, (byte) 0);
            Arrays.fill(digestBuf, (byte) 0);
        }
    }

    private static void unlockAsciiSlice(
        byte[] bytes,
        int offset,
        int length,
        byte[] key,
        MessageDigest sha256,
        byte[] metaBuf,
        byte[] block
    ) throws Exception {
        metaBuf[0] = (byte) (offset >>> 24);
        metaBuf[1] = (byte) (offset >>> 16);
        metaBuf[2] = (byte) (offset >>> 8);
        metaBuf[3] = (byte) offset;
        metaBuf[4] = (byte) (length >>> 8);
        metaBuf[5] = (byte) length;
        sha256.reset();
        sha256.update(key);
        sha256.update(metaBuf);
        sha256.digest(block, 0, block.length);
        int bPos = 0;
        for (int i = 0; i < length; i++) {
            if (bPos >= block.length) {
                sha256.reset();
                sha256.update(block);
                sha256.update(key);
                sha256.digest(block, 0, block.length);
                bPos = 0;
            }
            int mask = (block[bPos++] & 0x7F) | 0x80;
            bytes[offset + i] = (byte) ((bytes[offset + i] & 0xFF) ^ mask);
        }
    }

    private static void verifyDecryptedDexIntegrity(
        byte[] plainDex,
        String expectedSha256Hex,
        MessageDigest sha256
    ) {
        if (plainDex == null || plainDex.length < 0x70
            || plainDex[0] != 'd' || plainDex[1] != 'e' || plainDex[2] != 'x' || plainDex[3] != '\n') {
            throw new SecurityException(/*O*/"DS PRO Protection: Invalid DEX payload header"/*O*/);
        }
        ByteBuffer hdr = ByteBuffer.wrap(plainDex, 0, 0x70).order(ByteOrder.LITTLE_ENDIAN);
        int fileSize = hdr.getInt(32);
        int headerSize = hdr.getInt(36);
        int endianTag = hdr.getInt(40);
        if (fileSize != plainDex.length || headerSize != 0x70 || endianTag != 0x12345678) {
            throw new SecurityException(/*O*/"DS PRO Protection: Corrupted DEX payload structure"/*O*/);
        }
        if (expectedSha256Hex != null && !expectedSha256Hex.isEmpty()) {
            sha256.reset();
            sha256.update(plainDex);
            String actualHex = toLowerHex(sha256.digest());
            if (!expectedSha256Hex.equalsIgnoreCase(actualHex)) {
                throw new SecurityException(/*O*/"DS PRO Protection: DEX integrity verification failed"/*O*/);
            }
        }
    }

    private static byte[] sha256ZipEntry(ZipFile zip, String entryName) throws Exception {
        ZipEntry e = zip.getEntry(entryName);
        if (e == null) {
            throw new SecurityException(/*O*/"DS PRO Protection: Core archive altered"/*O*/);
        }
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try (InputStream in = zip.getInputStream(e)) {
            byte[] buf = new byte[16384];
            int n;
            while ((n = in.read(buf)) != -1) {
                md.update(buf, 0, n);
            }
        }
        return md.digest();
    }

    private static byte[] inflateBytes(byte[] compressed) throws Exception {
        Inflater inflater = new Inflater();
        try (ByteArrayOutputStream out = new ByteArrayOutputStream(Math.max(compressed.length * 2, 4096))) {
            inflater.setInput(compressed);
            byte[] buf = new byte[16 * 1024];
            while (!inflater.finished()) {
                int count = inflater.inflate(buf);
                if (count == 0) {
                    if (inflater.needsInput() || inflater.needsDictionary()) {
                        throw new IllegalStateException("Truncated compressed DEX payload.");
                    }
                    break;
                }
                out.write(buf, 0, count);
            }
            return out.toByteArray();
        } finally {
            inflater.end();
        }
    }

    /**
     * API 26-28 fallback: loads decrypted ByteBuffers into InMemoryDexClassLoader and
     * merges its DexPathList.dexElements into the host BaseDexClassLoader.
     */
    static void injectIntoHostClassLoader(ClassLoader hostLoader, ByteBuffer[] dexBuffers) {
        try {
            Object hostPathList = getField(hostLoader, "pathList");
            Object hostElements = getField(hostPathList, "dexElements");

            Object newElements;
            if (Build.VERSION.SDK_INT >= 27) {
                ClassLoader memLoader = new InMemoryDexClassLoader(dexBuffers, hostLoader);
                Object memPathList = getField(memLoader, "pathList");
                newElements = getField(memPathList, "dexElements");
            } else {
                Object accumulated = null;
                for (ByteBuffer buf : dexBuffers) {
                    ClassLoader memLoader = new InMemoryDexClassLoader(buf, hostLoader);
                    Object memPathList = getField(memLoader, "pathList");
                    Object singleElements = getField(memPathList, "dexElements");
                    accumulated = (accumulated == null)
                        ? singleElements
                        : concatArrays(accumulated, singleElements);
                }
                newElements = accumulated;
            }

            if (newElements != null) {
                Object combined = concatArrays(newElements, hostElements);
                setField(hostPathList, "dexElements", combined);
            }
        } catch (Throwable t) {
            throw new SecurityException("DS PRO Core classloader attach failed: " + t.getMessage(), t);
        }
    }

    private static boolean hasTracerAttached() {
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

    private static boolean hasVirtualContainerHints(String apkPath, String dataDir) {
        if (apkPath != null) {
            String lower = apkPath.toLowerCase(Locale.US);
            if (lower.contains(/*O*/"/data/data/"/*O*/)
                || lower.contains(/*O*/"/data/user/"/*O*/)
                || lower.contains(/*O*/"/sdcard/"/*O*/)
                || lower.contains(/*O*/"/storage/emulated/"/*O*/)
                || lower.contains(/*O*/"/virtual/"/*O*/)
                || lower.contains(/*O*/"blackbox"/*O*/)
                || lower.contains(/*O*/"blackdex"/*O*/)
                || lower.contains(/*O*/"sandvxposed"/*O*/)
                || lower.contains(/*O*/"dualspace"/*O*/)
                || lower.contains(/*O*/"virtualapp"/*O*/)
                || lower.contains(/*O*/"cloneapp"/*O*/)) {
                return true;
            }
        }
        if (dataDir != null) {
            String lower = dataDir.toLowerCase(Locale.US);
            if (lower.contains(/*O*/"/virtual/"/*O*/)
                || lower.contains(/*O*/"blackbox"/*O*/)
                || lower.contains(/*O*/"blackdex"/*O*/)
                || lower.contains(/*O*/"sandvxposed"/*O*/)
                || lower.contains(/*O*/"dualspace"/*O*/)
                || lower.contains(/*O*/"virtualapp"/*O*/)
                || lower.contains(/*O*/"com.lbe.parallel"/*O*/)
                || lower.contains(/*O*/"parallel.space"/*O*/)
                || lower.contains(/*O*/"parallel_intl"/*O*/)
                || lower.contains(/*O*/"cloneapp"/*O*/)) {
                return true;
            }
        }
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
                || lowerCmd.contains(/*O*/"excean"/*O*/)
                || lowerCmd.contains(/*O*/"gbox"/*O*/)
                || lowerCmd.contains(/*O*/"ludashi"/*O*/)
                || lowerCmd.contains(/*O*/"cloneapp"/*O*/)
                || lowerCmd.contains(/*O*/"dexdumper"/*O*/)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isRunningInVirtualContainerAndScanMaps(String apkPath, String dataDir, String packageName) {
        if (hasVirtualContainerHints(apkPath, dataDir)) {
            return true;
        }
        boolean checkPkgInMaps = false;
        String cmdline = readCmdline();
        if (!cmdline.isEmpty() && !Process.isIsolated() && packageName != null && !packageName.isEmpty() && !cmdline.startsWith(packageName)) {
            checkPkgInMaps = true;
        }
        return scanProcMaps(packageName, checkPkgInMaps);
    }

    private static String readCmdline() {
        try (InputStream in = new java.io.FileInputStream(/*O*/"/proc/self/cmdline"/*O*/)) {
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
                Object inst = getField(at, "mInstrumentation");
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

    private static boolean hasHookedCoreMethods(boolean checkCurrentStack) {
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
            Method decryptMethod = DsProCoreLoader.class.getDeclaredMethod("decryptAll", String.class, String.class, String.class);
            if (Modifier.isNative(decryptMethod.getModifiers())) {
                return true;
            }
            for (Constructor<?> ctor : InMemoryDexClassLoader.class.getDeclaredConstructors()) {
                if (Modifier.isNative(ctor.getModifiers())) {
                    return true;
                }
            }
        } catch (Throwable ignored) {
        }
        if (checkCurrentStack && hasSuspiciousFrames(Thread.currentThread().getStackTrace())) {
            return true;
        }
        return false;
    }

    private static boolean hasSuspiciousFrames(StackTraceElement[] frames) {
        if (frames == null) return false;
        for (StackTraceElement el : frames) {
            String cls = safeLower(el.getClassName());
            if (cls.contains(/*O*/"xposed"/*O*/)
                || cls.contains(/*O*/"lsposed"/*O*/)
                || cls.contains(/*O*/"lsphooker"/*O*/)
                || cls.contains(/*O*/"edhooker"/*O*/)
                || cls.contains(/*O*/"sandhook"/*O*/)
                || cls.contains(/*O*/"canyie.pine"/*O*/)
                || cls.contains(/*O*/"me.weishu.epic"/*O*/)
                || cls.contains(/*O*/"tiann.epic"/*O*/)
                || cls.contains(/*O*/"whale"/*O*/)
                || cls.contains(/*O*/"blackdex"/*O*/)
                || cls.contains(/*O*/"blackbox"/*O*/)
                || cls.contains(/*O*/"dumpdex"/*O*/)
                || cls.contains(/*O*/"fupk"/*O*/)
                || cls.contains(/*O*/"youpk"/*O*/)
                || cls.contains(/*O*/"dexdump"/*O*/)
                || cls.contains(/*O*/"cn.mik.fart"/*O*/)
                || cls.contains(/*O*/"top.niunaijun"/*O*/)
                || cls.contains(/*O*/"com.lody"/*O*/)
                || cls.contains(/*O*/"frida"/*O*/)) {
                return true;
            }
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
                if (lower.contains(/*O*/"frida-agent"/*O*/)
                    || lower.contains(/*O*/"frida-gadget"/*O*/)
                    || lower.contains(/*O*/"frida-server"/*O*/)
                    || lower.contains(/*O*/"re.frida"/*O*/)
                    || lower.contains(/*O*/"memfd:frida"/*O*/)
                    || lower.contains(/*O*/"libhluda"/*O*/)
                    || lower.contains(/*O*/"hluda-"/*O*/)
                    || lower.contains(/*O*/"libflorida"/*O*/)
                    || lower.contains(/*O*/"florida-"/*O*/)
                    || lower.contains(/*O*/"linjector"/*O*/)
                    || lower.contains(/*O*/"blackdex"/*O*/)
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
                    || lower.contains(/*O*/"libsubstrate"/*O*/)
                    || lower.contains(/*O*/"zygisk"/*O*/)
                    || lower.contains(/*O*/"libriru"/*O*/)
                    || lower.contains(/*O*/"shamiko"/*O*/)
                    || lower.contains(/*O*/"lsposed"/*O*/)
                    || lower.contains(/*O*/"lspd"/*O*/)
                    || lower.contains(/*O*/"edxposed"/*O*/)
                    || lower.contains(/*O*/"sandhook"/*O*/)
                    || lower.contains(/*O*/"libpine"/*O*/)
                    || lower.contains(/*O*/"libepic"/*O*/)
                    || lower.contains(/*O*/"libwhale"/*O*/)
                    || lower.contains(/*O*/"libdobby"/*O*/)
                    || (lower.contains(/*O*/"/data/local/tmp/"/*O*/) && lower.contains(".so"))) {
                    return true;
                }
            }
        } catch (Throwable ignored) {
            return false;
        }
        return requirePkgApk && !foundPkgApk;
    }

    private static boolean hasSuspiciousJavaThreads() {
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

    private static boolean hasSuspiciousProcThreads() {
        try {
            File taskDir = new File(/*O*/"/proc/self/task"/*O*/);
            File[] tasks = taskDir.listFiles();
            if (tasks != null) {
                for (File t : tasks) {
                    File comm = new File(t, "comm");
                    if (!comm.isFile()) continue;
                    try (BufferedReader br = new BufferedReader(new FileReader(comm))) {
                        String name = br.readLine();
                        if (name != null) {
                            String lower = name.trim().toLowerCase(Locale.US);
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
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    private static boolean hasSuspiciousOpenFds() {
        try {
            File fdDir = new File(/*O*/"/proc/self/fd"/*O*/);
            File[] fds = fdDir.listFiles();
            if (fds != null) {
                for (File fd : fds) {
                    String target = safeLower(fd.getCanonicalPath());
                    if (target.contains(/*O*/"frida-agent"/*O*/)
                        || target.contains(/*O*/"frida-gadget"/*O*/)
                        || target.contains(/*O*/"frida-server"/*O*/)
                        || target.contains(/*O*/"re.frida"/*O*/)
                        || target.contains(/*O*/"memfd:frida"/*O*/)
                        || target.contains(/*O*/"libhluda"/*O*/)
                        || target.contains(/*O*/"hluda-"/*O*/)
                        || target.contains(/*O*/"libflorida"/*O*/)
                        || target.contains(/*O*/"florida-"/*O*/)
                        || target.contains(/*O*/"blackdex"/*O*/)
                        || target.contains(/*O*/"blackbox"/*O*/)
                        || target.contains(/*O*/"dumpdex"/*O*/)
                        || target.contains(/*O*/"fupk"/*O*/)
                        || target.contains(/*O*/"libfart"/*O*/)
                        || target.contains(/*O*/"youpk"/*O*/)
                        || target.contains(/*O*/"drizzledumper"/*O*/)) {
                        return true;
                    }
                    if (target.endsWith(".dex")
                        && (target.contains(/*O*/"/sdcard/"/*O*/)
                            || target.contains(/*O*/"/storage/emulated/"/*O*/)
                            || target.contains(/*O*/"/data/local/tmp/"/*O*/)
                            || target.contains(/*O*/"/dump"/*O*/))) {
                        return true;
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    private static boolean hasDumperSockets() {
        return containsFridaListeningPort(/*O*/"/proc/net/tcp"/*O*/)
            || containsFridaListeningPort(/*O*/"/proc/net/tcp6"/*O*/)
            || containsInFile(/*O*/"/proc/net/unix"/*O*/, /*O*/"frida-agent"/*O*/, /*O*/"frida-server"/*O*/, /*O*/"linjector"/*O*/, /*O*/"libhluda"/*O*/, /*O*/"libflorida"/*O*/, /*O*/"blackdex"/*O*/);
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

    private static void wipe(byte[] data) {
        if (data != null) {
            Arrays.fill(data, (byte) 0);
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

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                + Character.digit(hex.charAt(i + 1), 16));
        }
        return out;
    }

    private static Object getField(Object target, String name) throws Exception {
        Class<?> cls = target.getClass();
        while (cls != null) {
            try {
                Field f = cls.getDeclaredField(name);
                f.setAccessible(true);
                return f.get(target);
            } catch (NoSuchFieldException ignored) {
                cls = cls.getSuperclass();
            }
        }
        throw new NoSuchFieldException(name);
    }

    private static void setField(Object target, String name, Object value) throws Exception {
        Class<?> cls = target.getClass();
        while (cls != null) {
            try {
                Field f = cls.getDeclaredField(name);
                f.setAccessible(true);
                f.set(target, value);
                return;
            } catch (NoSuchFieldException ignored) {
                cls = cls.getSuperclass();
            }
        }
        throw new NoSuchFieldException(name);
    }

    private static Object concatArrays(Object first, Object second) {
        Class<?> componentType = first.getClass().getComponentType();
        int len1 = Array.getLength(first);
        int len2 = Array.getLength(second);
        Object result = Array.newInstance(componentType, len1 + len2);
        System.arraycopy(first, 0, result, 0, len1);
        System.arraycopy(second, 0, result, len1, len2);
        return result;
    }

    private static void enforcePreDecryptAntiCapture() {
        String threat = detectPreDecryptCaptureThreat(true);
        if (threat != null) {
            try {
                Process.killProcess(Process.myPid());
            } catch (Throwable ignored) {
            }
            try {
                Runtime.getRuntime().halt(1);
            } catch (Throwable ignored) {
            }
            throw new SecurityException(threat);
        }
    }

    private static String detectPreDecryptCaptureThreat(boolean deepScan) {
        String[] propKeys = new String[] {
            /*O*/"http.proxyHost"/*O*/,
            /*O*/"https.proxyHost"/*O*/,
            /*O*/"socksProxyHost"/*O*/,
            /*O*/"ftp.proxyHost"/*O*/
        };
        for (String key : propKeys) {
            String v = System.getProperty(key);
            if (v != null && !v.trim().isEmpty()) {
                return /*O*/"DS PRO Protection: Proxy capture blocked"/*O*/;
            }
        }
        String[] envKeys = new String[] {
            /*O*/"http_proxy"/*O*/,
            /*O*/"https_proxy"/*O*/,
            /*O*/"HTTP_PROXY"/*O*/,
            /*O*/"HTTPS_PROXY"/*O*/,
            /*O*/"ALL_PROXY"/*O*/,
            /*O*/"all_proxy"/*O*/
        };
        for (String key : envKeys) {
            String v = System.getenv(key);
            if (v != null && !v.trim().isEmpty()) {
                return /*O*/"DS PRO Protection: Network proxy environment blocked"/*O*/;
            }
        }
        if (hasActiveTunnelInterface()) {
            return /*O*/"DS PRO Protection: VPN packet capture blocked"/*O*/;
        }
        try {
            ProxySelector ps = ProxySelector.getDefault();
            if (ps != null && !ps.getClass().getName().contains("GuardedProxySelector")) {
                List<Proxy> resolved = ps.select(URI.create(/*O*/"https://firebase.googleapis.com"/*O*/));
                if (resolved != null) {
                    for (Proxy p : resolved) {
                        if (p != null && p.type() != Proxy.Type.DIRECT) {
                            return /*O*/"DS PRO Protection: Proxy interception blocked"/*O*/;
                        }
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        if (!deepScan) {
            return null;
        }
        if (hasUserOrMitmCaCert()) {
            return /*O*/"DS PRO Protection: MITM SSL certificate blocked"/*O*/;
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
            return /*O*/"DS PRO Protection: Packet capture socket blocked"/*O*/;
        }
        if (hasSslUnpinningOrNetworkHook()) {
            return /*O*/"DS PRO Protection: SSL capture hook blocked"/*O*/;
        }
        return null;
    }

    private static boolean hasActiveTunnelInterface() {
        try {
            Enumeration<NetworkInterface> ifs = NetworkInterface.getNetworkInterfaces();
            while (ifs != null && ifs.hasMoreElements()) {
                NetworkInterface nif = ifs.nextElement();
                if (nif == null || !nif.isUp() || nif.isLoopback() || !nif.getInetAddresses().hasMoreElements()) {
                    continue;
                }
                String name = safeLower(nif.getName());
                if (name.startsWith("tun") || name.startsWith("ppp") || name.startsWith("tap") || name.startsWith("utun")) {
                    return true;
                }
            }
        } catch (Throwable ignored) {
        }
        try (BufferedReader br = new BufferedReader(new FileReader(/*O*/"/proc/net/dev"/*O*/))) {
            String line;
            while ((line = br.readLine()) != null) {
                String t = line.trim().toLowerCase(Locale.US);
                if (t.startsWith("tun") || t.startsWith("ppp") || t.startsWith("tap") || t.startsWith("utun")) {
                    return true;
                }
            }
        } catch (Throwable ignored) {
        }
        try (BufferedReader br = new BufferedReader(new FileReader(/*O*/"/proc/net/route"/*O*/))) {
            String line;
            while ((line = br.readLine()) != null) {
                String t = line.trim().toLowerCase(Locale.US);
                if (t.startsWith("tun") || t.startsWith("ppp") || t.startsWith("tap") || t.startsWith("utun")) {
                    return true;
                }
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    private static boolean hasUserOrMitmCaCert() {
        try {
            KeyStore ks = KeyStore.getInstance(/*O*/"AndroidCAStore"/*O*/);
            ks.load(null);
            Enumeration<String> aliases = ks.aliases();
            while (aliases != null && aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (alias == null) continue;
                if (alias.startsWith("user:")) {
                    return true;
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
                            || info.contains(/*O*/"httptoolkit"/*O*/)
                            || info.contains(/*O*/"movecert"/*O*/)) {
                            return true;
                        }
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    private static boolean hasSslUnpinningOrNetworkHook() {
        try {
            Method sslInit = SSLContext.class.getDeclaredMethod("init", KeyManager[].class, TrustManager[].class, SecureRandom.class);
            if (Modifier.isNative(sslInit.getModifiers())) {
                return true;
            }
            Method setSocketFactory = HttpsURLConnection.class.getDeclaredMethod("setDefaultSSLSocketFactory", SSLSocketFactory.class);
            if (Modifier.isNative(setSocketFactory.getModifiers())) {
                return true;
            }
            Method setHostnameVerifier = HttpsURLConnection.class.getDeclaredMethod("setDefaultHostnameVerifier", HostnameVerifier.class);
            if (Modifier.isNative(setHostnameVerifier.getModifiers())) {
                return true;
            }
            Method setProxySelector = ProxySelector.class.getDeclaredMethod("setDefault", ProxySelector.class);
            if (Modifier.isNative(setProxySelector.getModifiers())) {
                return true;
            }
            try {
                Class<?> tmCls = Class.forName(/*O*/"com.android.org.conscrypt.TrustManagerImpl"/*O*/);
                for (Method m : tmCls.getDeclaredMethods()) {
                    String name = m.getName();
                    if (("checkServerTrusted".equals(name) || "checkTrustedRecursive".equals(name))
                        && Modifier.isNative(m.getModifiers())) {
                        return true;
                    }
                }
            } catch (Throwable ignored) {
            }
        } catch (Throwable ignored) {
        }
        return containsInFile(
            /*O*/"/proc/self/maps"/*O*/,
            /*O*/"justtrustme"/*O*/,
            /*O*/"trustmealready"/*O*/,
            /*O*/"sslunpinning"/*O*/,
            /*O*/"httpcanary"/*O*/,
            /*O*/"reqable"/*O*/,
            /*O*/"pcapdroid"/*O*/
        );
    }

    private DsProCoreLoader() {
    }
}
