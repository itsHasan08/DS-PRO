package com.dspro.core;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ProviderInfo;
import android.os.Build;
import android.os.Debug;
import android.os.Process;
import dalvik.system.BaseDexClassLoader;
import dalvik.system.InMemoryDexClassLoader;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileReader;
import java.io.InputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Locale;
import java.util.zip.Inflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Decrypts unified AES-256-GCM encrypted DEX container in direct memory,
 * verifies anti-dump/anti-hook/virtual-container environment before decryption,
 * wipes plaintext DEX buffers immediately after ART ClassLoader loading,
 * and enforces guard anti-removal binding without breaking multi-provider init.
 */
final class DsProCoreLoader {

    static final class CoreMetadata {
        final int dexCount;
        final String originalAppClass;
        final String originalFactoryClass;
        final boolean requireGuard;
        final boolean antiDumpEnabled;

        CoreMetadata(
            int dexCount,
            String originalAppClass,
            String originalFactoryClass,
            boolean requireGuard,
            boolean antiDumpEnabled
        ) {
            this.dexCount = dexCount;
            this.originalAppClass = originalAppClass;
            this.originalFactoryClass = originalFactoryClass;
            this.requireGuard = requireGuard;
            this.antiDumpEnabled = antiDumpEnabled;
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

    private static final String CONTAINER_ASSET = "assets/dspro_core.bin";
    private static final String GUARD_POLICY_ASSET = "assets/dspro_guard.bin";
    private static final String GUARD_PROVIDER_NAME = "com.dspro.guard.DsProGuardProvider";

    private static volatile boolean initialized = false;
    private static volatile String initializedPackage = "";
    private static volatile CoreMetadata cachedMetadata = null;
    private static volatile ClassLoader activeClassLoader = null;
    private static volatile Object delegateFactory = null;
    private static volatile boolean guardProviderInstantiated = false;
    private static volatile boolean guardBindingVerified = false;

    static boolean isInitialized() {
        return initialized;
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
        // Only check once provider registration in loaded ClassLoader is verifiable;
        // avoids false crashes if an early SDK ContentProvider runs before DsProGuardProvider.
        ClassLoader cl = activeClassLoader;
        if (cl != null) {
            try {
                Class.forName(GUARD_PROVIDER_NAME, false, cl);
            } catch (ClassNotFoundException e) {
                throw new SecurityException("DS PRO Protection: Guard integrity compromised");
            }
        }
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

    static void enforcePreDecryptAntiDump(String apkPath, String dataDir, boolean strictAntiDump) {
        if (!strictAntiDump) {
            return;
        }
        if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) {
            throw new SecurityException("DS PRO Protection: Memory debugger blocked");
        }
        if (hasTracerAttached()) {
            throw new SecurityException("DS PRO Protection: Ptrace dump blocked");
        }
        if (isRunningInVirtualContainer(apkPath, dataDir)) {
            throw new SecurityException("DS PRO Protection: Virtual container / dumper sandbox blocked");
        }
        if (hasHookedCoreMethods()) {
            throw new SecurityException("DS PRO Protection: Runtime API hook / dumper blocked");
        }
        if (hasDumperInMapsThreadsOrFd()) {
            throw new SecurityException("DS PRO Protection: Memory dumper detected");
        }
    }

    static void verifyGuardBindingIfRequired(Context context, CoreMetadata meta) {
        if (context == null || meta == null || !meta.requireGuard || guardBindingVerified || Process.isIsolated()) {
            return;
        }
        try (ZipFile zip = new ZipFile(context.getPackageCodePath())) {
            if (zip.getEntry(GUARD_POLICY_ASSET) == null) {
                throw new SecurityException("DS PRO Protection: Guard policy missing");
            }
        } catch (SecurityException se) {
            throw se;
        } catch (Throwable t) {
            throw new SecurityException("DS PRO Protection: Guard check failed");
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
                throw new SecurityException("DS PRO Protection: Guard integrity compromised");
            }
            guardBindingVerified = true;
        } catch (SecurityException se) {
            throw se;
        } catch (Throwable t) {
            throw new SecurityException("DS PRO Protection: Guard verification error");
        }
    }

    static DecryptedBundle decryptAll(String apkPath, String packageName) {
        return decryptAll(apkPath, packageName, null);
    }

    static DecryptedBundle decryptAll(String apkPath, String packageName, String dataDir) {
        byte[] salt = null;
        byte[] metaKey = null;
        byte[] metaCipher = null;
        byte[] metaPlainBytes = null;
        byte[] aesKey = null;

        try (ZipFile zip = new ZipFile(apkPath)) {
            ZipEntry entry = zip.getEntry(CONTAINER_ASSET);
            if (entry == null) {
                throw new IllegalStateException("Missing DS PRO protected container.");
            }

            try (DataInputStream dis = new DataInputStream(new BufferedInputStream(zip.getInputStream(entry), 32768))) {
                salt = new byte[16];
                dis.readFully(salt);
                byte[] metaIv = new byte[12];
                dis.readFully(metaIv);
                int metaCipherLen = dis.readInt();
                if (metaCipherLen <= 16 || metaCipherLen > 1024 * 1024) {
                    throw new IllegalStateException("Corrupt protected container header.");
                }
                metaCipher = new byte[metaCipherLen];
                dis.readFully(metaCipher);

                String saltHex = toLowerHex(salt);
                Cipher metaDecryptor = Cipher.getInstance("AES/GCM/NoPadding");
                boolean isV4 = true;
                try {
                    metaKey = MessageDigest.getInstance("SHA-256").digest(
                        (packageName + ":DSPRO_CORE_V4:" + saltHex).getBytes(StandardCharsets.UTF_8)
                    );
                    metaDecryptor.init(
                        Cipher.DECRYPT_MODE,
                        new SecretKeySpec(metaKey, "AES"),
                        new GCMParameterSpec(128, metaIv)
                    );
                    metaPlainBytes = metaDecryptor.doFinal(metaCipher);
                } catch (Throwable v4Miss) {
                    isV4 = false;
                    wipe(metaKey);
                    metaKey = MessageDigest.getInstance("SHA-256").digest(
                        (packageName + ":DSPRO_CORE_V3:" + saltHex).getBytes(StandardCharsets.UTF_8)
                    );
                    metaDecryptor.init(
                        Cipher.DECRYPT_MODE,
                        new SecretKeySpec(metaKey, "AES"),
                        new GCMParameterSpec(128, metaIv)
                    );
                    metaPlainBytes = metaDecryptor.doFinal(metaCipher);
                }

                String metaText = new String(metaPlainBytes, StandardCharsets.UTF_8);
                String[] lines = metaText.split("\n", -1);
                if (lines.length < 4) {
                    throw new IllegalStateException("Invalid protected container metadata.");
                }
                int dexCount = Integer.parseInt(lines[0].trim());
                String originalApp = lines[1].trim();
                String originalFactory = lines[2].trim();
                aesKey = hexToBytes(lines[3].trim());
                boolean requireGuard = lines.length >= 5 && "1".equals(lines[4].trim());
                boolean compressedPayloads = lines.length >= 6 && "Z1".equals(lines[5].trim());
                boolean antiDumpEnabled = lines.length >= 7 && "1".equals(lines[6].trim());

                enforcePreDecryptAntiDump(apkPath, dataDir, antiDumpEnabled);

                if (requireGuard && zip.getEntry(GUARD_POLICY_ASSET) == null) {
                    throw new SecurityException("DS PRO Protection: Guard policy missing");
                }

                CoreMetadata meta = new CoreMetadata(dexCount, originalApp, originalFactory, requireGuard, antiDumpEnabled);

                ByteBuffer[] buffers = new ByteBuffer[dexCount];
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                MessageDigest sha256 = isV4 ? MessageDigest.getInstance("SHA-256") : null;
                SecretKeySpec v3KeySpec = isV4 ? null : new SecretKeySpec(aesKey, "AES");
                byte[] iv = new byte[12];
                for (int i = 0; i < dexCount; i++) {
                    dis.readFully(iv);
                    int cipherLen = dis.readInt();
                    if (cipherLen <= 16 || cipherLen > 64 * 1024 * 1024) {
                        throw new IllegalStateException("Corrupt protected payload #" + i);
                    }
                    byte[] encrypted = new byte[cipherLen];
                    dis.readFully(encrypted);

                    SecretKeySpec entryKeySpec;
                    byte[] entryKey = null;
                    if (isV4) {
                        String ivHex = toLowerHex(iv);
                        sha256.reset();
                        sha256.update(aesKey);
                        sha256.update((":DEX:" + i + ":" + ivHex).getBytes(StandardCharsets.UTF_8));
                        entryKey = sha256.digest();
                        entryKeySpec = new SecretKeySpec(entryKey, "AES");
                    } else {
                        entryKeySpec = v3KeySpec;
                    }

                    cipher.init(Cipher.DECRYPT_MODE, entryKeySpec, new GCMParameterSpec(128, iv));
                    byte[] decrypted = cipher.doFinal(encrypted);
                    Arrays.fill(encrypted, (byte) 0);
                    wipe(entryKey);

                    byte[] plainDex = compressedPayloads ? inflateBytes(decrypted) : decrypted;
                    if (compressedPayloads) {
                        Arrays.fill(decrypted, (byte) 0);
                    }

                    // Store in DirectByteBuffer and immediately wipe the Java heap byte[] copy.
                    ByteBuffer direct = ByteBuffer.allocateDirect(plainDex.length);
                    direct.put(plainDex);
                    direct.flip();
                    Arrays.fill(plainDex, (byte) 0);
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
            wipe(metaKey);
            wipe(metaCipher);
            wipe(metaPlainBytes);
            wipe(aesKey);
        }
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

    private static boolean isRunningInVirtualContainer(String apkPath, String dataDir) {
        if (apkPath != null) {
            String lower = apkPath.toLowerCase(Locale.US);
            if (lower.contains("/data/data/")
                || lower.contains("/data/user/")
                || lower.contains("/sdcard/")
                || lower.contains("/storage/emulated/")
                || lower.contains("/virtual/")
                || lower.contains("blackbox")
                || lower.contains("blackdex")
                || lower.contains("sandvxposed")) {
                return true;
            }
        }
        if (dataDir != null) {
            String lower = dataDir.toLowerCase(Locale.US);
            if (lower.contains("/virtual/")
                || lower.contains("blackbox")
                || lower.contains("blackdex")
                || lower.contains("sandvxposed")
                || lower.contains("dualspace")) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasHookedCoreMethods() {
        try {
            Method doFinalMethod = Cipher.class.getDeclaredMethod("doFinal", byte[].class);
            if (Modifier.isNative(doFinalMethod.getModifiers())) {
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
        } catch (Throwable ignored) {
        }
        for (StackTraceElement el : Thread.currentThread().getStackTrace()) {
            String cls = safeLower(el.getClassName());
            if (cls.contains("xposed")
                || cls.contains("lsposed")
                || cls.contains("lsphooker")
                || cls.contains("edhooker")
                || cls.contains("sandhook")
                || cls.contains("pine")
                || cls.contains("epic")
                || cls.contains("whale")
                || cls.contains("blackdex")
                || cls.contains("blackbox")
                || cls.contains("dumpdex")
                || cls.contains("fupk")
                || cls.contains("youpk")
                || cls.contains("dexdump")
                || cls.contains("frida")) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasDumperInMapsThreadsOrFd() {
        try (BufferedReader reader = new BufferedReader(new FileReader("/proc/self/maps"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String lower = line.toLowerCase(Locale.US);
                if (lower.contains("frida")
                    || lower.contains("re.frida")
                    || lower.contains("memfd:frida")
                    || lower.contains("linjector")
                    || lower.contains("blackdex")
                    || lower.contains("blackbox")
                    || lower.contains("dumpdex")
                    || lower.contains("fupk3")
                    || lower.contains("libfart")
                    || lower.contains("fart_art")
                    || lower.contains("youpk")
                    || lower.contains("drizzledumper")
                    || lower.contains("libsubstrate")
                    || lower.contains("zygisk")
                    || lower.contains("libriru")
                    || lower.contains("lsposed")
                    || lower.contains("lspd")
                    || lower.contains("edxposed")
                    || lower.contains("sandhook")
                    || lower.contains("libpine")
                    || lower.contains("libepic")
                    || lower.contains("libwhale")
                    || lower.contains("libdobby")) {
                    return true;
                }
            }
        } catch (Throwable ignored) {
        }

        try {
            File taskDir = new File("/proc/self/task");
            File[] tasks = taskDir.listFiles();
            if (tasks != null) {
                for (File t : tasks) {
                    File comm = new File(t, "comm");
                    if (!comm.isFile()) continue;
                    try (BufferedReader br = new BufferedReader(new FileReader(comm))) {
                        String name = br.readLine();
                        if (name != null) {
                            String lower = name.trim().toLowerCase(Locale.US);
                            if (lower.contains("gum-js-loop")
                                || lower.contains("pool-frida")
                                || lower.contains("linjector")
                                || lower.contains("blackdex")
                                || lower.contains("fupk3")) {
                                return true;
                            }
                        }
                    } catch (Throwable ignored) {
                    }
                }
            }
        } catch (Throwable ignored) {
        }

        try {
            File fdDir = new File("/proc/self/fd");
            File[] fds = fdDir.listFiles();
            if (fds != null) {
                for (File fd : fds) {
                    String target = safeLower(fd.getCanonicalPath());
                    if (target.contains("frida")
                        || target.contains("blackdex")
                        || target.contains("dumpdex")
                        || target.contains("fupk")
                        || target.contains("libfart")
                        || target.contains("youpk")) {
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

    private static String toLowerHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format(Locale.US, "%02x", b & 0xFF));
        }
        return sb.toString();
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

    private DsProCoreLoader() {
    }
}
