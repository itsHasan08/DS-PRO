package com.dspro.core;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ProviderInfo;
import android.os.Build;
import android.os.Debug;
import android.os.Process;
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
 * Decrypts unified AES-256-GCM encrypted DEX container purely in memory,
 * verifies guard anti-removal binding, and wipes keys/cipher buffers immediately.
 */
final class DsProCoreLoader {

    static final class CoreMetadata {
        final int dexCount;
        final String originalAppClass;
        final String originalFactoryClass;
        final boolean requireGuard;

        CoreMetadata(
            int dexCount,
            String originalAppClass,
            String originalFactoryClass,
            boolean requireGuard
        ) {
            this.dexCount = dexCount;
            this.originalAppClass = originalAppClass;
            this.originalFactoryClass = originalFactoryClass;
            this.requireGuard = requireGuard;
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
        if (meta != null && meta.requireGuard && !guardProviderInstantiated) {
            throw new SecurityException("DS PRO Protection: Guard integrity compromised");
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

    static void enforcePreDecryptAntiDump() {
        if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) {
            throw new SecurityException("DS PRO Protection: Memory debugger blocked");
        }
        if (hasTracerAttached()) {
            throw new SecurityException("DS PRO Protection: Ptrace dump blocked");
        }
        if (hasDumperInMapsOrThreads()) {
            throw new SecurityException("DS PRO Protection: Memory dumper detected");
        }
    }

    static void verifyGuardBindingIfRequired(Context context, CoreMetadata meta) {
        if (context == null || meta == null || !meta.requireGuard) {
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
        } catch (SecurityException se) {
            throw se;
        } catch (Throwable t) {
            throw new SecurityException("DS PRO Protection: Guard verification error");
        }
    }

    static DecryptedBundle decryptAll(String apkPath, String packageName) {
        enforcePreDecryptAntiDump();

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
                metaKey = MessageDigest.getInstance("SHA-256").digest(
                    (packageName + ":DSPRO_CORE_V3:" + saltHex).getBytes(StandardCharsets.UTF_8)
                );
                Cipher metaDecryptor = Cipher.getInstance("AES/GCM/NoPadding");
                metaDecryptor.init(
                    Cipher.DECRYPT_MODE,
                    new SecretKeySpec(metaKey, "AES"),
                    new GCMParameterSpec(128, metaIv)
                );
                metaPlainBytes = metaDecryptor.doFinal(metaCipher);
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
                if (requireGuard && zip.getEntry(GUARD_POLICY_ASSET) == null) {
                    throw new SecurityException("DS PRO Protection: Guard policy missing");
                }

                CoreMetadata meta = new CoreMetadata(dexCount, originalApp, originalFactory, requireGuard);

                ByteBuffer[] buffers = new ByteBuffer[dexCount];
                SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                byte[] iv = new byte[12];
                for (int i = 0; i < dexCount; i++) {
                    dis.readFully(iv);
                    int cipherLen = dis.readInt();
                    if (cipherLen <= 16 || cipherLen > 64 * 1024 * 1024) {
                        throw new IllegalStateException("Corrupt protected payload #" + i);
                    }
                    byte[] encrypted = new byte[cipherLen];
                    dis.readFully(encrypted);

                    cipher.init(Cipher.DECRYPT_MODE, keySpec, new GCMParameterSpec(128, iv));
                    byte[] decrypted = cipher.doFinal(encrypted);
                    Arrays.fill(encrypted, (byte) 0);
                    byte[] plainDex = compressedPayloads ? inflateBytes(decrypted) : decrypted;
                    if (compressedPayloads) {
                        Arrays.fill(decrypted, (byte) 0);
                    }
                    buffers[i] = ByteBuffer.wrap(plainDex);
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

    private static boolean hasDumperInMapsOrThreads() {
        try (BufferedReader reader = new BufferedReader(new FileReader("/proc/self/maps"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String lower = line.toLowerCase(Locale.US);
                if (lower.contains("frida")
                    || lower.contains("linjector")
                    || lower.contains("blackdex")
                    || lower.contains("dumpdex")
                    || lower.contains("fupk3")
                    || lower.contains("libfart")
                    || lower.contains("youpk")
                    || lower.contains("drizzledumper")
                    || lower.contains("libsubstrate")) {
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
                                || lower.contains("linjector")) {
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
