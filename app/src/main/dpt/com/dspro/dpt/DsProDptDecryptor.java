package com.dspro.dpt;

import android.os.Build;
import dalvik.system.InMemoryDexClassLoader;
import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Decrypts unified AES-256-GCM encrypted DEX container purely in memory (zero plaintext DEX on disk).
 */
final class DsProDptDecryptor {

    static final class DptMetadata {
        final int dexCount;
        final String originalAppClass;
        final String originalFactoryClass;
        final byte[] aesKey;

        DptMetadata(int dexCount, String originalAppClass, String originalFactoryClass, byte[] aesKey) {
            this.dexCount = dexCount;
            this.originalAppClass = originalAppClass;
            this.originalFactoryClass = originalFactoryClass;
            this.aesKey = aesKey;
        }
    }

    static final class DecryptedBundle {
        final ByteBuffer[] dexBuffers;
        final DptMetadata metadata;

        DecryptedBundle(ByteBuffer[] dexBuffers, DptMetadata metadata) {
            this.dexBuffers = dexBuffers;
            this.metadata = metadata;
        }
    }

    private static volatile boolean initialized = false;
    private static volatile String initializedPackage = "";
    private static volatile DptMetadata cachedMetadata = null;
    private static volatile ClassLoader activeClassLoader = null;
    private static volatile Object delegateFactory = null;

    static boolean isInitialized() {
        return initialized;
    }

    static boolean isInitializedFor(String packageName) {
        return initialized && packageName != null && packageName.equals(initializedPackage);
    }

    static DptMetadata getCachedMetadata() {
        return cachedMetadata;
    }

    static ClassLoader getActiveClassLoader() {
        return activeClassLoader;
    }

    static Object getDelegateFactory() {
        return delegateFactory;
    }

    static synchronized void markInitialized(
        String packageName,
        DptMetadata metadata,
        ClassLoader loader,
        Object factory
    ) {
        initializedPackage = packageName == null ? "" : packageName;
        cachedMetadata = metadata;
        activeClassLoader = loader;
        delegateFactory = factory;
        initialized = true;
    }

    private static final String CONTAINER_ASSET = "assets/dspro_dpt.bin";

    static DecryptedBundle decryptAll(String apkPath, String packageName) {
        try (ZipFile zip = new ZipFile(apkPath)) {
            ZipEntry entry = zip.getEntry(CONTAINER_ASSET);
            if (entry == null) {
                throw new IllegalStateException("Missing encrypted DEX container.");
            }

            try (DataInputStream dis = new DataInputStream(new BufferedInputStream(zip.getInputStream(entry), 32768))) {
                byte[] salt = new byte[16];
                dis.readFully(salt);
                byte[] metaIv = new byte[12];
                dis.readFully(metaIv);
                int metaCipherLen = dis.readInt();
                if (metaCipherLen <= 16 || metaCipherLen > 1024 * 1024) {
                    throw new IllegalStateException("Corrupt encrypted container header.");
                }
                byte[] metaCipher = new byte[metaCipherLen];
                dis.readFully(metaCipher);

                String saltHex = toLowerHex(salt);
                byte[] metaKey = MessageDigest.getInstance("SHA-256").digest(
                    (packageName + ":DSPRO_DPT_META_V2:" + saltHex).getBytes(StandardCharsets.UTF_8)
                );
                Cipher metaDecryptor = Cipher.getInstance("AES/GCM/NoPadding");
                metaDecryptor.init(
                    Cipher.DECRYPT_MODE,
                    new SecretKeySpec(metaKey, "AES"),
                    new GCMParameterSpec(128, metaIv)
                );
                String metaText = new String(metaDecryptor.doFinal(metaCipher), StandardCharsets.UTF_8);
                String[] lines = metaText.split("\n", -1);
                if (lines.length < 4) {
                    throw new IllegalStateException("Invalid encrypted container metadata.");
                }
                int dexCount = Integer.parseInt(lines[0].trim());
                String originalApp = lines[1].trim();
                String originalFactory = lines[2].trim();
                byte[] aesKey = hexToBytes(lines[3].trim());
                DptMetadata meta = new DptMetadata(dexCount, originalApp, originalFactory, aesKey);

                ByteBuffer[] buffers = new ByteBuffer[dexCount];
                SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
                byte[] iv = new byte[12];
                for (int i = 0; i < dexCount; i++) {
                    dis.readFully(iv);
                    int cipherLen = dis.readInt();
                    if (cipherLen <= 16 || cipherLen > 64 * 1024 * 1024) {
                        throw new IllegalStateException("Corrupt encrypted DEX payload #" + i);
                    }
                    byte[] encrypted = new byte[cipherLen];
                    dis.readFully(encrypted);

                    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                    cipher.init(Cipher.DECRYPT_MODE, keySpec, new GCMParameterSpec(128, iv));
                    byte[] plainDex = cipher.doFinal(encrypted);
                    encrypted = null;
                    buffers[i] = ByteBuffer.wrap(plainDex);
                }
                return new DecryptedBundle(buffers, meta);
            }
        } catch (Throwable t) {
            throw new SecurityException("DS PRO DPT failed: " + t.getMessage(), t);
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
            throw new SecurityException("DS PRO DPT classloader attach failed: " + t.getMessage(), t);
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

    private DsProDptDecryptor() {
    }
}
