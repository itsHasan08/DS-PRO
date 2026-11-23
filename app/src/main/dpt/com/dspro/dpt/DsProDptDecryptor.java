package com.dspro.dpt;

import android.app.AppComponentFactory;
import android.os.Build;
import dalvik.system.InMemoryDexClassLoader;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Decrypts AES-256-GCM encrypted DEX payloads purely in memory (zero plaintext DEX on disk).
 */
final class DsProDptDecryptor {

    static final String INDEX_ASSET = "assets/ds_pro_dpt.idx";
    private static final String PAYLOAD_PREFIX = "assets/ds_pro_dpt_";

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
    private static volatile DptMetadata cachedMetadata = null;
    private static volatile ClassLoader activeClassLoader = null;
    private static volatile AppComponentFactory delegateFactory = null;

    static boolean isInitialized() {
        return initialized;
    }

    static DptMetadata getCachedMetadata() {
        return cachedMetadata;
    }

    static ClassLoader getActiveClassLoader() {
        return activeClassLoader;
    }

    static AppComponentFactory getDelegateFactory() {
        return delegateFactory;
    }

    static synchronized void markInitialized(
        DptMetadata metadata,
        ClassLoader loader,
        AppComponentFactory factory
    ) {
        cachedMetadata = metadata;
        activeClassLoader = loader;
        delegateFactory = factory;
        initialized = true;
    }

    static DecryptedBundle decryptAll(String apkPath, String packageName) {
        try (ZipFile zip = new ZipFile(apkPath)) {
            DptMetadata meta = readMetadata(zip, packageName);
            ByteBuffer[] buffers = new ByteBuffer[meta.dexCount];
            SecretKeySpec keySpec = new SecretKeySpec(meta.aesKey, "AES");

            for (int i = 0; i < meta.dexCount; i++) {
                ZipEntry entry = zip.getEntry(PAYLOAD_PREFIX + i + ".bin");
                if (entry == null) {
                    throw new IllegalStateException("Missing encrypted DEX payload #" + i);
                }
                byte[] encrypted = readAllBytes(zip.getInputStream(entry));
                if (encrypted.length <= 12) {
                    throw new IllegalStateException("Corrupt encrypted DEX payload #" + i);
                }
                byte[] iv = new byte[12];
                System.arraycopy(encrypted, 0, iv, 0, 12);

                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE, keySpec, new GCMParameterSpec(128, iv));
                byte[] plainDex = cipher.doFinal(encrypted, 12, encrypted.length - 12);
                buffers[i] = ByteBuffer.wrap(plainDex);
            }
            return new DecryptedBundle(buffers, meta);
        } catch (Throwable t) {
            throw new SecurityException("DS PRO DPT failed: " + t.getMessage(), t);
        }
    }

    /**
     * API 26-28 fallback: loads decrypted ByteBuffers into an InMemoryDexClassLoader and
     * merges its DexPathList.dexElements into the host BaseDexClassLoader.
     */
    static void injectIntoHostClassLoader(ClassLoader hostLoader, ByteBuffer[] dexBuffers) {
        try {
            ClassLoader memLoader;
            if (Build.VERSION.SDK_INT >= 27) {
                memLoader = new InMemoryDexClassLoader(dexBuffers, hostLoader);
            } else {
                ClassLoader chain = hostLoader;
                for (ByteBuffer buf : dexBuffers) {
                    chain = new InMemoryDexClassLoader(buf, chain);
                }
                memLoader = chain;
            }

            Object hostPathList = getField(hostLoader, "pathList");
            Object hostElements = getField(hostPathList, "dexElements");

            Object memPathList = getField(memLoader, "pathList");
            Object memElements = getField(memPathList, "dexElements");

            Object combined = concatArrays(memElements, hostElements);
            setField(hostPathList, "dexElements", combined);
        } catch (Throwable t) {
            throw new SecurityException("DS PRO DPT classloader attach failed: " + t.getMessage(), t);
        }
    }

    private static DptMetadata readMetadata(ZipFile zip, String packageName) throws Exception {
        ZipEntry idxEntry = zip.getEntry(INDEX_ASSET);
        if (idxEntry == null) {
            throw new IllegalStateException("Missing DPT index metadata.");
        }
        try (BufferedReader reader = new BufferedReader(
            new InputStreamReader(zip.getInputStream(idxEntry), StandardCharsets.UTF_8)
        )) {
            String magic = reader.readLine();
            if (!"DSPRO_DPT_V1".equals(magic)) {
                throw new IllegalStateException("Invalid DPT index format.");
            }
            int dexCount = Integer.parseInt(reader.readLine().trim());
            String originalApp = reader.readLine();
            String originalFactory = reader.readLine();
            String saltHex = reader.readLine().trim();
            String maskedKeyHex = reader.readLine().trim();

            byte[] mask = MessageDigest.getInstance("SHA-256").digest(
                (packageName + ":DSPRO_DPT_V1:" + dexCount + ":" + saltHex).getBytes(StandardCharsets.UTF_8)
            );
            byte[] maskedKey = hexToBytes(maskedKeyHex);
            if (maskedKey.length != mask.length) {
                throw new IllegalStateException("Invalid DPT key length.");
            }
            byte[] aesKey = new byte[maskedKey.length];
            for (int i = 0; i < aesKey.length; i++) {
                aesKey[i] = (byte) (maskedKey[i] ^ mask[i]);
            }
            return new DptMetadata(
                dexCount,
                originalApp == null ? "" : originalApp.trim(),
                originalFactory == null ? "" : originalFactory.trim(),
                aesKey
            );
        }
    }

    private static byte[] readAllBytes(InputStream in) throws Exception {
        try (InputStream stream = in) {
            ByteArrayOutputStream out = new ByteArrayOutputStream(65536);
            byte[] buf = new byte[16384];
            int n;
            while ((n = stream.read(buf)) != -1) {
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        }
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
