package com.dspro.dpt;

import android.app.Activity;
import android.app.AppComponentFactory;
import android.app.Application;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.ContentProvider;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.os.Build;
import dalvik.system.InMemoryDexClassLoader;
import java.io.File;

/**
 * DPT AppComponentFactory loaded on API 28+.
 * On API 29+, instantiateClassLoader() decrypts original DEX buffers purely in RAM
 * before any Application, ContentProvider, or Activity is loaded.
 */
public final class DsProAppComponentFactory extends AppComponentFactory {

    @Override
    public ClassLoader instantiateClassLoader(ClassLoader cl, ApplicationInfo aInfo) {
        if (aInfo == null || aInfo.sourceDir == null || aInfo.packageName == null) {
            return super.instantiateClassLoader(cl, aInfo);
        }
        if (!DsProDptDecryptor.isInitialized()) {
            DsProDptDecryptor.DecryptedBundle bundle = DsProDptDecryptor.decryptAll(
                aInfo.sourceDir,
                aInfo.packageName
            );
            String librarySearchPath = buildLibrarySearchPath(aInfo);
            ClassLoader memLoader = new InMemoryDexClassLoader(
                bundle.dexBuffers,
                librarySearchPath,
                cl
            );

            AppComponentFactory origFactory = null;
            if (!bundle.metadata.originalFactoryClass.isEmpty()
                && !DsProAppComponentFactory.class.getName().equals(bundle.metadata.originalFactoryClass)) {
                try {
                    origFactory = (AppComponentFactory) memLoader
                        .loadClass(bundle.metadata.originalFactoryClass)
                        .getDeclaredConstructor()
                        .newInstance();
                } catch (Throwable ignored) {
                }
            }
            ClassLoader finalLoader = memLoader;
            if (origFactory != null && Build.VERSION.SDK_INT >= 29) {
                try {
                    ClassLoader delegated = origFactory.instantiateClassLoader(memLoader, aInfo);
                    if (delegated != null) {
                        finalLoader = delegated;
                    }
                } catch (Throwable ignored) {
                }
            }
            DsProDptDecryptor.markInitialized(aInfo.packageName, bundle.metadata, finalLoader, origFactory);
            return finalLoader;
        }
        if (DsProDptDecryptor.isInitializedFor(aInfo.packageName)) {
            ClassLoader cached = DsProDptDecryptor.getActiveClassLoader();
            if (cached != null) {
                return cached;
            }
        }
        return super.instantiateClassLoader(cl, aInfo);
    }

    private static String buildLibrarySearchPath(ApplicationInfo aInfo) {
        StringBuilder sb = new StringBuilder();
        if (aInfo.nativeLibraryDir != null && !aInfo.nativeLibraryDir.isEmpty()) {
            sb.append(aInfo.nativeLibraryDir);
        }
        if (aInfo.sourceDir != null && !aInfo.sourceDir.isEmpty()) {
            for (String abi : Build.SUPPORTED_ABIS) {
                if (sb.length() > 0) sb.append(File.pathSeparatorChar);
                sb.append(aInfo.sourceDir).append("!/lib/").append(abi);
            }
        }
        if (aInfo.splitSourceDirs != null) {
            for (String splitDir : aInfo.splitSourceDirs) {
                if (splitDir != null && !splitDir.isEmpty()) {
                    for (String abi : Build.SUPPORTED_ABIS) {
                        if (sb.length() > 0) sb.append(File.pathSeparatorChar);
                        sb.append(splitDir).append("!/lib/").append(abi);
                    }
                }
            }
        }
        return sb.toString();
    }

    @Override
    public Application instantiateApplication(ClassLoader cl, String className)
        throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        ClassLoader loader = activeLoader(cl);
        String targetClass = className;
        DsProDptDecryptor.DptMetadata meta = DsProDptDecryptor.getCachedMetadata();
        if (meta != null && DsProShellApplication.class.getName().equals(className)) {
            targetClass = meta.originalAppClass.isEmpty()
                ? Application.class.getName()
                : meta.originalAppClass;
        }
        AppComponentFactory delegate = delegateFactory();
        if (delegate != null) {
            return delegate.instantiateApplication(loader, targetClass);
        }
        return super.instantiateApplication(loader, targetClass);
    }

    @Override
    public Activity instantiateActivity(ClassLoader cl, String className, Intent intent)
        throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        ClassLoader loader = activeLoader(cl);
        AppComponentFactory delegate = delegateFactory();
        if (delegate != null) {
            return delegate.instantiateActivity(loader, className, intent);
        }
        return super.instantiateActivity(loader, className, intent);
    }

    @Override
    public BroadcastReceiver instantiateReceiver(ClassLoader cl, String className, Intent intent)
        throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        ClassLoader loader = activeLoader(cl);
        AppComponentFactory delegate = delegateFactory();
        if (delegate != null) {
            return delegate.instantiateReceiver(loader, className, intent);
        }
        return super.instantiateReceiver(loader, className, intent);
    }

    @Override
    public Service instantiateService(ClassLoader cl, String className, Intent intent)
        throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        ClassLoader loader = activeLoader(cl);
        AppComponentFactory delegate = delegateFactory();
        if (delegate != null) {
            return delegate.instantiateService(loader, className, intent);
        }
        return super.instantiateService(loader, className, intent);
    }

    @Override
    public ContentProvider instantiateProvider(ClassLoader cl, String className)
        throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        ClassLoader loader = activeLoader(cl);
        AppComponentFactory delegate = delegateFactory();
        if (delegate != null) {
            return delegate.instantiateProvider(loader, className);
        }
        return super.instantiateProvider(loader, className);
    }

    private static AppComponentFactory delegateFactory() {
        Object raw = DsProDptDecryptor.getDelegateFactory();
        return (raw instanceof AppComponentFactory) ? (AppComponentFactory) raw : null;
    }

    private static ClassLoader activeLoader(ClassLoader fallback) {
        ClassLoader active = DsProDptDecryptor.getActiveClassLoader();
        return active != null ? active : fallback;
    }
}
