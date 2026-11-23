package com.dspro.dpt;

import android.app.AppComponentFactory;
import android.app.Application;
import android.content.Context;
import android.os.Build;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.List;

/**
 * DPT Shell Application fallback for API 26-28 (before AppComponentFactory.instantiateClassLoader).
 * On API 29+, DsProAppComponentFactory swaps the ClassLoader and instantiates the real Application natively.
 */
public class DsProShellApplication extends Application {

    private Application realApplication;
    private Context attachedBase;

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        this.attachedBase = base;

        if (!DsProDptDecryptor.isInitialized()) {
            DsProDptDecryptor.DecryptedBundle bundle = DsProDptDecryptor.decryptAll(
                base.getPackageCodePath(),
                base.getPackageName()
            );
            DsProDptDecryptor.injectIntoHostClassLoader(base.getClassLoader(), bundle.dexBuffers);

            AppComponentFactory factory = null;
            if (Build.VERSION.SDK_INT >= 28 && !bundle.metadata.originalFactoryClass.isEmpty()
                && !DsProAppComponentFactory.class.getName().equals(bundle.metadata.originalFactoryClass)) {
                try {
                    factory = (AppComponentFactory) base.getClassLoader()
                        .loadClass(bundle.metadata.originalFactoryClass)
                        .getDeclaredConstructor()
                        .newInstance();
                } catch (Throwable ignored) {
                }
            }
            DsProDptDecryptor.markInitialized(bundle.metadata, base.getClassLoader(), factory);
        }

        DsProDptDecryptor.DptMetadata meta = DsProDptDecryptor.getCachedMetadata();
        if (meta != null && !meta.originalAppClass.isEmpty()
            && !DsProShellApplication.class.getName().equals(meta.originalAppClass)) {
            try {
                ClassLoader cl = DsProDptDecryptor.getActiveClassLoader();
                if (cl == null) {
                    cl = base.getClassLoader();
                }
                realApplication = (Application) cl.loadClass(meta.originalAppClass)
                    .getDeclaredConstructor()
                    .newInstance();
                Method attach = Application.class.getDeclaredMethod("attach", Context.class);
                attach.setAccessible(true);
                attach.invoke(realApplication, base);
            } catch (Throwable t) {
                throw new IllegalStateException("Failed to attach original Application: " + meta.originalAppClass, t);
            }
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        if (realApplication != null) {
            bindRealApplicationToSystem(realApplication);
            realApplication.onCreate();
        }
    }

    @SuppressWarnings("unchecked")
    private void bindRealApplicationToSystem(Application targetApp) {
        try {
            if (attachedBase != null) {
                try {
                    Method setOuter = attachedBase.getClass().getDeclaredMethod("setOuterContext", Context.class);
                    setOuter.setAccessible(true);
                    setOuter.invoke(attachedBase, targetApp);
                } catch (Throwable ignored) {
                }

                Field pkgInfoField = findField(attachedBase.getClass(), "mPackageInfo");
                if (pkgInfoField != null) {
                    Object loadedApk = pkgInfoField.get(attachedBase);
                    if (loadedApk != null) {
                        Field mAppField = findField(loadedApk.getClass(), "mApplication");
                        if (mAppField != null) {
                            mAppField.set(loadedApk, targetApp);
                        }
                        Field threadField = findField(loadedApk.getClass(), "mActivityThread");
                        if (threadField != null) {
                            Object activityThread = threadField.get(loadedApk);
                            if (activityThread != null) {
                                Field initAppField = findField(activityThread.getClass(), "mInitialApplication");
                                if (initAppField != null) {
                                    initAppField.set(activityThread, targetApp);
                                }
                                Field allAppsField = findField(activityThread.getClass(), "mAllApplications");
                                if (allAppsField != null) {
                                    List<Application> allApps = (List<Application>) allAppsField.get(activityThread);
                                    if (allApps != null) {
                                        for (int i = 0; i < allApps.size(); i++) {
                                            if (allApps.get(i) == this) {
                                                allApps.set(i, targetApp);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } catch (Throwable ignored) {
        }
    }

    private static Field findField(Class<?> cls, String name) {
        Class<?> cur = cls;
        while (cur != null) {
            try {
                Field f = cur.getDeclaredField(name);
                f.setAccessible(true);
                return f;
            } catch (NoSuchFieldException ignored) {
                cur = cur.getSuperclass();
            }
        }
        return null;
    }
}
