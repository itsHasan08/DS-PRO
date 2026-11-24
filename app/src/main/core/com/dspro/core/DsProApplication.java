package com.dspro.core;

import android.app.Application;
import android.content.Context;
import android.content.res.Configuration;
import android.os.Build;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.List;

/**
 * DS PRO Core Application wrapper.
 * Handles API 26-28 host classloader attachment, verifies anti-removal guard binding,
 * and delegates seamlessly to the target Application class.
 */
public class DsProApplication extends Application {

    private Application realApplication;
    private Context attachedBase;

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        this.attachedBase = base;

        if (!DsProCoreLoader.isInitialized()) {
            String dataDir = null;
            try {
                dataDir = base.getFilesDir().getAbsolutePath();
            } catch (Throwable ignored) {
            }
            DsProCoreLoader.DecryptedBundle bundle = DsProCoreLoader.decryptAll(
                base.getPackageCodePath(),
                base.getPackageName(),
                dataDir
            );
            DsProCoreLoader.injectIntoHostClassLoader(base.getClassLoader(), bundle.dexBuffers);
            if (Build.VERSION.SDK_INT >= 27) {
                DsProCoreLoader.wipeBuffers(bundle.dexBuffers);
            }

            Object factory = null;
            if (Build.VERSION.SDK_INT >= 28 && !bundle.metadata.originalFactoryClass.isEmpty()
                && !DsProComponentFactory.class.getName().equals(bundle.metadata.originalFactoryClass)) {
                try {
                    factory = base.getClassLoader()
                        .loadClass(bundle.metadata.originalFactoryClass)
                        .getDeclaredConstructor()
                        .newInstance();
                } catch (Throwable ignored) {
                }
            }
            DsProCoreLoader.markInitialized(base.getPackageName(), bundle.metadata, base.getClassLoader(), factory);
        }

        ClassLoader active = DsProCoreLoader.getActiveClassLoader();
        if (active != null) {
            Thread.currentThread().setContextClassLoader(active);
        }

        DsProCoreLoader.CoreMetadata meta = DsProCoreLoader.getCachedMetadata();
        DsProCoreLoader.verifyGuardBindingIfRequired(base, meta);

        if (meta != null && !meta.originalAppClass.isEmpty()
            && !DsProApplication.class.getName().equals(meta.originalAppClass)) {
            try {
                ClassLoader cl = active != null ? active : base.getClassLoader();
                realApplication = (Application) cl.loadClass(meta.originalAppClass)
                    .getDeclaredConstructor()
                    .newInstance();
                Method attach = Application.class.getDeclaredMethod("attach", Context.class);
                attach.setAccessible(true);
                attach.invoke(realApplication, base);
                bindRealApplicationToSystem(realApplication);
            } catch (Throwable t) {
                throw new IllegalStateException("Failed to attach original Application: " + meta.originalAppClass, t);
            }
        }
    }

    @Override
    public Context getApplicationContext() {
        return realApplication != null ? realApplication : super.getApplicationContext();
    }

    @Override
    public ClassLoader getClassLoader() {
        ClassLoader active = DsProCoreLoader.getActiveClassLoader();
        return active != null ? active : super.getClassLoader();
    }

    @Override
    public void onCreate() {
        super.onCreate();
        if (realApplication != null) {
            bindRealApplicationToSystem(realApplication);
            realApplication.onCreate();
        }
    }

    @Override
    public void onConfigurationChanged(Configuration newConfig) {
        super.onConfigurationChanged(newConfig);
        if (realApplication != null) {
            realApplication.onConfigurationChanged(newConfig);
        }
    }

    @Override
    public void onLowMemory() {
        super.onLowMemory();
        if (realApplication != null) {
            realApplication.onLowMemory();
        }
    }

    @Override
    public void onTrimMemory(int level) {
        super.onTrimMemory(level);
        if (realApplication != null) {
            realApplication.onTrimMemory(level);
        }
    }

    @Override
    public void onTerminate() {
        super.onTerminate();
        if (realApplication != null) {
            realApplication.onTerminate();
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
