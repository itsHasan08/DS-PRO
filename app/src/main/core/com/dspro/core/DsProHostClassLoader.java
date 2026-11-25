package com.dspro.core;

import dalvik.system.BaseDexClassLoader;
import dalvik.system.PathClassLoader;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Decoupled BaseDexClassLoader host shell.
 * Preserves BaseDexClassLoader / PathClassLoader compatibility for native libraries and
 * ServiceLoader resources via parent, while isolating InMemoryDexClassLoader out of
 * pathList.dexElements and parent chains, and caching resolved classes for instant lookup.
 */
final class DsProHostClassLoader extends PathClassLoader {

    private final Object[] vault;
    private final ConcurrentHashMap<String, Class<?>> classCache = new ConcurrentHashMap<>(512);

    DsProHostClassLoader(String librarySearchPath, ClassLoader parent, ClassLoader memLoader) {
        super("", librarySearchPath, parent);
        this.vault = new Object[]{ memLoader };
    }

    private ClassLoader mem() {
        return (ClassLoader) vault[0];
    }

    private static boolean isSystemOrCorePrefix(String name) {
        if (name == null) {
            return false;
        }
        return name.startsWith("java.")
            || name.startsWith("javax.")
            || name.startsWith("dalvik.")
            || name.startsWith("sun.")
            || name.startsWith("libcore.")
            || name.startsWith("org.w3c.")
            || name.startsWith("org.xml.")
            || name.startsWith("org.json.")
            || name.startsWith("com.dspro.")
            || (name.startsWith("android.")
                && !name.startsWith("android.support.")
                && !name.startsWith("android.arch.")
                && !name.startsWith("android.databinding."));
    }

    @Override
    protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
        if (name != null) {
            Class<?> cached = classCache.get(name);
            if (cached != null) {
                return cached;
            }
        }
        Class<?> loaded = findLoadedClass(name);
        if (loaded != null) {
            if (name != null) {
                classCache.putIfAbsent(name, loaded);
            }
            return loaded;
        }
        ClassLoader parent = getParent();
        if (isSystemOrCorePrefix(name) && parent != null) {
            try {
                Class<?> c = parent.loadClass(name);
                if (c != null && name != null) {
                    classCache.putIfAbsent(name, c);
                }
                return c;
            } catch (ClassNotFoundException ignored) {
            }
        }
        ClassLoader m = mem();
        if (m != null) {
            try {
                Class<?> c = m.loadClass(name);
                if (c != null && name != null) {
                    classCache.putIfAbsent(name, c);
                }
                return c;
            } catch (ClassNotFoundException ignored) {
            }
        }
        if (parent != null) {
            Class<?> c = parent.loadClass(name);
            if (c != null && name != null) {
                classCache.putIfAbsent(name, c);
            }
            return c;
        }
        throw new ClassNotFoundException(name);
    }

    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {
        if (name != null) {
            Class<?> cached = classCache.get(name);
            if (cached != null) {
                return cached;
            }
        }
        ClassLoader m = mem();
        if (m != null) {
            try {
                Class<?> c = m.loadClass(name);
                if (c != null && name != null) {
                    classCache.putIfAbsent(name, c);
                }
                return c;
            } catch (ClassNotFoundException ignored) {
            }
        }
        Class<?> fallback = super.findClass(name);
        if (fallback != null && name != null) {
            classCache.putIfAbsent(name, fallback);
        }
        return fallback;
    }

    @Override
    public String findLibrary(String name) {
        String lib = super.findLibrary(name);
        if (lib != null) {
            return lib;
        }
        ClassLoader parent = getParent();
        if (parent instanceof BaseDexClassLoader) {
            lib = ((BaseDexClassLoader) parent).findLibrary(name);
            if (lib != null) {
                return lib;
            }
        }
        ClassLoader m = mem();
        if (m instanceof BaseDexClassLoader) {
            return ((BaseDexClassLoader) m).findLibrary(name);
        }
        return null;
    }

    static final class ResourceBridgeClassLoader extends ClassLoader {
        private final ClassLoader resourceDelegate;

        ResourceBridgeClassLoader(ClassLoader bootParent, ClassLoader resourceDelegate) {
            super(bootParent);
            this.resourceDelegate = resourceDelegate;
        }

        @Override
        protected java.net.URL findResource(String name) {
            return resourceDelegate != null ? resourceDelegate.getResource(name) : null;
        }

        @Override
        protected java.util.Enumeration<java.net.URL> findResources(String name) throws java.io.IOException {
            return resourceDelegate != null
                ? resourceDelegate.getResources(name)
                : java.util.Collections.emptyEnumeration();
        }
    }
}
