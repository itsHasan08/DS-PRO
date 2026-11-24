package com.dspro.core;

import dalvik.system.BaseDexClassLoader;
import dalvik.system.PathClassLoader;

/**
 * Decoupled BaseDexClassLoader host shell.
 * Preserves BaseDexClassLoader / PathClassLoader compatibility for native libraries and
 * ServiceLoader resources via parent, while isolating InMemoryDexClassLoader out of
 * pathList.dexElements and parent chains.
 */
final class DsProHostClassLoader extends PathClassLoader {

    private final Object[] vault;

    DsProHostClassLoader(String librarySearchPath, ClassLoader parent, ClassLoader memLoader) {
        super("", librarySearchPath, parent);
        this.vault = new Object[]{ memLoader };
    }

    private ClassLoader mem() {
        return (ClassLoader) vault[0];
    }

    @Override
    protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
        Class<?> loaded = findLoadedClass(name);
        if (loaded != null) {
            return loaded;
        }
        ClassLoader parent = getParent();
        if (parent != null) {
            try {
                return parent.loadClass(name);
            } catch (ClassNotFoundException ignored) {
            }
        }
        return findClass(name);
    }

    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {
        ClassLoader m = mem();
        if (m != null) {
            try {
                return m.loadClass(name);
            } catch (ClassNotFoundException ignored) {
            }
        }
        return super.findClass(name);
    }

    @Override
    public String findLibrary(String name) {
        String lib = super.findLibrary(name);
        if (lib != null) {
            return lib;
        }
        ClassLoader m = mem();
        if (m instanceof BaseDexClassLoader) {
            return ((BaseDexClassLoader) m).findLibrary(name);
        }
        return null;
    }
}
