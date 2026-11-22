package dev.leakscan;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Packet field lookup BY TYPE, not by name. At runtime the fields are named func_/field_ (SRG),
 * but their types (ResourceLocation, Suggestions, ByteBuf, ...) are stable and mapping-independent.
 * The accessors include superclass fields too (vanilla packets have none; behavior is the same).
 * <p>
 * Reflection metadata is cached per class: getDeclaredFields() clones the array and setAccessible()
 * is noticeable, and this used to happen on EVERY packet (on team-heavy servers — thousands of
 * times per minute). A class's field set is immutable at runtime, so the cache is safe.
 */
final class Refl {
    private Refl() {}

    /** Cache of simple class names: getSimpleName() allocates a new string on every call. */
    private static final ClassValue<String> SIMPLE_NAMES = new ClassValue<String>() {
        @Override
        protected String computeValue(Class<?> type) {
            return type.getSimpleName();
        }
    };

    static String classNameOf(Object o) {
        return SIMPLE_NAMES.get(o.getClass());
    }

    /** All non-static fields of a class (including superclasses), with setAccessible already applied. */
    private static final Map<Class<?>, Field[]> FIELDS_CACHE = new ConcurrentHashMap<>();

    private static Field[] fieldsOf(Class<?> cls) {
        Field[] cached = FIELDS_CACHE.get(cls);
        if (cached != null) return cached;
        List<Field> fs = new ArrayList<>();
        for (Class<?> c = cls; c != null && c != Object.class; c = c.getSuperclass()) {
            for (Field f : c.getDeclaredFields()) {
                if (Modifier.isStatic(f.getModifiers())) continue;
                try {
                    f.setAccessible(true);
                    fs.add(f);
                } catch (Exception ignored) {
                }
            }
        }
        Field[] arr = fs.toArray(new Field[0]);
        FIELDS_CACHE.put(cls, arr);
        return arr;
    }

    static <T> T get(Object o, Class<T> type) {
        List<T> all = all(o, type);
        return all.isEmpty() ? null : all.get(0);
    }

    static <T> List<T> all(Object o, Class<T> type) {
        List<T> res = new ArrayList<>();
        if (o == null) return res;
        for (Field f : fieldsOf(o.getClass())) {
            if (!type.isAssignableFrom(f.getType())) continue;
            try {
                Object v = f.get(o);
                if (v != null) res.add(type.cast(v));
            } catch (Exception ignored) {
            }
        }
        return res;
    }

    /** All int fields in declaration order (for SJoinGamePacket: entityId, maxPlayers, viewDistance). */
    static List<Integer> ints(Object o) {
        List<Integer> res = new ArrayList<>();
        for (Field f : fieldsOf(o.getClass())) {
            if (f.getType() != int.class) continue;
            try {
                res.add(f.getInt(o));
            } catch (Exception ignored) {
            }
        }
        return res;
    }

    /** All long fields in declaration order (for SUpdateTimePacket: worldAge, dayTime). */
    static List<Long> longs(Object o) {
        List<Long> res = new ArrayList<>();
        for (Field f : fieldsOf(o.getClass())) {
            if (f.getType() != long.class) continue;
            try {
                res.add(f.getLong(o));
            } catch (Exception ignored) {
            }
        }
        return res;
    }

    /** All float fields in declaration order (for SUpdateHealthPacket: health first, saturation after). */
    static List<Float> floats(Object o) {
        List<Float> res = new ArrayList<>();
        for (Field f : fieldsOf(o.getClass())) {
            if (f.getType() != float.class) continue;
            try {
                res.add(f.getFloat(o));
            } catch (Exception ignored) {
            }
        }
        return res;
    }
}
