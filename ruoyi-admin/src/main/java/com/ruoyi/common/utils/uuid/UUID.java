package com.ruoyi.common.utils.uuid;

import com.ruoyi.common.exception.UtilException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

/**
 * 提供通用唯一识别码（universally unique identifier）（UUID）实现
 *
 * @author ruoyi
 */
public final class UUID implements java.io.Serializable, Comparable<UUID> {
    private static final long serialVersionUID = -1185015143654744140L;

    // SecureRandom的单例
    private static class Holder {
        static final SecureRandom numberGenerator = getSecureRandom();
    }

    // 此UUID的最高64有效位
    private final long mostSigBits;

    // 此UUID的最低64有效位
    private final long leastSigBits;

    /**
     * 私有构造
     *
     * @param data 数据
     */
    private UUID(byte[] data) {
        long msb = 0;
        long lsb = 0;
        assert data.length == 16 : "data must be 16 bytes in length";
        for (int i = 0; i < 8; i++) {
            msb = (msb << 8) | (data[i] & 0xff);
        }
        for (int i = 8; i < 16; i++) {
            lsb = (lsb << 8) | (data[i] & 0xff);
        }
        this.mostSigBits = msb;
        this.leastSigBits = lsb;
    }

    /**
     * 使用指定的数据构造新的UUID
     *
     * @param mostSigBits  用于 {@code UUID} 的最高有效64位
     * @param leastSigBits 用于 {@code UUID} 的最低有效64位
     */
    public UUID(long mostSigBits, long leastSigBits) {
        this.mostSigBits = mostSigBits;
        this.leastSigBits = leastSigBits;
    }

    /**
     * 获取类型4（伪随机生成的）UUID的静态工厂，使用加密的本地线程伪随机数生成器生成该UUID。
     *
     * @return 随机生成的 {@code UUID}
     */
    public static UUID fastUUID() {
        return randomUUID(false);
    }

    /**
     * 获取类型4（伪随机生成的）UUID的静态工厂，使用加密的强伪随机数生成器生成该UUID。
     *
     * @return 随机生成的 {@code UUID}
     */
    public static UUID randomUUID() {
        return randomUUID(true);
    }

    /**
     * 获取类型4（伪随机生成的）UUID的静态工厂，使用加密的强伪随机数生成器生成该UUID。
     *
     * @param isSecure 是否使用{@link SecureRandom} 如果是可以获得更安全的随机码，否则可以得到更好的性能。
     * @return 随机生成的 {@code UUID}
     */
    public static UUID randomUUID(boolean isSecure) {
        final Random ng = isSecure ? Holder.numberGenerator : getRandom();

        byte[] randomBytes = new byte[16];
        ng.nextBytes(randomBytes);
        randomBytes[6] &= 0x0f; /* clear version */
        randomBytes[6] |= 0x40; /* set to version 4 */
        randomBytes[8] &= 0x3f; /* clear variant */
        randomBytes[8] |= 0x80; /* set to IETF variant */
        return new UUID(randomBytes);
    }

    /**
     * 根据指定的字节数组获取类型3（基于名称的）UUID的静态工厂
     *
     * @param name 用于构造UUID的字节数组
     * @return 根据指定数组生成的 {@code UUID}
     */
    public static UUID nameUUIDFromBytes(byte[] name) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException nsae) {
            throw new InternalError("MD5 not supported");
        }
        byte[] md5Bytes = md.digest(name);
        md5Bytes[6] &= 0x0f; /* clear version */
        md5Bytes[6] |= 0x30; /* set to version 3 */
        md5Bytes[8] &= 0x3f; /* clear variant */
        md5Bytes[8] |= 0x80; /* set to IETF variant */
        return new UUID(md5Bytes);
    }

    /**
     * 根据 {@link #toString()} 方法中描述的字符串标准表示形式创建 {@code UUID}
     *
     * @param name 指定 {@code UUID} 字符串
     * @return 具有指定值的 {@code UUID}
     * @throws IllegalArgumentException 如果name与 {@link #toString} 中描述的字符串表示形式不符抛出此异常
     */
    public static UUID fromString(String name) {
        String[] components = name.split("-");
        if (components.length != 5) {
            throw new IllegalArgumentException("Invalid UUID string: " + name);
        }
        for (int i = 0; i < 5; i++) {
            components[i] = "0x" + components[i];
        }

        long mostSigBits = Long.decode(components[0]);
        mostSigBits <<= 16;
        mostSigBits |= Long.decode(components[1]);
        mostSigBits <<= 16;
        mostSigBits |= Long.decode(components[2]);

        long leastSigBits = Long.decode(components[3]);
        leastSigBits <<= 48;
        leastSigBits |= Long.decode(components[4]);

        return new UUID(mostSigBits, leastSigBits);
    }

    /**
     * 返回此UUID的128位值中的最低有效64位
     *
     * @return 此UUID的128位值中的最低有效64位
     */
    public long getLeastSignificantBits() {
        return leastSigBits;
    }

    /**
     * 返回此UUID的128位值中的最高有效64位
     *
     * @return 此UUID的128位值中最高有效64位
     */
    public long getMostSignificantBits() {
        return mostSigBits;
    }

    /**
     * 与此 {@code UUID} 相关联的版本号，版本号描述此 {@code UUID} 是如何生成的。
     *
     * @return 此 {@code UUID} 的版本号
     */
    public int version() {
        // Version is bits masked by 0x000000000000F000 in MS long
        return (int) ((mostSigBits >> 12) & 0x0f);
    }

    /**
     * 与此 {@code UUID} 相关联的变体号，变体号描述 {@code UUID} 的布局。
     *
     * @return 此 {@code UUID} 相关联的变体号
     */
    public int variant() {
        // This field is composed of a varying number of bits.
        // 0 - - Reserved for NCS backward compatibility
        // 1 0 - The IETF aka Leach-Salz variant (used by this class)
        // 1 1 0 Reserved, Microsoft backward compatibility
        // 1 1 1 Reserved for future definition.
        return (int) ((leastSigBits >>> (64 - (leastSigBits >>> 62))) & (leastSigBits >> 63));
    }

    /**
     * 与此UUID相关联的时间戳值
     *
     * 60位的时间戳值根据此 {@code UUID} 的time_low、time_mid和time_hi字段构造，所得到的时间戳以100毫微秒为单位，从UTC（通用协调时间）1582年10月15日零时开始，时间戳值仅在基于时间的UUID（其version类型为1）中才有意义。
     *
     * 如果此 {@code UUID} 不是基于时间的UUID，则此方法抛出UnsupportedOperationException。
     *
     * @throws UnsupportedOperationException 如果此 {@code UUID} 不是version为1的UUID
     */
    public long timestamp() throws UnsupportedOperationException {
        checkTimeBase();
        return (mostSigBits & 0x0FFFL) << 48 | ((mostSigBits >> 16) & 0x0FFFFL) << 32 | mostSigBits >>> 32;
    }

    /**
     * 与此UUID相关联的时钟序列值
     *
     * 14位的时钟序列值根据此UUID的clock_seq字段构造，clock_seq字段用于保证在基于时间的UUID中的时间唯一性。
     *
     * {@code clockSequence} 值仅在基于时间的UUID（其version类型为 1）中才有意义，如果此UUID不是基于时间的UUID，则此方法抛出UnsupportedOperationException。
     *
     * @return 此 {@code UUID} 的时钟序列
     * @throws UnsupportedOperationException 如果此UUID的version不为1
     */
    public int clockSequence() throws UnsupportedOperationException {
        checkTimeBase();
        return (int) ((leastSigBits & 0x3FFF000000000000L) >>> 48);
    }

    /**
     * 与此UUID相关的节点值
     *
     * 48位的节点值根据此UUID的node字段构造，此字段旨在用于保存机器的IEEE 802地址，该地址用于生成此UUID以保证空间唯一性，节点值仅在基于时间的UUID（其version类型为 1）中才有意义，如果此UUID不是基于时间的UUID，则此方法抛出UnsupportedOperationException。
     *
     * @return 此 {@code UUID} 的节点值
     * @throws UnsupportedOperationException 如果此UUID的version不为1
     */
    public long node() throws UnsupportedOperationException {
        checkTimeBase();
        return leastSigBits & 0x0000FFFFFFFFFFFFL;
    }

    /**
     * 返回此 {@code UUID} 的字符串表现形式
     *
     * @return 此 {@code UUID} 的字符串表现形式
     * @see #toString(boolean)
     */
    @Override
    public String toString() {
        return toString(false);
    }

    /**
     * 返回此 {@code UUID} 的字符串表现形式
     *
     * @param isSimple 是否简单模式，简单模式为不带-的UUID字符串。
     * @return 此 {@code UUID} 的字符串表现形式
     */
    public String toString(boolean isSimple) {
        final StringBuilder builder = new StringBuilder(isSimple ? 32 : 36);
        // time_low
        builder.append(digits(mostSigBits >> 32, 8));
        if (!isSimple) {
            builder.append('-');
        }
        // time_mid
        builder.append(digits(mostSigBits >> 16, 4));
        if (!isSimple) {
            builder.append('-');
        }
        // time_high_and_version
        builder.append(digits(mostSigBits, 4));
        if (!isSimple) {
            builder.append('-');
        }
        // variant_and_sequence
        builder.append(digits(leastSigBits >> 48, 4));
        if (!isSimple) {
            builder.append('-');
        }
        // node
        builder.append(digits(leastSigBits, 12));

        return builder.toString();
    }

    /**
     * 返回此UUID的哈希码
     *
     * @return UUID的哈希码值
     */
    @Override
    public int hashCode() {
        long hilo = mostSigBits ^ leastSigBits;
        return ((int) (hilo >> 32)) ^ (int) hilo;
    }

    /**
     * 将此对象与指定对象比较
     *
     * 当且仅当参数不为 {@code null}，而是一个UUID对象，具有与此UUID相同的varriant，包含相同的值（每一位均相同）时，结果才为 {@code true}。
     *
     * @param obj 要与之比较的对象
     * @return 如果对象相同，则返回 {@code true}，否则返回 {@code false}。
     */
    @Override
    public boolean equals(Object obj) {
        if ((null == obj) || (obj.getClass() != UUID.class)) {
            return false;
        }
        UUID id = (UUID) obj;
        return (mostSigBits == id.mostSigBits && leastSigBits == id.leastSigBits);
    }

    // Comparison Operations

    /**
     * 将此UUID与指定的UUID比较
     *
     * 如果两个UUID不同，且第一个UUID的最高有效字段大于第二个UUID的对应字段，则第一个UUID大于第二个UUID。
     *
     * @param val 与此UUID比较的UUID
     * @return 在此UUID小于、等于或大于val时，分别返回-1、0或1。
     */
    @Override
    public int compareTo(UUID val) {
        // The ordering is intentionally set up so that the UUIDs
        // can simply be numerically compared as two numbers
        return (this.mostSigBits < val.mostSigBits ? -1 : (this.mostSigBits > val.mostSigBits ? 1 : (Long.compare(this.leastSigBits, val.leastSigBits))));
    }

    // -------------------------------------------------------------------------------------------------------------------
    // Private method start

    /**
     * 返回指定数字对应的hex值
     *
     * @param val    值
     * @param digits 位
     * @return 值
     */
    private static String digits(long val, int digits) {
        long hi = 1L << (digits * 4);
        return Long.toHexString(hi | (val & (hi - 1))).substring(1);
    }

    /**
     * 检查是否为time-based版本UUID
     */
    private void checkTimeBase() {
        if (version() != 1) {
            throw new UnsupportedOperationException("Not a time-based UUID");
        }
    }

    /**
     * 获取 {@link SecureRandom}，类提供加密的强随机数生成器（RNG）。
     *
     * @return {@link SecureRandom}
     */
    public static SecureRandom getSecureRandom() {
        try {
            return SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e) {
            throw new UtilException(e);
        }
    }

    /**
     * 获取随机数生成器对象
     * ThreadLocalRandom是JDK 7之后提供并发产生随机数，能够解决多个线程发生的竞争争夺。
     *
     * @return {@link ThreadLocalRandom}
     */
    public static ThreadLocalRandom getRandom() {
        return ThreadLocalRandom.current();
    }
}
