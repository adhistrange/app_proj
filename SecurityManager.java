package com.securityresearch.fuzzer.instrumentation.security;

import com.securityresearch.fuzzer.core.exception.FuzzerException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Security manager that enforces constraints during fuzzing to prevent
 * malicious operations and resource exhaustion.
 */
public class SecurityManager {
    
    private static final Logger logger = LoggerFactory.getLogger(SecurityManager.class);
    
    // Global security state
    private static final AtomicLong startTime = new AtomicLong(0);
    private static final AtomicLong maxExecutionTimeNanos = new AtomicLong(30_000_000_000L); // 30 seconds
    private static final AtomicLong maxMemoryUsageBytes = new AtomicLong(512 * 1024 * 1024L); // 512MB
    private static final AtomicLong maxStackDepth = new AtomicLong(1000);
    private static final AtomicReference<Thread> currentThread = new AtomicReference<>();
    
    // Thread-local state
    private static final ThreadLocal<Long> threadStartTime = ThreadLocal.withInitial(() -> 0L);
    private static final ThreadLocal<Long> threadMemoryStart = ThreadLocal.withInitial(() -> 0L);
    private static final ThreadLocal<Integer> threadStackDepth = ThreadLocal.withInitial(() -> 0);
    
    // Security flags
    private static volatile boolean restrictFileAccess = true;
    private static volatile boolean restrictNetworkAccess = true;
    private static volatile boolean restrictSystemAccess = true;
    
    /**
     * Initialize security manager with default settings.
     */
    static {
        startTime.set(System.nanoTime());
        currentThread.set(Thread.currentThread());
    }
    
    /**
     * Check execution timeout.
     * 
     * @throws SecurityException if timeout exceeded
     */
    public static void checkTimeout() {
        long currentTime = System.nanoTime();
        long threadStart = threadStartTime.get();
        
        if (threadStart == 0) {
            threadStartTime.set(currentTime);
            return;
        }
        
        long elapsed = currentTime - threadStart;
        if (elapsed > maxExecutionTimeNanos.get()) {
            logger.warn("Execution timeout exceeded: {} ms", elapsed / 1_000_000);
            throw new SecurityException("Execution timeout exceeded");
        }
    }
    
    /**
     * Check memory usage.
     * 
     * @throws SecurityException if memory limit exceeded
     */
    public static void checkMemoryUsage() {
        Runtime runtime = Runtime.getRuntime();
        long currentMemory = runtime.totalMemory() - runtime.freeMemory();
        long threadStartMemory = threadMemoryStart.get();
        
        if (threadStartMemory == 0) {
            threadMemoryStart.set(currentMemory);
            return;
        }
        
        long memoryUsed = currentMemory - threadStartMemory;
        if (memoryUsed > maxMemoryUsageBytes.get()) {
            logger.warn("Memory usage exceeded: {} MB", memoryUsed / (1024 * 1024));
            throw new SecurityException("Memory usage exceeded");
        }
    }
    
    /**
     * Check stack depth.
     * 
     * @throws SecurityException if stack depth exceeded
     */
    public static void checkStackDepth() {
        int depth = threadStackDepth.get();
        threadStackDepth.set(depth + 1);
        
        if (depth > maxStackDepth.get()) {
            logger.warn("Stack depth exceeded: {}", depth);
            throw new SecurityException("Stack depth exceeded");
        }
    }
    
    /**
     * Check method access permissions.
     * 
     * @param className Class name
     * @param methodName Method name
     * @throws SecurityException if access denied
     */
    public static void checkMethodAccess(String className, String methodName) {
        String fullMethodName = className + "." + methodName;
        
        // File operations
        if (restrictFileAccess && isFileOperation(className, methodName)) {
            logger.warn("File access denied: {}", fullMethodName);
            throw new SecurityException("File access denied: " + fullMethodName);
        }
        
        // Network operations
        if (restrictNetworkAccess && isNetworkOperation(className, methodName)) {
            logger.warn("Network access denied: {}", fullMethodName);
            throw new SecurityException("Network access denied: " + fullMethodName);
        }
        
        // System operations
        if (restrictSystemAccess && isSystemOperation(className, methodName)) {
            logger.warn("System access denied: {}", fullMethodName);
            throw new SecurityException("System access denied: " + fullMethodName);
        }
        
        // Reflection operations
        if (isReflectionOperation(className, methodName)) {
            logger.warn("Reflection access denied: {}", fullMethodName);
            throw new SecurityException("Reflection access denied: " + fullMethodName);
        }
    }
    
    /**
     * Check field access permissions.
     * 
     * @param className Class name
     * @param fieldName Field name
     * @throws SecurityException if access denied
     */
    public static void checkFieldAccess(String className, String fieldName) {
        String fullFieldName = className + "." + fieldName;
        
        // System properties
        if (restrictSystemAccess && className.equals("java.lang.System") && 
            (fieldName.equals("out") || fieldName.equals("err") || fieldName.equals("in"))) {
            logger.warn("System field access denied: {}", fullFieldName);
            throw new SecurityException("System field access denied: " + fullFieldName);
        }
        
        // Security manager
        if (className.equals("java.lang.System") && fieldName.equals("security")) {
            logger.warn("Security manager access denied: {}", fullFieldName);
            throw new SecurityException("Security manager access denied: " + fullFieldName);
        }
    }
    
    /**
     * Check if a method is a file operation.
     * 
     * @param className Class name
     * @param methodName Method name
     * @return true if file operation
     */
    private static boolean isFileOperation(String className, String methodName) {
        return (className.equals("java.io.File") && 
                (methodName.equals("delete") || methodName.equals("createNewFile") || 
                 methodName.equals("mkdir") || methodName.equals("mkdirs"))) ||
               (className.equals("java.nio.file.Files") && 
                (methodName.equals("delete") || methodName.equals("createFile") || 
                 methodName.equals("createDirectory") || methodName.equals("write")));
    }
    
    /**
     * Check if a method is a network operation.
     * 
     * @param className Class name
     * @param methodName Method name
     * @return true if network operation
     */
    private static boolean isNetworkOperation(String className, String methodName) {
        return (className.equals("java.net.Socket") && 
                (methodName.equals("connect") || methodName.equals("bind"))) ||
               (className.equals("java.net.URLConnection") && 
                (methodName.equals("connect") || methodName.equals("getInputStream") || 
                 methodName.equals("getOutputStream"))) ||
               (className.equals("java.net.HttpURLConnection") && 
                (methodName.equals("connect") || methodName.equals("getInputStream") || 
                 methodName.equals("getOutputStream")));
    }
    
    /**
     * Check if a method is a system operation.
     * 
     * @param className Class name
     * @param methodName Method name
     * @return true if system operation
     */
    private static boolean isSystemOperation(String className, String methodName) {
        return (className.equals("java.lang.Runtime") && 
                (methodName.equals("exec") || methodName.equals("exit"))) ||
               (className.equals("java.lang.ProcessBuilder") && 
                (methodName.equals("start") || methodName.equals("command"))) ||
               (className.equals("java.lang.System") && 
                (methodName.equals("exit") || methodName.equals("gc") || 
                 methodName.equals("runFinalization")));
    }
    
    /**
     * Check if a method is a reflection operation.
     * 
     * @param className Class name
     * @param methodName Method name
     * @return true if reflection operation
     */
    private static boolean isReflectionOperation(String className, String methodName) {
        return (className.equals("java.lang.reflect.Method") && 
                methodName.equals("invoke")) ||
               (className.equals("java.lang.Class") && 
                (methodName.equals("newInstance") || methodName.equals("getMethod") || 
                 methodName.equals("getDeclaredMethod") || methodName.equals("getField") || 
                 methodName.equals("getDeclaredField")));
    }
    
    /**
     * Reset thread-local state.
     */
    public static void resetThreadState() {
        threadStartTime.set(0L);
        threadMemoryStart.set(0L);
        threadStackDepth.set(0);
    }
    
    /**
     * Set maximum execution time.
     * 
     * @param maxTimeNanos Maximum time in nanoseconds
     */
    public static void setMaxExecutionTime(long maxTimeNanos) {
        maxExecutionTimeNanos.set(maxTimeNanos);
    }
    
    /**
     * Set maximum memory usage.
     * 
     * @param maxMemoryBytes Maximum memory in bytes
     */
    public static void setMaxMemoryUsage(long maxMemoryBytes) {
        maxMemoryUsageBytes.set(maxMemoryBytes);
    }
    
    /**
     * Set maximum stack depth.
     * 
     * @param maxDepth Maximum stack depth
     */
    public static void setMaxStackDepth(long maxDepth) {
        maxStackDepth.set(maxDepth);
    }
    
    /**
     * Set file access restriction.
     * 
     * @param restrict true to restrict file access
     */
    public static void setRestrictFileAccess(boolean restrict) {
        restrictFileAccess = restrict;
    }
    
    /**
     * Set network access restriction.
     * 
     * @param restrict true to restrict network access
     */
    public static void setRestrictNetworkAccess(boolean restrict) {
        restrictNetworkAccess = restrict;
    }
    
    /**
     * Set system access restriction.
     * 
     * @param restrict true to restrict system access
     */
    public static void setRestrictSystemAccess(boolean restrict) {
        restrictSystemAccess = restrict;
    }
    
    /**
     * Get current security status.
     * 
     * @return Security status string
     */
    public static String getSecurityStatus() {
        return String.format(
            "Security Status - File Access: %s, Network Access: %s, System Access: %s, " +
            "Max Time: %d ms, Max Memory: %d MB, Max Stack: %d",
            restrictFileAccess ? "RESTRICTED" : "ALLOWED",
            restrictNetworkAccess ? "RESTRICTED" : "ALLOWED",
            restrictSystemAccess ? "RESTRICTED" : "ALLOWED",
            maxExecutionTimeNanos.get() / 1_000_000,
            maxMemoryUsageBytes.get() / (1024 * 1024),
            maxStackDepth.get()
        );
    }
} 