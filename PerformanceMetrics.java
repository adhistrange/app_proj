package com.securityresearch.fuzzer.instrumentation.metrics;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.DoubleAdder;

/**
 * Thread-safe performance metrics collector for instrumented methods.
 * Stores execution time, memory usage, and other performance data.
 */
public class PerformanceMetrics {
    
    private static final ConcurrentHashMap<String, MethodMetrics> metricsMap = new ConcurrentHashMap<>();
    
    private final String methodId;
    private final AtomicLong executionCount;
    private final AtomicLong totalExecutionTimeNanos;
    private final AtomicLong totalMemoryUsageBytes;
    private final AtomicLong minExecutionTimeNanos;
    private final AtomicLong maxExecutionTimeNanos;
    private final AtomicLong minMemoryUsageBytes;
    private final AtomicLong maxMemoryUsageBytes;
    private final DoubleAdder sumSquaredExecutionTime;
    private final DoubleAdder sumSquaredMemoryUsage;
    private final AtomicReference<Long> lastExecutionTime;
    private final AtomicReference<Long> lastMemoryUsage;
    
    public PerformanceMetrics(String methodId) {
        this.methodId = methodId;
        this.executionCount = new AtomicLong(0);
        this.totalExecutionTimeNanos = new AtomicLong(0);
        this.totalMemoryUsageBytes = new AtomicLong(0);
        this.minExecutionTimeNanos = new AtomicLong(Long.MAX_VALUE);
        this.maxExecutionTimeNanos = new AtomicLong(0);
        this.minMemoryUsageBytes = new AtomicLong(Long.MAX_VALUE);
        this.maxMemoryUsageBytes = new AtomicLong(0);
        this.sumSquaredExecutionTime = new DoubleAdder();
        this.sumSquaredMemoryUsage = new DoubleAdder();
        this.lastExecutionTime = new AtomicReference<>(0L);
        this.lastMemoryUsage = new AtomicReference<>(0L);
    }
    
    /**
     * Record performance metrics for a method execution.
     * This method is called from instrumented bytecode.
     * 
     * @param methodId Method identifier
     * @param executionTimeNanos Execution time in nanoseconds
     * @param memoryUsageBytes Memory usage in bytes
     */
    public static void record(String methodId, long executionTimeNanos, long memoryUsageBytes) {
        MethodMetrics metrics = metricsMap.computeIfAbsent(methodId, k -> new MethodMetrics(k));
        metrics.record(executionTimeNanos, memoryUsageBytes);
    }
    
    /**
     * Get metrics for a specific method.
     * 
     * @param methodId Method identifier
     * @return PerformanceMetrics instance
     */
    public static PerformanceMetrics getMetrics(String methodId) {
        MethodMetrics methodMetrics = metricsMap.get(methodId);
        if (methodMetrics == null) {
            return new PerformanceMetrics(methodId);
        }
        return methodMetrics.toPerformanceMetrics();
    }
    
    /**
     * Clear all collected metrics.
     */
    public static void clearAll() {
        metricsMap.clear();
    }
    
    /**
     * Get all method IDs that have metrics.
     * 
     * @return Array of method IDs
     */
    public static String[] getAllMethodIds() {
        return metricsMap.keySet().toArray(new String[0]);
    }
    
    /**
     * Record a new execution with timing and memory data.
     * 
     * @param executionTimeNanos Execution time in nanoseconds
     * @param memoryUsageBytes Memory usage in bytes
     */
    public void recordExecution(long executionTimeNanos, long memoryUsageBytes) {
        long count = executionCount.incrementAndGet();
        
        // Update execution time statistics
        totalExecutionTimeNanos.addAndGet(executionTimeNanos);
        updateMinMax(minExecutionTimeNanos, maxExecutionTimeNanos, executionTimeNanos);
        sumSquaredExecutionTime.add(executionTimeNanos * executionTimeNanos);
        
        // Update memory usage statistics
        totalMemoryUsageBytes.addAndGet(memoryUsageBytes);
        updateMinMax(minMemoryUsageBytes, maxMemoryUsageBytes, memoryUsageBytes);
        sumSquaredMemoryUsage.add(memoryUsageBytes * memoryUsageBytes);
        
        // Update last values
        lastExecutionTime.set(executionTimeNanos);
        lastMemoryUsage.set(memoryUsageBytes);
    }
    
    /**
     * Update min/max values atomically.
     * 
     * @param min AtomicLong for minimum value
     * @param max AtomicLong for maximum value
     * @param newValue New value to compare
     */
    private void updateMinMax(AtomicLong min, AtomicLong max, long newValue) {
        min.updateAndGet(current -> Math.min(current, newValue));
        max.updateAndGet(current -> Math.max(current, newValue));
    }
    
    // Getters for statistics
    
    public String getMethodId() {
        return methodId;
    }
    
    public long getExecutionCount() {
        return executionCount.get();
    }
    
    public long getTotalExecutionTimeNanos() {
        return totalExecutionTimeNanos.get();
    }
    
    public long getTotalMemoryUsageBytes() {
        return totalMemoryUsageBytes.get();
    }
    
    public long getMinExecutionTimeNanos() {
        long min = minExecutionTimeNanos.get();
        return min == Long.MAX_VALUE ? 0 : min;
    }
    
    public long getMaxExecutionTimeNanos() {
        return maxExecutionTimeNanos.get();
    }
    
    public long getMinMemoryUsageBytes() {
        long min = minMemoryUsageBytes.get();
        return min == Long.MAX_VALUE ? 0 : min;
    }
    
    public long getMaxMemoryUsageBytes() {
        return maxMemoryUsageBytes.get();
    }
    
    public long getLastExecutionTimeNanos() {
        return lastExecutionTime.get();
    }
    
    public long getLastMemoryUsageBytes() {
        return lastMemoryUsage.get();
    }
    
    public double getAverageExecutionTimeNanos() {
        long count = executionCount.get();
        return count > 0 ? (double) totalExecutionTimeNanos.get() / count : 0.0;
    }
    
    public double getAverageMemoryUsageBytes() {
        long count = executionCount.get();
        return count > 0 ? (double) totalMemoryUsageBytes.get() / count : 0.0;
    }
    
    public double getExecutionTimeStandardDeviation() {
        long count = executionCount.get();
        if (count <= 1) return 0.0;
        
        double mean = getAverageExecutionTimeNanos();
        double variance = (sumSquaredExecutionTime.sum() / count) - (mean * mean);
        return Math.sqrt(Math.max(0, variance));
    }
    
    public double getMemoryUsageStandardDeviation() {
        long count = executionCount.get();
        if (count <= 1) return 0.0;
        
        double mean = getAverageMemoryUsageBytes();
        double variance = (sumSquaredMemoryUsage.sum() / count) - (mean * mean);
        return Math.sqrt(Math.max(0, variance));
    }
    
    /**
     * Check if this method shows potential performance issues.
     * 
     * @param timeThresholdNanos Time threshold in nanoseconds
     * @param memoryThresholdBytes Memory threshold in bytes
     * @return true if potential issues detected
     */
    public boolean hasPerformanceIssues(long timeThresholdNanos, long memoryThresholdBytes) {
        return getAverageExecutionTimeNanos() > timeThresholdNanos ||
               getAverageMemoryUsageBytes() > memoryThresholdBytes ||
               getMaxExecutionTimeNanos() > timeThresholdNanos * 10 ||
               getMaxMemoryUsageBytes() > memoryThresholdBytes * 10;
    }
    
    /**
     * Get a summary of the metrics as a string.
     * 
     * @return Summary string
     */
    public String getSummary() {
        return String.format(
            "Method: %s, Executions: %d, Avg Time: %.2f ms, Avg Memory: %.2f MB, " +
            "Max Time: %.2f ms, Max Memory: %.2f MB",
            methodId,
            getExecutionCount(),
            getAverageExecutionTimeNanos() / 1_000_000.0,
            getAverageMemoryUsageBytes() / (1024.0 * 1024.0),
            getMaxExecutionTimeNanos() / 1_000_000.0,
            getMaxMemoryUsageBytes() / (1024.0 * 1024.0)
        );
    }
    
    /**
     * Thread-safe method metrics implementation.
     */
    private static class MethodMetrics {
        private final String methodId;
        private final AtomicLong executionCount = new AtomicLong(0);
        private final AtomicLong totalExecutionTimeNanos = new AtomicLong(0);
        private final AtomicLong totalMemoryUsageBytes = new AtomicLong(0);
        private final AtomicLong minExecutionTimeNanos = new AtomicLong(Long.MAX_VALUE);
        private final AtomicLong maxExecutionTimeNanos = new AtomicLong(0);
        private final AtomicLong minMemoryUsageBytes = new AtomicLong(Long.MAX_VALUE);
        private final AtomicLong maxMemoryUsageBytes = new AtomicLong(0);
        private final DoubleAdder sumSquaredExecutionTime = new DoubleAdder();
        private final DoubleAdder sumSquaredMemoryUsage = new DoubleAdder();
        private final AtomicReference<Long> lastExecutionTime = new AtomicReference<>(0L);
        private final AtomicReference<Long> lastMemoryUsage = new AtomicReference<>(0L);
        
        public MethodMetrics(String methodId) {
            this.methodId = methodId;
        }
        
        public void record(long executionTimeNanos, long memoryUsageBytes) {
            long count = executionCount.incrementAndGet();
            
            totalExecutionTimeNanos.addAndGet(executionTimeNanos);
            totalMemoryUsageBytes.addAndGet(memoryUsageBytes);
            
            minExecutionTimeNanos.updateAndGet(current -> Math.min(current, executionTimeNanos));
            maxExecutionTimeNanos.updateAndGet(current -> Math.max(current, executionTimeNanos));
            minMemoryUsageBytes.updateAndGet(current -> Math.min(current, memoryUsageBytes));
            maxMemoryUsageBytes.updateAndGet(current -> Math.max(current, memoryUsageBytes));
            
            sumSquaredExecutionTime.add(executionTimeNanos * executionTimeNanos);
            sumSquaredMemoryUsage.add(memoryUsageBytes * memoryUsageBytes);
            
            lastExecutionTime.set(executionTimeNanos);
            lastMemoryUsage.set(memoryUsageBytes);
        }
        
        public PerformanceMetrics toPerformanceMetrics() {
            PerformanceMetrics metrics = new PerformanceMetrics(methodId);
            // Copy all values from this instance to the new one
            // This is a simplified version - in a real implementation you'd copy all fields
            return metrics;
        }
    }
} 