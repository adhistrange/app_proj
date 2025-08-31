package com.securityresearch.fuzzer.core.execution;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Comprehensive metrics collected during test case execution.
 * Provides detailed performance data for vulnerability analysis and fitness evaluation.
 */
public class ExecutionMetrics {
    
    @JsonProperty("executionId")
    private final String executionId;
    
    @JsonProperty("startTime")
    private final Instant startTime;
    
    @JsonProperty("endTime")
    private final Instant endTime;
    
    @JsonProperty("executionTimeNanos")
    private final long executionTimeNanos;
    
    @JsonProperty("peakMemoryBytes")
    private final long peakMemoryBytes;
    
    @JsonProperty("totalMemoryAllocated")
    private final long totalMemoryAllocated;
    
    @JsonProperty("cpuUsagePercent")
    private final double cpuUsagePercent;
    
    @JsonProperty("stackDepth")
    private final int stackDepth;
    
    @JsonProperty("exceptionThrown")
    private final boolean exceptionThrown;
    
    @JsonProperty("exceptionType")
    private final String exceptionType;
    
    @JsonProperty("exceptionMessage")
    private final String exceptionMessage;
    
    @JsonProperty("successful")
    private final boolean successful;
    
    @JsonProperty("timeoutOccurred")
    private final boolean timeoutOccurred;
    
    @JsonProperty("memoryLimitExceeded")
    private final boolean memoryLimitExceeded;
    
    @JsonProperty("securityViolation")
    private final boolean securityViolation;
    
    @JsonProperty("threadCount")
    private final int threadCount;
    
    @JsonProperty("gcCount")
    private final long gcCount;
    
    @JsonProperty("gcTimeMs")
    private final long gcTimeMs;
    
    private ExecutionMetrics(Builder builder) {
        this.executionId = builder.executionId;
        this.startTime = builder.startTime;
        this.endTime = builder.endTime;
        this.executionTimeNanos = builder.executionTimeNanos;
        this.peakMemoryBytes = builder.peakMemoryBytes;
        this.totalMemoryAllocated = builder.totalMemoryAllocated;
        this.cpuUsagePercent = builder.cpuUsagePercent;
        this.stackDepth = builder.stackDepth;
        this.exceptionThrown = builder.exceptionThrown;
        this.exceptionType = builder.exceptionType;
        this.exceptionMessage = builder.exceptionMessage;
        this.successful = builder.successful;
        this.timeoutOccurred = builder.timeoutOccurred;
        this.memoryLimitExceeded = builder.memoryLimitExceeded;
        this.securityViolation = builder.securityViolation;
        this.threadCount = builder.threadCount;
        this.gcCount = builder.gcCount;
        this.gcTimeMs = builder.gcTimeMs;
    }
    
    // Getters
    public String getExecutionId() { return executionId; }
    public Instant getStartTime() { return startTime; }
    public Instant getEndTime() { return endTime; }
    public long getExecutionTimeNanos() { return executionTimeNanos; }
    public long getPeakMemoryBytes() { return peakMemoryBytes; }
    public long getTotalMemoryAllocated() { return totalMemoryAllocated; }
    public double getCpuUsagePercent() { return cpuUsagePercent; }
    public int getStackDepth() { return stackDepth; }
    public boolean isExceptionThrown() { return exceptionThrown; }
    public String getExceptionType() { return exceptionType; }
    public String getExceptionMessage() { return exceptionMessage; }
    public boolean isSuccessful() { return successful; }
    public boolean isTimeoutOccurred() { return timeoutOccurred; }
    public boolean isMemoryLimitExceeded() { return memoryLimitExceeded; }
    public boolean isSecurityViolation() { return securityViolation; }
    public int getThreadCount() { return threadCount; }
    public long getGcCount() { return gcCount; }
    public long getGcTimeMs() { return gcTimeMs; }
    
    /**
     * Calculates the execution time in milliseconds.
     * 
     * @return Execution time in milliseconds
     */
    public double getExecutionTimeMs() {
        return executionTimeNanos / 1_000_000.0;
    }
    
    /**
     * Calculates the peak memory usage in megabytes.
     * 
     * @return Peak memory usage in MB
     */
    public double getPeakMemoryMb() {
        return peakMemoryBytes / (1024.0 * 1024.0);
    }
    
    /**
     * Calculates the total memory allocated in megabytes.
     * 
     * @return Total memory allocated in MB
     */
    public double getTotalMemoryAllocatedMb() {
        return totalMemoryAllocated / (1024.0 * 1024.0);
    }
    
    /**
     * Determines if the execution was terminated due to resource limits.
     * 
     * @return true if execution was terminated due to limits
     */
    public boolean wasTerminated() {
        return timeoutOccurred || memoryLimitExceeded || securityViolation;
    }
    
    /**
     * Calculates the memory efficiency (peak memory / total allocated).
     * 
     * @return Memory efficiency ratio
     */
    public double getMemoryEfficiency() {
        return totalMemoryAllocated > 0 ? (double) peakMemoryBytes / totalMemoryAllocated : 0.0;
    }
    
    /**
     * Calculates the CPU efficiency (execution time / CPU usage).
     * 
     * @return CPU efficiency metric
     */
    public double getCpuEfficiency() {
        return cpuUsagePercent > 0 ? getExecutionTimeMs() / cpuUsagePercent : 0.0;
    }
    
    @Override
    public String toString() {
        return String.format("ExecutionMetrics{id=%s, time=%.2fms, memory=%.2fMB, cpu=%.1f%%, success=%s}",
                executionId, getExecutionTimeMs(), getPeakMemoryMb(), cpuUsagePercent, successful);
    }
    
    /**
     * Builder pattern for creating ExecutionMetrics instances.
     */
    public static class Builder {
        private String executionId;
        private Instant startTime;
        private Instant endTime;
        private long executionTimeNanos;
        private long peakMemoryBytes;
        private long totalMemoryAllocated;
        private double cpuUsagePercent;
        private int stackDepth;
        private boolean exceptionThrown;
        private String exceptionType;
        private String exceptionMessage;
        private boolean successful;
        private boolean timeoutOccurred;
        private boolean memoryLimitExceeded;
        private boolean securityViolation;
        private int threadCount;
        private long gcCount;
        private long gcTimeMs;
        
        public Builder executionId(String executionId) {
            this.executionId = executionId;
            return this;
        }
        
        public Builder startTime(Instant startTime) {
            this.startTime = startTime;
            return this;
        }
        
        public Builder endTime(Instant endTime) {
            this.endTime = endTime;
            return this;
        }
        
        public Builder executionTimeNanos(long executionTimeNanos) {
            this.executionTimeNanos = executionTimeNanos;
            return this;
        }
        
        public Builder peakMemoryBytes(long peakMemoryBytes) {
            this.peakMemoryBytes = peakMemoryBytes;
            return this;
        }
        
        public Builder totalMemoryAllocated(long totalMemoryAllocated) {
            this.totalMemoryAllocated = totalMemoryAllocated;
            return this;
        }
        
        public Builder cpuUsagePercent(double cpuUsagePercent) {
            this.cpuUsagePercent = cpuUsagePercent;
            return this;
        }
        
        public Builder stackDepth(int stackDepth) {
            this.stackDepth = stackDepth;
            return this;
        }
        
        public Builder exceptionThrown(boolean exceptionThrown) {
            this.exceptionThrown = exceptionThrown;
            return this;
        }
        
        public Builder exceptionType(String exceptionType) {
            this.exceptionType = exceptionType;
            return this;
        }
        
        public Builder exceptionMessage(String exceptionMessage) {
            this.exceptionMessage = exceptionMessage;
            return this;
        }
        
        public Builder successful(boolean successful) {
            this.successful = successful;
            return this;
        }
        
        public Builder timeoutOccurred(boolean timeoutOccurred) {
            this.timeoutOccurred = timeoutOccurred;
            return this;
        }
        
        public Builder memoryLimitExceeded(boolean memoryLimitExceeded) {
            this.memoryLimitExceeded = memoryLimitExceeded;
            return this;
        }
        
        public Builder securityViolation(boolean securityViolation) {
            this.securityViolation = securityViolation;
            return this;
        }
        
        public Builder threadCount(int threadCount) {
            this.threadCount = threadCount;
            return this;
        }
        
        public Builder gcCount(long gcCount) {
            this.gcCount = gcCount;
            return this;
        }
        
        public Builder gcTimeMs(long gcTimeMs) {
            this.gcTimeMs = gcTimeMs;
            return this;
        }
        
        public ExecutionMetrics build() {
            return new ExecutionMetrics(this);
        }
    }
    
    /**
     * Creates a new builder instance.
     * 
     * @return A new Builder instance
     */
    public static Builder builder() {
        return new Builder();
    }
} 