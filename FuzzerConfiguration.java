package com.securityresearch.fuzzer.core.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * Configuration properties for the Java Micro-Fuzzing Framework.
 * Provides comprehensive settings for genetic algorithms, execution limits, and performance tuning.
 */
@Component
@ConfigurationProperties(prefix = "fuzzer")
public class FuzzerConfiguration {
    
    /**
     * Genetic algorithm configuration settings.
     */
    private GeneticAlgorithm geneticAlgorithm = new GeneticAlgorithm();
    
    /**
     * Execution harness configuration settings.
     */
    private Execution execution = new Execution();
    
    /**
     * Performance monitoring configuration settings.
     */
    private Performance performance = new Performance();
    
    /**
     * Security configuration settings.
     */
    private Security security = new Security();
    
    public GeneticAlgorithm getGeneticAlgorithm() {
        return geneticAlgorithm;
    }
    
    public void setGeneticAlgorithm(GeneticAlgorithm geneticAlgorithm) {
        this.geneticAlgorithm = geneticAlgorithm;
    }
    
    public Execution getExecution() {
        return execution;
    }
    
    public void setExecution(Execution execution) {
        this.execution = execution;
    }
    
    public Performance getPerformance() {
        return performance;
    }
    
    public void setPerformance(Performance performance) {
        this.performance = performance;
    }
    
    public Security getSecurity() {
        return security;
    }
    
    public void setSecurity(Security security) {
        this.security = security;
    }
    
    /**
     * Genetic algorithm specific configuration.
     */
    public static class GeneticAlgorithm {
        private int populationSize = 100;
        private int maxGenerations = 1000;
        private double crossoverRate = 0.8;
        private double mutationRate = 0.1;
        private double elitismRate = 0.1;
        private int tournamentSize = 3;
        private double diversityThreshold = 0.3;
        private int stagnationLimit = 50;
        private boolean adaptiveMutation = true;
        private double adaptiveMutationFactor = 1.5;
        
        public int getPopulationSize() {
            return populationSize;
        }
        
        public void setPopulationSize(int populationSize) {
            this.populationSize = populationSize;
        }
        
        public int getMaxGenerations() {
            return maxGenerations;
        }
        
        public void setMaxGenerations(int maxGenerations) {
            this.maxGenerations = maxGenerations;
        }
        
        public double getCrossoverRate() {
            return crossoverRate;
        }
        
        public void setCrossoverRate(double crossoverRate) {
            this.crossoverRate = crossoverRate;
        }
        
        public double getMutationRate() {
            return mutationRate;
        }
        
        public void setMutationRate(double mutationRate) {
            this.mutationRate = mutationRate;
        }
        
        public double getElitismRate() {
            return elitismRate;
        }
        
        public void setElitismRate(double elitismRate) {
            this.elitismRate = elitismRate;
        }
        
        public int getTournamentSize() {
            return tournamentSize;
        }
        
        public void setTournamentSize(int tournamentSize) {
            this.tournamentSize = tournamentSize;
        }
        
        public double getDiversityThreshold() {
            return diversityThreshold;
        }
        
        public void setDiversityThreshold(double diversityThreshold) {
            this.diversityThreshold = diversityThreshold;
        }
        
        public int getStagnationLimit() {
            return stagnationLimit;
        }
        
        public void setStagnationLimit(int stagnationLimit) {
            this.stagnationLimit = stagnationLimit;
        }
        
        public boolean isAdaptiveMutation() {
            return adaptiveMutation;
        }
        
        public void setAdaptiveMutation(boolean adaptiveMutation) {
            this.adaptiveMutation = adaptiveMutation;
        }
        
        public double getAdaptiveMutationFactor() {
            return adaptiveMutationFactor;
        }
        
        public void setAdaptiveMutationFactor(double adaptiveMutationFactor) {
            this.adaptiveMutationFactor = adaptiveMutationFactor;
        }
    }
    
    /**
     * Execution harness configuration.
     */
    public static class Execution {
        private Duration timeout = Duration.ofSeconds(30);
        private long maxMemoryBytes = 512 * 1024 * 1024; // 512MB
        private int maxStackDepth = 1000;
        private boolean enableSandbox = true;
        private boolean enableReflection = false;
        private int maxConcurrentExecutions = 4;
        private Duration warmupTime = Duration.ofSeconds(5);
        private int minExecutionCount = 3;
        
        public Duration getTimeout() {
            return timeout;
        }
        
        public void setTimeout(Duration timeout) {
            this.timeout = timeout;
        }
        
        public long getMaxMemoryBytes() {
            return maxMemoryBytes;
        }
        
        public void setMaxMemoryBytes(long maxMemoryBytes) {
            this.maxMemoryBytes = maxMemoryBytes;
        }
        
        public int getMaxStackDepth() {
            return maxStackDepth;
        }
        
        public void setMaxStackDepth(int maxStackDepth) {
            this.maxStackDepth = maxStackDepth;
        }
        
        public boolean isEnableSandbox() {
            return enableSandbox;
        }
        
        public void setEnableSandbox(boolean enableSandbox) {
            this.enableSandbox = enableSandbox;
        }
        
        public boolean isEnableReflection() {
            return enableReflection;
        }
        
        public void setEnableReflection(boolean enableReflection) {
            this.enableReflection = enableReflection;
        }
        
        public int getMaxConcurrentExecutions() {
            return maxConcurrentExecutions;
        }
        
        public void setMaxConcurrentExecutions(int maxConcurrentExecutions) {
            this.maxConcurrentExecutions = maxConcurrentExecutions;
        }
        
        public Duration getWarmupTime() {
            return warmupTime;
        }
        
        public void setWarmupTime(Duration warmupTime) {
            this.warmupTime = warmupTime;
        }
        
        public int getMinExecutionCount() {
            return minExecutionCount;
        }
        
        public void setMinExecutionCount(int minExecutionCount) {
            this.minExecutionCount = minExecutionCount;
        }
    }
    
    /**
     * Performance monitoring configuration.
     */
    public static class Performance {
        private boolean enableDetailedProfiling = true;
        private boolean enableMemoryTracking = true;
        private boolean enableCpuTracking = true;
        private int samplingIntervalMs = 10;
        private double outlierThreshold = 2.0;
        private int baselineSampleSize = 100;
        private double confidenceLevel = 0.95;
        
        public boolean isEnableDetailedProfiling() {
            return enableDetailedProfiling;
        }
        
        public void setEnableDetailedProfiling(boolean enableDetailedProfiling) {
            this.enableDetailedProfiling = enableDetailedProfiling;
        }
        
        public boolean isEnableMemoryTracking() {
            return enableMemoryTracking;
        }
        
        public void setEnableMemoryTracking(boolean enableMemoryTracking) {
            this.enableMemoryTracking = enableMemoryTracking;
        }
        
        public boolean isEnableCpuTracking() {
            return enableCpuTracking;
        }
        
        public void setEnableCpuTracking(boolean enableCpuTracking) {
            this.enableCpuTracking = enableCpuTracking;
        }
        
        public int getSamplingIntervalMs() {
            return samplingIntervalMs;
        }
        
        public void setSamplingIntervalMs(int samplingIntervalMs) {
            this.samplingIntervalMs = samplingIntervalMs;
        }
        
        public double getOutlierThreshold() {
            return outlierThreshold;
        }
        
        public void setOutlierThreshold(double outlierThreshold) {
            this.outlierThreshold = outlierThreshold;
        }
        
        public int getBaselineSampleSize() {
            return baselineSampleSize;
        }
        
        public void setBaselineSampleSize(int baselineSampleSize) {
            this.baselineSampleSize = baselineSampleSize;
        }
        
        public double getConfidenceLevel() {
            return confidenceLevel;
        }
        
        public void setConfidenceLevel(double confidenceLevel) {
            this.confidenceLevel = confidenceLevel;
        }
    }
    
    /**
     * Security configuration settings.
     */
    public static class Security {
        private boolean enableSecurityManager = true;
        private boolean restrictFileAccess = true;
        private boolean restrictNetworkAccess = true;
        private boolean restrictSystemAccess = true;
        private String[] allowedPackages = {"java.util", "java.lang"};
        private String[] forbiddenPackages = {"java.lang.System", "java.lang.Runtime"};
        
        public boolean isEnableSecurityManager() {
            return enableSecurityManager;
        }
        
        public void setEnableSecurityManager(boolean enableSecurityManager) {
            this.enableSecurityManager = enableSecurityManager;
        }
        
        public boolean isRestrictFileAccess() {
            return restrictFileAccess;
        }
        
        public void setRestrictFileAccess(boolean restrictFileAccess) {
            this.restrictFileAccess = restrictFileAccess;
        }
        
        public boolean isRestrictNetworkAccess() {
            return restrictNetworkAccess;
        }
        
        public void setRestrictNetworkAccess(boolean restrictNetworkAccess) {
            this.restrictNetworkAccess = restrictNetworkAccess;
        }
        
        public boolean isRestrictSystemAccess() {
            return restrictSystemAccess;
        }
        
        public void setRestrictSystemAccess(boolean restrictSystemAccess) {
            this.restrictSystemAccess = restrictSystemAccess;
        }
        
        public String[] getAllowedPackages() {
            return allowedPackages;
        }
        
        public void setAllowedPackages(String[] allowedPackages) {
            this.allowedPackages = allowedPackages;
        }
        
        public String[] getForbiddenPackages() {
            return forbiddenPackages;
        }
        
        public void setForbiddenPackages(String[] forbiddenPackages) {
            this.forbiddenPackages = forbiddenPackages;
        }
    }
} 