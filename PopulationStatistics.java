package com.securityresearch.fuzzer.core.population;

import com.securityresearch.fuzzer.core.execution.TestCaseExecution;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.DoubleAdder;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Tracks and analyzes population statistics for monitoring evolutionary progress
 * and maintaining population health.
 */
public class PopulationStatistics {
    
    private final AtomicInteger totalTestCases;
    private final AtomicInteger evaluatedTestCases;
    private final AtomicInteger successfulTestCases;
    private final AtomicInteger failedTestCases;
    
    private final AtomicReference<Double> bestFitness;
    private final AtomicReference<Double> worstFitness;
    private final AtomicReference<Double> averageFitness;
    private final AtomicReference<Double> fitnessVariance;
    
    private final AtomicReference<Double> averageInputSize;
    private final AtomicReference<Double> averageInputComplexity;
    private final AtomicReference<Double> populationDiversity;
    
    private final AtomicLong totalExecutionTime;
    private final AtomicLong totalMemoryUsage;
    private final AtomicLong totalMutations;
    private final AtomicLong totalCrossovers;
    
    private final ConcurrentHashMap<String, Integer> targetMethodDistribution;
    private final ConcurrentHashMap<String, Integer> exceptionTypeDistribution;
    private final ConcurrentHashMap<String, Integer> inputTypeDistribution;
    
    public PopulationStatistics() {
        this.totalTestCases = new AtomicInteger(0);
        this.evaluatedTestCases = new AtomicInteger(0);
        this.successfulTestCases = new AtomicInteger(0);
        this.failedTestCases = new AtomicInteger(0);
        
        this.bestFitness = new AtomicReference<>(Double.NEGATIVE_INFINITY);
        this.worstFitness = new AtomicReference<>(Double.POSITIVE_INFINITY);
        this.averageFitness = new AtomicReference<>(0.0);
        this.fitnessVariance = new AtomicReference<>(0.0);
        
        this.averageInputSize = new AtomicReference<>(0.0);
        this.averageInputComplexity = new AtomicReference<>(0.0);
        this.populationDiversity = new AtomicReference<>(0.0);
        
        this.totalExecutionTime = new AtomicLong(0);
        this.totalMemoryUsage = new AtomicLong(0);
        this.totalMutations = new AtomicLong(0);
        this.totalCrossovers = new AtomicLong(0);
        
        this.targetMethodDistribution = new ConcurrentHashMap<>();
        this.exceptionTypeDistribution = new ConcurrentHashMap<>();
        this.inputTypeDistribution = new ConcurrentHashMap<>();
    }
    
    /**
     * Updates statistics when a test case is added to the population.
     * 
     * @param testCase The test case being added
     */
    public void updateStatistics(TestCaseExecution testCase) {
        totalTestCases.incrementAndGet();
        
        // Update target method distribution
        String targetKey = testCase.getTargetClassName() + "." + testCase.getTargetMethodName();
        targetMethodDistribution.merge(targetKey, 1, Integer::sum);
        
        // Update input type distribution
        if (testCase.getInputTypes() != null) {
            for (Class<?> type : testCase.getInputTypes()) {
                String typeName = type.getSimpleName();
                inputTypeDistribution.merge(typeName, 1, Integer::sum);
            }
        }
        
        // Update mutation and crossover counts
        totalMutations.addAndGet(testCase.getMutationCount());
        totalCrossovers.addAndGet(testCase.getCrossoverCount());
        
        // Update fitness statistics if test case has been evaluated
        if (testCase.getExecutionMetrics() != null) {
            updateFitnessStatistics(testCase);
        }
    }
    
    /**
     * Updates statistics when a test case is removed from the population.
     * 
     * @param testCase The test case being removed
     */
    public void removeTestCase(TestCaseExecution testCase) {
        totalTestCases.decrementAndGet();
        
        // Update target method distribution
        String targetKey = testCase.getTargetClassName() + "." + testCase.getTargetMethodName();
        targetMethodDistribution.merge(targetKey, -1, (oldValue, decrement) -> 
            oldValue + decrement <= 0 ? null : oldValue + decrement);
        
        // Update input type distribution
        if (testCase.getInputTypes() != null) {
            for (Class<?> type : testCase.getInputTypes()) {
                String typeName = type.getSimpleName();
                inputTypeDistribution.merge(typeName, -1, (oldValue, decrement) -> 
                    oldValue + decrement <= 0 ? null : oldValue + decrement);
            }
        }
        
        // Update mutation and crossover counts
        totalMutations.addAndGet(-testCase.getMutationCount());
        totalCrossovers.addAndGet(-testCase.getCrossoverCount());
        
        // Note: Fitness statistics are not updated here as they require
        // recalculation across the entire population
    }
    
    /**
     * Updates fitness-related statistics for a test case.
     * 
     * @param testCase The test case with updated fitness
     */
    public void updateFitnessStatistics(TestCaseExecution testCase) {
        double fitness = testCase.getFitness();
        
        // Update best and worst fitness
        bestFitness.updateAndGet(current -> Math.max(current, fitness));
        worstFitness.updateAndGet(current -> Math.min(current, fitness));
        
        // Update evaluation counts
        evaluatedTestCases.incrementAndGet();
        
        if (testCase.getExecutionMetrics() != null) {
            if (testCase.getExecutionMetrics().isSuccessful()) {
                successfulTestCases.incrementAndGet();
            } else {
                failedTestCases.incrementAndGet();
                
                // Update exception type distribution
                if (testCase.getExecutionMetrics().isExceptionThrown()) {
                    String exceptionType = testCase.getExecutionMetrics().getExceptionType();
                    if (exceptionType != null) {
                        exceptionTypeDistribution.merge(exceptionType, 1, Integer::sum);
                    }
                }
            }
            
            // Update execution metrics
            totalExecutionTime.addAndGet(testCase.getExecutionMetrics().getExecutionTimeNanos());
            totalMemoryUsage.addAndGet(testCase.getExecutionMetrics().getPeakMemoryBytes());
        }
    }
    
    /**
     * Recalculates all statistics based on the current population.
     * This is useful after major population changes.
     * 
     * @param testCases The current population test cases
     */
    public void recalculateStatistics(List<TestCaseExecution> testCases) {
        if (testCases.isEmpty()) {
            reset();
            return;
        }
        
        // Reset counters
        evaluatedTestCases.set(0);
        successfulTestCases.set(0);
        failedTestCases.set(0);
        totalExecutionTime.set(0);
        totalMemoryUsage.set(0);
        
        double fitnessSum = 0.0;
        double inputSizeSum = 0.0;
        double inputComplexitySum = 0.0;
        int evaluatedCount = 0;
        
        double currentBest = Double.NEGATIVE_INFINITY;
        double currentWorst = Double.POSITIVE_INFINITY;
        
        for (TestCaseExecution testCase : testCases) {
            inputSizeSum += testCase.getInputSize();
            inputComplexitySum += testCase.getInputTypeComplexity();
            
            if (testCase.getExecutionMetrics() != null) {
                evaluatedCount++;
                double fitness = testCase.getFitness();
                fitnessSum += fitness;
                
                currentBest = Math.max(currentBest, fitness);
                currentWorst = Math.min(currentWorst, fitness);
                
                evaluatedTestCases.incrementAndGet();
                
                if (testCase.getExecutionMetrics().isSuccessful()) {
                    successfulTestCases.incrementAndGet();
                } else {
                    failedTestCases.incrementAndGet();
                    
                    if (testCase.getExecutionMetrics().isExceptionThrown()) {
                        String exceptionType = testCase.getExecutionMetrics().getExceptionType();
                        if (exceptionType != null) {
                            exceptionTypeDistribution.merge(exceptionType, 1, Integer::sum);
                        }
                    }
                }
                
                totalExecutionTime.addAndGet(testCase.getExecutionMetrics().getExecutionTimeNanos());
                totalMemoryUsage.addAndGet(testCase.getExecutionMetrics().getPeakMemoryBytes());
            }
        }
        
        // Update statistics
        bestFitness.set(currentBest);
        worstFitness.set(currentWorst);
        averageFitness.set(evaluatedCount > 0 ? fitnessSum / evaluatedCount : 0.0);
        averageInputSize.set(testCases.size() > 0 ? inputSizeSum / testCases.size() : 0.0);
        averageInputComplexity.set(testCases.size() > 0 ? inputComplexitySum / testCases.size() : 0.0);
        
        // Calculate fitness variance
        if (evaluatedCount > 1) {
            double variance = 0.0;
            for (TestCaseExecution testCase : testCases) {
                if (testCase.getExecutionMetrics() != null) {
                    double diff = testCase.getFitness() - averageFitness.get();
                    variance += diff * diff;
                }
            }
            fitnessVariance.set(variance / (evaluatedCount - 1));
        } else {
            fitnessVariance.set(0.0);
        }
    }
    
    /**
     * Updates the population diversity score.
     * 
     * @param diversity The calculated diversity score
     */
    public void setPopulationDiversity(double diversity) {
        this.populationDiversity.set(diversity);
    }
    
    /**
     * Resets all statistics to initial values.
     */
    public void reset() {
        totalTestCases.set(0);
        evaluatedTestCases.set(0);
        successfulTestCases.set(0);
        failedTestCases.set(0);
        
        bestFitness.set(Double.NEGATIVE_INFINITY);
        worstFitness.set(Double.POSITIVE_INFINITY);
        averageFitness.set(0.0);
        fitnessVariance.set(0.0);
        
        averageInputSize.set(0.0);
        averageInputComplexity.set(0.0);
        populationDiversity.set(0.0);
        
        totalExecutionTime.set(0);
        totalMemoryUsage.set(0);
        totalMutations.set(0);
        totalCrossovers.set(0);
        
        targetMethodDistribution.clear();
        exceptionTypeDistribution.clear();
        inputTypeDistribution.clear();
    }
    
    // Getters
    public int getTotalTestCases() { return totalTestCases.get(); }
    public int getEvaluatedTestCases() { return evaluatedTestCases.get(); }
    public int getSuccessfulTestCases() { return successfulTestCases.get(); }
    public int getFailedTestCases() { return failedTestCases.get(); }
    
    public double getBestFitness() { return bestFitness.get(); }
    public double getWorstFitness() { return worstFitness.get(); }
    public double getAverageFitness() { return averageFitness.get(); }
    public double getFitnessVariance() { return fitnessVariance.get(); }
    public double getFitnessStandardDeviation() { return Math.sqrt(fitnessVariance.get()); }
    
    public double getAverageInputSize() { return averageInputSize.get(); }
    public double getAverageInputComplexity() { return averageInputComplexity.get(); }
    public double getPopulationDiversity() { return populationDiversity.get(); }
    
    public long getTotalExecutionTime() { return totalExecutionTime.get(); }
    public long getTotalMemoryUsage() { return totalMemoryUsage.get(); }
    public long getTotalMutations() { return totalMutations.get(); }
    public long getTotalCrossovers() { return totalCrossovers.get(); }
    
    public Map<String, Integer> getTargetMethodDistribution() { 
        return new ConcurrentHashMap<>(targetMethodDistribution); 
    }
    
    public Map<String, Integer> getExceptionTypeDistribution() { 
        return new ConcurrentHashMap<>(exceptionTypeDistribution); 
    }
    
    public Map<String, Integer> getInputTypeDistribution() { 
        return new ConcurrentHashMap<>(inputTypeDistribution); 
    }
    
    /**
     * Gets the success rate of test case executions.
     * 
     * @return Success rate as a percentage (0.0 to 100.0)
     */
    public double getSuccessRate() {
        int evaluated = evaluatedTestCases.get();
        return evaluated > 0 ? (double) successfulTestCases.get() / evaluated * 100.0 : 0.0;
    }
    
    /**
     * Gets the average execution time in milliseconds.
     * 
     * @return Average execution time in milliseconds
     */
    public double getAverageExecutionTimeMs() {
        int evaluated = evaluatedTestCases.get();
        return evaluated > 0 ? (double) totalExecutionTime.get() / evaluated / 1_000_000.0 : 0.0;
    }
    
    /**
     * Gets the average memory usage in megabytes.
     * 
     * @return Average memory usage in MB
     */
    public double getAverageMemoryUsageMb() {
        int evaluated = evaluatedTestCases.get();
        return evaluated > 0 ? (double) totalMemoryUsage.get() / evaluated / (1024.0 * 1024.0) : 0.0;
    }
    
    /**
     * Gets the top N most common target methods.
     * 
     * @param n The number of top methods to return
     * @return List of target methods sorted by frequency
     */
    public List<Map.Entry<String, Integer>> getTopTargetMethods(int n) {
        return targetMethodDistribution.entrySet().stream()
                .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                .limit(n)
                .collect(Collectors.toList());
    }
    
    /**
     * Gets the top N most common exception types.
     * 
     * @param n The number of top exception types to return
     * @return List of exception types sorted by frequency
     */
    public List<Map.Entry<String, Integer>> getTopExceptionTypes(int n) {
        return exceptionTypeDistribution.entrySet().stream()
                .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                .limit(n)
                .collect(Collectors.toList());
    }
    
    /**
     * Gets the top N most common input types.
     * 
     * @param n The number of top input types to return
     * @return List of input types sorted by frequency
     */
    public List<Map.Entry<String, Integer>> getTopInputTypes(int n) {
        return inputTypeDistribution.entrySet().stream()
                .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                .limit(n)
                .collect(Collectors.toList());
    }
    
    @Override
    public String toString() {
        return String.format("PopulationStatistics{size=%d, evaluated=%d, successRate=%.1f%%, " +
                "bestFitness=%.3f, avgFitness=%.3f, diversity=%.3f}",
                totalTestCases.get(), evaluatedTestCases.get(), getSuccessRate(),
                bestFitness.get(), averageFitness.get(), populationDiversity.get());
    }
} 