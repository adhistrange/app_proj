package com.securityresearch.fuzzer.core.fitness;

import com.securityresearch.fuzzer.core.execution.TestCaseExecution;
import com.securityresearch.fuzzer.core.execution.ExecutionMetrics;

/**
 * Interface for fitness functions that evaluate the performance characteristics
 * of test cases to guide the genetic algorithm evolution.
 * 
 * @param <T> The type of test case being evaluated
 */
public interface FitnessFunction<T> {
    
    /**
     * Evaluates the fitness of a test case based on its execution metrics.
     * Higher fitness values indicate better candidates for discovering vulnerabilities.
     * 
     * @param testCase The test case to evaluate
     * @param metrics The execution metrics from running the test case
     * @return A fitness score (higher is better)
     */
    double evaluate(T testCase, ExecutionMetrics metrics);
    
    /**
     * Determines if a test case should be considered for further evolution
     * based on its fitness score.
     * 
     * @param fitness The calculated fitness score
     * @return true if the test case should be retained, false otherwise
     */
    boolean shouldRetain(double fitness);
    
    /**
     * Gets the name of this fitness function for logging and reporting.
     * 
     * @return The fitness function name
     */
    String getName();
}

/**
 * Multi-objective fitness function that considers both execution time and memory usage
 * to identify potential algorithmic complexity vulnerabilities.
 */
class ComplexityVulnerabilityFitness implements FitnessFunction<TestCaseExecution> {
    
    private final double timeWeight;
    private final double memoryWeight;
    private final double baselineTime;
    private final double baselineMemory;
    private final double amplificationThreshold;
    
    public ComplexityVulnerabilityFitness(double timeWeight, double memoryWeight, 
                                        double baselineTime, double baselineMemory,
                                        double amplificationThreshold) {
        this.timeWeight = timeWeight;
        this.memoryWeight = memoryWeight;
        this.baselineTime = baselineTime;
        this.baselineMemory = baselineMemory;
        this.amplificationThreshold = amplificationThreshold;
    }
    
    @Override
    public double evaluate(TestCaseExecution testCase, ExecutionMetrics metrics) {
        if (metrics == null || !metrics.isSuccessful()) {
            return 0.0; // Failed executions get zero fitness
        }
        
        // Calculate amplification factors
        double timeAmplification = metrics.getExecutionTimeNanos() / baselineTime;
        double memoryAmplification = metrics.getPeakMemoryBytes() / baselineMemory;
        
        // Penalize if amplification is below threshold (not interesting)
        if (timeAmplification < amplificationThreshold && memoryAmplification < amplificationThreshold) {
            return 0.1; // Minimal fitness for non-amplifying cases
        }
        
        // Calculate weighted fitness score
        double timeFitness = Math.log(timeAmplification) * timeWeight;
        double memoryFitness = Math.log(memoryAmplification) * memoryWeight;
        
        // Bonus for cases that amplify both time and memory
        double synergyBonus = 0.0;
        if (timeAmplification > amplificationThreshold && memoryAmplification > amplificationThreshold) {
            synergyBonus = Math.min(timeAmplification, memoryAmplification) * 0.5;
        }
        
        return timeFitness + memoryFitness + synergyBonus;
    }
    
    @Override
    public boolean shouldRetain(double fitness) {
        return fitness > 0.5; // Retain cases with meaningful fitness
    }
    
    @Override
    public String getName() {
        return "ComplexityVulnerabilityFitness";
    }
}

/**
 * Fitness function focused on discovering worst-case algorithmic complexity.
 * Rewards test cases that demonstrate exponential or polynomial growth patterns.
 */
class WorstCaseComplexityFitness implements FitnessFunction<TestCaseExecution> {
    
    private final double exponentialBonus;
    private final double polynomialBonus;
    private final double linearPenalty;
    
    public WorstCaseComplexityFitness(double exponentialBonus, double polynomialBonus, double linearPenalty) {
        this.exponentialBonus = exponentialBonus;
        this.polynomialBonus = polynomialBonus;
        this.linearPenalty = linearPenalty;
    }
    
    @Override
    public double evaluate(TestCaseExecution testCase, ExecutionMetrics metrics) {
        if (metrics == null || !metrics.isSuccessful()) {
            return 0.0;
        }
        
        double inputSize = testCase.getInputSize();
        double executionTime = metrics.getExecutionTimeNanos();
        
        if (inputSize <= 1) {
            return 0.1; // Minimal fitness for trivial inputs
        }
        
        // Estimate complexity based on input size vs execution time relationship
        double complexityRatio = executionTime / (inputSize * Math.log(inputSize));
        
        // Classify complexity and assign fitness
        if (complexityRatio > 1000) {
            // Likely exponential or worse
            return exponentialBonus * complexityRatio;
        } else if (complexityRatio > 100) {
            // Likely polynomial (quadratic or cubic)
            return polynomialBonus * complexityRatio;
        } else if (complexityRatio > 10) {
            // Likely linear or log-linear
            return complexityRatio;
        } else {
            // Likely constant or sub-linear
            return complexityRatio * linearPenalty;
        }
    }
    
    @Override
    public boolean shouldRetain(double fitness) {
        return fitness > 1.0; // Retain cases with significant complexity
    }
    
    @Override
    public String getName() {
        return "WorstCaseComplexityFitness";
    }
}

/**
 * Fitness function that rewards diversity in test case characteristics
 * to maintain population variety and avoid premature convergence.
 */
class DiversityFitness implements FitnessFunction<TestCaseExecution> {
    
    private final double noveltyWeight;
    private final double uniquenessWeight;
    
    public DiversityFitness(double noveltyWeight, double uniquenessWeight) {
        this.noveltyWeight = noveltyWeight;
        this.uniquenessWeight = uniquenessWeight;
    }
    
    @Override
    public double evaluate(TestCaseExecution testCase, ExecutionMetrics metrics) {
        if (metrics == null) {
            return 0.0;
        }
        
        // Calculate novelty based on input characteristics
        double inputNovelty = calculateInputNovelty(testCase);
        
        // Calculate uniqueness based on execution pattern
        double executionUniqueness = calculateExecutionUniqueness(metrics);
        
        return (inputNovelty * noveltyWeight) + (executionUniqueness * uniquenessWeight);
    }
    
    private double calculateInputNovelty(TestCaseExecution testCase) {
        // Simple novelty calculation based on input size and type diversity
        double sizeNovelty = Math.log(testCase.getInputSize() + 1);
        double typeNovelty = testCase.getInputTypeComplexity();
        
        return sizeNovelty * typeNovelty;
    }
    
    private double calculateExecutionUniqueness(ExecutionMetrics metrics) {
        // Calculate uniqueness based on execution characteristics
        double timeUniqueness = Math.log(metrics.getExecutionTimeNanos() + 1);
        double memoryUniqueness = Math.log(metrics.getPeakMemoryBytes() + 1);
        double cpuUniqueness = metrics.getCpuUsagePercent();
        
        return (timeUniqueness + memoryUniqueness + cpuUniqueness) / 3.0;
    }
    
    @Override
    public boolean shouldRetain(double fitness) {
        return fitness > 0.3; // Retain diverse cases
    }
    
    @Override
    public String getName() {
        return "DiversityFitness";
    }
} 