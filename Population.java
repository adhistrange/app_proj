package com.securityresearch.fuzzer.core.population;

import com.securityresearch.fuzzer.core.execution.TestCaseExecution;
import com.securityresearch.fuzzer.core.fitness.FitnessFunction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

/**
 * Manages a population of test cases for the genetic algorithm.
 * Provides fitness tracking, diversity maintenance, and evolutionary operations.
 */
public class Population {
    
    private static final Logger logger = LoggerFactory.getLogger(Population.class);
    
    private final String populationId;
    private final int maxSize;
    private final int generation;
    private final Map<String, TestCaseExecution> testCases;
    private final AtomicInteger nextTestCaseId;
    private final FitnessFunction<TestCaseExecution> fitnessFunction;
    private final PopulationStatistics statistics;
    
    private Population(Builder builder) {
        this.populationId = builder.populationId;
        this.maxSize = builder.maxSize;
        this.generation = builder.generation;
        this.testCases = new ConcurrentHashMap<>();
        this.nextTestCaseId = new AtomicInteger(1);
        this.fitnessFunction = builder.fitnessFunction;
        this.statistics = new PopulationStatistics();
        
        if (builder.initialTestCases != null) {
            builder.initialTestCases.forEach(this::addTestCase);
        }
    }
    
    /**
     * Adds a test case to the population.
     * 
     * @param testCase The test case to add
     * @return true if added successfully, false if population is full
     */
    public boolean addTestCase(TestCaseExecution testCase) {
        if (testCases.size() >= maxSize) {
            logger.warn("Population {} is full (size: {}), cannot add test case", populationId, maxSize);
            return false;
        }
        
        testCases.put(testCase.getTestCaseId(), testCase);
        statistics.updateStatistics(testCase);
        logger.debug("Added test case {} to population {} (size: {})", 
                testCase.getTestCaseId(), populationId, testCases.size());
        return true;
    }
    
    /**
     * Removes a test case from the population.
     * 
     * @param testCaseId The ID of the test case to remove
     * @return The removed test case, or null if not found
     */
    public TestCaseExecution removeTestCase(String testCaseId) {
        TestCaseExecution removed = testCases.remove(testCaseId);
        if (removed != null) {
            statistics.removeTestCase(removed);
            logger.debug("Removed test case {} from population {}", testCaseId, populationId);
        }
        return removed;
    }
    
    /**
     * Gets a test case by ID.
     * 
     * @param testCaseId The test case ID
     * @return The test case, or null if not found
     */
    public TestCaseExecution getTestCase(String testCaseId) {
        return testCases.get(testCaseId);
    }
    
    /**
     * Gets all test cases in the population.
     * 
     * @return A list of all test cases
     */
    public List<TestCaseExecution> getAllTestCases() {
        return new ArrayList<>(testCases.values());
    }
    
    /**
     * Gets test cases sorted by fitness (descending).
     * 
     * @return Test cases sorted by fitness
     */
    public List<TestCaseExecution> getTestCasesByFitness() {
        return testCases.values().stream()
                .sorted(Comparator.comparing(TestCaseExecution::getFitness).reversed())
                .collect(Collectors.toList());
    }
    
    /**
     * Gets the top N test cases by fitness.
     * 
     * @param n The number of top test cases to return
     * @return The top N test cases
     */
    public List<TestCaseExecution> getTopTestCases(int n) {
        return getTestCasesByFitness().stream()
                .limit(n)
                .collect(Collectors.toList());
    }
    
    /**
     * Gets the best test case in the population.
     * 
     * @return The test case with the highest fitness, or null if population is empty
     */
    public TestCaseExecution getBestTestCase() {
        return testCases.values().stream()
                .max(Comparator.comparing(TestCaseExecution::getFitness))
                .orElse(null);
    }
    
    /**
     * Gets the worst test case in the population.
     * 
     * @return The test case with the lowest fitness, or null if population is empty
     */
    public TestCaseExecution getWorstTestCase() {
        return testCases.values().stream()
                .min(Comparator.comparing(TestCaseExecution::getFitness))
                .orElse(null);
    }
    
    /**
     * Selects test cases using tournament selection.
     * 
     * @param tournamentSize The size of each tournament
     * @param numSelections The number of selections to make
     * @return Selected test cases
     */
    public List<TestCaseExecution> tournamentSelection(int tournamentSize, int numSelections) {
        List<TestCaseExecution> selected = new ArrayList<>();
        Random random = new Random();
        List<TestCaseExecution> testCaseList = getAllTestCases();
        
        if (testCaseList.isEmpty()) {
            return selected;
        }
        
        for (int i = 0; i < numSelections; i++) {
            TestCaseExecution best = null;
            double bestFitness = Double.NEGATIVE_INFINITY;
            
            // Run tournament
            for (int j = 0; j < tournamentSize; j++) {
                TestCaseExecution candidate = testCaseList.get(random.nextInt(testCaseList.size()));
                if (candidate.getFitness() > bestFitness) {
                    best = candidate;
                    bestFitness = candidate.getFitness();
                }
            }
            
            if (best != null) {
                selected.add(best);
            }
        }
        
        return selected;
    }
    
    /**
     * Selects test cases using roulette wheel selection.
     * 
     * @param numSelections The number of selections to make
     * @return Selected test cases
     */
    public List<TestCaseExecution> rouletteWheelSelection(int numSelections) {
        List<TestCaseExecution> selected = new ArrayList<>();
        List<TestCaseExecution> testCaseList = getAllTestCases();
        
        if (testCaseList.isEmpty()) {
            return selected;
        }
        
        // Calculate total fitness
        double totalFitness = testCaseList.stream()
                .mapToDouble(TestCaseExecution::getFitness)
                .sum();
        
        if (totalFitness <= 0) {
            // If all fitness values are zero or negative, use uniform selection
            Random random = new Random();
            for (int i = 0; i < numSelections; i++) {
                selected.add(testCaseList.get(random.nextInt(testCaseList.size())));
            }
            return selected;
        }
        
        Random random = new Random();
        for (int i = 0; i < numSelections; i++) {
            double randomValue = random.nextDouble() * totalFitness;
            double cumulativeFitness = 0.0;
            
            for (TestCaseExecution testCase : testCaseList) {
                cumulativeFitness += testCase.getFitness();
                if (cumulativeFitness >= randomValue) {
                    selected.add(testCase);
                    break;
                }
            }
        }
        
        return selected;
    }
    
    /**
     * Calculates the diversity of the population.
     * 
     * @return Diversity score (0.0 = no diversity, 1.0 = maximum diversity)
     */
    public double calculateDiversity() {
        List<TestCaseExecution> testCaseList = getAllTestCases();
        if (testCaseList.size() < 2) {
            return 0.0;
        }
        
        double totalDistance = 0.0;
        int comparisons = 0;
        
        for (int i = 0; i < testCaseList.size(); i++) {
            for (int j = i + 1; j < testCaseList.size(); j++) {
                totalDistance += calculateDistance(testCaseList.get(i), testCaseList.get(j));
                comparisons++;
            }
        }
        
        return comparisons > 0 ? totalDistance / comparisons : 0.0;
    }
    
    /**
     * Removes the worst test cases to maintain population size.
     * 
     * @param numToRemove The number of test cases to remove
     */
    public void removeWorstTestCases(int numToRemove) {
        List<TestCaseExecution> sorted = getTestCasesByFitness();
        int removeCount = Math.min(numToRemove, sorted.size());
        
        for (int i = sorted.size() - removeCount; i < sorted.size(); i++) {
            removeTestCase(sorted.get(i).getTestCaseId());
        }
        
        logger.debug("Removed {} worst test cases from population {}", removeCount, populationId);
    }
    
    /**
     * Replaces the entire population with new test cases.
     * 
     * @param newTestCases The new test cases
     */
    public void replacePopulation(List<TestCaseExecution> newTestCases) {
        testCases.clear();
        statistics.reset();
        
        int added = 0;
        for (TestCaseExecution testCase : newTestCases) {
            if (added < maxSize) {
                addTestCase(testCase);
                added++;
            }
        }
        
        logger.info("Replaced population {} with {} test cases", populationId, added);
    }
    
    /**
     * Updates the fitness of a test case.
     * 
     * @param testCaseId The test case ID
     * @param newFitness The new fitness value
     * @param metrics The execution metrics
     */
    public void updateFitness(String testCaseId, double newFitness, 
                            com.securityresearch.fuzzer.core.execution.ExecutionMetrics metrics) {
        TestCaseExecution testCase = testCases.get(testCaseId);
        if (testCase != null) {
            TestCaseExecution updated = testCase.withExecutionResults(newFitness, metrics);
            testCases.put(testCaseId, updated);
            statistics.updateStatistics(updated);
            logger.debug("Updated fitness for test case {}: {}", testCaseId, newFitness);
        }
    }
    
    /**
     * Evaluates all test cases in the population using the fitness function.
     * 
     * @param executionHarness The execution harness to run test cases
     */
    public void evaluateAll(ExecutionHarness executionHarness) {
        logger.info("Evaluating {} test cases in population {}", testCases.size(), populationId);
        
        for (TestCaseExecution testCase : getAllTestCases()) {
            try {
                com.securityresearch.fuzzer.core.execution.ExecutionMetrics metrics = 
                    executionHarness.execute(testCase);
                double fitness = fitnessFunction.evaluate(testCase, metrics);
                updateFitness(testCase.getTestCaseId(), fitness, metrics);
            } catch (Exception e) {
                logger.error("Failed to evaluate test case {}: {}", testCase.getTestCaseId(), e.getMessage());
                updateFitness(testCase.getTestCaseId(), 0.0, null);
            }
        }
        
        logger.info("Population {} evaluation complete. Best fitness: {}", 
                populationId, getBestTestCase() != null ? getBestTestCase().getFitness() : 0.0);
    }
    
    private double calculateDistance(TestCaseExecution testCase1, TestCaseExecution testCase2) {
        // Simple distance calculation based on input characteristics
        double sizeDiff = Math.abs(testCase1.getInputSize() - testCase2.getInputSize());
        double typeDiff = Math.abs(testCase1.getInputTypeComplexity() - testCase2.getInputTypeComplexity());
        double fitnessDiff = Math.abs(testCase1.getFitness() - testCase2.getFitness());
        
        return (sizeDiff + typeDiff + fitnessDiff) / 3.0;
    }
    
    // Getters
    public String getPopulationId() { return populationId; }
    public int getMaxSize() { return maxSize; }
    public int getGeneration() { return generation; }
    public int getSize() { return testCases.size(); }
    public boolean isEmpty() { return testCases.isEmpty(); }
    public boolean isFull() { return testCases.size() >= maxSize; }
    public FitnessFunction<TestCaseExecution> getFitnessFunction() { return fitnessFunction; }
    public PopulationStatistics getStatistics() { return statistics; }
    
    @Override
    public String toString() {
        return String.format("Population{id=%s, size=%d/%d, generation=%d, bestFitness=%.3f}",
                populationId, testCases.size(), maxSize, generation,
                getBestTestCase() != null ? getBestTestCase().getFitness() : 0.0);
    }
    
    /**
     * Builder pattern for creating Population instances.
     */
    public static class Builder {
        private String populationId = UUID.randomUUID().toString();
        private int maxSize = 100;
        private int generation = 0;
        private List<TestCaseExecution> initialTestCases;
        private FitnessFunction<TestCaseExecution> fitnessFunction;
        
        public Builder populationId(String populationId) {
            this.populationId = populationId;
            return this;
        }
        
        public Builder maxSize(int maxSize) {
            this.maxSize = maxSize;
            return this;
        }
        
        public Builder generation(int generation) {
            this.generation = generation;
            return this;
        }
        
        public Builder initialTestCases(List<TestCaseExecution> initialTestCases) {
            this.initialTestCases = initialTestCases;
            return this;
        }
        
        public Builder fitnessFunction(FitnessFunction<TestCaseExecution> fitnessFunction) {
            this.fitnessFunction = fitnessFunction;
            return this;
        }
        
        public Population build() {
            if (fitnessFunction == null) {
                throw new IllegalArgumentException("Fitness function is required");
            }
            return new Population(this);
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
    
    /**
     * Simple interface for execution harness to avoid circular dependencies.
     */
    public interface ExecutionHarness {
        com.securityresearch.fuzzer.core.execution.ExecutionMetrics execute(TestCaseExecution testCase);
    }
} 