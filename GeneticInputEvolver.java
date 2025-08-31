package com.securityresearch.fuzzer.core.genetic;

import com.securityresearch.fuzzer.core.config.FuzzerConfiguration;
import com.securityresearch.fuzzer.core.exception.FuzzerException;
import com.securityresearch.fuzzer.core.execution.TestCaseExecution;
import com.securityresearch.fuzzer.core.fitness.FitnessFunction;
import com.securityresearch.fuzzer.core.input.InputGenerator;
import com.securityresearch.fuzzer.core.population.Population;
import com.securityresearch.fuzzer.core.population.PopulationStatistics;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.lang.reflect.Method;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Core genetic algorithm engine for evolving test cases to discover
 * algorithmic complexity vulnerabilities in Java libraries.
 */
@Component
public class GeneticInputEvolver {
    
    private static final Logger logger = LoggerFactory.getLogger(GeneticInputEvolver.class);
    
    private final FuzzerConfiguration configuration;
    private final InputGenerator inputGenerator;
    private final GeneticOperators geneticOperators;
    private final AtomicInteger generationCounter;
    
    public GeneticInputEvolver(FuzzerConfiguration configuration) {
        this.configuration = configuration;
        this.inputGenerator = new InputGenerator();
        this.geneticOperators = new GeneticOperators(configuration);
        this.generationCounter = new AtomicInteger(0);
    }
    
    /**
     * Evolves test cases for a target method to discover vulnerabilities.
     * 
     * @param targetMethod The method to fuzz
     * @param fitnessFunction The fitness function to evaluate test cases
     * @param executionHarness The execution harness to run test cases
     * @return Evolution results with discovered vulnerabilities
     */
    public EvolutionResult evolveTestCases(Method targetMethod, 
                                         FitnessFunction<TestCaseExecution> fitnessFunction,
                                         Population.ExecutionHarness executionHarness) {
        
        logger.info("Starting evolution for method: {}.{}", 
                targetMethod.getDeclaringClass().getName(), targetMethod.getName());
        
        // Initialize population
        Population population = initializePopulation(targetMethod, fitnessFunction);
        
        // Evolution parameters
        int maxGenerations = configuration.getGeneticAlgorithm().getMaxGenerations();
        int stagnationLimit = configuration.getGeneticAlgorithm().getStagnationLimit();
        double diversityThreshold = configuration.getGeneticAlgorithm().getDiversityThreshold();
        
        // Evolution tracking
        List<TestCaseExecution> bestTestCases = new ArrayList<>();
        double bestFitness = Double.NEGATIVE_INFINITY;
        int stagnationCount = 0;
        int generation = 0;
        
        // Evolution loop
        while (generation < maxGenerations) {
            logger.info("Generation {}: Population size = {}, Best fitness = {:.3f}", 
                    generation, population.getSize(), 
                    population.getBestTestCase() != null ? population.getBestTestCase().getFitness() : 0.0);
            
            // Evaluate current population
            population.evaluateAll(executionHarness);
            
            // Update best test cases
            TestCaseExecution currentBest = population.getBestTestCase();
            if (currentBest != null && currentBest.getFitness() > bestFitness) {
                bestFitness = currentBest.getFitness();
                bestTestCases.add(currentBest);
                stagnationCount = 0;
                logger.info("New best fitness: {:.3f} for test case {}", 
                        bestFitness, currentBest.getTestCaseId());
            } else {
                stagnationCount++;
            }
            
            // Check for stagnation
            if (stagnationCount >= stagnationLimit) {
                logger.info("Evolution stagnated for {} generations, stopping", stagnationLimit);
                break;
            }
            
            // Check population diversity
            double diversity = population.calculateDiversity();
            population.getStatistics().setPopulationDiversity(diversity);
            
            if (diversity < diversityThreshold) {
                logger.info("Population diversity too low ({:.3f}), injecting diversity", diversity);
                injectDiversity(population, targetMethod);
            }
            
            // Generate next generation
            Population nextGeneration = generateNextGeneration(population, targetMethod);
            
            // Replace current population
            population.replacePopulation(nextGeneration.getAllTestCases());
            
            generation++;
            generationCounter.incrementAndGet();
            
            // Log statistics
            logGenerationStatistics(population, generation);
        }
        
        logger.info("Evolution completed after {} generations. Best fitness: {:.3f}", 
                generation, bestFitness);
        
        return new EvolutionResult(bestTestCases, population, generation, bestFitness);
    }
    
    /**
     * Initializes the initial population for evolution.
     * 
     * @param targetMethod The target method
     * @param fitnessFunction The fitness function
     * @return Initialized population
     */
    private Population initializePopulation(Method targetMethod, 
                                          FitnessFunction<TestCaseExecution> fitnessFunction) {
        
        int populationSize = configuration.getGeneticAlgorithm().getPopulationSize();
        List<TestCaseExecution> initialTestCases = new ArrayList<>();
        
        // Generate random test cases
        int randomCount = populationSize / 2;
        for (int i = 0; i < randomCount; i++) {
            initialTestCases.add(inputGenerator.generateTestCase(targetMethod));
        }
        
        // Generate edge cases
        List<TestCaseExecution> edgeCases = inputGenerator.generateEdgeCases(targetMethod);
        initialTestCases.addAll(edgeCases);
        
        // Fill remaining with more random cases
        while (initialTestCases.size() < populationSize) {
            initialTestCases.add(inputGenerator.generateTestCase(targetMethod));
        }
        
        // Trim to exact population size
        if (initialTestCases.size() > populationSize) {
            initialTestCases = initialTestCases.subList(0, populationSize);
        }
        
        logger.info("Initialized population with {} test cases", initialTestCases.size());
        
        return Population.builder()
                .maxSize(populationSize)
                .generation(0)
                .initialTestCases(initialTestCases)
                .fitnessFunction(fitnessFunction)
                .build();
    }
    
    /**
     * Generates the next generation using genetic operators.
     * 
     * @param currentPopulation The current population
     * @param targetMethod The target method
     * @return Next generation population
     */
    private Population generateNextGeneration(Population currentPopulation, Method targetMethod) {
        
        FuzzerConfiguration.GeneticAlgorithm config = configuration.getGeneticAlgorithm();
        int populationSize = config.getPopulationSize();
        double elitismRate = config.getElitismRate();
        double crossoverRate = config.getCrossoverRate();
        double mutationRate = config.getMutationRate();
        
        List<TestCaseExecution> nextGeneration = new ArrayList<>();
        
        // Elitism: Keep best individuals
        int eliteCount = (int) (populationSize * elitismRate);
        List<TestCaseExecution> elite = currentPopulation.getTopTestCases(eliteCount);
        nextGeneration.addAll(elite);
        
        // Generate offspring through crossover and mutation
        while (nextGeneration.size() < populationSize) {
            TestCaseExecution offspring = null;
            
            if (random.nextDouble() < crossoverRate) {
                // Perform crossover
                List<TestCaseExecution> parents = currentPopulation.tournamentSelection(
                        config.getTournamentSize(), 2);
                
                if (parents.size() >= 2) {
                    offspring = geneticOperators.crossover(parents.get(0), parents.get(1));
                }
            }
            
            if (offspring == null) {
                // Perform mutation on a single parent
                List<TestCaseExecution> parent = currentPopulation.tournamentSelection(
                        config.getTournamentSize(), 1);
                
                if (!parent.isEmpty()) {
                    offspring = geneticOperators.mutate(parent.get(0));
                }
            }
            
            if (offspring != null) {
                nextGeneration.add(offspring);
            } else {
                // Fallback: generate new random test case
                nextGeneration.add(inputGenerator.generateTestCase(targetMethod));
            }
        }
        
        // Trim to exact population size
        if (nextGeneration.size() > populationSize) {
            nextGeneration = nextGeneration.subList(0, populationSize);
        }
        
        return Population.builder()
                .maxSize(populationSize)
                .generation(currentPopulation.getGeneration() + 1)
                .initialTestCases(nextGeneration)
                .fitnessFunction(currentPopulation.getFitnessFunction())
                .build();
    }
    
    /**
     * Injects diversity into the population to prevent premature convergence.
     * 
     * @param population The current population
     * @param targetMethod The target method
     */
    private void injectDiversity(Population population, Method targetMethod) {
        
        // Remove worst 20% of population
        int removeCount = population.getSize() / 5;
        population.removeWorstTestCases(removeCount);
        
        // Add diverse test cases
        List<TestCaseExecution> diverseTestCases = new ArrayList<>();
        
        // Generate edge cases
        diverseTestCases.addAll(inputGenerator.generateEdgeCases(targetMethod));
        
        // Generate test cases with different strategies
        for (int i = 0; i < removeCount - diverseTestCases.size(); i++) {
            diverseTestCases.add(inputGenerator.generateTestCase(targetMethod));
        }
        
        // Add to population
        for (TestCaseExecution testCase : diverseTestCases) {
            if (diverseTestCases.size() < removeCount) {
                population.addTestCase(testCase);
            }
        }
        
        logger.info("Injected {} diverse test cases into population", diverseTestCases.size());
    }
    
    /**
     * Logs statistics for the current generation.
     * 
     * @param population The current population
     * @param generation The generation number
     */
    private void logGenerationStatistics(Population population, int generation) {
        
        PopulationStatistics stats = population.getStatistics();
        
        logger.debug("Generation {} Statistics:", generation);
        logger.debug("  Population Size: {}", population.getSize());
        logger.debug("  Evaluated: {}", stats.getEvaluatedTestCases());
        logger.debug("  Success Rate: {:.1f}%", stats.getSuccessRate());
        logger.debug("  Best Fitness: {:.3f}", stats.getBestFitness());
        logger.debug("  Average Fitness: {:.3f}", stats.getAverageFitness());
        logger.debug("  Fitness Std Dev: {:.3f}", stats.getFitnessStandardDeviation());
        logger.debug("  Diversity: {:.3f}", stats.getPopulationDiversity());
        logger.debug("  Average Execution Time: {:.2f}ms", stats.getAverageExecutionTimeMs());
        logger.debug("  Average Memory Usage: {:.2f}MB", stats.getAverageMemoryUsageMb());
        
        // Log top exception types
        List<Map.Entry<String, Integer>> topExceptions = stats.getTopExceptionTypes(3);
        if (!topExceptions.isEmpty()) {
            logger.debug("  Top Exception Types: {}", topExceptions);
        }
    }
    
    /**
     * Gets the current generation counter.
     * 
     * @return Current generation number
     */
    public int getCurrentGeneration() {
        return generationCounter.get();
    }
    
    /**
     * Resets the generation counter.
     */
    public void resetGenerationCounter() {
        generationCounter.set(0);
    }
    
    /**
     * Result of the evolution process containing discovered vulnerabilities.
     */
    public static class EvolutionResult {
        private final List<TestCaseExecution> bestTestCases;
        private final Population finalPopulation;
        private final int generationsCompleted;
        private final double bestFitness;
        
        public EvolutionResult(List<TestCaseExecution> bestTestCases, 
                             Population finalPopulation,
                             int generationsCompleted, 
                             double bestFitness) {
            this.bestTestCases = bestTestCases;
            this.finalPopulation = finalPopulation;
            this.generationsCompleted = generationsCompleted;
            this.bestFitness = bestFitness;
        }
        
        public List<TestCaseExecution> getBestTestCases() { return bestTestCases; }
        public Population getFinalPopulation() { return finalPopulation; }
        public int getGenerationsCompleted() { return generationsCompleted; }
        public double getBestFitness() { return bestFitness; }
        
        /**
         * Gets test cases that likely represent vulnerabilities.
         * 
         * @param fitnessThreshold Minimum fitness to consider a vulnerability
         * @return List of potential vulnerability test cases
         */
        public List<TestCaseExecution> getPotentialVulnerabilities(double fitnessThreshold) {
            return bestTestCases.stream()
                    .filter(testCase -> testCase.getFitness() >= fitnessThreshold)
                    .toList();
        }
        
        /**
         * Gets the most promising test case for further analysis.
         * 
         * @return The test case with the highest fitness
         */
        public TestCaseExecution getMostPromisingTestCase() {
            return bestTestCases.stream()
                    .max(Comparator.comparing(TestCaseExecution::getFitness))
                    .orElse(null);
        }
    }
    
    // Random instance for evolution decisions
    private final Random random = new Random();
} 