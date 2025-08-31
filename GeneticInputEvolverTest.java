package com.securityresearch.fuzzer.core;

import com.securityresearch.fuzzer.core.config.FuzzerConfiguration;
import com.securityresearch.fuzzer.core.execution.ExecutionMetrics;
import com.securityresearch.fuzzer.core.execution.TestCaseExecution;
import com.securityresearch.fuzzer.core.fitness.FitnessFunction;
import com.securityresearch.fuzzer.core.genetic.GeneticInputEvolver;
import com.securityresearch.fuzzer.core.population.Population;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class GeneticInputEvolverTest {
    
    private GeneticInputEvolver evolver;
    private FuzzerConfiguration configuration;
    
    @Mock
    private Population.ExecutionHarness executionHarness;
    
    @BeforeEach
    void setUp() {
        configuration = new FuzzerConfiguration();
        // Configure for faster testing
        configuration.getGeneticAlgorithm().setPopulationSize(10);
        configuration.getGeneticAlgorithm().setMaxGenerations(5);
        configuration.getGeneticAlgorithm().setStagnationLimit(3);
        
        evolver = new GeneticInputEvolver(configuration);
    }
    
    @Test
    void testEvolveTestCases_ShouldCompleteEvolution() throws Exception {
        // Arrange
        Method targetMethod = String.class.getMethod("contains", CharSequence.class);
        FitnessFunction<TestCaseExecution> fitnessFunction = createMockFitnessFunction();
        
        // Mock execution harness to return successful metrics
        when(executionHarness.execute(any(TestCaseExecution.class)))
                .thenReturn(createMockExecutionMetrics(true));
        
        // Act
        GeneticInputEvolver.EvolutionResult result = evolver.evolveTestCases(
                targetMethod, fitnessFunction, executionHarness);
        
        // Assert
        assertNotNull(result);
        assertNotNull(result.getBestTestCases());
        assertTrue(result.getGenerationsCompleted() > 0);
        assertTrue(result.getBestFitness() >= 0.0);
        assertNotNull(result.getFinalPopulation());
        assertEquals(10, result.getFinalPopulation().getSize());
    }
    
    @Test
    void testEvolveTestCases_ShouldHandleFailedExecutions() throws Exception {
        // Arrange
        Method targetMethod = String.class.getMethod("contains", CharSequence.class);
        FitnessFunction<TestCaseExecution> fitnessFunction = createMockFitnessFunction();
        
        // Mock execution harness to return failed metrics
        when(executionHarness.execute(any(TestCaseExecution.class)))
                .thenReturn(createMockExecutionMetrics(false));
        
        // Act
        GeneticInputEvolver.EvolutionResult result = evolver.evolveTestCases(
                targetMethod, fitnessFunction, executionHarness);
        
        // Assert
        assertNotNull(result);
        assertNotNull(result.getBestTestCases());
        // Should still complete evolution even with failed executions
        assertTrue(result.getGenerationsCompleted() > 0);
    }
    
    @Test
    void testEvolveTestCases_ShouldHandleStagnation() throws Exception {
        // Arrange
        Method targetMethod = String.class.getMethod("contains", CharSequence.class);
        FitnessFunction<TestCaseExecution> fitnessFunction = createMockFitnessFunction();
        
        // Mock execution harness to return consistent metrics (causing stagnation)
        when(executionHarness.execute(any(TestCaseExecution.class)))
                .thenReturn(createMockExecutionMetrics(true));
        
        // Act
        GeneticInputEvolver.EvolutionResult result = evolver.evolveTestCases(
                targetMethod, fitnessFunction, executionHarness);
        
        // Assert
        assertNotNull(result);
        // Should stop due to stagnation
        assertTrue(result.getGenerationsCompleted() <= configuration.getGeneticAlgorithm().getStagnationLimit());
    }
    
    @Test
    void testEvolveTestCases_ShouldMaintainPopulationSize() throws Exception {
        // Arrange
        Method targetMethod = String.class.getMethod("contains", CharSequence.class);
        FitnessFunction<TestCaseExecution> fitnessFunction = createMockFitnessFunction();
        
        when(executionHarness.execute(any(TestCaseExecution.class)))
                .thenReturn(createMockExecutionMetrics(true));
        
        // Act
        GeneticInputEvolver.EvolutionResult result = evolver.evolveTestCases(
                targetMethod, fitnessFunction, executionHarness);
        
        // Assert
        Population finalPopulation = result.getFinalPopulation();
        assertEquals(configuration.getGeneticAlgorithm().getPopulationSize(), finalPopulation.getSize());
    }
    
    @Test
    void testEvolveTestCases_ShouldGenerateDiverseTestCases() throws Exception {
        // Arrange
        Method targetMethod = String.class.getMethod("contains", CharSequence.class);
        FitnessFunction<TestCaseExecution> fitnessFunction = createMockFitnessFunction();
        
        when(executionHarness.execute(any(TestCaseExecution.class)))
                .thenReturn(createMockExecutionMetrics(true));
        
        // Act
        GeneticInputEvolver.EvolutionResult result = evolver.evolveTestCases(
                targetMethod, fitnessFunction, executionHarness);
        
        // Assert
        List<TestCaseExecution> allTestCases = result.getFinalPopulation().getAllTestCases();
        
        // Check that we have different inputs
        List<String> inputStrings = new ArrayList<>();
        for (TestCaseExecution testCase : allTestCases) {
            if (testCase.getInputs() != null && testCase.getInputs().length > 0) {
                Object input = testCase.getInputs()[0];
                if (input instanceof String) {
                    inputStrings.add((String) input);
                }
            }
        }
        
        // Should have some diversity in inputs
        assertTrue(inputStrings.size() > 1);
        assertTrue(inputStrings.stream().distinct().count() > 1);
    }
    
    @Test
    void testEvolveTestCases_ShouldTrackEvolutionProgress() throws Exception {
        // Arrange
        Method targetMethod = String.class.getMethod("contains", CharSequence.class);
        FitnessFunction<TestCaseExecution> fitnessFunction = createMockFitnessFunction();
        
        when(executionHarness.execute(any(TestCaseExecution.class)))
                .thenReturn(createMockExecutionMetrics(true));
        
        // Act
        GeneticInputEvolver.EvolutionResult result = evolver.evolveTestCases(
                targetMethod, fitnessFunction, executionHarness);
        
        // Assert
        assertTrue(result.getGenerationsCompleted() > 0);
        assertTrue(result.getGenerationsCompleted() <= configuration.getGeneticAlgorithm().getMaxGenerations());
        assertNotNull(result.getBestTestCases());
        assertFalse(result.getBestTestCases().isEmpty());
    }
    
    @Test
    void testEvolveTestCases_ShouldHandleComplexMethodSignatures() throws Exception {
        // Arrange - Test with a method that has multiple parameters
        Method targetMethod = List.class.getMethod("addAll", int.class, Collection.class);
        FitnessFunction<TestCaseExecution> fitnessFunction = createMockFitnessFunction();
        
        when(executionHarness.execute(any(TestCaseExecution.class)))
                .thenReturn(createMockExecutionMetrics(true));
        
        // Act
        GeneticInputEvolver.EvolutionResult result = evolver.evolveTestCases(
                targetMethod, fitnessFunction, executionHarness);
        
        // Assert
        assertNotNull(result);
        assertNotNull(result.getBestTestCases());
        
        // Check that test cases have correct number of inputs
        TestCaseExecution testCase = result.getBestTestCases().get(0);
        assertEquals(2, testCase.getInputs().length);
        assertEquals(int.class, testCase.getInputTypes()[0]);
        assertEquals(Collection.class, testCase.getInputTypes()[1]);
    }
    
    @Test
    void testGetCurrentGeneration_ShouldReturnCorrectValue() {
        // Arrange
        assertEquals(0, evolver.getCurrentGeneration());
        
        // Act
        evolver.resetGenerationCounter();
        
        // Assert
        assertEquals(0, evolver.getCurrentGeneration());
    }
    
    @Test
    void testEvolutionResult_ShouldProvideVulnerabilityAnalysis() throws Exception {
        // Arrange
        Method targetMethod = String.class.getMethod("contains", CharSequence.class);
        FitnessFunction<TestCaseExecution> fitnessFunction = createMockFitnessFunction();
        
        when(executionHarness.execute(any(TestCaseExecution.class)))
                .thenReturn(createMockExecutionMetrics(true));
        
        // Act
        GeneticInputEvolver.EvolutionResult result = evolver.evolveTestCases(
                targetMethod, fitnessFunction, executionHarness);
        
        // Assert
        // Test potential vulnerabilities with different thresholds
        List<TestCaseExecution> highFitnessCases = result.getPotentialVulnerabilities(0.5);
        List<TestCaseExecution> veryHighFitnessCases = result.getPotentialVulnerabilities(0.9);
        
        assertNotNull(highFitnessCases);
        assertNotNull(veryHighFitnessCases);
        assertTrue(highFitnessCases.size() >= veryHighFitnessCases.size());
        
        // Test most promising test case
        TestCaseExecution mostPromising = result.getMostPromisingTestCase();
        if (mostPromising != null) {
            assertTrue(mostPromising.getFitness() >= 0.0);
            assertNotNull(mostPromising.getTestCaseId());
            assertNotNull(mostPromising.getTargetClassName());
            assertNotNull(mostPromising.getTargetMethodName());
        }
    }
    
    @Test
    void testEvolutionResult_ShouldHandleEmptyResults() throws Exception {
        // Arrange
        Method targetMethod = String.class.getMethod("contains", CharSequence.class);
        FitnessFunction<TestCaseExecution> fitnessFunction = createMockFitnessFunction();
        
        when(executionHarness.execute(any(TestCaseExecution.class)))
                .thenReturn(createMockExecutionMetrics(false)); // All executions fail
        
        // Act
        GeneticInputEvolver.EvolutionResult result = evolver.evolveTestCases(
                targetMethod, fitnessFunction, executionHarness);
        
        // Assert
        assertNotNull(result);
        assertNotNull(result.getBestTestCases());
        assertTrue(result.getBestFitness() <= 0.0);
        
        // Should handle empty results gracefully
        List<TestCaseExecution> vulnerabilities = result.getPotentialVulnerabilities(1.0);
        assertNotNull(vulnerabilities);
        assertTrue(vulnerabilities.isEmpty());
    }
    
    private FitnessFunction<TestCaseExecution> createMockFitnessFunction() {
        return new FitnessFunction<TestCaseExecution>() {
            @Override
            public double evaluate(TestCaseExecution testCase, ExecutionMetrics metrics) {
                if (metrics == null || !metrics.isSuccessful()) {
                    return 0.0;
                }
                // Simple fitness based on execution time and input size
                double timeFitness = Math.log(metrics.getExecutionTimeNanos() + 1);
                double sizeFitness = Math.log(testCase.getInputSize() + 1);
                return timeFitness + sizeFitness;
            }
            
            @Override
            public boolean shouldRetain(double fitness) {
                return fitness > 0.1;
            }
            
            @Override
            public String getName() {
                return "TestFitnessFunction";
            }
        };
    }
    
    private ExecutionMetrics createMockExecutionMetrics(boolean successful) {
        return ExecutionMetrics.builder()
                .executionId("test-execution-" + System.currentTimeMillis())
                .startTime(java.time.Instant.now())
                .endTime(java.time.Instant.now().plusNanos(1000000)) // 1ms
                .executionTimeNanos(1000000)
                .peakMemoryBytes(1024 * 1024) // 1MB
                .totalMemoryAllocated(2048 * 1024) // 2MB
                .cpuUsagePercent(50.0)
                .stackDepth(10)
                .exceptionThrown(!successful)
                .exceptionType(successful ? null : "TestException")
                .exceptionMessage(successful ? null : "Test exception message")
                .successful(successful)
                .timeoutOccurred(false)
                .memoryLimitExceeded(false)
                .securityViolation(false)
                .threadCount(1)
                .gcCount(0)
                .gcTimeMs(0)
                .build();
    }
} 