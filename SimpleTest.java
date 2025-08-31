package com.securityresearch.fuzzer.core;

import com.securityresearch.fuzzer.core.config.FuzzerConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Simple test to verify basic functionality.
 */
@SpringBootTest
public class SimpleTest {
    
    @Test
    public void testConfigurationCreation() {
        FuzzerConfiguration config = new FuzzerConfiguration();
        assertNotNull(config);
        assertNotNull(config.getGeneticAlgorithm());
        assertNotNull(config.getExecution());
        assertNotNull(config.getPerformance());
        assertNotNull(config.getSecurity());
    }
    
    @Test
    public void testConfigurationDefaults() {
        FuzzerConfiguration config = new FuzzerConfiguration();
        
        // Test genetic algorithm defaults
        assertEquals(100, config.getGeneticAlgorithm().getPopulationSize());
        assertEquals(1000, config.getGeneticAlgorithm().getMaxGenerations());
        assertEquals(0.8, config.getGeneticAlgorithm().getCrossoverRate(), 0.001);
        assertEquals(0.1, config.getGeneticAlgorithm().getMutationRate(), 0.001);
        
        // Test execution defaults
        assertEquals("30s", config.getExecution().getTimeout());
        assertEquals(536870912L, config.getExecution().getMaxMemoryBytes());
        assertEquals(1000, config.getExecution().getMaxStackDepth());
        
        // Test performance defaults
        assertTrue(config.getPerformance().isEnableDetailedProfiling());
        assertTrue(config.getPerformance().isEnableMemoryTracking());
        assertEquals(2.0, config.getPerformance().getOutlierThreshold(), 0.001);
        
        // Test security defaults
        assertTrue(config.getSecurity().isEnableSecurityManager());
        assertTrue(config.getSecurity().isRestrictFileAccess());
        assertTrue(config.getSecurity().isRestrictNetworkAccess());
        assertTrue(config.getSecurity().isRestrictSystemAccess());
    }
} 