package com.securityresearch.fuzzer.instrumentation;

import com.securityresearch.fuzzer.core.config.FuzzerConfiguration;
import com.securityresearch.fuzzer.instrumentation.transformer.PerformanceTransformer;
import com.securityresearch.fuzzer.instrumentation.transformer.SecurityTransformer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Java agent for instrumenting classes during fuzzing to collect performance
 * metrics and enforce security constraints.
 */
public class FuzzerAgent {
    
    private static final Logger logger = LoggerFactory.getLogger(FuzzerAgent.class);
    private static final AtomicBoolean initialized = new AtomicBoolean(false);
    
    private static Instrumentation instrumentation;
    private static PerformanceTransformer performanceTransformer;
    private static SecurityTransformer securityTransformer;
    
    /**
     * Premain method called by the JVM when the agent is loaded.
     * 
     * @param agentArgs Agent arguments
     * @param inst Instrumentation instance
     */
    public static void premain(String agentArgs, Instrumentation inst) {
        if (initialized.compareAndSet(false, true)) {
            logger.info("Initializing Fuzzer Agent");
            instrumentation = inst;
            
            // Initialize transformers
            FuzzerConfiguration config = parseConfiguration(agentArgs);
            performanceTransformer = new PerformanceTransformer(config);
            securityTransformer = new SecurityTransformer(config);
            
            // Register transformers
            inst.addTransformer(performanceTransformer, true);
            inst.addTransformer(securityTransformer, true);
            
            logger.info("Fuzzer Agent initialized successfully");
        }
    }
    
    /**
     * Agentmain method for dynamic attachment (if supported).
     * 
     * @param agentArgs Agent arguments
     * @param inst Instrumentation instance
     */
    public static void agentmain(String agentArgs, Instrumentation inst) {
        premain(agentArgs, inst);
    }
    
    /**
     * Parse configuration from agent arguments.
     * 
     * @param agentArgs Agent arguments string
     * @return FuzzerConfiguration instance
     */
    private static FuzzerConfiguration parseConfiguration(String agentArgs) {
        FuzzerConfiguration config = new FuzzerConfiguration();
        
        if (agentArgs != null && !agentArgs.trim().isEmpty()) {
            String[] args = agentArgs.split(",");
            for (String arg : args) {
                String[] keyValue = arg.split("=");
                if (keyValue.length == 2) {
                    String key = keyValue[0].trim();
                    String value = keyValue[1].trim();
                    
                    switch (key) {
                        case "enablePerformanceProfiling":
                            config.getPerformance().setEnableDetailedProfiling(Boolean.parseBoolean(value));
                            break;
                        case "enableMemoryTracking":
                            config.getPerformance().setEnableMemoryTracking(Boolean.parseBoolean(value));
                            break;
                        case "enableSecurityManager":
                            config.getSecurity().setEnableSecurityManager(Boolean.parseBoolean(value));
                            break;
                        case "timeout":
                            config.getExecution().setTimeout(Duration.parse(value));
                            break;
                        default:
                            logger.warn("Unknown agent argument: {}", key);
                    }
                }
            }
        }
        
        return config;
    }
    
    /**
     * Get the instrumentation instance.
     * 
     * @return Instrumentation instance
     */
    public static Instrumentation getInstrumentation() {
        return instrumentation;
    }
    
    /**
     * Get the performance transformer.
     * 
     * @return PerformanceTransformer instance
     */
    public static PerformanceTransformer getPerformanceTransformer() {
        return performanceTransformer;
    }
    
    /**
     * Get the security transformer.
     * 
     * @return SecurityTransformer instance
     */
    public static SecurityTransformer getSecurityTransformer() {
        return securityTransformer;
    }
    
    /**
     * Check if the agent is initialized.
     * 
     * @return true if initialized
     */
    public static boolean isInitialized() {
        return initialized.get();
    }
    
    /**
     * Retransform a class to apply instrumentation.
     * 
     * @param clazz Class to retransform
     * @throws Exception if retransformation fails
     */
    public static void retransformClass(Class<?> clazz) throws Exception {
        if (instrumentation != null && instrumentation.isRetransformClassesSupported()) {
            instrumentation.retransformClasses(clazz);
        } else {
            logger.warn("Class retransformation not supported");
        }
    }
    
    /**
     * Redefine a class with new bytecode.
     * 
     * @param clazz Class to redefine
     * @param classfileBuffer New bytecode
     * @throws Exception if redefinition fails
     */
    public static void redefineClass(Class<?> clazz, byte[] classfileBuffer) throws Exception {
        if (instrumentation != null && instrumentation.isRedefineClassesSupported()) {
            instrumentation.redefineClasses(new java.lang.instrument.ClassDefinition(clazz, classfileBuffer));
        } else {
            logger.warn("Class redefinition not supported");
        }
    }
} 