package com.securityresearch.fuzzer.core.execution;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Objects;
import java.util.UUID;

/**
 * Represents a test case with its inputs and execution context.
 * This is the core unit that the genetic algorithm evolves to discover vulnerabilities.
 */
public class TestCaseExecution {
    
    @JsonProperty("testCaseId")
    private final String testCaseId;
    
    @JsonProperty("targetClassName")
    private final String targetClassName;
    
    @JsonProperty("targetMethodName")
    private final String targetMethodName;
    
    @JsonProperty("targetMethodSignature")
    private final String targetMethodSignature;
    
    @JsonProperty("inputs")
    private final Object[] inputs;
    
    @JsonProperty("inputTypes")
    private final Class<?>[] inputTypes;
    
    @JsonProperty("generation")
    private final int generation;
    
    @JsonProperty("fitness")
    private final double fitness;
    
    @JsonProperty("executionMetrics")
    private final ExecutionMetrics executionMetrics;
    
    @JsonProperty("creationTimestamp")
    private final long creationTimestamp;
    
    @JsonProperty("parentIds")
    private final String[] parentIds;
    
    @JsonProperty("mutationCount")
    private final int mutationCount;
    
    @JsonProperty("crossoverCount")
    private final int crossoverCount;
    
    private TestCaseExecution(Builder builder) {
        this.testCaseId = builder.testCaseId;
        this.targetClassName = builder.targetClassName;
        this.targetMethodName = builder.targetMethodName;
        this.targetMethodSignature = builder.targetMethodSignature;
        this.inputs = builder.inputs;
        this.inputTypes = builder.inputTypes;
        this.generation = builder.generation;
        this.fitness = builder.fitness;
        this.executionMetrics = builder.executionMetrics;
        this.creationTimestamp = builder.creationTimestamp;
        this.parentIds = builder.parentIds;
        this.mutationCount = builder.mutationCount;
        this.crossoverCount = builder.crossoverCount;
    }
    
    // Getters
    public String getTestCaseId() { return testCaseId; }
    public String getTargetClassName() { return targetClassName; }
    public String getTargetMethodName() { return targetMethodName; }
    public String getTargetMethodSignature() { return targetMethodSignature; }
    public Object[] getInputs() { return inputs; }
    public Class<?>[] getInputTypes() { return inputTypes; }
    public int getGeneration() { return generation; }
    public double getFitness() { return fitness; }
    public ExecutionMetrics getExecutionMetrics() { return executionMetrics; }
    public long getCreationTimestamp() { return creationTimestamp; }
    public String[] getParentIds() { return parentIds; }
    public int getMutationCount() { return mutationCount; }
    public int getCrossoverCount() { return crossoverCount; }
    
    /**
     * Calculates the size of the input data for complexity analysis.
     * 
     * @return Input size metric
     */
    public double getInputSize() {
        if (inputs == null) return 0.0;
        
        double totalSize = 0.0;
        for (Object input : inputs) {
            totalSize += calculateObjectSize(input);
        }
        return totalSize;
    }
    
    /**
     * Calculates the complexity of input types for diversity analysis.
     * 
     * @return Input type complexity score
     */
    public double getInputTypeComplexity() {
        if (inputTypes == null) return 0.0;
        
        double complexity = 0.0;
        for (Class<?> type : inputTypes) {
            complexity += calculateTypeComplexity(type);
        }
        return complexity;
    }
    
    /**
     * Creates a deep copy of this test case for evolution.
     * 
     * @return A new TestCaseExecution with copied data
     */
    public TestCaseExecution copy() {
        return builder()
                .testCaseId(UUID.randomUUID().toString())
                .targetClassName(targetClassName)
                .targetMethodName(targetMethodName)
                .targetMethodSignature(targetMethodSignature)
                .inputs(deepCopyInputs())
                .inputTypes(inputTypes)
                .generation(generation)
                .parentIds(new String[]{testCaseId})
                .mutationCount(mutationCount)
                .crossoverCount(crossoverCount)
                .build();
    }
    
    /**
     * Creates a mutated version of this test case.
     * 
     * @return A new TestCaseExecution with mutations applied
     */
    public TestCaseExecution mutate() {
        return builder()
                .testCaseId(UUID.randomUUID().toString())
                .targetClassName(targetClassName)
                .targetMethodName(targetMethodName)
                .targetMethodSignature(targetMethodSignature)
                .inputs(deepCopyInputs()) // Will be mutated by genetic algorithm
                .inputTypes(inputTypes)
                .generation(generation + 1)
                .parentIds(new String[]{testCaseId})
                .mutationCount(mutationCount + 1)
                .crossoverCount(crossoverCount)
                .build();
    }
    
    /**
     * Creates a crossover version with another test case.
     * 
     * @param other The other test case to crossover with
     * @return A new TestCaseExecution with crossover applied
     */
    public TestCaseExecution crossover(TestCaseExecution other) {
        if (!Objects.equals(targetClassName, other.targetClassName) ||
            !Objects.equals(targetMethodName, other.targetMethodName)) {
            throw new IllegalArgumentException("Cannot crossover test cases with different targets");
        }
        
        return builder()
                .testCaseId(UUID.randomUUID().toString())
                .targetClassName(targetClassName)
                .targetMethodName(targetMethodName)
                .targetMethodSignature(targetMethodSignature)
                .inputs(deepCopyInputs()) // Will be crossed over by genetic algorithm
                .inputTypes(inputTypes)
                .generation(Math.max(generation, other.generation) + 1)
                .parentIds(new String[]{testCaseId, other.testCaseId})
                .mutationCount(mutationCount)
                .crossoverCount(crossoverCount + 1)
                .build();
    }
    
    /**
     * Updates the fitness score and execution metrics.
     * 
     * @param newFitness The new fitness score
     * @param metrics The execution metrics
     * @return A new TestCaseExecution with updated fitness and metrics
     */
    public TestCaseExecution withExecutionResults(double newFitness, ExecutionMetrics metrics) {
        return builder()
                .testCaseId(testCaseId)
                .targetClassName(targetClassName)
                .targetMethodName(targetMethodName)
                .targetMethodSignature(targetMethodSignature)
                .inputs(inputs)
                .inputTypes(inputTypes)
                .generation(generation)
                .fitness(newFitness)
                .executionMetrics(metrics)
                .creationTimestamp(creationTimestamp)
                .parentIds(parentIds)
                .mutationCount(mutationCount)
                .crossoverCount(crossoverCount)
                .build();
    }
    
    private Object[] deepCopyInputs() {
        if (inputs == null) return null;
        
        Object[] copy = new Object[inputs.length];
        for (int i = 0; i < inputs.length; i++) {
            copy[i] = deepCopyObject(inputs[i]);
        }
        return copy;
    }
    
    private Object deepCopyObject(Object obj) {
        if (obj == null) return null;
        
        if (obj instanceof String) {
            return new String((String) obj);
        } else if (obj instanceof Number) {
            return obj; // Numbers are immutable
        } else if (obj instanceof Boolean) {
            return obj; // Booleans are immutable
        } else if (obj.getClass().isArray()) {
            return deepCopyArray(obj);
        } else if (obj instanceof java.util.Collection) {
            return deepCopyCollection((java.util.Collection<?>) obj);
        } else {
            // For complex objects, return the original for now
            // In a full implementation, this would use serialization or reflection
            return obj;
        }
    }
    
    private Object deepCopyArray(Object array) {
        if (array instanceof Object[]) {
            Object[] original = (Object[]) array;
            Object[] copy = new Object[original.length];
            for (int i = 0; i < original.length; i++) {
                copy[i] = deepCopyObject(original[i]);
            }
            return copy;
        } else if (array instanceof int[]) {
            return ((int[]) array).clone();
        } else if (array instanceof long[]) {
            return ((long[]) array).clone();
        } else if (array instanceof double[]) {
            return ((double[]) array).clone();
        } else if (array instanceof boolean[]) {
            return ((boolean[]) array).clone();
        } else if (array instanceof byte[]) {
            return ((byte[]) array).clone();
        } else if (array instanceof char[]) {
            return ((char[]) array).clone();
        } else if (array instanceof short[]) {
            return ((short[]) array).clone();
        } else if (array instanceof float[]) {
            return ((float[]) array).clone();
        }
        return array;
    }
    
    private Object deepCopyCollection(java.util.Collection<?> collection) {
        if (collection instanceof java.util.List) {
            java.util.List<Object> copy = new java.util.ArrayList<>();
            for (Object item : collection) {
                copy.add(deepCopyObject(item));
            }
            return copy;
        } else if (collection instanceof java.util.Set) {
            java.util.Set<Object> copy = new java.util.HashSet<>();
            for (Object item : collection) {
                copy.add(deepCopyObject(item));
            }
            return copy;
        }
        return collection; // Return original for other collection types
    }
    
    private double calculateObjectSize(Object obj) {
        if (obj == null) return 0.0;
        
        if (obj instanceof String) {
            return ((String) obj).length();
        } else if (obj instanceof Number) {
            return 1.0; // Fixed size for numbers
        } else if (obj instanceof Boolean) {
            return 1.0; // Fixed size for booleans
        } else if (obj.getClass().isArray()) {
            return java.lang.reflect.Array.getLength(obj);
        } else if (obj instanceof java.util.Collection) {
            return ((java.util.Collection<?>) obj).size();
        } else {
            return 1.0; // Default size for complex objects
        }
    }
    
    private double calculateTypeComplexity(Class<?> type) {
        if (type == null) return 0.0;
        
        if (type.isPrimitive()) {
            return 1.0;
        } else if (type == String.class) {
            return 2.0;
        } else if (type.isArray()) {
            return 3.0;
        } else if (java.util.Collection.class.isAssignableFrom(type)) {
            return 4.0;
        } else if (java.util.Map.class.isAssignableFrom(type)) {
            return 5.0;
        } else {
            return 6.0; // Custom objects
        }
    }
    
    @Override
    public String toString() {
        return String.format("TestCaseExecution{id=%s, target=%s.%s, generation=%d, fitness=%.3f}",
                testCaseId, targetClassName, targetMethodName, generation, fitness);
    }
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        TestCaseExecution that = (TestCaseExecution) obj;
        return Objects.equals(testCaseId, that.testCaseId);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(testCaseId);
    }
    
    /**
     * Builder pattern for creating TestCaseExecution instances.
     */
    public static class Builder {
        private String testCaseId = UUID.randomUUID().toString();
        private String targetClassName;
        private String targetMethodName;
        private String targetMethodSignature;
        private Object[] inputs;
        private Class<?>[] inputTypes;
        private int generation = 0;
        private double fitness = 0.0;
        private ExecutionMetrics executionMetrics;
        private long creationTimestamp = System.currentTimeMillis();
        private String[] parentIds = new String[0];
        private int mutationCount = 0;
        private int crossoverCount = 0;
        
        public Builder testCaseId(String testCaseId) {
            this.testCaseId = testCaseId;
            return this;
        }
        
        public Builder targetClassName(String targetClassName) {
            this.targetClassName = targetClassName;
            return this;
        }
        
        public Builder targetMethodName(String targetMethodName) {
            this.targetMethodName = targetMethodName;
            return this;
        }
        
        public Builder targetMethodSignature(String targetMethodSignature) {
            this.targetMethodSignature = targetMethodSignature;
            return this;
        }
        
        public Builder targetMethod(Method method) {
            this.targetClassName = method.getDeclaringClass().getName();
            this.targetMethodName = method.getName();
            this.targetMethodSignature = method.toGenericString();
            return this;
        }
        
        public Builder inputs(Object[] inputs) {
            this.inputs = inputs;
            return this;
        }
        
        public Builder inputTypes(Class<?>[] inputTypes) {
            this.inputTypes = inputTypes;
            return this;
        }
        
        public Builder generation(int generation) {
            this.generation = generation;
            return this;
        }
        
        public Builder fitness(double fitness) {
            this.fitness = fitness;
            return this;
        }
        
        public Builder executionMetrics(ExecutionMetrics executionMetrics) {
            this.executionMetrics = executionMetrics;
            return this;
        }
        
        public Builder creationTimestamp(long creationTimestamp) {
            this.creationTimestamp = creationTimestamp;
            return this;
        }
        
        public Builder parentIds(String[] parentIds) {
            this.parentIds = parentIds;
            return this;
        }
        
        public Builder mutationCount(int mutationCount) {
            this.mutationCount = mutationCount;
            return this;
        }
        
        public Builder crossoverCount(int crossoverCount) {
            this.crossoverCount = crossoverCount;
            return this;
        }
        
        public TestCaseExecution build() {
            return new TestCaseExecution(this);
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