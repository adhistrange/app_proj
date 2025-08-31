package com.securityresearch.fuzzer.core.input;

import com.securityresearch.fuzzer.core.exception.FuzzerException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Generates diverse Java objects for fuzzing target methods.
 * Supports primitives, collections, strings, arrays, and custom objects.
 */
public class InputGenerator {
    
    private static final Logger logger = LoggerFactory.getLogger(InputGenerator.class);
    
    private final Random random;
    private final int maxStringLength;
    private final int maxCollectionSize;
    private final int maxArrayLength;
    private final int maxNestingDepth;
    
    public InputGenerator() {
        this(ThreadLocalRandom.current(), 1000, 100, 100, 5);
    }
    
    public InputGenerator(Random random, int maxStringLength, int maxCollectionSize, 
                         int maxArrayLength, int maxNestingDepth) {
        this.random = random;
        this.maxStringLength = maxStringLength;
        this.maxCollectionSize = maxCollectionSize;
        this.maxArrayLength = maxArrayLength;
        this.maxNestingDepth = maxNestingDepth;
    }
    
    /**
     * Generates inputs for a target method based on its parameter types.
     * 
     * @param method The target method
     * @return Array of generated inputs matching the method signature
     */
    public Object[] generateInputsForMethod(Method method) {
        Class<?>[] parameterTypes = method.getParameterTypes();
        Object[] inputs = new Object[parameterTypes.length];
        
        for (int i = 0; i < parameterTypes.length; i++) {
            inputs[i] = generateObject(parameterTypes[i], 0);
        }
        
        return inputs;
    }
    
    /**
     * Generates an object of the specified type.
     * 
     * @param type The target type
     * @param depth Current nesting depth
     * @return Generated object
     */
    public Object generateObject(Class<?> type, int depth) {
        if (depth > maxNestingDepth) {
            return generateSimpleValue(type);
        }
        
        try {
            if (type.isPrimitive()) {
                return generatePrimitive(type);
            } else if (type == String.class) {
                return generateString();
            } else if (type.isArray()) {
                return generateArray(type, depth);
            } else if (Collection.class.isAssignableFrom(type)) {
                return generateCollection(type, depth);
            } else if (Map.class.isAssignableFrom(type)) {
                return generateMap(type, depth);
            } else if (type.isEnum()) {
                return generateEnum(type);
            } else {
                return generateCustomObject(type, depth);
            }
        } catch (Exception e) {
            logger.warn("Failed to generate object of type {}: {}", type.getName(), e.getMessage());
            return generateSimpleValue(type);
        }
    }
    
    /**
     * Generates a primitive value.
     * 
     * @param type The primitive type
     * @return Generated primitive value
     */
    private Object generatePrimitive(Class<?> type) {
        if (type == boolean.class) {
            return random.nextBoolean();
        } else if (type == byte.class) {
            return (byte) random.nextInt(Byte.MIN_VALUE, Byte.MAX_VALUE + 1);
        } else if (type == char.class) {
            return (char) random.nextInt(32, 127); // Printable ASCII
        } else if (type == short.class) {
            return (short) random.nextInt(Short.MIN_VALUE, Short.MAX_VALUE + 1);
        } else if (type == int.class) {
            return random.nextInt();
        } else if (type == long.class) {
            return random.nextLong();
        } else if (type == float.class) {
            return random.nextFloat();
        } else if (type == double.class) {
            return random.nextDouble();
        } else {
            throw new IllegalArgumentException("Unknown primitive type: " + type);
        }
    }
    
    /**
     * Generates a string with various characteristics.
     * 
     * @return Generated string
     */
    private String generateString() {
        int length = random.nextInt(1, maxStringLength + 1);
        StringBuilder sb = new StringBuilder(length);
        
        // Choose string generation strategy
        int strategy = random.nextInt(10);
        
        if (strategy < 3) {
            // Random printable ASCII
            for (int i = 0; i < length; i++) {
                sb.append((char) random.nextInt(32, 127));
            }
        } else if (strategy < 5) {
            // Repetitive patterns (good for finding algorithmic issues)
            String pattern = generateRandomPattern();
            while (sb.length() < length) {
                sb.append(pattern);
            }
            sb.setLength(length);
        } else if (strategy < 7) {
            // Very long strings (stress testing)
            for (int i = 0; i < length; i++) {
                sb.append('a');
            }
        } else if (strategy < 9) {
            // Special characters and Unicode
            for (int i = 0; i < length; i++) {
                if (random.nextBoolean()) {
                    sb.append((char) random.nextInt(32, 127));
                } else {
                    sb.append((char) random.nextInt(0x1000, 0x10FFF)); // Unicode
                }
            }
        } else {
            // Empty or very short strings
            if (random.nextBoolean()) {
                return "";
            } else {
                return String.valueOf((char) random.nextInt(32, 127));
            }
        }
        
        return sb.toString();
    }
    
    /**
     * Generates a random pattern for string generation.
     * 
     * @return Random pattern string
     */
    private String generateRandomPattern() {
        int patternLength = random.nextInt(1, 10);
        StringBuilder pattern = new StringBuilder(patternLength);
        
        for (int i = 0; i < patternLength; i++) {
            pattern.append((char) random.nextInt(32, 127));
        }
        
        return pattern.toString();
    }
    
    /**
     * Generates an array of the specified type.
     * 
     * @param type The array type
     * @param depth Current nesting depth
     * @return Generated array
     */
    private Object generateArray(Class<?> type, int depth) {
        Class<?> componentType = type.getComponentType();
        int length = random.nextInt(0, maxArrayLength + 1);
        
        Object array = Array.newInstance(componentType, length);
        
        for (int i = 0; i < length; i++) {
            Array.set(array, i, generateObject(componentType, depth + 1));
        }
        
        return array;
    }
    
    /**
     * Generates a collection of the specified type.
     * 
     * @param type The collection type
     * @param depth Current nesting depth
     * @return Generated collection
     */
    private Collection<?> generateCollection(Class<?> type, int depth) {
        int size = random.nextInt(0, maxCollectionSize + 1);
        Collection<Object> collection;
        
        if (type == List.class || type == ArrayList.class) {
            collection = new ArrayList<>();
        } else if (type == Set.class || type == HashSet.class) {
            collection = new HashSet<>();
        } else if (type == LinkedList.class) {
            collection = new LinkedList<>();
        } else if (type == TreeSet.class) {
            collection = new TreeSet<>();
        } else {
            // Default to ArrayList for unknown collection types
            collection = new ArrayList<>();
        }
        
        // Generate elements with various strategies
        for (int i = 0; i < size; i++) {
            Object element = generateCollectionElement(depth);
            collection.add(element);
        }
        
        return collection;
    }
    
    /**
     * Generates a map of the specified type.
     * 
     * @param type The map type
     * @param depth Current nesting depth
     * @return Generated map
     */
    private Map<?, ?> generateMap(Class<?> type, int depth) {
        int size = random.nextInt(0, maxCollectionSize + 1);
        Map<Object, Object> map;
        
        if (type == Map.class || type == HashMap.class) {
            map = new HashMap<>();
        } else if (type == TreeMap.class) {
            map = new TreeMap<>();
        } else if (type == LinkedHashMap.class) {
            map = new LinkedHashMap<>();
        } else {
            // Default to HashMap for unknown map types
            map = new HashMap<>();
        }
        
        for (int i = 0; i < size; i++) {
            Object key = generateCollectionElement(depth);
            Object value = generateCollectionElement(depth);
            map.put(key, value);
        }
        
        return map;
    }
    
    /**
     * Generates an enum value.
     * 
     * @param type The enum type
     * @return Random enum value
     */
    private Object generateEnum(Class<?> type) {
        Object[] constants = type.getEnumConstants();
        if (constants.length == 0) {
            return null;
        }
        return constants[random.nextInt(constants.length)];
    }
    
    /**
     * Generates a custom object using reflection.
     * 
     * @param type The object type
     * @param depth Current nesting depth
     * @return Generated object
     */
    private Object generateCustomObject(Class<?> type, int depth) {
        try {
            // Try to find a no-arg constructor
            Constructor<?> constructor = type.getDeclaredConstructor();
            constructor.setAccessible(true);
            return constructor.newInstance();
        } catch (NoSuchMethodException e) {
            // Try to find a constructor with parameters
            try {
                Constructor<?>[] constructors = type.getDeclaredConstructors();
                if (constructors.length > 0) {
                    Constructor<?> constructor = constructors[0];
                    constructor.setAccessible(true);
                    
                    Class<?>[] paramTypes = constructor.getParameterTypes();
                    Object[] params = new Object[paramTypes.length];
                    
                    for (int i = 0; i < paramTypes.length; i++) {
                        params[i] = generateObject(paramTypes[i], depth + 1);
                    }
                    
                    return constructor.newInstance(params);
                }
            } catch (Exception ex) {
                logger.warn("Failed to create instance with parameters for {}: {}", type.getName(), ex.getMessage());
            }
        } catch (Exception e) {
            logger.warn("Failed to create instance of {}: {}", type.getName(), e.getMessage());
        }
        
        // Fallback to null
        return null;
    }
    
    /**
     * Generates an element for collections and maps.
     * 
     * @param depth Current nesting depth
     * @return Generated element
     */
    private Object generateCollectionElement(int depth) {
        // Choose element type with bias towards simple types
        int choice = random.nextInt(20);
        
        if (choice < 5) {
            return random.nextInt();
        } else if (choice < 8) {
            return generateString();
        } else if (choice < 10) {
            return random.nextDouble();
        } else if (choice < 12) {
            return random.nextBoolean();
        } else if (choice < 14) {
            return generateArray(Object.class, depth + 1);
        } else if (choice < 16) {
            return generateCollection(ArrayList.class, depth + 1);
        } else if (choice < 18) {
            return generateMap(HashMap.class, depth + 1);
        } else {
            return null;
        }
    }
    
    /**
     * Generates a simple value as fallback.
     * 
     * @param type The target type
     * @return Simple value or null
     */
    private Object generateSimpleValue(Class<?> type) {
        if (type.isPrimitive()) {
            return generatePrimitive(type);
        } else if (type == String.class) {
            return "";
        } else if (type.isArray()) {
            return Array.newInstance(type.getComponentType(), 0);
        } else if (Collection.class.isAssignableFrom(type)) {
            return new ArrayList<>();
        } else if (Map.class.isAssignableFrom(type)) {
            return new HashMap<>();
        } else {
            return null;
        }
    }
    
    /**
     * Generates a test case with inputs for a specific method.
     * 
     * @param method The target method
     * @return TestCaseExecution with generated inputs
     */
    public com.securityresearch.fuzzer.core.execution.TestCaseExecution generateTestCase(Method method) {
        Object[] inputs = generateInputsForMethod(method);
        Class<?>[] inputTypes = method.getParameterTypes();
        
        return com.securityresearch.fuzzer.core.execution.TestCaseExecution.builder()
                .targetMethod(method)
                .inputs(inputs)
                .inputTypes(inputTypes)
                .build();
    }
    
    /**
     * Generates multiple test cases for a method with different input strategies.
     * 
     * @param method The target method
     * @param count The number of test cases to generate
     * @return List of generated test cases
     */
    public List<com.securityresearch.fuzzer.core.execution.TestCaseExecution> generateTestCases(Method method, int count) {
        List<com.securityresearch.fuzzer.core.execution.TestCaseExecution> testCases = new ArrayList<>();
        
        for (int i = 0; i < count; i++) {
            testCases.add(generateTestCase(method));
        }
        
        return testCases;
    }
    
    /**
     * Generates edge case inputs that are likely to trigger vulnerabilities.
     * 
     * @param method The target method
     * @return List of edge case test cases
     */
    public List<com.securityresearch.fuzzer.core.execution.TestCaseExecution> generateEdgeCases(Method method) {
        List<com.securityresearch.fuzzer.core.execution.TestCaseExecution> edgeCases = new ArrayList<>();
        Class<?>[] parameterTypes = method.getParameterTypes();
        
        // Generate null inputs
        for (int i = 0; i < parameterTypes.length; i++) {
            Object[] inputs = new Object[parameterTypes.length];
            for (int j = 0; j < parameterTypes.length; j++) {
                inputs[j] = (j == i) ? null : generateObject(parameterTypes[j], 0);
            }
            edgeCases.add(com.securityresearch.fuzzer.core.execution.TestCaseExecution.builder()
                    .targetMethod(method)
                    .inputs(inputs)
                    .inputTypes(parameterTypes)
                    .build());
        }
        
        // Generate empty collections/arrays
        for (int i = 0; i < parameterTypes.length; i++) {
            if (parameterTypes[i].isArray() || Collection.class.isAssignableFrom(parameterTypes[i])) {
                Object[] inputs = new Object[parameterTypes.length];
                for (int j = 0; j < parameterTypes.length; j++) {
                    if (j == i) {
                        inputs[j] = generateEmptyValue(parameterTypes[j]);
                    } else {
                        inputs[j] = generateObject(parameterTypes[j], 0);
                    }
                }
                edgeCases.add(com.securityresearch.fuzzer.core.execution.TestCaseExecution.builder()
                        .targetMethod(method)
                        .inputs(inputs)
                        .inputTypes(parameterTypes)
                        .build());
            }
        }
        
        // Generate very large inputs
        Object[] largeInputs = new Object[parameterTypes.length];
        for (int i = 0; i < parameterTypes.length; i++) {
            largeInputs[i] = generateLargeValue(parameterTypes[i]);
        }
        edgeCases.add(com.securityresearch.fuzzer.core.execution.TestCaseExecution.builder()
                .targetMethod(method)
                .inputs(largeInputs)
                .inputTypes(parameterTypes)
                .build());
        
        return edgeCases;
    }
    
    /**
     * Generates an empty value for the specified type.
     * 
     * @param type The target type
     * @return Empty value
     */
    private Object generateEmptyValue(Class<?> type) {
        if (type.isArray()) {
            return Array.newInstance(type.getComponentType(), 0);
        } else if (type == String.class) {
            return "";
        } else if (Collection.class.isAssignableFrom(type)) {
            if (type == List.class || type == ArrayList.class) {
                return new ArrayList<>();
            } else if (type == Set.class || type == HashSet.class) {
                return new HashSet<>();
            } else {
                return new ArrayList<>();
            }
        } else if (Map.class.isAssignableFrom(type)) {
            if (type == Map.class || type == HashMap.class) {
                return new HashMap<>();
            } else {
                return new HashMap<>();
            }
        } else {
            return null;
        }
    }
    
    /**
     * Generates a very large value for the specified type.
     * 
     * @param type The target type
     * @return Large value
     */
    private Object generateLargeValue(Class<?> type) {
        if (type == String.class) {
            StringBuilder sb = new StringBuilder(10000);
            for (int i = 0; i < 10000; i++) {
                sb.append('a');
            }
            return sb.toString();
        } else if (type.isArray()) {
            Object array = Array.newInstance(type.getComponentType(), 10000);
            for (int i = 0; i < 10000; i++) {
                Array.set(array, i, generateObject(type.getComponentType(), 0));
            }
            return array;
        } else if (Collection.class.isAssignableFrom(type)) {
            Collection<Object> collection = new ArrayList<>();
            for (int i = 0; i < 10000; i++) {
                collection.add(generateCollectionElement(0));
            }
            return collection;
        } else {
            return generateObject(type, 0);
        }
    }
} 