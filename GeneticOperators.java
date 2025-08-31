package com.securityresearch.fuzzer.core.genetic;

import com.securityresearch.fuzzer.core.config.FuzzerConfiguration;
import com.securityresearch.fuzzer.core.execution.TestCaseExecution;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Array;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Implements genetic operators (crossover and mutation) for evolving test case inputs.
 * Provides various strategies for combining and modifying test case data.
 */
public class GeneticOperators {
    
    private static final Logger logger = LoggerFactory.getLogger(GeneticOperators.class);
    
    private final FuzzerConfiguration configuration;
    private final Random random;
    
    public GeneticOperators(FuzzerConfiguration configuration) {
        this.configuration = configuration;
        this.random = ThreadLocalRandom.current();
    }
    
    /**
     * Performs crossover between two parent test cases.
     * 
     * @param parent1 First parent test case
     * @param parent2 Second parent test case
     * @return Offspring test case
     */
    public TestCaseExecution crossover(TestCaseExecution parent1, TestCaseExecution parent2) {
        
        if (!Objects.equals(parent1.getTargetClassName(), parent2.getTargetClassName()) ||
            !Objects.equals(parent1.getTargetMethodName(), parent2.getTargetMethodName())) {
            throw new IllegalArgumentException("Cannot crossover test cases with different targets");
        }
        
        Object[] parent1Inputs = parent1.getInputs();
        Object[] parent2Inputs = parent2.getInputs();
        Class<?>[] inputTypes = parent1.getInputTypes();
        
        Object[] offspringInputs = new Object[parent1Inputs.length];
        
        for (int i = 0; i < parent1Inputs.length; i++) {
            offspringInputs[i] = crossoverObject(parent1Inputs[i], parent2Inputs[i], inputTypes[i]);
        }
        
        return TestCaseExecution.builder()
                .targetClassName(parent1.getTargetClassName())
                .targetMethodName(parent1.getTargetMethodName())
                .targetMethodSignature(parent1.getTargetMethodSignature())
                .inputs(offspringInputs)
                .inputTypes(inputTypes)
                .generation(Math.max(parent1.getGeneration(), parent2.getGeneration()) + 1)
                .parentIds(new String[]{parent1.getTestCaseId(), parent2.getTestCaseId()})
                .mutationCount(parent1.getMutationCount())
                .crossoverCount(parent1.getCrossoverCount() + 1)
                .build();
    }
    
    /**
     * Performs mutation on a test case.
     * 
     * @param parent Parent test case
     * @return Mutated test case
     */
    public TestCaseExecution mutate(TestCaseExecution parent) {
        
        Object[] parentInputs = parent.getInputs();
        Class<?>[] inputTypes = parent.getInputTypes();
        
        Object[] mutatedInputs = new Object[parentInputs.length];
        
        for (int i = 0; i < parentInputs.length; i++) {
            mutatedInputs[i] = mutateObject(parentInputs[i], inputTypes[i]);
        }
        
        return TestCaseExecution.builder()
                .targetClassName(parent.getTargetClassName())
                .targetMethodName(parent.getTargetMethodName())
                .targetMethodSignature(parent.getTargetMethodSignature())
                .inputs(mutatedInputs)
                .inputTypes(inputTypes)
                .generation(parent.getGeneration() + 1)
                .parentIds(new String[]{parent.getTestCaseId()})
                .mutationCount(parent.getMutationCount() + 1)
                .crossoverCount(parent.getCrossoverCount())
                .build();
    }
    
    /**
     * Performs crossover between two objects of the same type.
     * 
     * @param obj1 First object
     * @param obj2 Second object
     * @param type The type of both objects
     * @return Crossover result
     */
    private Object crossoverObject(Object obj1, Object obj2, Class<?> type) {
        
        if (obj1 == null && obj2 == null) {
            return null;
        } else if (obj1 == null) {
            return obj2;
        } else if (obj2 == null) {
            return obj1;
        }
        
        if (type.isPrimitive() || type == String.class || type == Number.class) {
            return crossoverPrimitive(obj1, obj2);
        } else if (type.isArray()) {
            return crossoverArray(obj1, obj2);
        } else if (Collection.class.isAssignableFrom(type)) {
            return crossoverCollection((Collection<?>) obj1, (Collection<?>) obj2);
        } else if (Map.class.isAssignableFrom(type)) {
            return crossoverMap((Map<?, ?>) obj1, (Map<?, ?>) obj2);
        } else {
            // For custom objects, randomly choose one parent
            return random.nextBoolean() ? obj1 : obj2;
        }
    }
    
    /**
     * Performs crossover between primitive values.
     * 
     * @param obj1 First primitive
     * @param obj2 Second primitive
     * @return Crossover result
     */
    private Object crossoverPrimitive(Object obj1, Object obj2) {
        
        if (obj1 instanceof String && obj2 instanceof String) {
            return crossoverString((String) obj1, (String) obj2);
        } else if (obj1 instanceof Number && obj2 instanceof Number) {
            return crossoverNumber((Number) obj1, (Number) obj2);
        } else if (obj1 instanceof Boolean && obj2 instanceof Boolean) {
            return random.nextBoolean() ? obj1 : obj2;
        } else {
            // For different types, randomly choose one
            return random.nextBoolean() ? obj1 : obj2;
        }
    }
    
    /**
     * Performs crossover between strings.
     * 
     * @param str1 First string
     * @param str2 Second string
     * @return Crossover result
     */
    private String crossoverString(String str1, String str2) {
        
        if (str1.isEmpty() && str2.isEmpty()) {
            return "";
        } else if (str1.isEmpty()) {
            return str2;
        } else if (str2.isEmpty()) {
            return str1;
        }
        
        // Choose crossover strategy
        int strategy = random.nextInt(4);
        
        switch (strategy) {
            case 0:
                // Single-point crossover
                return singlePointCrossover(str1, str2);
            case 1:
                // Two-point crossover
                return twoPointCrossover(str1, str2);
            case 2:
                // Uniform crossover
                return uniformCrossover(str1, str2);
            case 3:
                // Concatenation crossover
                return concatenationCrossover(str1, str2);
            default:
                return random.nextBoolean() ? str1 : str2;
        }
    }
    
    /**
     * Single-point crossover for strings.
     * 
     * @param str1 First string
     * @param str2 Second string
     * @return Crossover result
     */
    private String singlePointCrossover(String str1, String str2) {
        int point1 = random.nextInt(str1.length() + 1);
        int point2 = random.nextInt(str2.length() + 1);
        
        String part1 = str1.substring(0, point1);
        String part2 = str2.substring(point2);
        
        return part1 + part2;
    }
    
    /**
     * Two-point crossover for strings.
     * 
     * @param str1 First string
     * @param str2 Second string
     * @return Crossover result
     */
    private String twoPointCrossover(String str1, String str2) {
        int point1 = random.nextInt(str1.length() + 1);
        int point2 = random.nextInt(str2.length() + 1);
        int point3 = random.nextInt(str1.length() + 1);
        int point4 = random.nextInt(str2.length() + 1);
        
        // Ensure points are ordered
        if (point1 > point3) {
            int temp = point1;
            point1 = point3;
            point3 = temp;
        }
        if (point2 > point4) {
            int temp = point2;
            point2 = point4;
            point4 = temp;
        }
        
        String part1 = str1.substring(0, point1);
        String part2 = str2.substring(point2, point4);
        String part3 = str1.substring(point3);
        
        return part1 + part2 + part3;
    }
    
    /**
     * Uniform crossover for strings.
     * 
     * @param str1 First string
     * @param str2 Second string
     * @return Crossover result
     */
    private String uniformCrossover(String str1, String str2) {
        int maxLength = Math.max(str1.length(), str2.length());
        StringBuilder result = new StringBuilder(maxLength);
        
        for (int i = 0; i < maxLength; i++) {
            if (i < str1.length() && i < str2.length()) {
                result.append(random.nextBoolean() ? str1.charAt(i) : str2.charAt(i));
            } else if (i < str1.length()) {
                result.append(str1.charAt(i));
            } else {
                result.append(str2.charAt(i));
            }
        }
        
        return result.toString();
    }
    
    /**
     * Concatenation crossover for strings.
     * 
     * @param str1 First string
     * @param str2 Second string
     * @return Crossover result
     */
    private String concatenationCrossover(String str1, String str2) {
        if (random.nextBoolean()) {
            return str1 + str2;
        } else {
            return str2 + str1;
        }
    }
    
    /**
     * Performs crossover between numbers.
     * 
     * @param num1 First number
     * @param num2 Second number
     * @return Crossover result
     */
    private Number crossoverNumber(Number num1, Number num2) {
        double val1 = num1.doubleValue();
        double val2 = num2.doubleValue();
        
        // Arithmetic crossover
        double alpha = random.nextDouble();
        double result = alpha * val1 + (1 - alpha) * val2;
        
        // Return the same type as the first number
        if (num1 instanceof Integer) {
            return (int) result;
        } else if (num1 instanceof Long) {
            return (long) result;
        } else if (num1 instanceof Float) {
            return (float) result;
        } else if (num1 instanceof Double) {
            return result;
        } else {
            return result;
        }
    }
    
    /**
     * Performs crossover between arrays.
     * 
     * @param arr1 First array
     * @param arr2 Second array
     * @return Crossover result
     */
    private Object crossoverArray(Object arr1, Object arr2) {
        int length1 = Array.getLength(arr1);
        int length2 = Array.getLength(arr2);
        
        if (length1 == 0 && length2 == 0) {
            return arr1;
        } else if (length1 == 0) {
            return arr2;
        } else if (length2 == 0) {
            return arr1;
        }
        
        Class<?> componentType = arr1.getClass().getComponentType();
        int resultLength = Math.max(length1, length2);
        Object result = Array.newInstance(componentType, resultLength);
        
        for (int i = 0; i < resultLength; i++) {
            if (i < length1 && i < length2) {
                Object elem1 = Array.get(arr1, i);
                Object elem2 = Array.get(arr2, i);
                Array.set(result, i, crossoverObject(elem1, elem2, componentType));
            } else if (i < length1) {
                Array.set(result, i, Array.get(arr1, i));
            } else {
                Array.set(result, i, Array.get(arr2, i));
            }
        }
        
        return result;
    }
    
    /**
     * Performs crossover between collections.
     * 
     * @param coll1 First collection
     * @param coll2 Second collection
     * @return Crossover result
     */
    private Collection<?> crossoverCollection(Collection<?> coll1, Collection<?> coll2) {
        
        if (coll1.isEmpty() && coll2.isEmpty()) {
            return new ArrayList<>();
        } else if (coll1.isEmpty()) {
            return new ArrayList<>(coll2);
        } else if (coll2.isEmpty()) {
            return new ArrayList<>(coll1);
        }
        
        List<Object> list1 = new ArrayList<>(coll1);
        List<Object> list2 = new ArrayList<>(coll2);
        List<Object> result = new ArrayList<>();
        
        int maxSize = Math.max(list1.size(), list2.size());
        
        for (int i = 0; i < maxSize; i++) {
            if (i < list1.size() && i < list2.size()) {
                Object elem1 = list1.get(i);
                Object elem2 = list2.get(i);
                result.add(crossoverObject(elem1, elem2, 
                        elem1 != null ? elem1.getClass() : (elem2 != null ? elem2.getClass() : Object.class)));
            } else if (i < list1.size()) {
                result.add(list1.get(i));
            } else {
                result.add(list2.get(i));
            }
        }
        
        return result;
    }
    
    /**
     * Performs crossover between maps.
     * 
     * @param map1 First map
     * @param map2 Second map
     * @return Crossover result
     */
    private Map<?, ?> crossoverMap(Map<?, ?> map1, Map<?, ?> map2) {
        
        if (map1.isEmpty() && map2.isEmpty()) {
            return new HashMap<>();
        } else if (map1.isEmpty()) {
            return new HashMap<>(map2);
        } else if (map2.isEmpty()) {
            return new HashMap<>(map1);
        }
        
        Map<Object, Object> result = new HashMap<>();
        
        // Add all keys from both maps
        Set<Object> allKeys = new HashSet<>();
        allKeys.addAll(map1.keySet());
        allKeys.addAll(map2.keySet());
        
        for (Object key : allKeys) {
            Object val1 = map1.get(key);
            Object val2 = map2.get(key);
            
            if (val1 != null && val2 != null) {
                result.put(key, crossoverObject(val1, val2, val1.getClass()));
            } else if (val1 != null) {
                result.put(key, val1);
            } else {
                result.put(key, val2);
            }
        }
        
        return result;
    }
    
    /**
     * Performs mutation on an object.
     * 
     * @param obj The object to mutate
     * @param type The type of the object
     * @return Mutated object
     */
    private Object mutateObject(Object obj, Class<?> type) {
        
        if (obj == null) {
            return generateRandomValue(type);
        }
        
        if (type.isPrimitive() || type == String.class || type == Number.class) {
            return mutatePrimitive(obj);
        } else if (type.isArray()) {
            return mutateArray(obj);
        } else if (Collection.class.isAssignableFrom(type)) {
            return mutateCollection((Collection<?>) obj);
        } else if (Map.class.isAssignableFrom(type)) {
            return mutateMap((Map<?, ?>) obj);
        } else {
            // For custom objects, return the original (no mutation)
            return obj;
        }
    }
    
    /**
     * Performs mutation on primitive values.
     * 
     * @param obj The primitive to mutate
     * @return Mutated primitive
     */
    private Object mutatePrimitive(Object obj) {
        
        if (obj instanceof String) {
            return mutateString((String) obj);
        } else if (obj instanceof Number) {
            return mutateNumber((Number) obj);
        } else if (obj instanceof Boolean) {
            return !(Boolean) obj; // Flip boolean
        } else {
            return obj;
        }
    }
    
    /**
     * Performs mutation on a string.
     * 
     * @param str The string to mutate
     * @return Mutated string
     */
    private String mutateString(String str) {
        
        if (str.isEmpty()) {
            return String.valueOf((char) random.nextInt(32, 127));
        }
        
        // Choose mutation strategy
        int strategy = random.nextInt(6);
        
        switch (strategy) {
            case 0:
                // Insert random character
                int insertPos = random.nextInt(str.length() + 1);
                char insertChar = (char) random.nextInt(32, 127);
                return str.substring(0, insertPos) + insertChar + str.substring(insertPos);
            case 1:
                // Delete random character
                if (str.length() > 1) {
                    int deletePos = random.nextInt(str.length());
                    return str.substring(0, deletePos) + str.substring(deletePos + 1);
                }
                return str;
            case 2:
                // Replace random character
                int replacePos = random.nextInt(str.length());
                char replaceChar = (char) random.nextInt(32, 127);
                return str.substring(0, replacePos) + replaceChar + str.substring(replacePos + 1);
            case 3:
                // Duplicate substring
                if (str.length() > 1) {
                    int start = random.nextInt(str.length() - 1);
                    int end = random.nextInt(start + 1, str.length());
                    String substring = str.substring(start, end);
                    return str + substring;
                }
                return str;
            case 4:
                // Reverse substring
                if (str.length() > 1) {
                    int start = random.nextInt(str.length() - 1);
                    int end = random.nextInt(start + 1, str.length());
                    String substring = str.substring(start, end);
                    String reversed = new StringBuilder(substring).reverse().toString();
                    return str.substring(0, start) + reversed + str.substring(end);
                }
                return str;
            case 5:
                // Random string
                return generateRandomString(str.length());
            default:
                return str;
        }
    }
    
    /**
     * Performs mutation on a number.
     * 
     * @param num The number to mutate
     * @return Mutated number
     */
    private Number mutateNumber(Number num) {
        double value = num.doubleValue();
        
        // Choose mutation strategy
        int strategy = random.nextInt(4);
        
        switch (strategy) {
            case 0:
                // Add random value
                value += random.nextDouble() * 100 - 50;
                break;
            case 1:
                // Multiply by random factor
                value *= random.nextDouble() * 2 + 0.5;
                break;
            case 2:
                // Bit flip (for integers)
                if (num instanceof Integer) {
                    int intValue = (Integer) num;
                    int bitPos = random.nextInt(32);
                    intValue ^= (1 << bitPos);
                    return intValue;
                }
                break;
            case 3:
                // Random value
                value = random.nextDouble() * 1000 - 500;
                break;
        }
        
        // Return the same type as the original
        if (num instanceof Integer) {
            return (int) value;
        } else if (num instanceof Long) {
            return (long) value;
        } else if (num instanceof Float) {
            return (float) value;
        } else if (num instanceof Double) {
            return value;
        } else {
            return value;
        }
    }
    
    /**
     * Performs mutation on an array.
     * 
     * @param arr The array to mutate
     * @return Mutated array
     */
    private Object mutateArray(Object arr) {
        int length = Array.getLength(arr);
        
        if (length == 0) {
            return arr;
        }
        
        // Choose mutation strategy
        int strategy = random.nextInt(3);
        
        switch (strategy) {
            case 0:
                // Mutate random element
                int index = random.nextInt(length);
                Object element = Array.get(arr, index);
                Class<?> componentType = arr.getClass().getComponentType();
                Array.set(arr, index, mutateObject(element, componentType));
                return arr;
            case 1:
                // Add random element
                Class<?> type = arr.getClass().getComponentType();
                Object newArr = Array.newInstance(type, length + 1);
                System.arraycopy(arr, 0, newArr, 0, length);
                Array.set(newArr, length, generateRandomValue(type));
                return newArr;
            case 2:
                // Remove random element
                if (length > 1) {
                    int removeIndex = random.nextInt(length);
                    Object result = Array.newInstance(arr.getClass().getComponentType(), length - 1);
                    System.arraycopy(arr, 0, result, 0, removeIndex);
                    System.arraycopy(arr, removeIndex + 1, result, removeIndex, length - removeIndex - 1);
                    return result;
                }
                return arr;
            default:
                return arr;
        }
    }
    
    /**
     * Performs mutation on a collection.
     * 
     * @param coll The collection to mutate
     * @return Mutated collection
     */
    private Collection<?> mutateCollection(Collection<?> coll) {
        
        if (coll.isEmpty()) {
            return new ArrayList<>();
        }
        
        List<Object> list = new ArrayList<>(coll);
        
        // Choose mutation strategy
        int strategy = random.nextInt(3);
        
        switch (strategy) {
            case 0:
                // Mutate random element
                int index = random.nextInt(list.size());
                Object element = list.get(index);
                list.set(index, mutateObject(element, 
                        element != null ? element.getClass() : Object.class));
                break;
            case 1:
                // Add random element
                list.add(generateRandomValue(Object.class));
                break;
            case 2:
                // Remove random element
                if (list.size() > 1) {
                    list.remove(random.nextInt(list.size()));
                }
                break;
        }
        
        return list;
    }
    
    /**
     * Performs mutation on a map.
     * 
     * @param map The map to mutate
     * @return Mutated map
     */
    private Map<?, ?> mutateMap(Map<?, ?> map) {
        
        if (map.isEmpty()) {
            return new HashMap<>();
        }
        
        Map<Object, Object> result = new HashMap<>(map);
        
        // Choose mutation strategy
        int strategy = random.nextInt(3);
        
        switch (strategy) {
            case 0:
                // Mutate random value
                List<Object> keys = new ArrayList<>(result.keySet());
                Object key = keys.get(random.nextInt(keys.size()));
                Object value = result.get(key);
                result.put(key, mutateObject(value, 
                        value != null ? value.getClass() : Object.class));
                break;
            case 1:
                // Add random key-value pair
                result.put(generateRandomValue(Object.class), generateRandomValue(Object.class));
                break;
            case 2:
                // Remove random key
                if (result.size() > 1) {
                    List<Object> keyList = new ArrayList<>(result.keySet());
                    result.remove(keyList.get(random.nextInt(keyList.size())));
                }
                break;
        }
        
        return result;
    }
    
    /**
     * Generates a random value of the specified type.
     * 
     * @param type The target type
     * @return Random value
     */
    private Object generateRandomValue(Class<?> type) {
        if (type == String.class) {
            return generateRandomString(random.nextInt(1, 20));
        } else if (type == Integer.class || type == int.class) {
            return random.nextInt();
        } else if (type == Long.class || type == long.class) {
            return random.nextLong();
        } else if (type == Double.class || type == double.class) {
            return random.nextDouble();
        } else if (type == Float.class || type == float.class) {
            return random.nextFloat();
        } else if (type == Boolean.class || type == boolean.class) {
            return random.nextBoolean();
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
     * Generates a random string of the specified length.
     * 
     * @param length The desired length
     * @return Random string
     */
    private String generateRandomString(int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append((char) random.nextInt(32, 127));
        }
        return sb.toString();
    }
} 