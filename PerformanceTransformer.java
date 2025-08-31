package com.securityresearch.fuzzer.instrumentation.transformer;

import com.securityresearch.fuzzer.core.config.FuzzerConfiguration;
import com.securityresearch.fuzzer.instrumentation.metrics.PerformanceMetrics;
import org.objectweb.asm.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.security.ProtectionDomain;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Bytecode transformer that instruments methods to collect performance metrics
 * including execution time, memory usage, and CPU utilization.
 */
public class PerformanceTransformer implements ClassFileTransformer {
    
    private static final Logger logger = LoggerFactory.getLogger(PerformanceTransformer.class);
    
    private final FuzzerConfiguration configuration;
    private final ConcurrentHashMap<String, PerformanceMetrics> metricsMap;
    private final AtomicLong methodCounter;
    
    public PerformanceTransformer(FuzzerConfiguration configuration) {
        this.configuration = configuration;
        this.metricsMap = new ConcurrentHashMap<>();
        this.methodCounter = new AtomicLong(0);
    }
    
    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                          ProtectionDomain protectionDomain, byte[] classfileBuffer) 
                          throws IllegalClassFormatException {
        
        if (className == null || !shouldInstrument(className)) {
            return classfileBuffer;
        }
        
        try {
            ClassReader reader = new ClassReader(classfileBuffer);
            ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_FRAMES);
            PerformanceClassVisitor visitor = new PerformanceClassVisitor(writer, configuration);
            reader.accept(visitor, ClassReader.EXPAND_FRAMES);
            return writer.toByteArray();
        } catch (Exception e) {
            logger.warn("Failed to transform class {}: {}", className, e.getMessage());
            return classfileBuffer;
        }
    }
    
    /**
     * Check if a class should be instrumented.
     * 
     * @param className Class name
     * @return true if should be instrumented
     */
    private boolean shouldInstrument(String className) {
        // Skip system classes and the fuzzer itself
        if (className.startsWith("java/") || 
            className.startsWith("sun/") || 
            className.startsWith("com/securityresearch/fuzzer/")) {
            return false;
        }
        
        // Only instrument if performance profiling is enabled
        return configuration.getPerformance().isEnableDetailedProfiling();
    }
    
    /**
     * Get performance metrics for a method.
     * 
     * @param methodId Method identifier
     * @return PerformanceMetrics instance
     */
    public PerformanceMetrics getMetrics(String methodId) {
        return metricsMap.get(methodId);
    }
    
    /**
     * Clear all collected metrics.
     */
    public void clearMetrics() {
        metricsMap.clear();
    }
    
    /**
     * Class visitor that instruments methods for performance monitoring.
     */
    private class PerformanceClassVisitor extends ClassVisitor {
        
        private final FuzzerConfiguration config;
        private String className;
        
        public PerformanceClassVisitor(ClassVisitor cv, FuzzerConfiguration config) {
            super(Opcodes.ASM9, cv);
            this.config = config;
        }
        
        @Override
        public void visit(int version, int access, String name, String signature, 
                         String superName, String[] interfaces) {
            this.className = name;
            super.visit(version, access, name, signature, superName, interfaces);
        }
        
        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor, 
                                       String signature, String[] exceptions) {
            MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
            
            // Skip constructors and static initializers
            if (name.equals("<init>") || name.equals("<clinit>")) {
                return mv;
            }
            
            // Only instrument public methods
            if ((access & Opcodes.ACC_PUBLIC) != 0) {
                return new PerformanceMethodVisitor(mv, className, name, descriptor, config);
            }
            
            return mv;
        }
    }
    
    /**
     * Method visitor that adds performance monitoring code.
     */
    private class PerformanceMethodVisitor extends MethodVisitor {
        
        private final String className;
        private final String methodName;
        private final String descriptor;
        private final FuzzerConfiguration config;
        private final String methodId;
        private final Label startLabel = new Label();
        private final Label endLabel = new Label();
        private final Label exceptionLabel = new Label();
        
        public PerformanceMethodVisitor(MethodVisitor mv, String className, String methodName, 
                                      String descriptor, FuzzerConfiguration config) {
            super(Opcodes.ASM9, mv);
            this.className = className;
            this.methodName = methodName;
            this.descriptor = descriptor;
            this.config = config;
            this.methodId = className + "." + methodName + descriptor;
        }
        
        @Override
        public void visitCode() {
            super.visitCode();
            
            // Mark start of method
            mv.visitLabel(startLabel);
            
            // Record start time
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/System", "nanoTime", "()J", false);
            mv.visitVarInsn(Opcodes.LSTORE, getLocalVariableIndex());
            
            // Record start memory if enabled
            if (config.getPerformance().isEnableMemoryTracking()) {
                mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Runtime", "getRuntime", "()Ljava/lang/Runtime;", false);
                mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Runtime", "totalMemory", "()J", false);
                mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Runtime", "getRuntime", "()Ljava/lang/Runtime;", false);
                mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Runtime", "freeMemory", "()J", false);
                mv.visitInsn(Opcodes.LSUB);
                mv.visitVarInsn(Opcodes.LSTORE, getLocalVariableIndex() + 2);
            }
        }
        
        @Override
        public void visitInsn(int opcode) {
            // Before return statements, add performance recording
            if (opcode >= Opcodes.IRETURN && opcode <= Opcodes.RETURN) {
                recordPerformanceMetrics();
            }
            super.visitInsn(opcode);
        }
        
        @Override
        public void visitMaxs(int maxStack, int maxLocals) {
            // Add exception handler for performance recording
            mv.visitTryCatchBlock(startLabel, endLabel, exceptionLabel, null);
            
            // Exception handler
            mv.visitLabel(exceptionLabel);
            recordPerformanceMetrics();
            mv.visitInsn(Opcodes.ATHROW);
            
            // End of method
            mv.visitLabel(endLabel);
            
            super.visitMaxs(maxStack + 4, maxLocals + 4);
        }
        
        /**
         * Add bytecode to record performance metrics.
         */
        private void recordPerformanceMetrics() {
            // Calculate execution time
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/System", "nanoTime", "()J", false);
            mv.visitVarInsn(Opcodes.LLOAD, getLocalVariableIndex());
            mv.visitInsn(Opcodes.LSUB);
            mv.visitVarInsn(Opcodes.LSTORE, getLocalVariableIndex() + 1);
            
            // Calculate memory usage if enabled
            if (config.getPerformance().isEnableMemoryTracking()) {
                mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Runtime", "getRuntime", "()Ljava/lang/Runtime;", false);
                mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Runtime", "totalMemory", "()J", false);
                mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Runtime", "getRuntime", "()Ljava/lang/Runtime;", false);
                mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Runtime", "freeMemory", "()J", false);
                mv.visitInsn(Opcodes.LSUB);
                mv.visitVarInsn(Opcodes.LLOAD, getLocalVariableIndex() + 2);
                mv.visitInsn(Opcodes.LSUB);
                mv.visitVarInsn(Opcodes.LSTORE, getLocalVariableIndex() + 3);
            }
            
            // Store metrics in the metrics map
            mv.visitLdcInsn(methodId);
            mv.visitVarInsn(Opcodes.LLOAD, getLocalVariableIndex() + 1);
            if (config.getPerformance().isEnableMemoryTracking()) {
                mv.visitVarInsn(Opcodes.LLOAD, getLocalVariableIndex() + 3);
            } else {
                mv.visitInsn(Opcodes.LCONST_0);
            }
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, 
                             "com/securityresearch/fuzzer/instrumentation/metrics/PerformanceMetrics", 
                             "record", "(Ljava/lang/String;JJ)V", false);
        }
        
        /**
         * Get the local variable index for storing performance data.
         * 
         * @return Local variable index
         */
        private int getLocalVariableIndex() {
            // Calculate based on method parameters
            Type[] paramTypes = Type.getArgumentTypes(descriptor);
            int index = 0;
            for (Type paramType : paramTypes) {
                index += paramType.getSize();
            }
            return index;
        }
    }
} 