package com.securityresearch.fuzzer.instrumentation.transformer;

import com.securityresearch.fuzzer.core.config.FuzzerConfiguration;
import org.objectweb.asm.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.security.ProtectionDomain;

/**
 * Bytecode transformer that adds security checks and sandboxing to prevent
 * malicious operations during fuzzing.
 */
public class SecurityTransformer implements ClassFileTransformer {
    
    private static final Logger logger = LoggerFactory.getLogger(SecurityTransformer.class);
    
    private final FuzzerConfiguration configuration;
    
    public SecurityTransformer(FuzzerConfiguration configuration) {
        this.configuration = configuration;
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
            SecurityClassVisitor visitor = new SecurityClassVisitor(writer, configuration);
            reader.accept(visitor, ClassReader.EXPAND_FRAMES);
            return writer.toByteArray();
        } catch (Exception e) {
            logger.warn("Failed to transform class {} for security: {}", className, e.getMessage());
            return classfileBuffer;
        }
    }
    
    /**
     * Check if a class should be instrumented for security.
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
        
        // Only instrument if security manager is enabled
        return configuration.getSecurity().isEnableSecurityManager();
    }
    
    /**
     * Class visitor that adds security checks to methods.
     */
    private class SecurityClassVisitor extends ClassVisitor {
        
        private final FuzzerConfiguration config;
        private String className;
        
        public SecurityClassVisitor(ClassVisitor cv, FuzzerConfiguration config) {
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
                return new SecurityMethodVisitor(mv, className, name, descriptor, config);
            }
            
            return mv;
        }
    }
    
    /**
     * Method visitor that adds security checks.
     */
    private class SecurityMethodVisitor extends MethodVisitor {
        
        private final String className;
        private final String methodName;
        private final String descriptor;
        private final FuzzerConfiguration config;
        
        public SecurityMethodVisitor(MethodVisitor mv, String className, String methodName, 
                                   String descriptor, FuzzerConfiguration config) {
            super(Opcodes.ASM9, mv);
            this.className = className;
            this.methodName = methodName;
            this.descriptor = descriptor;
            this.config = config;
        }
        
        @Override
        public void visitCode() {
            super.visitCode();
            
            // Add security checks at the beginning of the method
            addSecurityChecks();
        }
        
        @Override
        public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
            // Add security checks before potentially dangerous method calls
            if (isDangerousMethod(owner, name)) {
                addMethodSecurityCheck(owner, name);
            }
            
            super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
        }
        
        @Override
        public void visitFieldInsn(int opcode, String owner, String name, String descriptor) {
            // Add security checks before field access
            if (isDangerousField(owner, name)) {
                addFieldSecurityCheck(owner, name);
            }
            
            super.visitFieldInsn(opcode, owner, name, descriptor);
        }
        
        /**
         * Add general security checks at method entry.
         */
        private void addSecurityChecks() {
            // Check execution timeout
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, 
                             "com/securityresearch/fuzzer/instrumentation/security/SecurityManager", 
                             "checkTimeout", "()V", false);
            
            // Check memory usage
            if (config.getPerformance().isEnableMemoryTracking()) {
                mv.visitMethodInsn(Opcodes.INVOKESTATIC, 
                                 "com/securityresearch/fuzzer/instrumentation/security/SecurityManager", 
                                 "checkMemoryUsage", "()V", false);
            }
            
            // Check stack depth
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, 
                             "com/securityresearch/fuzzer/instrumentation/security/SecurityManager", 
                             "checkStackDepth", "()V", false);
        }
        
        /**
         * Add security check before dangerous method calls.
         */
        private void addMethodSecurityCheck(String owner, String name) {
            mv.visitLdcInsn(owner);
            mv.visitLdcInsn(name);
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, 
                             "com/securityresearch/fuzzer/instrumentation/security/SecurityManager", 
                             "checkMethodAccess", "(Ljava/lang/String;Ljava/lang/String;)V", false);
        }
        
        /**
         * Add security check before dangerous field access.
         */
        private void addFieldSecurityCheck(String owner, String name) {
            mv.visitLdcInsn(owner);
            mv.visitLdcInsn(name);
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, 
                             "com/securityresearch/fuzzer/instrumentation/security/SecurityManager", 
                             "checkFieldAccess", "(Ljava/lang/String;Ljava/lang/String;)V", false);
        }
        
        /**
         * Check if a method is potentially dangerous.
         * 
         * @param owner Class name
         * @param name Method name
         * @return true if dangerous
         */
        private boolean isDangerousMethod(String owner, String name) {
            // File operations
            if (owner.equals("java/io/File") || owner.equals("java/nio/file/Files")) {
                return config.getSecurity().isRestrictFileAccess();
            }
            
            // Network operations
            if (owner.equals("java/net/Socket") || owner.equals("java/net/URLConnection")) {
                return config.getSecurity().isRestrictNetworkAccess();
            }
            
            // System operations
            if (owner.equals("java/lang/Runtime") || owner.equals("java/lang/ProcessBuilder")) {
                return config.getSecurity().isRestrictSystemAccess();
            }
            
            // Reflection
            if (owner.equals("java/lang/reflect/Method") || owner.equals("java/lang/Class")) {
                return true;
            }
            
            return false;
        }
        
        /**
         * Check if a field is potentially dangerous.
         * 
         * @param owner Class name
         * @param name Field name
         * @return true if dangerous
         */
        private boolean isDangerousField(String owner, String name) {
            // System properties
            if (owner.equals("java/lang/System") && name.equals("out")) {
                return config.getSecurity().isRestrictSystemAccess();
            }
            
            // Security manager
            if (owner.equals("java/lang/System") && name.equals("security")) {
                return true;
            }
            
            return false;
        }
    }
} 