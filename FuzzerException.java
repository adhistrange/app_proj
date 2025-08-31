package com.securityresearch.fuzzer.core.exception;

/**
 * Base exception class for all fuzzer-related errors.
 * Provides a foundation for categorizing and handling different types of fuzzing failures.
 */
public class FuzzerException extends RuntimeException {
    
    private final ErrorType errorType;
    
    public FuzzerException(String message) {
        super(message);
        this.errorType = ErrorType.GENERAL;
    }
    
    public FuzzerException(String message, Throwable cause) {
        super(message, cause);
        this.errorType = ErrorType.GENERAL;
    }
    
    public FuzzerException(String message, ErrorType errorType) {
        super(message);
        this.errorType = errorType;
    }
    
    public FuzzerException(String message, Throwable cause, ErrorType errorType) {
        super(message, cause);
        this.errorType = errorType;
    }
    
    public ErrorType getErrorType() {
        return errorType;
    }
    
    /**
     * Categorizes different types of fuzzing errors for better error handling and reporting.
     */
    public enum ErrorType {
        GENERAL("General fuzzing error"),
        EXECUTION_TIMEOUT("Test execution exceeded timeout limit"),
        MEMORY_LIMIT_EXCEEDED("Memory usage exceeded configured limit"),
        SECURITY_VIOLATION("Security constraint violation detected"),
        INVALID_INPUT("Generated input is invalid or malformed"),
        TARGET_NOT_FOUND("Target method or class not found"),
        INSTRUMENTATION_FAILED("Bytecode instrumentation failed"),
        GENETIC_ALGORITHM_ERROR("Genetic algorithm operation failed"),
        DATABASE_ERROR("Database operation failed"),
        CONFIGURATION_ERROR("Invalid configuration detected");
        
        private final String description;
        
        ErrorType(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
    }
} 