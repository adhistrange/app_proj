package com.securityresearch.fuzzer.ui;

import com.vaadin.flow.component.page.AppShellConfigurator;
import com.vaadin.flow.theme.Theme;
import com.vaadin.flow.theme.lumo.Lumo;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

/**
 * Main Spring Boot application class for the Java micro-fuzzing framework.
 * This is the entry point for the Vaadin web interface.
 */
@SpringBootApplication
@ComponentScan(basePackages = {
    "com.securityresearch.fuzzer.core",
    "com.securityresearch.fuzzer.analysis", 
    "com.securityresearch.fuzzer.api",
    "com.securityresearch.fuzzer.ui"
})
@Theme(value = Lumo.class, variant = Lumo.DARK)
public class FuzzerApplication implements AppShellConfigurator {
    
    public static void main(String[] args) {
        SpringApplication.run(FuzzerApplication.class, args);
    }
} 