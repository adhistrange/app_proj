package com.securityresearch.fuzzer.ui.view;

import com.securityresearch.fuzzer.analysis.model.VulnerabilityReport;
import com.securityresearch.fuzzer.ui.component.*;
import com.vaadin.flow.component.html.H1;
import com.vaadin.flow.component.html.H2;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.router.PageTitle;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.router.RouteAlias;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;

/**
 * Main dashboard view for the Java micro-fuzzing framework.
 * Provides an overview of fuzzing activities, vulnerabilities, and performance metrics.
 */
@Route(value = "", layout = MainLayout.class)
@RouteAlias(value = "dashboard", layout = MainLayout.class)
@PageTitle("Dashboard - Java Micro-Fuzzer")
public class DashboardView extends VerticalLayout {
    
    private final FuzzingPanel fuzzingPanel;
    private final VulnerabilityPanel vulnerabilityPanel;
    private final MetricsPanel metricsPanel;
    private final StatisticsPanel statisticsPanel;
    
    @Autowired
    public DashboardView(FuzzingPanel fuzzingPanel, 
                        VulnerabilityPanel vulnerabilityPanel,
                        MetricsPanel metricsPanel,
                        StatisticsPanel statisticsPanel) {
        this.fuzzingPanel = fuzzingPanel;
        this.vulnerabilityPanel = vulnerabilityPanel;
        this.metricsPanel = metricsPanel;
        this.statisticsPanel = statisticsPanel;
        
        initView();
    }
    
    private void initView() {
        setSizeFull();
        setPadding(true);
        setSpacing(true);
        
        // Header
        H1 header = new H1("Java Micro-Fuzzing Framework");
        header.getStyle().set("color", "var(--lumo-primary-color)");
        header.getStyle().set("margin-bottom", "1rem");
        
        // Main content layout
        HorizontalLayout mainLayout = new HorizontalLayout();
        mainLayout.setSizeFull();
        mainLayout.setSpacing(true);
        
        // Left column - Fuzzing and Statistics
        VerticalLayout leftColumn = new VerticalLayout();
        leftColumn.setWidth("50%");
        leftColumn.setSpacing(true);
        
        // Fuzzing panel
        H2 fuzzingHeader = new H2("Fuzzing Control");
        fuzzingHeader.getStyle().set("margin-top", "0");
        leftColumn.add(fuzzingHeader, fuzzingPanel);
        
        // Statistics panel
        H2 statsHeader = new H2("Statistics");
        statsHeader.getStyle().set("margin-top", "1rem");
        leftColumn.add(statsHeader, statisticsPanel);
        
        // Right column - Vulnerabilities and Metrics
        VerticalLayout rightColumn = new VerticalLayout();
        rightColumn.setWidth("50%");
        rightColumn.setSpacing(true);
        
        // Vulnerability panel
        H2 vulnHeader = new H2("Detected Vulnerabilities");
        vulnHeader.getStyle().set("margin-top", "0");
        rightColumn.add(vulnHeader, vulnerabilityPanel);
        
        // Metrics panel
        H2 metricsHeader = new H2("Performance Metrics");
        metricsHeader.getStyle().set("margin-top", "1rem");
        rightColumn.add(metricsHeader, metricsPanel);
        
        mainLayout.add(leftColumn, rightColumn);
        
        add(header, mainLayout);
        
        // Set up auto-refresh
        setupAutoRefresh();
    }
    
    private void setupAutoRefresh() {
        // Refresh panels every 5 seconds
        getUI().ifPresent(ui -> {
            ui.setPollInterval(5000);
            ui.addPollListener(event -> {
                vulnerabilityPanel.refresh();
                metricsPanel.refresh();
                statisticsPanel.refresh();
            });
        });
    }
    
    /**
     * Update vulnerability data.
     * 
     * @param vulnerabilities List of vulnerability reports
     */
    public void updateVulnerabilities(List<VulnerabilityReport> vulnerabilities) {
        vulnerabilityPanel.updateVulnerabilities(vulnerabilities);
    }
    
    /**
     * Show fuzzing progress.
     * 
     * @param generation Current generation
     * @param maxGenerations Maximum generations
     * @param bestFitness Current best fitness
     */
    public void updateFuzzingProgress(int generation, int maxGenerations, double bestFitness) {
        fuzzingPanel.updateProgress(generation, maxGenerations, bestFitness);
    }
    
    /**
     * Show fuzzing completion.
     * 
     * @param vulnerabilitiesFound Number of vulnerabilities found
     * @param testCasesGenerated Number of test cases generated
     */
    public void showFuzzingCompletion(int vulnerabilitiesFound, int testCasesGenerated) {
        fuzzingPanel.showCompletion(vulnerabilitiesFound, testCasesGenerated);
    }
} 