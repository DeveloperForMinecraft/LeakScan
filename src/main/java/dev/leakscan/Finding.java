package dev.leakscan;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

final class Finding {
    final int phase;
    final Severity severity;
    final String category;
    String title; // not final: recomputed when content-identical findings are merged (see mergeLabel)
    final String recommendation;
    final long firstSeenMs = System.currentTimeMillis();
    final Set<String> evidence = new LinkedHashSet<>();
    int hits;

    /** For findings like "/version, /ver, /about ..." — labels merged into the title via mergeTemplate. */
    private String mergeTemplate;
    private final List<String> mergeLabels = new ArrayList<>();

    Finding(int phase, Severity severity, String category, String title, String recommendation) {
        this.phase = phase;
        this.severity = severity;
        this.category = category;
        this.title = title;
        this.recommendation = recommendation;
    }

    /** template — a string with a single "%s" placeholder for join(labels, ", "). */
    void mergeLabel(String template, String label) {
        this.mergeTemplate = template;
        if (!mergeLabels.contains(label)) mergeLabels.add(label);
        this.title = String.format(mergeTemplate, String.join(", ", mergeLabels));
    }
}
