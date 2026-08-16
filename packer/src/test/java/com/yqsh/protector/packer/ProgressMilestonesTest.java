package com.yqsh.protector.packer;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class ProgressMilestonesTest {
    @Test
    public void emitsDecileMilestones() {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        PrintStream prev = System.out;
        System.setOut(new PrintStream(buf));
        try {
            ProgressMilestones p = new ProgressMilestones("unzip", 100);
            for (int i = 0; i < 100; i++) {
                p.tick();
            }
            p.finish();
        } finally {
            System.setOut(prev);
        }
        String s = buf.toString();
        assertTrue(s.contains("unzip: 0/100 (0%)"));
        assertTrue(s.contains("unzip: 10/100 (10%)"));
        assertTrue(s.contains("unzip: 50/100 (50%)"));
        assertTrue(s.contains("unzip: 100/100 (100%)"));
    }
}
