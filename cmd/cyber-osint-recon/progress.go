package main

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

type progressTracker struct {
	mu            sync.Mutex
	totalSteps    int
	completed     int
	startTime     time.Time
	stepStartTime time.Time
	currentStep   string
}

func newProgressTracker(totalSteps int) *progressTracker {
	now := time.Now()
	return &progressTracker{
		totalSteps:    totalSteps,
		completed:     0,
		startTime:     now,
		stepStartTime: now,
	}
}

func (p *progressTracker) startStep(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.currentStep = name
	p.stepStartTime = time.Now()
	fmt.Printf("[*] %s...\n", name)
}

func (p *progressTracker) completeStep() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.completed++
	elapsedStep := time.Since(p.stepStartTime)
	elapsedTotal := time.Since(p.startTime)

	progress := float64(p.completed) / float64(p.totalSteps) * 100
	var remaining time.Duration
	if p.completed > 0 {
		avg := elapsedTotal / time.Duration(p.completed)
		remaining = avg * time.Duration(p.totalSteps-p.completed)
	}

	fmt.Printf("[+] %s completed (elapsed: %s) [Progress: %.1f%% | Time: %s | Remaining: ~%s]\n",
		p.currentStep,
		formatDuration(elapsedStep),
		progress,
		formatDuration(elapsedTotal),
		formatDuration(remaining),
	)
}

func (p *progressTracker) totalElapsed() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	return time.Since(p.startTime)
}

func formatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh%dm%ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm%ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

func formatDurationWithPadding(d time.Duration, width int) string {
	s := formatDuration(d)
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}
