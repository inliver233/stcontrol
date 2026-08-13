package controller

import (
	"context"
	"log"
	"time"

	"stcontrol/internal/ai"
)

// startAIPhaseWorkers starts the per-task phase workers (Phases 2-6B). Each
// worker is a low-frequency background loop that builds a redacted observation
// and enqueues it through the supervisor; all of them are no-ops when the AI
// supervisor is disabled (aiSupervisor == nil). Workers never touch business
// request paths and every advisory still passes the validator before storage.
func (s *Server) startAIPhaseWorkers(ctx context.Context) {
	if s.aiSupervisor == nil {
		return
	}
	start := func(name string, every time.Duration, fn func(context.Context) error) {
		go func() {
			ticker := time.NewTicker(every)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if err := fn(ctx); err != nil && ctx.Err() == nil {
						log.Printf("ai: %s: %v", name, err)
					}
				}
			}
		}()
	}
	// Phase 2: 告警归因（对未解决的严重告警生成 anomaly_attribution 请求）。
	start("anomaly attribution", 60*time.Second, s.enqueueAnomalyAttribution)
	// Phase 3: 节点/备份目标排序（对 eligible 候选生成 schedule_recommendation）。
	start("schedule recommendation", 10*time.Minute, s.enqueueScheduleRecommendation)
	// Phase 4: 恢复目标/步骤排序。
	start("recovery plan", 10*time.Minute, s.enqueueRecoveryPlan)
	// Phase 5: 导入歧义分类说明。
	start("import review", 30*time.Minute, s.enqueueImportReview)
	// Phase 6A: 灾难判断只读建议。
	start("disaster review", 60*time.Second, s.enqueueDisasterReview)
	// Phase 6B: 冲突元数据建议。
	start("conflict review", 60*time.Second, s.enqueueConflictReview)
}

var _ = ai.ModeShadow
