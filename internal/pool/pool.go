// Package pool 实现号池的选号策略（分组过滤 + 失败度加权轮询 + 余额感知）。
//
// 选号是业务策略而不是持久化细节：抽出来后 Scheduler 不持有账号列表，
// 调用方在持锁状态下把快照传进来即可。
package pool

import (
	"strconv"
	"strings"
	"time"

	"scnet2api/internal/scnet"
)

// BalanceStaleAfter 是「余额为 0 / 欠费」被判为陈旧、需要重探的时限。
//
// 免费模型不受余额影响；付费模型在欠费时会稳定 402。把陈旧的 0 当未知，
// 避免充值后账号被永久排除在调度之外。
const BalanceStaleAfter = 15 * time.Minute

// Scheduler 保存轮询游标，实现号池选号。
//
// 非并发安全：调用方必须在自己的锁内使用（store 用写锁保护它）。
type Scheduler struct {
	rotate int
}

// New 构造调度器。
func New() *Scheduler { return &Scheduler{} }

// Pick 在 accounts 里按分组与健康度选一个账号；无可用账号时返回 nil。
//
// freeOnly 为 true 时（调用免费模型）优先选择余额充足或未探测的账号；
// 为 false 时（付费模型）跳过已知欠费账号。
func (s *Scheduler) Pick(accounts []*scnet.Account, group string, preferPaid bool) *scnet.Account {
	group = strings.TrimSpace(group)
	eligible := func(a *scnet.Account) bool {
		if a == nil || !a.Enabled || a.APIKey == nil || a.APIKey.APIKey == "" {
			return false
		}
		return group == "" || strings.EqualFold(a.GroupName(), group)
	}
	if a := s.pick(accounts, eligible, preferPaid); a != nil {
		return a
	}
	// 第二轮不再过滤余额：有账号总比直接失败强。
	if a := s.pick(accounts, eligible, false); a != nil {
		return a
	}
	return nil
}

// pick 按「失败最少 + 轮询」选号。
func (s *Scheduler) pick(accounts []*scnet.Account, eligible func(*scnet.Account) bool, needBalance bool) *scnet.Account {
	n := len(accounts)
	if n == 0 {
		return nil
	}
	var best *scnet.Account
	bestIdx := -1
	for i := 0; i < n; i++ {
		idx := (s.rotate + i) % n
		a := accounts[idx]
		if !eligible(a) {
			continue
		}
		if needBalance && BalanceExhausted(a) {
			continue
		}
		if best == nil || a.Failures < best.Failures {
			best = a
			bestIdx = idx
		}
		if a.Failures == 0 {
			s.rotate = (idx + 1) % n
			return a
		}
	}
	if bestIdx >= 0 {
		s.rotate = (bestIdx + 1) % n
	}
	return best
}

// BalanceExhausted 报告账号是否「已知欠费 / 余额为 0」。
//
// 保守为准：只有探测过、明确 unpaid 或余额可解析为 0 且刚探过的账号才算耗尽。
func BalanceExhausted(a *scnet.Account) bool {
	if a == nil || a.Balance == nil {
		return false
	}
	b := a.Balance
	if b.Unpaid {
		return true
	}
	bal := strings.TrimSpace(b.Balance)
	if bal == "" {
		return false
	}
	v, err := strconv.ParseFloat(bal, 64)
	if err != nil {
		return false
	}
	if v > 0 {
		return false
	}
	if b.CheckedAt <= 0 {
		return false
	}
	return time.Since(time.Unix(b.CheckedAt, 0)) < BalanceStaleAfter
}

// NeedsProbe 报告账号余额快照是否已过期。
func NeedsProbe(a *scnet.Account, maxAge time.Duration) bool {
	if a == nil {
		return false
	}
	if a.Balance == nil || a.Balance.CheckedAt <= 0 {
		return true
	}
	return time.Since(time.Unix(a.Balance.CheckedAt, 0)) > maxAge
}
