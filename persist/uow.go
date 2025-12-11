package persist

// Config stores configuration for the Execute method.
type Config struct {
	// PreCommitHooks controls whether the onCommit hook executes before or after a database commit.
	// false (default): Post-Commit Hooks - executes after a successful database transaction commit.
	// true: Pre-Commit Hooks - executes before a database transaction commit. If the hook fails, the transaction is rolled back.
	PreCommitHooks bool
}

// ExecuteOption is a function used to modify Config.
type ExecuteOption func(*Config)
