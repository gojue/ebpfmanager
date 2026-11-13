package manager

type pauser interface {
	Pause() error
	Resume() error
}
