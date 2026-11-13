package manager

type state uint

const (
	reset state = iota
	elfLoaded
	initialized
	stopping
	paused
	running
)
