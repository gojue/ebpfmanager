package manager

import "errors"

var (
	ErrManagerNotInitialized = errors.New("the manager must be initialized first")
	ErrManagerNotStarted     = errors.New("the manager must be started first")
	ErrManagerRunning        = errors.New("the manager is already running")

	// Deprecated: 废弃段相关问题
	ErrUnknownSection = errors.New("unknown section")

	ErrUnknownMatchFuncName    = errors.New("unknown EbpfFuncName")
	ErrUnknownMatchFuncSpec    = errors.New("unknown MatchFuncSpec")
	ErrUnknownMap              = errors.New("unknown bpf map")
	ErrPinnedObjectNotFound    = errors.New("pinned object not found")
	ErrMapNameInUse            = errors.New("the provided map name is already taken")
	ErrIdentificationPairInUse = errors.New("the provided identification pair already exists")
	ErrProbeNotInitialized     = errors.New("the probe must be initialized first")
	ErrSectionFormat           = errors.New("invalid section format")
	ErrSymbolNotFound          = errors.New("symbol not found")
	ErrKprobeIDNotExist        = errors.New("kprobe id file doesn't exist")
	ErrUprobeIDNotExist        = errors.New("uprobe id file doesn't exist")
	ErrCloneProbeRequired      = errors.New("use CloneProbe to load 2 instances of the same program")
	ErrInterfaceNotSet         = errors.New("interface not provided: at least one of Ifindex and Ifname must be set")
	ErrMapInitialized          = errors.New("map already initialized")
	ErrMapNotInitialized       = errors.New("the map must be initialized first")
	ErrMapNotRunning           = errors.New("the map is not running")
	ErrLoopbackDisabled        = errors.New("loopback is disabled")
	ErrMissingEditorFlags      = errors.New("missing editor flags in map editor")
)
