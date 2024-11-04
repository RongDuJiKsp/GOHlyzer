package capture

import "GOHlyzer/flowhd"

type Caper interface {
	StartWith(h flowhd.FlowHandler)
}
