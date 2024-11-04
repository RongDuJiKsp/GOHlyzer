package capture

import "GOHlyzer/handler"

type Caper interface {
	StartWith(h handler.FlowHandler)
}
