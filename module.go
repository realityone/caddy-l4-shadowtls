package caddyl4

import (
	// plugging in the standard modules for the layer4 app
	_ "github.com/mholt/caddy-l4/layer4"
	_ "github.com/mholt/caddy-l4/modules/l4proxy"
	_ "github.com/realityone/caddy-l4-shadowtls/l4shadowtls"
)
