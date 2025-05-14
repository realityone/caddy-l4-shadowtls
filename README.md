# caddy-l4-shadowtls

Embed ShadowTLS into Caddy

## Example

```caddyfile
{
    layer4 {
        :443 {
            @secure {
                tls {
                    sni www.huya.com
                }
                shadow_tls {
                    password yoursecret
                }
            }
            route @secure {
                shadow_tls {
                    data_server 127.0.0.1:8888
                }
            }
            route {
                proxy www.huya.com:443
            }
        }
    }
}
```
