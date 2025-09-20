import test from "ava"

import { TunnelClient, TunnelServer } from "ra-https-tunnel"

test("tunnel modules import", (t) => {
  t.truthy(TunnelClient)
  t.truthy(TunnelServer)
})
