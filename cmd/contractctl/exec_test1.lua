local system = require("system");

system.nextBlock()

block = call("getBlock")
system.print(block)

call("set", "foo", "bar")
res = call("get", "foo")
system.print(res)

system.nextBlock()

call("set", "foo", {foo = 3.14, bar = false})
res = call("get", "foo")
system.print(res)

system.nextBlock()

call("set", "foo", {true, 2, 3})
res = call("get", "foo")
system.print(res)

system.nextBlock()

system.nextBlock()

res = call ("sha256", "hello world")
system.print(res)

system.printErr("last!!!")
res = call("testError")
system.print("line never reached")
