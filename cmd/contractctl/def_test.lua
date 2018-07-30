local system = require("system");

function printBlock()
	system.print(system.getBlockhash());
	system.print(system.getBlockheight());
end

function getBlock()
	return {
		hash = system.getBlockhash(),
		height = system.getBlockheight()
	}
end

function set(k, v)
	system.setItem(k, v)
end

function get(k)
	return system.getItem(k)
end

function testError()
	system.print("testing error")
	assert(false)
end

function sha256(payload)
	return system.sha256(payload)
end
