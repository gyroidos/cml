.PHONY: all
all: container.pb-c.c guestos.pb-c.c device.pb-c.c

container.pb-c.c: container.proto
	protoc --c_out=. $<

guestos.pb-c.c: guestos.proto
	protoc --c_out=. $<

device.pb-c.c: device.proto
	protoc --c_out=. $<
