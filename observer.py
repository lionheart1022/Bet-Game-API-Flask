#!/usr/bin/env python3

# Observer daemon:
# listens on some port/path,
# may have some children configured,
# knows how many streams can it handle.
# Messaging flow:
#
# Client -> Master: Please watch the stream with URL ... for game ...
# Master: checks if this stream is already watched
# Master -> Slave1: Can you watch one more stream? (details)
# Slave1 -> Master: no
# Master -> Slave2: Can you watch one more stream? (details)
# Slave2 -> Master: yes
# ...
# Slave2 -> Master: stream X finished, result is Xres
# Master -> Poller: stream X done
