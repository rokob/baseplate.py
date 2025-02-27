import os
import socket
import unittest

from baseplate import BaseplateObserver, SpanObserver
from baseplate.lib.config import Endpoint
from baseplate.lib.edgecontext import EdgeContextFactory


def get_endpoint_or_skip_container(name, default_port):
    """Find a test server of the given type or raise SkipTest.

    This is useful for running tests in environments where we can't launch
    servers.

    If an environment variable like BASEPLATE_MEMCACHED_ADDR is present, that will
    override the default of {name}:{default_port}.

    """
    address = os.environ.get(f"BASEPLATE_{name.upper()}_ADDR", f"{name}:{default_port:d}")
    endpoint = Endpoint(address)

    try:
        sock = socket.socket(endpoint.family, socket.SOCK_STREAM)
        sock.settimeout(0.1)
        sock.connect(endpoint.address)
    except OSError:
        raise unittest.SkipTest(f"could not find {name} server for integration tests")
    else:
        sock.close()

    return endpoint


class TestSpanObserver(SpanObserver):
    def __init__(self, span):
        self.span = span
        self.on_start_called = False
        self.on_finish_called = False
        self.on_finish_exc_info = None
        self.tags = {}
        self.logs = []
        self.children = []

    def on_start(self):
        assert not self.on_start_called, "start was already called on this span"
        self.on_start_called = True

    def on_set_tag(self, key, value):
        self.tags[key] = value

    def assert_tag(self, key, value):
        assert key in self.tags, f"{key!r} not found in tags ({list(self.tags.keys())!r})"
        assert (
            self.tags[key] == value
        ), f"tag {key!r}: expected value {value!r} but found {self.tags[key]!r}"

    def on_log(self, name, payload):
        self.logs.append((name, payload))

    def on_finish(self, exc_info):
        assert not self.on_finish_called, "finish was already called on this span"
        self.on_finish_called = True
        self.on_finish_exc_info = exc_info

    def on_child_span_created(self, span):
        child = TestSpanObserver(span)
        self.children.append(child)
        span.register(child)

    def get_only_child(self):
        assert len(self.children) == 1, "observer has wrong number of children"
        return self.children[0]


class TestBaseplateObserver(BaseplateObserver):
    def __init__(self):
        self.children = []

    def get_only_child(self):
        assert len(self.children) == 1, "observer has wrong number of children"
        return self.children[0]

    def on_server_span_created(self, context, server_span):
        child = TestSpanObserver(server_span)
        self.children.append(child)
        server_span.register(child)


class FakeEdgeContextFactory(EdgeContextFactory):
    RAW_BYTES = b"raw_payload"
    DECODED_CONTEXT = "foo"

    def from_upstream(self, header_value):
        if header_value == self.RAW_BYTES:
            return self.DECODED_CONTEXT
        elif header_value is None:
            return None
