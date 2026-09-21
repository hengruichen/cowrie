# -*- test-case-name: cowrie.test.protocol -*-
# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

from __future__ import annotations

import os
import socket
import sys
import time
import traceback
from typing import ClassVar

from twisted.conch import recvline
from twisted.conch.insults import insults
from twisted.internet import error
from twisted.protocols.policies import TimeoutMixin
from twisted.python import failure, log

import cowrie.commands
from cowrie.core.config import CowrieConfig
from cowrie.shell import command, honeypot


class HoneyPotBaseProtocol(insults.TerminalProtocol, TimeoutMixin):
    """
    Base protocol for interactive and non-interactive use
    """

    commands: ClassVar = {}
    for c in cowrie.commands.__all__:
        try:
            module = __import__(
                f"cowrie.commands.{c}", globals(), locals(), ["commands"]
            )
            commands.update(module.commands)
        except ImportError as e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            log.err(
                "Failed to import command {}: {}: {}".format(
                    c,
                    e,
                    "".join(
                        traceback.format_exception(exc_type, exc_value, exc_traceback)
                    ),
                )
            )

    def __init__(self, avatar):
        self.user = avatar
        self.environ = avatar.environ
        self.hostname: str = self.user.server.hostname
        self.fs = self.user.server.fs
        self.pp = None
        self.logintime: float
        self.realClientIP: str
        self.realClientPort: int
        self.kippoIP: str
        self.clientIP: str
        self.sessionno: int
        self.factory = None

        if self.fs.exists(self.user.avatar.home):
            self.cwd = self.user.avatar.home
        else:
            self.cwd = "/"
        self.data = None
        self.password_input = False
        self.cmdstack = []

    def getProtoTransport(self):
        """
        Due to protocol nesting differences, we need provide how we grab
        the proper transport to access underlying SSH information. Meant to be
        overridden for other protocols.
        """
        return self.terminal.transport.session.conn.transport

    def logDispatch(self, **args):
        """
        Send log directly to factory, avoiding normal log dispatch
        """
        args["sessionno"] = self.sessionno
        self.factory.logDispatch(**args)

    def connectionMade(self) -> None:
        pt = self.getProtoTransport()

        self.factory = pt.factory
        self.sessionno = pt.transport.sessionno
        self.realClientIP = pt.transport.getPeer().host
        self.realClientPort = pt.transport.getPeer().port
        self.logintime = time.time()

        log.msg(eventid="cowrie.session.params", arch=self.user.server.arch)

        timeout = CowrieConfig.getint("honeypot", "interactive_timeout", fallback=180)
        self.setTimeout(timeout)

        # Source IP of client in user visible reports (can be fake or real)
        self.clientIP = CowrieConfig.get(
            "honeypot", "fake_addr", fallback=self.realClientIP
        )

        # Source IP of server in user visible reports (can be fake or real)
        if CowrieConfig.has_option("honeypot", "internet_facing_ip"):
            self.kippoIP = CowrieConfig.get("honeypot", "internet_facing_ip")
        else:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.connect(("8.8.8.8", 80))
                    self.kippoIP = s.getsockname()[0]
            except Exception:
                self.kippoIP = "192.168.0.1"

    def timeoutConnection(self) -> None:
        """
        this logs out when connection times out
        """
        ret = failure.Failure(error.ProcessTerminated(exitCode=1))
        self.terminal.transport.processEnded(ret)

    def connectionLost(self, reason):
        HoneyPotBaseProtocol.connectionLost(self, reason)
        recvline.HistoricRecvLine.connectionLost(self, reason)
        self.keyHandlers = {}

    def initializeScreen(self) -> None:
        """
        Overriding super to prevent terminal.reset()
        """
        self.setInsertMode()

    def call_command(self, pp, cmd, *args):
        self.pp = pp
        self.setTypeoverMode()
        HoneyPotBaseProtocol.call_command(self, pp, cmd, *args)

    def characterReceived(self, ch, moreCharactersComing):
        """
        Easier way to implement password input?
        """
        if self.mode == "insert":
            self.lineBuffer.insert(self.lineBufferIndex, ch)
        else:
            self.lineBuffer[self.lineBufferIndex : self.lineBufferIndex + 1] = [ch]
        self.lineBufferIndex += 1
        if not self.password_input:
            self.terminal.write(ch)

    def handle_RETURN(self):
        if len(self.cmdstack) == 1:
            if self.lineBuffer:
                self.historyLines.append(b"".join(self.lineBuffer))
            self.historyPosition = len(self.historyLines)
        return recvline.RecvLine.handle_RETURN(self)

    def handle_CTRL_C(self) -> None:
        if self.cmdstack:
            self.cmdstack[-1].handle_CTRL_C()

    def handle_CTRL_D(self) -> None:
        if self.cmdstack:
            self.cmdstack[-1].handle_CTRL_D()

    def handle_TAB(self) -> None:
        if self.cmdstack:
            self.cmdstack[-1].handle_TAB()

    def handle_CTRL_K(self) -> None:
        self.terminal.eraseToLineEnd()
        self.lineBuffer = self.lineBuffer[0 : self.lineBufferIndex]

    def handle_CTRL_L(self) -> None:
        """
        Handle a 'form feed' byte - generally used to request a screen
        refresh/redraw.
        """
        self.terminal.eraseDisplay()
        self.terminal.cursorHome()
        self.drawInputLine()

    def handle_CTRL_U(self) -> None:
        for _ in range(self.lineBufferIndex):
            self.terminal.cursorBackward()
            self.terminal.deleteCharacter()
        self.lineBuffer = self.lineBuffer[self.lineBufferIndex :]
        self.lineBufferIndex = 0

    def handle_CTRL_V(self) -> None:
        pass

    def handle_ESC(self) -> None:
        pass


class HoneyPotInteractiveTelnetProtocol(HoneyPotInteractiveProtocol):
    """
    Specialized HoneyPotInteractiveProtocol that provides Telnet specific
    overrides.
    """

    def __init__(self, avatar):
        HoneyPotInteractiveProtocol.__init__(self, avatar)

    def getProtoTransport(self):
        """
        Due to protocol nesting differences, we need to override how we grab
        the proper transport to access underlying Telnet information.
        """
        return self.terminal.transport.session.transport

