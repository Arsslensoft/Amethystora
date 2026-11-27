#!/usr/bin/python3
"""A stand-in for GameMode's daemon for the While you play suite (77): the session bus name, object, property and signals of
com.feralinteractive.GameMode as its source declares them, written from that declaration (ClientCount "i"; GameRegistered
and GameUnregistered "io"; RegisterGame, UnregisterGame and ListGames), counting the process numbers it is given. Like the
real daemon it emits the two signals and no PropertiesChanged. A lab file: it never goes into the image.

  gamemodestandin.py      owns com.feralinteractive.GameMode until killed
"""
from gi.repository import Gio, GLib

NAME = "com.feralinteractive.GameMode"
PATH = "/com/feralinteractive/GameMode"
XML = """<node>
  <interface name='com.feralinteractive.GameMode'>
    <method name='RegisterGame'><arg type='i' direction='in'/><arg type='i' direction='out'/></method>
    <method name='UnregisterGame'><arg type='i' direction='in'/><arg type='i' direction='out'/></method>
    <method name='ListGames'><arg type='a(io)' direction='out'/></method>
    <property name='ClientCount' type='i' access='read'/>
    <signal name='GameRegistered'><arg type='i'/><arg type='o'/></signal>
    <signal name='GameUnregistered'><arg type='i'/><arg type='o'/></signal>
  </interface>
</node>"""

games = {}
bus = None


def game_path(pid):
    return f"{PATH}/Games/{pid}"


def called(connection, sender, path, interface, method, params, invocation):
    if method == "ListGames":
        invocation.return_value(GLib.Variant("(a(io))", ([(pid, game_path(pid)) for pid in games],)))
        return
    (pid,) = params.unpack()
    if method == "RegisterGame":
        games[pid] = True
        name = "GameRegistered"
    else:
        games.pop(pid, None)
        name = "GameUnregistered"
    invocation.return_value(GLib.Variant("(i)", (0,)))
    bus.emit_signal(None, PATH, "com.feralinteractive.GameMode", name, GLib.Variant("(io)", (pid, game_path(pid))))


def get(connection, sender, path, interface, name):
    return GLib.Variant("i", len(games))


def acquired(connection, name):
    global bus
    bus = connection
    node = Gio.DBusNodeInfo.new_for_xml(XML)
    connection.register_object(PATH, node.interfaces[0], called, get, None)


Gio.bus_own_name(Gio.BusType.SESSION, NAME, Gio.BusNameOwnerFlags.NONE, acquired, None, None)
GLib.MainLoop().run()
