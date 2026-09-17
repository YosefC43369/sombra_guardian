"""
plugins.builtin — plugins that ship with Sombra Guardian.

Every module here that defines a BasePlugin subclass is auto-discovered by
plugins.loader at boot. Keep built-ins conservative: they demonstrate the
plugin hooks and add genuinely non-invasive behaviour, but they must never be
required for the core bot to run (that is what failure isolation guarantees).
"""
