# dmgbuild settings for Sequent's disk image: the app and a shortcut to
# Applications side by side over a background with an arrow between them,
# so installing is a drag. dmgbuild writes the window's layout itself,
# without scripting Finder, which suits a build on a headless runner.
#
#   make dmg   (after `make app`; needs `pip install dmgbuild`)
import os.path

app = defines.get("app", "build/Sequent.app")  # noqa: F821, dmgbuild provides defines
appname = os.path.basename(app)

format = "ULFO"  # lzfse: smaller than zlib, opens on any macOS Sequent runs on
files = [app]
symlinks = {"Applications": "/Applications"}
icon = os.path.join(app, "Contents", "Resources", "AppIcon.icns")

# The window: the size of background.svg, nothing but the two icons.
background = defines.get("background", "build/dmg-background.tiff")  # noqa: F821
window_rect = ((200, 140), (600, 380))
default_view = "icon-view"
show_status_bar = False
show_tab_view = False
show_toolbar = False
show_pathbar = False
show_sidebar = False
icon_size = 128
text_size = 13
icon_locations = {appname: (150, 190), "Applications": (450, 190)}
