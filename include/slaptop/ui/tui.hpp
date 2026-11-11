#pragma once

#include "slaptop/config.hpp"

namespace slaptop {

class MonitorEngine;

namespace ui {

/// Runs the notcurses dashboard until the user quits.
///
/// The engine is expected to be started by the caller; the dashboard only
/// reads snapshots, so a slow instance never blocks a redraw.
/// Returns 0 on a normal quit, non-zero when the terminal cannot be
/// initialized.
int runDashboard(MonitorEngine& engine, const Theme& theme);

/// Connection parameters shown by the help screen: bind mode, where the
/// password came from, and the ldaprc files libldap applies on its own.  Set
/// once before runDashboard, so a refused bind can be explained from the UI.
void setConnectionInfo(const std::string& summary);

/// Reports what the current terminal can do graphically: TERM, whether
/// notcurses found kitty-graphics or sixel support, and a gradient test image
/// drawn with NCBLIT_PIXEL when available.
///
/// Run it *inside* the terminal you intend to use (not over tmux/ssh unless
/// the multiplexer forwards the protocol): `slaptop --probe-pixels`.
int probePixelSupport();

}  // namespace ui
}  // namespace slaptop
