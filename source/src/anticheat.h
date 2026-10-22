// anticheat.h: ACGuard status inside the client (the /anticheat console command and a one-line HUD).
//
// ACGuard is a report-only DMA anti-cheat: a Windows service scans the PCI bus and writes status.json and
// findings.jsonl to its output directory (env ACGUARD_DIR, default C:\ProgramData\ACGuard). The game only READS
// those files and shows what they say; it judges nothing and changes nothing about gameplay, protocol or server.
//
// Not to be confused with the closed-source server-side "ACAC" anticheat.h that serverchecks.h includes under
// #ifdef ACAC; that header is not part of this repository and this one is never built with ACAC defined.

#ifndef ACGUARD_ANTICHEAT_H
#define ACGUARD_ANTICHEAT_H

extern void anticheat_init();       // once from main() after the config is loaded: picks the output dir, first read
extern void anticheat_update();     // every frame: re-reads status.json and the new tail of findings.jsonl every 1000 ms
extern void anticheat_drawhud();    // from the HUD pass: one line when anticheat_hud != 0
extern int anticheat_hud;           // VARP(anticheat_hud, 0, 1, 1)

#endif
