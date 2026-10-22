// acguard_client.h: ACGuard status inside the client (the /anticheat console command and a one-line HUD).
//
// ACGuard is a report-only DMA anti-cheat: a Windows service scans the PCI bus and writes status.json and
// findings.jsonl to its output directory (env ACGUARD_DIR, default C:\ProgramData\ACGuard). The game only READS
// those files and shows what they say; it judges nothing and changes nothing about gameplay, protocol or server.
//
// Named acguard_client.* (not anticheat.*) because serverchecks.h includes a closed-source "anticheat.h" under
// #ifdef ACAC; the two must never be confused.

#ifndef ACGUARD_CLIENT_H
#define ACGUARD_CLIENT_H

extern void anticheat_init();       // once from main() after the config is loaded: picks the output dir, reads all findings
extern void anticheat_update();     // every frame: re-reads status.json and the new tail of findings.jsonl every 1000 ms
extern void anticheat_drawhud();    // from the HUD pass: one line when anticheat_hud != 0
extern int anticheat_hud;           // VARP(anticheat_hud, 0, 1, 1)

#endif
