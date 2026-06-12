//! 9P2000.L frontend for SlateFS.
//!
//! Implemented in Phase 4 (see `slatefs-plan.md` §9.3 and §14): own codec
//! (little-endian `size[4] type[1] tag[2]` framing), per-connection fid table,
//! bearer-token auth at `Tattach`, optional rustls.
