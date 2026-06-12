//! NFSv3 frontend for SlateFS.
//!
//! Implemented in Phase 2 (see `slatefs-plan.md` §9.2 and §14). The Phase 2 spike
//! selects between `zerofs_nfsserve` and `nfs3_server` based on readdir-cookie
//! control, WRITE stable-flag exposure, READDIRPLUS support, maintenance, license.
