/**
 * Matches CTFd's real create.js pattern (see CTFd/plugins/dynamic_challenges/
 * assets/create.js) — the admin create modal doesn't use the
 * CTFd._internal.challenge render/submit pipeline at all; that's exclusively
 * for the participant-facing view/solve flow (see view.js). Mutating it here
 * was wrong: it stomps a shared global CTFd's own admin JS may still be using
 * for the description's live markdown preview, which can throw and silently
 * break the rest of the modal's setup — including wiring the Create button.
 */
CTFd.plugin.run((_CTFd) => {
  const $ = _CTFd.lib.$;
  const md = _CTFd.lib.markdown();
});
