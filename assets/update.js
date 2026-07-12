/**
 * CTFd's real dynamic_challenges/assets/update.js is empty — the admin edit
 * modal doesn't use the CTFd._internal.challenge render/submit pipeline
 * (that's exclusively for the participant-facing view/solve flow, see
 * view.js). This file used to mutate that shared global here too, which
 * could throw and silently break the rest of the edit modal's JS setup.
 * Flag-weight editing is handled inline in update.html since it needs the
 * challenge id, which this file has no reason to touch.
 */
