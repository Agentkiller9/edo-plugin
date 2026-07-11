/**
 * Loaded by CTFd when a user opens the challenge modal.
 *
 * The heavy lifting -- countdown, spawn/stop/extend buttons, and the
 * rate-limited submit -- lives inline in view.html so it can read the
 * challenge id from the DOM without any bootstrapping ceremony. This file
 * exists so CTFd's asset pipeline is happy with the scripts registration
 * in EdoChallengeType.
 */
CTFd._internal.challenge = CTFd._internal.challenge || {};

CTFd._internal.challenge.preRender  = function () {};
CTFd._internal.challenge.render     = function (markdown) {
  return CTFd.lib.markdown().render(markdown);
};
CTFd._internal.challenge.postRender = function () {
  // Injected view.html script wires itself up on DOMContentLoaded-equivalent.
};

CTFd._internal.challenge.submit = function (preview) {
  // Delegated to our /plugins/edo_plugin/challenges/<id>/submit endpoint by view.html
  // so we get the rate limiter. Return a resolved promise for compatibility.
  return Promise.resolve({ data: { status: "handled_by_edo_plugin" } });
};
