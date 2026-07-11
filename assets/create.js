/**
 * CTFd's admin challenge modal loads scripts declared in EdoChallengeType.scripts.
 * Our create.html already has an inline <script> that wires the scoring-mode
 * toggle -- this file exists as an integration point in case CTFd upgrades
 * change how forms serialize.
 *
 * Kept intentionally minimal.
 */
CTFd._internal.challenge = CTFd._internal.challenge || {};
CTFd._internal.challenge.data = undefined;

CTFd._internal.challenge.renderer = null;

CTFd._internal.challenge.preRender = function () {};
CTFd._internal.challenge.render = null;
CTFd._internal.challenge.postRender = function () {};
