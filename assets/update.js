/**
 * Companion to update.html. Flag CRUD is handled inline in the template
 * because it needs access to the challenge id.
 */
CTFd._internal.challenge = CTFd._internal.challenge || {};
CTFd._internal.challenge.data = undefined;
CTFd._internal.challenge.preRender  = function () {};
CTFd._internal.challenge.render     = null;
CTFd._internal.challenge.postRender = function () {};
