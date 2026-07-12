/**
 * Matches CTFd's real dynamic_challenges/assets/view.js pattern almost
 * exactly. CTFd._internal.challenge.{data,renderer,preRender,render,
 * postRender,submit} is a shared global the participant-facing challenge
 * modal's Alpine component (submitChallenge()) reads from — every
 * challenge type must set these (there's no usable default), unlike
 * create.js/update.js where this same object is NOT read at all.
 *
 * submit() posts straight to CTFd's own /api/v1/challenges/attempt, which
 * CTFd dispatches server-side to EdoChallengeType.attempt()/.solve() for
 * "edo"-type challenges — no custom endpoint needed. Rate limiting lives
 * inside attempt() itself (challenge_type.py) precisely so this default
 * native path enforces it too.
 */
CTFd._internal.challenge.data = undefined;

// TODO: Remove in CTFd v4.0
CTFd._internal.challenge.renderer = null;

CTFd._internal.challenge.preRender = function () {};

// TODO: Remove in CTFd v4.0
CTFd._internal.challenge.render = null;

CTFd._internal.challenge.postRender = function () {};

CTFd._internal.challenge.submit = function (preview) {
  var challenge_id = parseInt(CTFd.lib.$("#challenge-id").val());
  var submission = CTFd.lib.$("#challenge-input").val();

  var body = {
    challenge_id: challenge_id,
    submission: submission,
  };
  var params = {};
  if (preview) {
    params["preview"] = true;
  }

  return CTFd.api.post_challenge_attempt(params, body).then(function (response) {
    return response;
  });
};
