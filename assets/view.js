/**
 * CTFd._internal.challenge.{data,renderer,preRender,render,postRender,
 * submit} is a shared global every challenge type must set (there's no
 * usable default) — unlike create.js/update.js where this object is not
 * read at all.
 *
 * The normal participant flag-submission UI in view.html no longer calls
 * submitChallenge()/this hook at all: it POSTs directly to
 * /plugins/edo_plugin/challenges/<id>/submit (see view.html), because
 * CTFd 3.7.5's native /api/v1/challenges/attempt has no partial-credit
 * concept and can't represent multi-flag progress (see challenge_type.py's
 * class docstring on EdoChallengeType.attempt()).
 *
 * `submit` below is kept only because CTFd's ADMIN "Preview challenge"
 * feature (themes/admin/assets/js/challenges/challenge.js) renders this
 * same view.html client-side via nunjucks and independently wires its own
 * "#submit-key" button to call this exact hook — that path still needs a
 * working native-endpoint submit function. EdoChallengeType.attempt() is
 * written to be a safe fallback for exactly this case: it only ever
 * returns truthy for the flag that completes the full set, never
 * over-awards a partial find.
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
