%% MSG-2345 P5: callback module for exercising the custom AUTH reply shapes
%% (`{reply, Reply, State}` success and `{error, Reply, State}` failure) that
%% email_submission's ASM-backed handle_AUTH returns. Lives in test/ so the
%% shipped src surface is unchanged.
-module(gen_smtp_server_auth_reply_test_callback).

-export([
    init/4,
    handle_HELO/2,
    handle_EHLO/3,
    handle_MAIL/2,
    handle_MAIL_extension/2,
    handle_RCPT/2,
    handle_RCPT_extension/2,
    handle_DATA/4,
    handle_RSET/1,
    handle_VRFY/2,
    handle_other/3,
    handle_AUTH/4,
    handle_STARTTLS/1,
    code_change/3,
    terminate/2
]).

init(_Hostname, _SessionCount, _Peername, _Options) ->
    {ok, <<"localhost test banner">>, #{}}.

handle_HELO(_Hostname, State) ->
    {ok, 65536, State}.

handle_EHLO(_Hostname, Extensions, State) ->
    {ok, Extensions ++ [{"AUTH", "PLAIN LOGIN"}], State}.

handle_MAIL(_From, State) ->
    {ok, State}.

handle_MAIL_extension(_Extension, _State) ->
    error.

handle_RCPT(_To, State) ->
    {ok, State}.

handle_RCPT_extension(_Extension, _State) ->
    error.

handle_DATA(_From, _To, _Data, State) ->
    {ok, <<"queued">>, State}.

handle_RSET(State) ->
    State.

handle_VRFY(_Address, State) ->
    {error, <<"252 VRFY disabled">>, State}.

handle_other(_Verb, _Args, State) ->
    {[<<"500 Error: command not recognized">>], State}.

%% Valid credential -> success with a custom 235 reply.
handle_AUTH(_Type, <<"apikey">>, <<"valid-key">>, State) ->
    {reply, <<"235 2.7.0 Authenticated">>, State};
%% Invalid credential -> failure with a custom 535 reply (5yz keeps the
%% session open so the client may retry; 4yz is terminal and tested
%% separately below).
handle_AUTH(_Type, <<"apikey">>, <<"invalid-key">>, State) ->
    {error, <<"535 5.7.8 Authentication credentials invalid">>, State};
%% Terminal temporary failure: a 4yz custom reply must close the session
%% exactly like the timeout-421 does (P6 A-M1).
handle_AUTH(_Type, <<"apikey">>, <<"down-key">>, State) ->
    {error, <<"421 4.7.0 Temporary authentication failure, retry later">>, State};
%% Unicode charlist success reply: must be validated, normalized to UTF-8
%% and sent as that binary — never the original list (P6 A-H1).
handle_AUTH(_Type, <<"apikey">>, <<"unicode-key">>, State) ->
    {reply, "235 2.7.0 Authenticated \x{03bb}", State};
%% Shape/status-class contradictions must fall back to stock 535 (P6 A-M2).
handle_AUTH(_Type, <<"apikey">>, <<"contradiction-key">>, State) ->
    {error, <<"235 2.7.0 should not be an error shape">>, State};
%% Any other shape keeps the stock behavior: plain failure.
handle_AUTH(_Type, _Username, _Password, _State) ->
    error.

handle_STARTTLS(State) ->
    State.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

terminate(Reason, State) ->
    {ok, Reason, State}.
