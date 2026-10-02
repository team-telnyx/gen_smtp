%% MSG-2345 P5: callback whose handle_AUTH returns an INVALID custom reply
%% (no 3-digit SMTP code) — the session must fall back to the stock 535
%% instead of emitting protocol garbage on the wire.
-module(gen_smtp_server_auth_reply_invalid_callback).

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

%% Always returns a custom error reply WITHOUT a valid SMTP reply code.
handle_AUTH(_Type, _Username, _Password, State) ->
    {error, <<"no smtp code here">>, State}.

handle_STARTTLS(State) ->
    State.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

terminate(Reason, State) ->
    {ok, Reason, State}.
