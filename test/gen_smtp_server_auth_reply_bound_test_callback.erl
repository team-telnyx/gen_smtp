%% MSG-2345 P7: callback for the complete-line bound probe. Replies are
%% built to EXACT byte sizes: 510 (last legal: 510 + CRLF = 512) and 511
%% (first illegal: 511 + CRLF = 513 > 512).
-module(gen_smtp_server_auth_reply_bound_test_callback).

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

%% "535 5.7.8 bound 510 ok" = 24 bytes; pad to exactly 510 with spaces.
handle_AUTH(_Type, <<"apikey">>, <<"bound510">>, State) ->
    Prefix = <<"535 5.7.8 bound 510 ok">>,
    Reply = <<Prefix/binary, (padding(510 - byte_size(Prefix)))/binary>>,
    {error, Reply, State};

%% Same prefix padded to 511 — first illegal complete-line size.
handle_AUTH(_Type, <<"apikey">>, <<"bound511">>, State) ->
    Prefix = <<"535 5.7.8 bound 511 too long">>,
    Reply = <<Prefix/binary, (padding(511 - byte_size(Prefix)))/binary>>,
    {error, Reply, State};

handle_AUTH(_Type, _Username, _Password, _State) ->
    error.

handle_STARTTLS(State) ->
    State.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

terminate(Reason, State) ->
    {ok, Reason, State}.

%% Spaces are a legal SMTP reply character (no CR/LF/NUL).
padding(N) when N >= 0 ->
    binary:copy(<<" ">>, N).
