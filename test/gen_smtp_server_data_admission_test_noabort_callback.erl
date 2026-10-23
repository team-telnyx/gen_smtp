%% MSG-2693: the admission test callback WITHOUT handle_DATA_aborted/2 — the
%% optional callback is absent, so the session's wire output must be exactly
%% what it was before the callback existed. Every other callback delegates.
-module(gen_smtp_server_data_admission_test_noabort_callback).

-export([
    init/4,
    handle_HELO/2,
    handle_EHLO/3,
    handle_MAIL/2,
    handle_MAIL_extension/2,
    handle_RCPT/2,
    handle_RCPT_extension/2,
    handle_DATA/4,
    handle_DATA_admission/2,
    handle_RSET/1,
    handle_VRFY/2,
    handle_other/3,
    handle_error/3,
    code_change/3,
    terminate/2
]).

-define(CB, gen_smtp_server_data_admission_test_callback).

init(Hostname, SessionCount, Peername, Options) -> ?CB:init(Hostname, SessionCount, Peername, Options).
handle_HELO(Hostname, State) -> ?CB:handle_HELO(Hostname, State).
handle_EHLO(Hostname, Extensions, State) -> ?CB:handle_EHLO(Hostname, Extensions, State).
handle_MAIL(From, State) -> ?CB:handle_MAIL(From, State).
handle_MAIL_extension(Extension, State) -> ?CB:handle_MAIL_extension(Extension, State).
handle_RCPT(To, State) -> ?CB:handle_RCPT(To, State).
handle_RCPT_extension(Extension, State) -> ?CB:handle_RCPT_extension(Extension, State).
handle_DATA(From, To, Data, State) -> ?CB:handle_DATA(From, To, Data, State).
handle_DATA_admission(ReceivedBytes, State) -> ?CB:handle_DATA_admission(ReceivedBytes, State).
handle_RSET(State) -> ?CB:handle_RSET(State).
handle_VRFY(Address, State) -> ?CB:handle_VRFY(Address, State).
handle_other(Verb, Args, State) -> ?CB:handle_other(Verb, Args, State).
handle_error(Class, Details, State) -> ?CB:handle_error(Class, Details, State).
code_change(OldVsn, State, Extra) -> ?CB:code_change(OldVsn, State, Extra).
terminate(Reason, State) -> ?CB:terminate(Reason, State).
