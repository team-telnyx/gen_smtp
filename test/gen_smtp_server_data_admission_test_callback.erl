%% MSG-2693: callback module for the opt-in receive-time DATA admission tests
%% (gen_smtp_server_data_admission_test). Every callback reports to the test
%% process named in the callback options; handle_DATA_admission/2 answers as
%% the test configured. Lives in test/ so the shipped src surface is unchanged.
-module(gen_smtp_server_data_admission_test_callback).

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

%% Options: #{test := pid(), admission := Answer, maxsize => pos_integer()}
%% Answer: ok | {refuse, Reply} | {block, Millis, Then} | bad_shape
init(_Hostname, _SessionCount, _Peername, #{test := Test} = Options) ->
    Test ! {session, self()},
    {ok, <<"localhost admission test">>, Options}.

handle_HELO(_Hostname, State) ->
    {ok, maps:get(maxsize, State, 10485760), State}.

handle_EHLO(_Hostname, Extensions, State) ->
    MaxSize = integer_to_list(maps:get(maxsize, State, 10485760)),
    {ok, lists:keystore("SIZE", 1, Extensions, {"SIZE", MaxSize}), State}.

handle_MAIL(_From, State) ->
    {ok, State}.

handle_MAIL_extension(_Extension, _State) ->
    error.

handle_RCPT(_To, State) ->
    {ok, State}.

handle_RCPT_extension(_Extension, _State) ->
    error.

handle_DATA(_From, To, Data, #{test := Test} = State) ->
    Test ! {handle_DATA, self(), byte_size(Data), erlang:md5(Data)},
    case maps:get(protocol, State, smtp) of
        lmtp -> {multiple, [{ok, "queued"} || _ <- To], State};
        smtp -> {ok, "queued", State}
    end.

handle_DATA_admission(ReceivedBytes, #{test := Test} = State) ->
    Test ! {admission, self(), ReceivedBytes},
    answer(maps:get(admission, State), State).

answer(ok, State) ->
    {ok, State};
answer({refuse, Reply}, State) ->
    {refuse, Reply, State};
answer({block, Millis, Then}, State) ->
    timer:sleep(Millis),
    answer(Then, State);
answer(bad_shape, _State) ->
    unexpected.

handle_RSET(#{test := Test} = State) ->
    Test ! {handle_RSET, self()},
    State.

handle_VRFY(_Address, State) ->
    {error, "252 VRFY disabled", State}.

handle_other(_Verb, _Args, State) ->
    {["500 Error: command not recognized"], State}.

handle_error(Class, Details, #{test := Test} = State) ->
    Test ! {handle_error, self(), Class, Details},
    {ok, State}.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

terminate(Reason, #{test := Test} = State) ->
    Test ! {terminate, self(), Reason},
    {ok, Reason, State}.
