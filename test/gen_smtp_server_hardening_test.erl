-module(gen_smtp_server_hardening_test).

-include_lib("eunit/include/eunit.hrl").

-define(RECV_TIMEOUT, 200).

%% P3: fused AUTH PLAIN RFC 4954 empty initial response marker.
auth_plain_empty_initial_response_test() ->
    with_server([{auth, true}], [], fun(Socket) ->
        ehlo(Socket),
        ok = gen_tcp:send(Socket, "AUTH PLAIN =\r\n"),
        Challenge = recv(Socket),
        ok = gen_tcp:send(Socket, [base64:encode(<<0, "username", 0, "PaSSw0rd">>), "\r\n"]),
        Authentication = recv(Socket),
        Noop = noop(Socket),
        ?assertEqual(
            {<<"334\r\n">>, <<"235 Authentication successful.\r\n">>, <<"250 Ok\r\n">>},
            {Challenge, Authentication, Noop}
        )
    end).

%% P3: fused AUTH PLAIN invalid base64.
auth_plain_fused_invalid_base64_test() ->
    with_auth_server(fun(Socket) ->
        assert_rejection_and_noop(
            Socket,
            "AUTH PLAIN !!!!not-base64!!!!\r\n",
            <<"501 Authentication line too long / invalid\r\n">>
        )
    end).

%% P3: RFC 4954 SASL cancellation.
auth_plain_cancellation_test() ->
    with_auth_server(fun(Socket) ->
        begin_plain_auth(Socket),
        assert_rejection_and_noop(Socket, "*\r\n", <<"501 Authentication aborted\r\n">>)
    end).

%% P3: invalid base64 at the shared SASL continuation decode site.
auth_plain_continuation_invalid_base64_test() ->
    with_auth_server(fun(Socket) ->
        begin_plain_auth(Socket),
        assert_rejection_and_noop(
            Socket,
            "!!!!not-base64!!!!\r\n",
            <<"501 Authentication line too long / invalid\r\n">>
        )
    end).

%% P3: invalid base64 at the first AUTH LOGIN response stage.
auth_login_username_invalid_base64_test() ->
    with_auth_server(fun(Socket) ->
        begin_login_auth(Socket),
        assert_rejection_and_noop(
            Socket,
            "!!!!not-base64!!!!\r\n",
            <<"501 Authentication line too long / invalid\r\n">>
        )
    end).

%% P3: invalid base64 at the second AUTH LOGIN response stage.
auth_login_password_invalid_base64_test() ->
    with_auth_server(fun(Socket) ->
        begin_login_auth(Socket),
        ok = gen_tcp:send(Socket, [base64:encode(<<"username">>), "\r\n"]),
        ?assertEqual(<<"334 UGFzc3dvcmQ6\r\n">>, recv(Socket)),
        assert_rejection_and_noop(
            Socket,
            "!!!!not-base64!!!!\r\n",
            <<"501 Authentication line too long / invalid\r\n">>
        )
    end).

%% P3: valid base64 without PLAIN NUL separators must not be ignored.
auth_plain_fused_no_nul_test() ->
    with_auth_server(fun(Socket) ->
        assert_rejection_and_noop(
            Socket,
            ["AUTH PLAIN ", base64:encode(<<"no-nul-separators">>), "\r\n"],
            <<"501 Authentication line too long / invalid\r\n">>
        )
    end).

%% P3: same malformed decoded PLAIN structure through the continuation path.
auth_plain_continuation_no_nul_test() ->
    with_auth_server(fun(Socket) ->
        begin_plain_auth(Socket),
        assert_rejection_and_noop(
            Socket,
            [base64:encode(<<"no-nul-separators">>), "\r\n"],
            <<"501 Authentication line too long / invalid\r\n">>
        )
    end).

%% P4: non-numeric SIZE with a finite advertised maximum.
mail_size_non_numeric_finite_test() ->
    with_server([{size, 100}], [], fun(Socket) ->
        ehlo(Socket),
        assert_rejection_and_noop(
            Socket,
            "MAIL FROM:<sender@example.com> SIZE=banana\r\n",
            <<"501 Syntax error\r\n">>
        )
    end).

%% P4: the SIZE=0 advertisement selects maxsize=infinity and must be equally safe.
mail_size_non_numeric_unlimited_test() ->
    with_server([{size, infinity}], [], fun(Socket) ->
        ehlo(Socket),
        assert_rejection_and_noop(
            Socket,
            "MAIL FROM:<sender@example.com> SIZE=banana\r\n",
            <<"501 Syntax error\r\n">>
        )
    end).

%% P4: an empty SIZE value is invalid with a finite advertised maximum.
mail_size_empty_finite_test() ->
    with_server([{size, 100}], [], fun(Socket) ->
        ehlo(Socket),
        assert_rejection_and_noop(
            Socket,
            "MAIL FROM:<sender@example.com> SIZE=\r\n",
            <<"501 Syntax error\r\n">>
        )
    end).

%% P4: an empty SIZE value is invalid with SIZE=0/maxsize=infinity too.
mail_size_empty_unlimited_test() ->
    with_server([{size, infinity}], [], fun(Socket) ->
        ehlo(Socket),
        assert_rejection_and_noop(
            Socket,
            "MAIL FROM:<sender@example.com> SIZE=\r\n",
            <<"501 Syntax error\r\n">>
        )
    end).

%% P4: unrecognized BODY values must use the existing 555 path, not crash.
mail_body_unknown_test() ->
    with_server([], [], fun(Socket) ->
        ehlo(Socket),
        assert_rejection_and_noop(
            Socket,
            "MAIL FROM:<sender@example.com> BODY=FOO\r\n",
            <<"555 Unsupported option BODY\r\n">>
        )
    end).

%% P1: command_timeout is the idle wait between SMTP commands.
command_timeout_5_seconds_test_() ->
    {timeout, 10, fun() ->
        with_server([], [{command_timeout, 5000}], fun(Socket) ->
            Started = erlang:monotonic_time(millisecond),
            Reply = recv(Socket, 7000),
            Elapsed = erlang:monotonic_time(millisecond) - Started,
            Closed = recv(Socket, 1000),
            ?assertEqual(<<"421 Error: timeout exceeded\r\n">>, Reply),
            ?assert(Elapsed >= 4500 andalso Elapsed =< 6500),
            ?assertEqual({error, closed}, Closed)
        end)
    end}.

%% P1: data_timeout is a wall-clock DATA budget, not an idle timeout.
data_timeout_5_seconds_test_() ->
    {timeout, 10, fun() ->
        with_server_context([], [{command_timeout, 10000}, {data_timeout, 5000}], fun(Socket, Name) ->
            ehlo(Socket),
            command(Socket, "MAIL FROM:<sender@example.com>\r\n", <<"250 sender Ok\r\n">>),
            command(Socket, "RCPT TO:<recipient@example.com>\r\n", <<"250 recipient Ok\r\n">>),
            command(
                Socket,
                "DATA\r\n",
                <<"354 enter mail, end with line containing only '.'\r\n">>
            ),
            [SessionPid] = gen_smtp_server:sessions(Name),
            gen_server:cast(SessionPid, cancel_session_timer),
            Started = erlang:monotonic_time(millisecond),
            {Reply, Elapsed} = trickle_until_reply(Socket, Started),
            Closed = recv(Socket, 1000),
            ?assertEqual(<<"421 Error: timeout exceeded\r\n">>, Reply),
            ?assert(Elapsed >= 4500 andalso Elapsed =< 6500),
            ?assertEqual({error, closed}, Closed)
        end)
    end}.

%% P5 (MSG-2345): custom AUTH reply shapes. Submission-tier auth is backed by a
%% remote auth service; temporary failures must answer a 421 with an enhanced
%% code and successes must be able to carry an enhanced code too, while stock
%% callers keep the byte-for-byte stock replies.

p5_auth_reply_callback_module_test() ->
    with_callback_server(
        gen_smtp_server_auth_reply_test_callback,
        [{auth, true}],
        fun(Socket) ->
            ehlo(Socket),
            command(
                Socket,
                ["AUTH PLAIN ", base64:encode(<<0, "apikey", 0, "valid-key">>), "\r\n"],
                <<"235 2.7.0 Authenticated\r\n">>
            ),
            assert_rejection_and_noop(
                Socket,
                ["AUTH PLAIN ", base64:encode(<<0, "apikey", 0, "invalid-key">>), "\r\n"],
                <<"421 4.7.0 Temporary authentication failure, retry later\r\n">>
            ),
            %% A malformed custom reply (no valid SMTP code) must not be sent
            %% verbatim: the session falls back to the stock 535 failure
            %% rather than emitting protocol garbage. Tested via the third
            %% clause below? No - third clause returns plain `error'; see
            %% p5_auth_reply_invalid_reply_falls_back_to_stock_test/0.
            noop(Socket)
        end
    ).

%% P5: success shape `{reply, Reply, State}' must accept lists as well as
%% binaries (the stock 235 path sends iodata).
p5_auth_reply_accepts_list_reply_test() ->
    with_callback_server(
        gen_smtp_server_auth_reply_test_callback,
        [{auth, true}],
        fun(Socket) ->
            ehlo(Socket),
            %% LOGIN form exercises the 3-step path and the same try_auth.
            %% (login_auth/2 in the helpers shows the sequence: AUTH LOGIN →
            %% 334 Username prompt → username → 334 Password prompt →
            %% password → final reply.)
            begin_login_auth(Socket),
            command(
                Socket,
                [base64:encode(<<"apikey">>), "\r\n"],
                <<"334 UGFzc3dvcmQ6\r\n">>
            ),
            command(
                Socket,
                [base64:encode(<<"valid-key">>), "\r\n"],
                <<"235 2.7.0 Authenticated\r\n">>
            )
        end
    ).

%% P5: an invalid custom reply (missing SMTP reply code) must never reach the
%% wire; the session answers the stock 535 instead.
p5_auth_reply_invalid_reply_falls_back_to_stock_test() ->
    %% gen_smtp_server_auth_reply_test_callback's third clause returns plain
    %% `error' (the stock failure), so drive the invalid-reply path through a
    %% dedicated callback exported by the same test module: it returns an
    %% {error, <<"no code">>, State} reply with no 3-digit prefix.
    with_callback_server(
        gen_smtp_server_auth_reply_invalid_callback,
        [{auth, true}],
        fun(Socket) ->
            ehlo(Socket),
            assert_rejection_and_noop(
                Socket,
                ["AUTH PLAIN ", base64:encode(<<0, "apikey", 0, "bad">>), "\r\n"],
                <<"535 Authentication failed.\r\n">>
            )
        end
    ).

%% P2: a caller can replace the stock reply when AUTH is not advertised.
auth_required_reply_custom_test() ->
    with_server([], [{auth_required_reply, "538 Encryption required"}], fun(Socket) ->
        ehlo(Socket),
        assert_rejection_and_noop(
            Socket,
            "AUTH PLAIN AHVzZXIAcGFzcw==\r\n",
            <<"538 Encryption required\r\n">>
        )
    end).

%% P2: omitting auth_required_reply remains byte-for-byte compatible with stock 1.3.0.
auth_required_reply_default_test() ->
    with_server([], [], fun(Socket) ->
        ehlo(Socket),
        assert_rejection_and_noop(
            Socket,
            "AUTH PLAIN AHVzZXIAcGFzcw==\r\n",
            <<"502 Error: AUTH not implemented\r\n">>
        )
    end).

%% P2: AUTH before EHLO remains a 503 even when auth_required_reply is configured.
auth_before_ehlo_still_503_test() ->
    with_server([], [{auth_required_reply, "538 Encryption required"}], fun(Socket) ->
        assert_rejection_and_noop(
            Socket,
            "AUTH PLAIN AHVzZXIAcGFzcw==\r\n",
            <<"503 Error: send EHLO first\r\n">>
        )
    end).

%% P2: callback authentication failures remain 535.
auth_failure_still_535_test() ->
    with_auth_server(fun(Socket) ->
        assert_rejection_and_noop(
            Socket,
            ["AUTH PLAIN ", base64:encode(<<0, "username", 0, "wrong-password">>), "\r\n"],
            <<"535 Authentication failed.\r\n">>
        )
    end).

%% Astra review round (H1): repeat-AUTH regressions. A second AUTH PLAIN on a
%% connection that already authenticated successfully must follow base parity:
%% re-authenticate (235), fail closed (535), or reject malformed input (501)
%% while keeping the session usable — never crash the connection.

repeat_fused_plain_valid_test() ->
    with_auth_server(fun(Socket) ->
        Valid = fused_auth_plain(<<0, "username", 0, "PaSSw0rd">>),
        command(Socket, Valid, <<"235 Authentication successful.\r\n">>),
        command(Socket, Valid, <<"235 Authentication successful.\r\n">>),
        command(Socket, "NOOP\r\n", <<"250 Ok\r\n">>)
    end).

repeat_fused_plain_wrong_password_test() ->
    with_auth_server(fun(Socket) ->
        Valid = fused_auth_plain(<<0, "username", 0, "PaSSw0rd">>),
        command(Socket, Valid, <<"235 Authentication successful.\r\n">>),
        command(
            Socket,
            fused_auth_plain(<<0, "username", 0, "wrong-password">>),
            <<"535 Authentication failed.\r\n">>
        ),
        command(Socket, "NOOP\r\n", <<"250 Ok\r\n">>)
    end).

repeat_fused_plain_no_nul_test() ->
    with_auth_server(fun(Socket) ->
        Valid = fused_auth_plain(<<0, "username", 0, "PaSSw0rd">>),
        command(Socket, Valid, <<"235 Authentication successful.\r\n">>),
        command(
            Socket,
            fused_auth_plain(<<"no-nul-separators">>),
            <<"501 Authentication line too long / invalid\r\n">>
        ),
        command(Socket, "NOOP\r\n", <<"250 Ok\r\n">>)
    end).

%% Same fused trio, this time after a successful AUTH LOGIN: the stored
%% envelope auth fields come from the LOGIN exchange, which must not crash
%% the fused PLAIN path either.
repeat_fused_plain_valid_after_login_test() ->
    with_auth_server(fun(Socket) ->
        login_auth(Socket),
        command(
            Socket,
            fused_auth_plain(<<0, "username", 0, "PaSSw0rd">>),
            <<"235 Authentication successful.\r\n">>
        ),
        command(Socket, "NOOP\r\n", <<"250 Ok\r\n">>)
    end).

repeat_fused_plain_wrong_password_after_login_test() ->
    with_auth_server(fun(Socket) ->
        login_auth(Socket),
        command(
            Socket,
            fused_auth_plain(<<0, "username", 0, "wrong-password">>),
            <<"535 Authentication failed.\r\n">>
        ),
        command(Socket, "NOOP\r\n", <<"250 Ok\r\n">>)
    end).

repeat_fused_plain_no_nul_after_login_test() ->
    with_auth_server(fun(Socket) ->
        login_auth(Socket),
        command(
            Socket,
            fused_auth_plain(<<"no-nul-separators">>),
            <<"501 Authentication line too long / invalid\r\n">>
        ),
        command(Socket, "NOOP\r\n", <<"250 Ok\r\n">>)
    end).

%% Continuation-form PLAIN (bare AUTH PLAIN, then the base64 line) repeated
%% after a successful authentication re-authenticates as well.
repeat_continuation_plain_after_auth_test() ->
    with_auth_server(fun(Socket) ->
        command(
            Socket,
            fused_auth_plain(<<0, "username", 0, "PaSSw0rd">>),
            <<"235 Authentication successful.\r\n">>
        ),
        begin_plain_auth(Socket),
        command(
            Socket,
            [base64:encode(<<0, "username", 0, "PaSSw0rd">>), "\r\n"],
            <<"235 Authentication successful.\r\n">>
        ),
        command(Socket, "NOOP\r\n", <<"250 Ok\r\n">>)
    end).

%% Astra review round (M1): invalid sessionoptions fail fast at session init,
%% before the banner, with a clean {stop, {invalid_option, Key}}.

invalid_timeout_option_test_() ->
    Values = [banana, -1, 1.5, <<"3000">>, 4294967296, 18446744073709551616],
    [
        {lists:flatten(io_lib:format("~s rejects ~p at init", [Key, Value])), fun() ->
            assert_invalid_session_option(Key, Value)
        end}
     || Key <- [command_timeout, data_timeout], Value <- Values
    ].

invalid_auth_required_reply_option_test_() ->
    Values = [
        {"embedded CR", <<"538 bad\r\ninjected">>},
        {"embedded LF", <<"538 bad\ninjected">>},
        {"embedded NUL", <<"538 bad\0injected">>},
        {"oversize reply", <<"538 ", (binary:copy(<<"a">>, 600))/binary>>},
        {"atom", five_hundred_thirty_eight},
        {"empty binary", <<>>},
        {"missing reply code", <<"Encryption required">>},
        {"non-digit reply code", <<"53x Encryption required">>},
        {"invalid UTF-8", <<"538 ", 16#FF>>},
        {"improper list", ["538 " | bad_tail]},
        {"proper list with tuple", [<<"538 ">>, {bad}]}
    ],
    [
        {lists:flatten(io_lib:format("auth_required_reply rejects ~s at init", [Label])), fun() ->
            assert_invalid_session_option(auth_required_reply, Value)
        end}
     || {Label, Value} <- Values
    ].

%% A listener configured with an invalid option drops the connection before
%% the banner instead of serving it.
invalid_command_timeout_no_banner_test() ->
    ok = ensure_gen_smtp_started(),
    Name = {?MODULE, make_ref()},
    {ok, _Pid} = gen_smtp_server:start(Name, smtp_server_example, [
        {domain, "localhost"},
        {port, 0},
        {sessionoptions, [{callbackoptions, []}, {command_timeout, banana}]}
    ]),
    Port = ranch:get_port(Name),
    {ok, Socket} = gen_tcp:connect("localhost", Port, [binary, {packet, line}, {active, false}]),
    try
        ?assertEqual({error, closed}, recv(Socket, 2000))
    after
        gen_tcp:close(Socket),
        gen_smtp_server:stop(Name)
    end.

%% 0 and 1 are valid, if brutal, timeout values: the session starts and the
%% inactivity timer closes it with 421.
command_timeout_zero_421_test() ->
    with_server([], [{command_timeout, 0}], fun(Socket) ->
        ?assertEqual(<<"421 Error: timeout exceeded\r\n">>, recv(Socket, 2000)),
        ?assertEqual({error, closed}, recv(Socket, 2000))
    end).

command_timeout_one_421_test() ->
    with_server([], [{command_timeout, 1}], fun(Socket) ->
        ?assertEqual(<<"421 Error: timeout exceeded\r\n">>, recv(Socket, 2000)),
        ?assertEqual({error, closed}, recv(Socket, 2000))
    end).

%% data_timeout 0/1 are valid; the DATA wall-clock budget expires immediately
%% after the 354 with 421 and close.
data_timeout_zero_421_test() ->
    with_server([], [{command_timeout, 10000}, {data_timeout, 0}], fun(Socket) ->
        begin_data(Socket),
        ?assertEqual(<<"421 Error: timeout exceeded\r\n">>, recv(Socket, 2000)),
        ?assertEqual({error, closed}, recv(Socket, 2000))
    end).

data_timeout_one_421_test() ->
    with_server([], [{command_timeout, 10000}, {data_timeout, 1}], fun(Socket) ->
        begin_data(Socket),
        ?assertEqual(<<"421 Error: timeout exceeded\r\n">>, recv(Socket, 2000)),
        ?assertEqual({error, closed}, recv(Socket, 2000))
    end).

%% The atom `infinity' is an explicitly accepted timeout.
command_timeout_infinity_session_stays_up_test() ->
    with_server([], [{command_timeout, infinity}], fun(Socket) ->
        ehlo(Socket),
        timer:sleep(300),
        command(Socket, "NOOP\r\n", <<"250 Ok\r\n">>)
    end).

%% data_timeout = infinity disables the DATA wall-clock budget; a complete
%% DATA transaction must still succeed.
data_timeout_infinity_data_transaction_test() ->
    with_server([], [{data_timeout, infinity}], fun(Socket) ->
        begin_data(Socket),
        ok = gen_tcp:send(Socket, "Subject: hello\r\n\r\nBody\r\n.\r\n"),
        ?assertMatch(<<"250 queued as ", _/binary>>, recv(Socket, 5000)),
        command(Socket, "NOOP\r\n", <<"250 Ok\r\n">>)
    end).

%% Astra review round (L1): the SIZE parameter grammar is digits only
%% (RFC 1870); signed text such as "+1" or "-0" is a syntax error.

mail_size_signed_plus_rejected_test() ->
    with_server([{size, 100}], [], fun(Socket) ->
        ehlo(Socket),
        assert_rejection_and_noop(
            Socket, "MAIL FROM:<sender@example.com> SIZE=+1\r\n", <<"501 Syntax error\r\n">>
        )
    end).

mail_size_signed_negative_zero_rejected_test() ->
    with_server([{size, 100}], [], fun(Socket) ->
        ehlo(Socket),
        assert_rejection_and_noop(
            Socket, "MAIL FROM:<sender@example.com> SIZE=-0\r\n", <<"501 Syntax error\r\n">>
        )
    end).

%% Plain digits remain accepted, unchanged.
mail_size_digits_accepted_test() ->
    with_server([{size, 100}], [], fun(Socket) ->
        ehlo(Socket),
        command(Socket, "MAIL FROM:<sender@example.com> SIZE=100\r\n", <<"250 sender Ok\r\n">>)
    end).

mail_size_zero_unlimited_accepted_test() ->
    with_server([{size, infinity}], [], fun(Socket) ->
        ehlo(Socket),
        command(Socket, "MAIL FROM:<sender@example.com> SIZE=0\r\n", <<"250 sender Ok\r\n">>)
    end).

with_auth_server(Fun) ->
    with_server([{auth, true}], [], fun(Socket) ->
        ehlo(Socket),
        Fun(Socket)
    end).

with_server(CallbackOptions, SessionOptions, Fun) ->
    with_server_context(CallbackOptions, SessionOptions, fun(Socket, _Name) -> Fun(Socket) end).

%% P5 (MSG-2345): like with_server/3 but with a caller-supplied callback
%% module, for exercising the custom AUTH reply shapes.
with_callback_server(CallbackModule, CallbackOptions, Fun) ->
    ok = ensure_gen_smtp_started(),
    Name = {?MODULE, make_ref()},
    {ok, _Pid} = gen_smtp_server:start(
        Name,
        CallbackModule,
        [
            {domain, "localhost"},
            {port, 0},
            {sessionoptions, [{callbackoptions, CallbackOptions}]}
        ]
    ),
    Port = ranch:get_port(Name),
    {ok, Socket} = gen_tcp:connect("localhost", Port, [binary, {packet, line}, {active, false}]),
    try
        ?assertMatch(<<"220 localhost", _/binary>>, recv(Socket)),
        Fun(Socket)
    after
        gen_tcp:close(Socket),
        gen_smtp_server:stop(Name)
    end.

with_server_context(CallbackOptions, SessionOptions, Fun) ->
    ok = ensure_gen_smtp_started(),
    Name = {?MODULE, make_ref()},
    {ok, _Pid} = gen_smtp_server:start(
        Name,
        smtp_server_example,
        [
            {domain, "localhost"},
            {port, 0},
            {sessionoptions, [{callbackoptions, CallbackOptions} | SessionOptions]}
        ]
    ),
    Port = ranch:get_port(Name),
    {ok, Socket} = gen_tcp:connect("localhost", Port, [binary, {packet, line}, {active, false}]),
    try
        ?assertMatch(<<"220 localhost", _/binary>>, recv(Socket)),
        Fun(Socket, Name)
    after
        gen_tcp:close(Socket),
        gen_smtp_server:stop(Name)
    end.

ensure_gen_smtp_started() ->
    case application:ensure_all_started(gen_smtp) of
        {ok, _} -> ok;
        {error, {already_started, gen_smtp}} -> ok
    end.

ehlo(Socket) ->
    ok = gen_tcp:send(Socket, "EHLO client.example\r\n"),
    recv_ehlo(Socket).

recv_ehlo(Socket) ->
    case recv(Socket) of
        <<"250 ", _/binary>> -> ok;
        <<"250-", _/binary>> -> recv_ehlo(Socket)
    end.

begin_plain_auth(Socket) ->
    ok = gen_tcp:send(Socket, "AUTH PLAIN\r\n"),
    ?assertEqual(<<"334\r\n">>, recv(Socket)).

begin_login_auth(Socket) ->
    ok = gen_tcp:send(Socket, "AUTH LOGIN\r\n"),
    ?assertEqual(<<"334 VXNlcm5hbWU6\r\n">>, recv(Socket)).

login_auth(Socket) ->
    begin_login_auth(Socket),
    command(Socket, [base64:encode(<<"username">>), "\r\n"], <<"334 UGFzc3dvcmQ6\r\n">>),
    command(Socket, [base64:encode(<<"PaSSw0rd">>), "\r\n"], <<"235 Authentication successful.\r\n">>).

fused_auth_plain(Plain) ->
    ["AUTH PLAIN ", base64:encode(Plain), "\r\n"].

begin_data(Socket) ->
    ehlo(Socket),
    command(Socket, "MAIL FROM:<sender@example.com>\r\n", <<"250 sender Ok\r\n">>),
    command(Socket, "RCPT TO:<recipient@example.com>\r\n", <<"250 recipient Ok\r\n">>),
    command(
        Socket, "DATA\r\n", <<"354 enter mail, end with line containing only '.'\r\n">>
    ).

assert_invalid_session_option(Key, Value) ->
    {ok, Listen} = gen_tcp:listen(0, [binary, {active, false}]),
    try
        SessionOptions = [{callbackoptions, []}, {Key, Value}],
        ?assertEqual(
            {stop, {invalid_option, Key}},
            gen_smtp_server_session:init([
                make_ref(), ranch_tcp, Listen, smtp_server_example, SessionOptions
            ])
        )
    after
        gen_tcp:close(Listen)
    end.

assert_rejection_and_noop(Socket, Command, ExpectedReply) ->
    ok = gen_tcp:send(Socket, Command),
    Reply = recv(Socket),
    Noop = noop(Socket),
    ?assertEqual({ExpectedReply, <<"250 Ok\r\n">>}, {Reply, Noop}).

command(Socket, Command, ExpectedReply) ->
    ok = gen_tcp:send(Socket, Command),
    ?assertEqual(ExpectedReply, recv(Socket)).

trickle_until_reply(Socket, Started) ->
    Elapsed = erlang:monotonic_time(millisecond) - Started,
    case Elapsed >= 7000 of
        true ->
            {{error, timeout}, Elapsed};
        false ->
            _ = gen_tcp:send(Socket, <<"x">>),
            case recv(Socket, 300) of
                {error, timeout} ->
                    trickle_until_reply(Socket, Started);
                Reply ->
                    {Reply, erlang:monotonic_time(millisecond) - Started}
            end
    end.

noop(Socket) ->
    _ = gen_tcp:send(Socket, "NOOP\r\n"),
    recv(Socket).

recv(Socket) ->
    recv(Socket, ?RECV_TIMEOUT).

recv(Socket, Timeout) ->
    case gen_tcp:recv(Socket, 0, Timeout) of
        {ok, Packet} -> Packet;
        Error -> Error
    end.
