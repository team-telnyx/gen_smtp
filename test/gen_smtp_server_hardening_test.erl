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

with_auth_server(Fun) ->
    with_server([{auth, true}], [], fun(Socket) ->
        ehlo(Socket),
        Fun(Socket)
    end).

with_server(CallbackOptions, SessionOptions, Fun) ->
    with_server_context(CallbackOptions, SessionOptions, fun(Socket, _Name) -> Fun(Socket) end).

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
