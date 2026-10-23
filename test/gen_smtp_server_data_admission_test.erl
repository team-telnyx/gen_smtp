%% MSG-2693: opt-in receive-time DATA admission.
%%
%% With `{data_admission_threshold, Bytes}' set AND handle_DATA_admission/2
%% exported, the DATA receiver asks the session (a message round trip; the
%% callback runs in the session process) the first time its accumulated bytes
%% exceed the threshold, and does not read while it waits. `ok' continues;
%% `{refuse, Reply, State}' discards the rest of the body up to the terminator
%% — retaining no more than the packet in hand — and answers Reply instead of
%% calling handle_DATA/4. Without the option, or without the callback,
%% nothing changes.
-module(gen_smtp_server_data_admission_test).

-include_lib("eunit/include/eunit.hrl").

-define(CALLBACK, gen_smtp_server_data_admission_test_callback).
-define(RECV_TIMEOUT, 2000).
-define(CHUNK, 65536).

%% Each case gets its own timeout: a RED run (no admission) waits on events
%% that never come, and must not cancel the rest.
data_admission_test_() ->
    [
        {"no option admission never called", {timeout, 60, fun no_option_admission_never_called/0}},
        {"option without callback identical", {timeout, 60, fun option_without_callback_identical/0}},
        {"threshold not crossed no callback", {timeout, 60, fun threshold_not_crossed_no_callback/0}},
        {"admission ok continues and delivers whole body",
            {timeout, 60, fun admission_ok_continues_and_delivers_whole_body/0}},
        {"admission asked at terminator", {timeout, 60, fun admission_asked_at_terminator/0}},
        {"refuse discards with bounded memory and replies",
            {timeout, 60, fun refuse_discards_with_bounded_memory_and_replies/0}},
        {"refuse then pipelined command", {timeout, 60, fun refuse_then_pipelined_command/0}},
        {"refuse terminator split across packets", {timeout, 60, fun refuse_terminator_split_across_packets/0}},
        {"lmtp refusal once per recipient", {timeout, 60, fun lmtp_refusal_once_per_recipient/0}},
        {"refuse then size exceeded", {timeout, 60, fun refuse_then_size_exceeded/0}},
        {"refuse then bare newline", {timeout, 60, fun refuse_then_bare_newline/0}},
        {"refuse then data deadline", {timeout, 60, fun refuse_then_data_deadline/0}},
        {"deadline while waiting for admission", {timeout, 60, fun deadline_while_waiting_for_admission/0}},
        {"session crash while receiver waits", {timeout, 60, fun session_crash_while_receiver_waits/0}},
        {"socket close during discard", {timeout, 60, fun socket_close_during_discard/0}},
        {"quit after refusal", {timeout, 60, fun quit_after_refusal/0}},
        %% An admitted DATA ends in exactly one of handle_DATA/4 or
        %% handle_DATA_aborted/2 (the second finding of Astra r3).
        {"admitted final packet over size aborts", {timeout, 60, fun admitted_final_packet_over_size_aborts/0}},
        {"admitted final packet over size without abort callback identical",
            {timeout, 60, fun admitted_final_packet_over_size_without_abort_callback_identical/0}},
        {"admitted stream over size aborts", {timeout, 60, fun admitted_stream_over_size_aborts/0}},
        {"admitted bare newline aborts", {timeout, 60, fun admitted_bare_newline_aborts/0}},
        {"admitted data deadline aborts", {timeout, 60, fun admitted_data_deadline_aborts/0}},
        {"admitted socket close aborts", {timeout, 60, fun admitted_socket_close_aborts/0}},
        {"delivered refused or unadmitted DATA never aborts",
            {timeout, 60, fun delivered_refused_or_unadmitted_data_never_aborts/0}},
        %% The end-of-data terminator across the admission boundary (Astra r3
        %% finding 4).
        {"split terminator below threshold refuse callback",
            {timeout, 60, fun() -> split_terminator_below_threshold({refuse, "451 4.3.0 later"}) end}},
        {"split terminator below threshold ok callback",
            {timeout, 60, fun() -> split_terminator_below_threshold(ok) end}},
        {"three packet terminator completed by the crossing packet",
            {timeout, 60, fun three_packet_terminator_completed_by_crossing_packet/0}},
        {"three packet terminator after admission ok", {timeout, 60, fun three_packet_terminator_after_admission_ok/0}},
        {"split across the refusal transition", {timeout, 60, fun split_across_the_refusal_transition/0}},
        {"terminator before the admission answer ok pipelined",
            {timeout, 60, fun terminator_before_the_admission_answer_ok_pipelined/0}},
        {"terminator before the admission answer refuse pipelined",
            {timeout, 60, fun terminator_before_the_admission_answer_refuse_pipelined/0}},
        %% A terminator split across packets wins over a later whole one in the
        %% packet that completes it (Astra r4).
        {"boundary terminator plus full terminator refuse not asked",
            {timeout, 60, fun() -> boundary_terminator_plus_full_terminator({refuse, "451 4.3.0 later"}, 1024) end}},
        {"boundary terminator plus full terminator ok not asked",
            {timeout, 60, fun() -> boundary_terminator_plus_full_terminator(ok, 1024) end}},
        {"boundary terminator plus full terminator refused",
            {timeout, 60, fun() -> boundary_terminator_plus_full_terminator({refuse, "451 4.3.0 later"}, 1000) end}},
        {"boundary terminator plus full terminator admitted",
            {timeout, 60, fun() -> boundary_terminator_plus_full_terminator(ok, 1000) end}},
        {"boundary terminator overlapping a full terminator",
            {timeout, 60, fun boundary_terminator_overlapping_a_full_terminator/0}}
    ].

%% -- option absent / callback absent: unchanged -------------------------------

no_option_admission_never_called() ->
    Body = body(2 * 1024 * 1024),
    with_admission_server(#{admission => {refuse, "451 4.3.0 must not be used"}}, [], fun(Socket) ->
        Replies = data_transaction(Socket, Body),
        ?assertEqual(
            [
                <<"250 sender Ok\r\n">>,
                <<"250 recipient Ok\r\n">>,
                <<"354 enter mail, end with line containing only '.'\r\n">>,
                <<"250 queued\r\n">>
            ],
            Replies
        ),
        ?assertMatch({handle_DATA, _, Size, _} when Size =:= byte_size(Body), next_event(handle_DATA)),
        ?assertEqual(none, next_event(admission, 0))
    end).

%% The stock example callback does not export handle_DATA_admission/2: the
%% option alone changes nothing — the same replies, byte for byte.
option_without_callback_identical() ->
    Body = body(1024 * 1024),
    Run = fun(SessionOptions) ->
        with_example_server(SessionOptions, fun(Socket) ->
            Replies = data_transaction(Socket, Body),
            Noop = command(Socket, "NOOP\r\n"),
            [strip_queue_id(R) || R <- Replies ++ [Noop]]
        end)
    end,
    Without = Run([]),
    With = Run([{data_admission_threshold, 1024}]),
    ?assertMatch([_, _, _, <<"250 queued as ", _/binary>>, <<"250 Ok\r\n">>], Without),
    ?assertEqual(Without, With).

invalid_threshold_option_test_() ->
    [
        ?_test(assert_invalid_session_option(data_admission_threshold, Value))
     || Value <- [-1, 1.5, infinity, "1024", <<"1024">>]
    ].

%% -- threshold not crossed ------------------------------------------------------

threshold_not_crossed_no_callback() ->
    Body = body(100 * 1024),
    with_admission_server(#{admission => {refuse, "451 4.3.0 no"}}, [{data_admission_threshold, 1024 * 1024}], fun(
        Socket
    ) ->
        ?assertMatch([_, _, _, <<"250 queued\r\n">>], data_transaction(Socket, Body)),
        ?assertMatch({handle_DATA, _, Size, _} when Size =:= byte_size(Body), next_event(handle_DATA)),
        ?assertEqual(none, next_event(admission, 0))
    end).

%% -- admission ok ---------------------------------------------------------------

admission_ok_continues_and_delivers_whole_body() ->
    Threshold = 256 * 1024,
    Body = body(8 * 1024 * 1024),
    with_admission_server(#{admission => ok}, [{data_admission_threshold, Threshold}], fun(Socket, Session) ->
        Sampler = start_sampler(Session),
        ?assertMatch([_, _, _, <<"250 queued\r\n">>], data_transaction(Socket, Body)),
        %% Asked once, in the session process, when the receiver first held
        %% more than the threshold — long before the whole body had arrived.
        {admission, Session, Received} = next_event(admission),
        ?assert(Received > Threshold),
        ?assert(Received < byte_size(Body) div 2),
        ?assertEqual(none, next_event(admission, 0)),
        %% handle_DATA got the whole body, byte for byte.
        Md5 = erlang:md5(Body),
        Size = byte_size(Body),
        ?assertMatch({handle_DATA, Session, Size, Md5}, next_event(handle_DATA)),
        %% Sanity for the memory probe used below: an admitted receiver
        %% does buffer the body.
        Peak = stop_sampler(Sampler),
        io:format(user, "~nadmitted: receiver peak ~B bytes for a ~B-byte body~n", [Peak, byte_size(Body)]),
        ?assert(Peak > 4 * 1024 * 1024)
    end).

%% A body whose terminator arrives in the same packet that first crosses the
%% threshold is asked about before handle_DATA/4.
admission_asked_at_terminator() ->
    Body = body(3000),
    with_admission_server(#{admission => {refuse, "452 4.3.1 busy"}}, [{data_admission_threshold, 2000}], fun(Socket) ->
        Replies = data_transaction(Socket, Body),
        ?assertEqual(<<"452 4.3.1 busy\r\n">>, lists:last(Replies)),
        ?assertMatch({admission, _, Received} when Received > 2000, next_event(admission)),
        ?assertEqual(none, next_event(handle_DATA, 0)),
        ?assertEqual(<<"250 Ok\r\n">>, command(Socket, "NOOP\r\n"))
    end).

%% -- refuse: discard and reply --------------------------------------------------

refuse_discards_with_bounded_memory_and_replies() ->
    Threshold = 512 * 1024,
    Body = body(16 * 1024 * 1024),
    with_admission_server(
        #{
            admission => {refuse, "451 4.3.0 Large messages are temporarily at capacity"},
            maxsize => 32 * 1024 * 1024
        },
        [{data_admission_threshold, Threshold}],
        fun(Socket, Session) ->
            Sampler = start_sampler(Session),
            Replies = data_transaction(Socket, Body, 1),
            ?assertEqual(<<"451 4.3.0 Large messages are temporarily at capacity\r\n">>, lists:last(Replies)),
            {admission, Session, Received} = next_event(admission),
            ?assert(Received > Threshold),
            ?assert(Received =< Threshold + 4 * ?CHUNK),
            %% Never handed to handle_DATA/4.
            ?assertEqual(none, next_event(handle_DATA, 0)),
            %% The receiver never held more than the threshold plus a packet,
            %% for a body 32× the threshold.
            Peak = stop_sampler(Sampler),
            io:format(
                user,
                "~nrefused: receiver peak ~B bytes for a ~B-byte body (threshold ~B)~n",
                [Peak, byte_size(Body), Threshold]
            ),
            ?assert(Peak > 0),
            ?assert(Peak =< Threshold + 4 * ?CHUNK),
            %% The receiver is gone and the session carries on.
            ?assertEqual([], receivers(Session)),
            ?assertEqual(<<"250 Ok\r\n">>, command(Socket, "NOOP\r\n")),
            ?assertEqual(<<"250 Ok\r\n">>, command(Socket, "RSET\r\n")),
            ?assertMatch({handle_RSET, Session}, next_event(handle_RSET)),
            ?assertMatch([_, _, _, <<"451 4.3.0", _/binary>>], data_transaction(Socket, body(Threshold * 2)))
        end
    ).

%% Pipelined commands after the terminator survive the discard.
refuse_then_pipelined_command() ->
    with_admission_server(#{admission => {refuse, "451 4.3.0 later"}}, [{data_admission_threshold, 1024}], fun(Socket) ->
        begin_data(Socket),
        ok = gen_tcp:send(Socket, [body(64 * 1024), "\r\n.\r\nNOOP\r\n"]),
        ?assertEqual(<<"451 4.3.0 later\r\n">>, recv(Socket)),
        ?assertEqual(<<"250 Ok\r\n">>, recv(Socket))
    end).

%% A terminator split across packets in discard mode is still found.
refuse_terminator_split_across_packets() ->
    with_admission_server(#{admission => {refuse, "451 4.3.0 later"}}, [{data_admission_threshold, 1024}], fun(Socket) ->
        begin_data(Socket),
        ok = gen_tcp:send(Socket, body(64 * 1024)),
        {admission, _, _} = next_event(admission),
        timer:sleep(50),
        ok = gen_tcp:send(Socket, "\r\n."),
        timer:sleep(50),
        ok = gen_tcp:send(Socket, "\r\n"),
        ?assertEqual(<<"451 4.3.0 later\r\n">>, recv(Socket))
    end).

invalid_refusal_reply_falls_back_to_451_test_() ->
    Default = <<"451 Requested action aborted: local error in processing\r\n">>,
    [
        ?_test(
            with_admission_server(#{admission => Answer}, [{data_admission_threshold, 1024}], fun(Socket) ->
                ?assertEqual(Default, lists:last(data_transaction(Socket, body(64 * 1024)))),
                ?assertEqual(none, next_event(handle_DATA, 0))
            end)
        )
     || Answer <- [
            {refuse, "250 2.0.0 not a refusal"},
            {refuse, "354 go ahead"},
            {refuse, "451 4.3.0 two\r\n250 lines"},
            {refuse, binary:copy(<<"4">>, 600)},
            {refuse, not_a_reply},
            bad_shape
        ]
    ].

lmtp_refusal_once_per_recipient() ->
    with_admission_server(
        #{admission => {refuse, "451 4.3.0 later"}, protocol => lmtp},
        [{data_admission_threshold, 1024}, {protocol, lmtp}],
        fun(Socket) ->
            ok = gen_tcp:send(Socket, "LHLO client.example\r\n"),
            recv_ehlo(Socket),
            ?assertEqual(<<"250 sender Ok\r\n">>, command(Socket, "MAIL FROM:<sender@example.com>\r\n")),
            ?assertEqual(<<"250 recipient Ok\r\n">>, command(Socket, "RCPT TO:<one@example.com>\r\n")),
            ?assertEqual(<<"250 recipient Ok\r\n">>, command(Socket, "RCPT TO:<two@example.com>\r\n")),
            ?assertMatch(<<"354 ", _/binary>>, command(Socket, "DATA\r\n")),
            ok = gen_tcp:send(Socket, [body(64 * 1024), "\r\n.\r\n"]),
            ?assertEqual(<<"451 4.3.0 later\r\n">>, recv(Socket)),
            ?assertEqual(<<"451 4.3.0 later\r\n">>, recv(Socket)),
            ?assertEqual({error, timeout}, recv(Socket, 200))
        end
    ).

%% -- the size, bare-newline and deadline paths in discard mode -------------------

refuse_then_size_exceeded() ->
    with_admission_server(
        #{admission => {refuse, "451 4.3.0 later"}, maxsize => 1024 * 1024},
        [{data_admission_threshold, 64 * 1024}],
        fun(Socket) ->
            begin_data(Socket),
            spawn_sender(Socket, body(4 * 1024 * 1024), 0),
            ?assertEqual(<<"552 Message too large\r\n">>, recv(Socket, 5000)),
            ?assertMatch({handle_error, _, data_rejected, size_exceeded}, next_event(handle_error)),
            ?assertEqual(none, next_event(handle_DATA, 0))
        end
    ).

refuse_then_bare_newline() ->
    with_admission_server(#{admission => {refuse, "451 4.3.0 later"}}, [{data_admission_threshold, 1024}], fun(Socket) ->
        begin_data(Socket),
        ok = gen_tcp:send(Socket, body(64 * 1024)),
        {admission, _, _} = next_event(admission),
        ok = gen_tcp:send(Socket, "bare\nnewline\r\n"),
        ?assertEqual(<<"451 Bare newline detected\r\n">>, recv(Socket)),
        ?assertEqual(none, next_event(handle_DATA, 0))
    end).

refuse_then_data_deadline() ->
    with_admission_server(
        #{admission => {refuse, "451 4.3.0 later"}},
        [{data_admission_threshold, 1024}, {data_timeout, 1000}],
        fun(Socket, Session) ->
            begin_data(Socket),
            ok = gen_tcp:send(Socket, body(64 * 1024)),
            {admission, Session, _} = next_event(admission),
            %% No terminator: the DATA deadline still ends it.
            ?assertEqual(<<"421 Error: timeout exceeded\r\n">>, recv(Socket, 3000)),
            ?assertEqual({error, closed}, recv(Socket, 2000)),
            assert_gone(Session)
        end
    ).

%% The deadline also bounds the wait for the session's answer.
deadline_while_waiting_for_admission() ->
    with_admission_server(
        #{admission => {block, 1500, ok}},
        [{data_admission_threshold, 1024}, {data_timeout, 500}],
        fun(Socket, Session) ->
            begin_data(Socket),
            ok = gen_tcp:send(Socket, body(64 * 1024)),
            {admission, Session, _} = next_event(admission),
            ?assertEqual(<<"421 Error: timeout exceeded\r\n">>, recv(Socket, 4000)),
            ?assertEqual({error, closed}, recv(Socket, 2000)),
            assert_gone(Session),
            ?assertEqual(none, next_event(handle_DATA, 0))
        end
    ).

%% -- nothing leaks ----------------------------------------------------------------

session_crash_while_receiver_waits() ->
    with_admission_server(#{admission => {block, 10000, ok}}, [{data_admission_threshold, 1024}], fun(Socket, Session) ->
        begin_data(Socket),
        ok = gen_tcp:send(Socket, body(64 * 1024)),
        {admission, Session, _} = next_event(admission),
        [Receiver] = receivers(Session),
        exit(Session, kill),
        assert_gone(Session),
        assert_gone(Receiver)
    end).

socket_close_during_discard() ->
    with_admission_server(#{admission => {refuse, "451 4.3.0 later"}}, [{data_admission_threshold, 1024}], fun(
        Socket, Session
    ) ->
        begin_data(Socket),
        ok = gen_tcp:send(Socket, body(64 * 1024)),
        {admission, Session, _} = next_event(admission),
        [Receiver] = wait_receivers(Session),
        ok = gen_tcp:close(Socket),
        assert_gone(Receiver),
        assert_gone(Session),
        ?assertMatch({terminate, Session, _}, next_event(terminate))
    end).

quit_after_refusal() ->
    with_admission_server(#{admission => {refuse, "451 4.3.0 later"}}, [{data_admission_threshold, 1024}], fun(
        Socket, Session
    ) ->
        ?assertEqual(<<"451 4.3.0 later\r\n">>, lists:last(data_transaction(Socket, body(64 * 1024)))),
        ?assertMatch(<<"221 ", _/binary>>, command(Socket, "QUIT\r\n")),
        assert_gone(Session),
        ?assertEqual([], receivers(Session))
    end).

%% -- an admitted DATA ends in handle_DATA/4 or handle_DATA_aborted/2 ---------------
%%
%% After an `ok' admission the callback may hold a resource (email_submission:
%% a large-message budget permit) that only handle_DATA/4 would release. Every
%% other way the DATA can end tells the callback through the optional
%% handle_DATA_aborted(Reason, State).

%% The final packet takes an admitted body over SIZE while also carrying the
%% terminator: the post-read check answers 552 — and the callback is told.
admitted_final_packet_over_size_aborts() ->
    MaxSize = 1024 * 1024,
    with_admission_server(
        #{admission => ok, maxsize => MaxSize},
        [{data_admission_threshold, 64 * 1024}],
        fun(Socket, Session) ->
            ?assertEqual(
                [<<"552 Message too large\r\n">>, <<"250 Ok\r\n">>], over_size_in_final_packet(Socket, MaxSize)
            ),
            ?assertMatch({admission, Session, _}, next_event(admission)),
            ?assertEqual({handle_DATA_aborted, Session, size_exceeded}, next_event(handle_DATA_aborted)),
            ?assertEqual(none, next_event(handle_DATA, 0)),
            ?assertEqual(none, next_event(handle_DATA_aborted, 0)),
            %% The session carries on: the next DATA is delivered.
            ?assertMatch([_, _, _, <<"250 queued\r\n">>], data_transaction(Socket, body(4096))),
            ?assertEqual(none, next_event(handle_DATA_aborted, 0))
        end
    ).

%% Without handle_DATA_aborted/2 the same scenario is answered byte for byte as
%% before the callback existed.
admitted_final_packet_over_size_without_abort_callback_identical() ->
    MaxSize = 1024 * 1024,
    Run = fun(Module) ->
        with_callback_server(
            Module,
            #{admission => ok, maxsize => MaxSize},
            [{data_admission_threshold, 64 * 1024}],
            fun(Socket, _Session) ->
                Replies = over_size_in_final_packet(Socket, MaxSize),
                Next = data_transaction(Socket, body(4096)),
                Replies ++ Next
            end
        )
    end,
    Without = Run(gen_smtp_server_data_admission_test_noabort_callback),
    ?assertEqual(none, next_event(handle_DATA_aborted, 0)),
    With = Run(?CALLBACK),
    ?assertMatch([<<"552 Message too large\r\n">>, <<"250 Ok\r\n">> | _], Without),
    ?assertEqual(Without, With).

admitted_stream_over_size_aborts() ->
    with_admission_server(
        #{admission => ok, maxsize => 1024 * 1024},
        [{data_admission_threshold, 64 * 1024}],
        fun(Socket, Session) ->
            begin_data(Socket),
            spawn_sender(Socket, body(4 * 1024 * 1024), 0),
            ?assertEqual(<<"552 Message too large\r\n">>, recv(Socket, 5000)),
            ?assertMatch({admission, Session, _}, next_event(admission)),
            ?assertMatch({handle_error, Session, data_rejected, size_exceeded}, next_event(handle_error)),
            ?assertEqual({handle_DATA_aborted, Session, size_exceeded}, next_event(handle_DATA_aborted)),
            ?assertEqual(none, next_event(handle_DATA, 0))
        end
    ).

admitted_bare_newline_aborts() ->
    with_admission_server(#{admission => ok}, [{data_admission_threshold, 1024}], fun(Socket, Session) ->
        begin_data(Socket),
        ok = gen_tcp:send(Socket, body(64 * 1024)),
        {admission, Session, _} = next_event(admission),
        ok = gen_tcp:send(Socket, "bare\nnewline\r\n"),
        ?assertEqual(<<"451 Bare newline detected\r\n">>, recv(Socket)),
        ?assertEqual({handle_DATA_aborted, Session, bare_newline}, next_event(handle_DATA_aborted)),
        ?assertEqual(none, next_event(handle_DATA, 0)),
        ?assertEqual(<<"250 Ok\r\n">>, command(Socket, "NOOP\r\n"))
    end).

admitted_data_deadline_aborts() ->
    with_admission_server(
        #{admission => ok},
        [{data_admission_threshold, 1024}, {data_timeout, 1000}],
        fun(Socket, Session) ->
            begin_data(Socket),
            ok = gen_tcp:send(Socket, body(64 * 1024)),
            {admission, Session, _} = next_event(admission),
            ?assertEqual(<<"421 Error: timeout exceeded\r\n">>, recv(Socket, 3000)),
            ?assertEqual({handle_DATA_aborted, Session, data_timeout}, next_event(handle_DATA_aborted)),
            assert_gone(Session),
            ?assertEqual(none, next_event(handle_DATA, 0))
        end
    ).

admitted_socket_close_aborts() ->
    with_admission_server(#{admission => ok}, [{data_admission_threshold, 1024}], fun(Socket, Session) ->
        begin_data(Socket),
        ok = gen_tcp:send(Socket, body(64 * 1024)),
        {admission, Session, _} = next_event(admission),
        ok = gen_tcp:close(Socket),
        ?assertEqual({handle_DATA_aborted, Session, {receive_error, closed}}, next_event(handle_DATA_aborted)),
        assert_gone(Session),
        ?assertMatch({terminate, Session, _}, next_event(terminate))
    end).

%% Delivered (handle_DATA/4), refused (never admitted) and unadmitted DATAs
%% never reach handle_DATA_aborted/2.
delivered_refused_or_unadmitted_data_never_aborts() ->
    with_admission_server(#{admission => ok}, [{data_admission_threshold, 1024}], fun(Socket) ->
        ?assertMatch([_, _, _, <<"250 queued\r\n">>], data_transaction(Socket, body(64 * 1024))),
        ?assertMatch({handle_DATA, _, _, _}, next_event(handle_DATA))
    end),
    with_admission_server(#{admission => {refuse, "451 4.3.0 later"}}, [{data_admission_threshold, 1024}], fun(Socket) ->
        ?assertMatch([_, _, _, <<"451 4.3.0 later\r\n">>], data_transaction(Socket, body(64 * 1024)))
    end),
    %% Below the threshold and over SIZE in one packet: never asked, so
    %% never admitted.
    with_admission_server(
        #{admission => ok, maxsize => 4096},
        [{data_admission_threshold, 1024 * 1024}],
        fun(Socket) ->
            begin_data(Socket),
            ok = gen_tcp:send(Socket, [body(8192), "\r\n.\r\n"]),
            ?assertEqual(<<"552 Message too large\r\n">>, recv(Socket)),
            ?assertEqual(none, next_event(admission, 0))
        end
    ),
    ?assertEqual(none, next_event(handle_DATA_aborted, 0)).

%% -- the end-of-data terminator across the admission boundary ----------------------
%%
%% Each `send_packets' element is written separately and given time to be read
%% on its own, so the receiver sees exactly these packets.

%% Astra's vector: the packet that crosses the threshold completes a terminator
%% split across packets, and the body before it is under the threshold — it is
%% delivered without asking (whatever admission would answer), and the
%% pipelined NOOP is processed.
split_terminator_below_threshold(Answer) ->
    Body = binary:copy(<<"a">>, 1020),
    with_admission_server(#{admission => Answer}, [{data_admission_threshold, 1024}, {data_timeout, 3000}], fun(
        Socket, Session
    ) ->
        begin_data(Socket),
        send_packets(Socket, [<<Body/binary, "\r\n.">>, <<"\r\nNOOP\r\n">>]),
        ?assertEqual(<<"250 queued\r\n">>, recv(Socket)),
        ?assertEqual(<<"250 Ok\r\n">>, recv(Socket)),
        ?assertEqual({handle_DATA, Session, 1020, erlang:md5(Body)}, next_event(handle_DATA)),
        ?assertEqual(none, next_event(admission, 0))
    end).

%% The same, the terminator split over three packets.
three_packet_terminator_completed_by_crossing_packet() ->
    Body = binary:copy(<<"a">>, 1020),
    with_admission_server(
        #{admission => {refuse, "451 4.3.0 later"}},
        [{data_admission_threshold, 1024}, {data_timeout, 3000}],
        fun(Socket, Session) ->
            begin_data(Socket),
            send_packets(Socket, [<<Body/binary, "\r\n">>, <<".">>, <<"\r\nNOOP\r\n">>]),
            ?assertEqual(<<"250 queued\r\n">>, recv(Socket)),
            ?assertEqual(<<"250 Ok\r\n">>, recv(Socket)),
            ?assertEqual({handle_DATA, Session, 1020, erlang:md5(Body)}, next_event(handle_DATA)),
            ?assertEqual(none, next_event(admission, 0))
        end
    ).

%% Admitted (`ok'), then a terminator split over three packets: found, the
%% body is delivered whole, the pipelined command survives.
three_packet_terminator_after_admission_ok() ->
    Body = body(4096),
    with_admission_server(#{admission => ok}, [{data_admission_threshold, 1024}, {data_timeout, 3000}], fun(
        Socket, Session
    ) ->
        begin_data(Socket),
        %% body/1 ends with CRLF: the terminator's first two bytes.
        send_packets(Socket, [Body, <<".">>, <<"\r\nNOOP\r\n">>]),
        ?assertEqual(<<"250 queued\r\n">>, recv(Socket)),
        ?assertEqual(<<"250 Ok\r\n">>, recv(Socket)),
        Delivered = binary:part(Body, 0, byte_size(Body) - 2),
        ?assertEqual(
            {handle_DATA, Session, byte_size(Delivered), erlang:md5(Delivered)},
            next_event(handle_DATA)
        ),
        ?assertMatch({admission, Session, _}, next_event(admission))
    end).

%% The crossing packet is shorter than the terminator: the refusal's discard
%% loop must keep the delimiter history from the packets before it.
split_across_the_refusal_transition() ->
    with_admission_server(
        #{admission => {refuse, "451 4.3.0 later"}},
        [{data_admission_threshold, 1024}, {data_timeout, 3000}],
        fun(Socket, Session) ->
            begin_data(Socket),
            %% 1023 bytes (not over the threshold), then "\n." crosses it.
            First = <<(binary:copy(<<"a">>, 1022))/binary, "\r">>,
            send_packets(Socket, [First, <<"\n.">>, <<"\r\nNOOP\r\n">>]),
            ?assertEqual(<<"451 4.3.0 later\r\n">>, recv(Socket)),
            ?assertEqual(<<"250 Ok\r\n">>, recv(Socket)),
            ?assertMatch({admission, Session, 1025}, next_event(admission)),
            ?assertEqual(none, next_event(handle_DATA, 0))
        end
    ).

%% The terminator (and a pipelined command) arrives in the packet that crosses
%% the threshold: asked before handle_DATA/4, then delivered or refused, and
%% the pipelined command is processed either way.
terminator_before_the_admission_answer_ok_pipelined() ->
    Body = body(4096),
    with_admission_server(#{admission => {block, 200, ok}}, [{data_admission_threshold, 1024}], fun(Socket, Session) ->
        begin_data(Socket),
        ok = gen_tcp:send(Socket, [Body, "\r\n.\r\nNOOP\r\n"]),
        ?assertEqual(<<"250 queued\r\n">>, recv(Socket)),
        ?assertEqual(<<"250 Ok\r\n">>, recv(Socket)),
        ?assertMatch({admission, Session, _}, next_event(admission)),
        ?assertEqual({handle_DATA, Session, byte_size(Body), erlang:md5(Body)}, next_event(handle_DATA))
    end).

terminator_before_the_admission_answer_refuse_pipelined() ->
    with_admission_server(
        #{admission => {block, 200, {refuse, "451 4.3.0 later"}}},
        [{data_admission_threshold, 1024}],
        fun(Socket, Session) ->
            begin_data(Socket),
            %% The crossing packet ends inside the terminator; the rest of it
            %% and the pipelined command arrive while admission is pending.
            ok = gen_tcp:send(Socket, [body(4096), "\r"]),
            {admission, Session, _} = next_event(admission),
            ok = gen_tcp:send(Socket, "\n.\r\nNOOP\r\n"),
            ?assertEqual(<<"451 4.3.0 later\r\n">>, recv(Socket)),
            ?assertEqual(<<"250 Ok\r\n">>, recv(Socket)),
            ?assertEqual(none, next_event(handle_DATA, 0))
        end
    ).

%% Astra r4's vector: the packet that completes a terminator split across
%% packets also holds a later whole one ("NOOP\r\n.\r\n"). The first ends the
%% message: the body is the 1020 bytes before it, and everything after it, the
%% pipelined NOOP first, is the remainder handed back to the session. Under a
%% 1024-byte threshold the body is never asked about; under 1000 the 1023
%% bytes before the crossing packet are, and the answer decides.
boundary_terminator_plus_full_terminator(Answer, Threshold) ->
    Body = binary:copy(<<"a">>, 1020),
    Asked = Threshold < 1023,
    Delivered = not Asked orelse Answer =:= ok,
    with_admission_server(
        #{admission => Answer},
        [{data_admission_threshold, Threshold}, {data_timeout, 3000}],
        fun(Socket, Session) ->
            begin_data(Socket),
            send_packets(Socket, [<<Body/binary, "\r\n.">>, <<"\r\nNOOP\r\n.\r\nQUIT\r\n">>]),
            DataReply = recv(Socket),
            case Asked of
                true -> ?assertEqual({admission, Session, 1023}, next_event(admission));
                false -> ?assertEqual(none, next_event(admission, 0))
            end,
            case Delivered of
                true ->
                    ?assertEqual(<<"250 queued\r\n">>, DataReply),
                    ?assertEqual({handle_DATA, Session, 1020, erlang:md5(Body)}, next_event(handle_DATA));
                false ->
                    ?assertEqual(<<"451 4.3.0 later\r\n">>, DataReply),
                    ?assertEqual(none, next_event(handle_DATA, 0))
            end,
            assert_remainder(Socket, Session, <<"NOOP\r\n.\r\nQUIT">>)
        end
    ).

%% The later whole terminator starts inside the split one: the "." line ends
%% the message, it is not body.
boundary_terminator_overlapping_a_full_terminator() ->
    Body = binary:copy(<<"a">>, 1020),
    with_admission_server(#{admission => ok}, [{data_admission_threshold, 1024}, {data_timeout, 3000}], fun(
        Socket, Session
    ) ->
        begin_data(Socket),
        send_packets(Socket, [<<Body/binary, "\r\n.">>, <<"\r\n.\r\nNOOP\r\n">>]),
        ?assertEqual(<<"250 queued\r\n">>, recv(Socket)),
        ?assertEqual({handle_DATA, Session, 1020, erlang:md5(Body)}, next_event(handle_DATA)),
        ?assertEqual(none, next_event(admission, 0)),
        assert_remainder(Socket, Session, <<".\r\nNOOP">>)
    end).

%% The session handed the remainder after the terminator to the command
%% parser. It parses a remainder as one command line (as upstream does), so a
%% remainder of several lines reaches handle_other/3 whole and is answered
%% once; the session then carries on taking commands.
assert_remainder(Socket, Session, Line) ->
    ?assertEqual(<<"500 Error: command not recognized\r\n">>, recv(Socket)),
    ?assertEqual({handle_other, Session, Line, <<>>}, next_event(handle_other)),
    ?assertEqual(<<"250 Ok\r\n">>, command(Socket, "NOOP\r\n")).

%% -- helpers ------------------------------------------------------------------------

with_admission_server(CallbackOptions, SessionOptions, Fun) when is_function(Fun, 1) ->
    with_admission_server(CallbackOptions, SessionOptions, fun(Socket, _Session) -> Fun(Socket) end);
with_admission_server(CallbackOptions, SessionOptions, Fun) ->
    with_callback_server(?CALLBACK, CallbackOptions, SessionOptions, Fun).

with_callback_server(Module, CallbackOptions, SessionOptions, Fun) ->
    flush_events(),
    ok = ensure_gen_smtp_started(),
    Name = {?MODULE, make_ref()},
    {ok, _Pid} = gen_smtp_server:start(
        Name,
        Module,
        [
            {domain, "localhost"},
            {port, 0},
            {sessionoptions, [{callbackoptions, CallbackOptions#{test => self()}} | SessionOptions]}
        ]
    ),
    Port = ranch:get_port(Name),
    {ok, Socket} = gen_tcp:connect("localhost", Port, [binary, {packet, line}, {active, false}]),
    try
        ?assertMatch(<<"220 localhost", _/binary>>, recv(Socket)),
        {session, Session} = next_event(session),
        Fun(Socket, Session)
    after
        gen_tcp:close(Socket),
        gen_smtp_server:stop(Name)
    end.

with_example_server(SessionOptions, Fun) ->
    ok = ensure_gen_smtp_started(),
    Name = {?MODULE, make_ref()},
    {ok, _Pid} = gen_smtp_server:start(
        Name,
        smtp_server_example,
        [
            {domain, "localhost"},
            {port, 0},
            {sessionoptions, [{callbackoptions, []} | SessionOptions]}
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

ensure_gen_smtp_started() ->
    case application:ensure_all_started(gen_smtp) of
        {ok, _} -> ok;
        {error, {already_started, gen_smtp}} -> ok
    end.

%% MAIL, RCPT, DATA, then the body (in ?CHUNK pieces, optionally pausing
%% between them) and the terminator. Returns the four replies.
data_transaction(Socket, Body) ->
    data_transaction(Socket, Body, 0).

data_transaction(Socket, Body, PauseMs) ->
    ok = gen_tcp:send(Socket, "EHLO client.example\r\n"),
    recv_ehlo(Socket),
    Mail = command(Socket, "MAIL FROM:<sender@example.com>\r\n"),
    Rcpt = command(Socket, "RCPT TO:<recipient@example.com>\r\n"),
    Data = command(Socket, "DATA\r\n"),
    send_chunks(Socket, Body, PauseMs),
    ok = gen_tcp:send(Socket, "\r\n.\r\n"),
    [Mail, Rcpt, Data, recv(Socket, 30000)].

begin_data(Socket) ->
    ok = gen_tcp:send(Socket, "EHLO client.example\r\n"),
    recv_ehlo(Socket),
    ?assertEqual(<<"250 sender Ok\r\n">>, command(Socket, "MAIL FROM:<sender@example.com>\r\n")),
    ?assertEqual(<<"250 recipient Ok\r\n">>, command(Socket, "RCPT TO:<recipient@example.com>\r\n")),
    ?assertMatch(<<"354 ", _/binary>>, command(Socket, "DATA\r\n")).

send_chunks(_Socket, <<>>, _PauseMs) ->
    ok;
send_chunks(Socket, Body, PauseMs) ->
    Size = min(?CHUNK, byte_size(Body)),
    <<Chunk:Size/binary, Rest/binary>> = Body,
    ok = gen_tcp:send(Socket, Chunk),
    PauseMs > 0 andalso timer:sleep(PauseMs),
    send_chunks(Socket, Rest, PauseMs).

%% Each packet on its own: written, then given time to be read alone.
send_packets(Socket, Packets) ->
    lists:foreach(
        fun(Packet) ->
            ok = gen_tcp:send(Socket, Packet),
            timer:sleep(150)
        end,
        Packets
    ).

%% An admitted DATA (threshold well below MaxSize) whose last packet both
%% takes it one byte over MaxSize and carries the terminator. Returns the
%% DATA reply and the reply to a NOOP after it.
over_size_in_final_packet(Socket, MaxSize) ->
    begin_data(Socket),
    Head = body(MaxSize - 2000),
    send_chunks(Socket, Head, 0),
    {admission, _, _} = Admission = next_event(admission),
    self() ! Admission,
    %% Everything so far has been read: the final packet is read alone.
    timer:sleep(200),
    Last = binary:copy(<<"z">>, MaxSize + 1 - byte_size(Head)),
    ok = gen_tcp:send(Socket, [Last, "\r\n.\r\n"]),
    DataReply = recv(Socket, 5000),
    [DataReply, command(Socket, "NOOP\r\n")].

spawn_sender(Socket, Body, PauseMs) ->
    spawn(fun() -> catch send_chunks(Socket, Body, PauseMs) end).

%% CRLF lines of printable ASCII, never a lone "." line.
body(Size) ->
    Line = <<"0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz..\r\n">>,
    Full = binary:copy(Line, Size div byte_size(Line) + 1),
    binary:part(Full, 0, Size - (Size rem byte_size(Line))).

recv_ehlo(Socket) ->
    case recv(Socket) of
        <<"250 ", _/binary>> -> ok;
        <<"250-", _/binary>> -> recv_ehlo(Socket)
    end.

command(Socket, Command) ->
    ok = gen_tcp:send(Socket, Command),
    recv(Socket).

recv(Socket) ->
    recv(Socket, ?RECV_TIMEOUT).

recv(Socket, Timeout) ->
    case gen_tcp:recv(Socket, 0, Timeout) of
        {ok, Packet} -> Packet;
        Error -> Error
    end.

strip_queue_id(<<"250 queued as ", _/binary>>) -> <<"250 queued as <id>\r\n">>;
strip_queue_id(Reply) -> Reply.

next_event(Tag) ->
    next_event(Tag, 5000).

next_event(Tag, Timeout) ->
    receive
        Event when element(1, Event) =:= Tag -> Event
    after Timeout -> none
    end.

flush_events() ->
    receive
        _ -> flush_events()
    after 0 -> ok
    end.

assert_invalid_session_option(Key, Value) ->
    {ok, Listen} = gen_tcp:listen(0, [binary, {active, false}]),
    try
        SessionOptions = [{callbackoptions, #{test => self()}}, {Key, Value}],
        ?assertEqual(
            {stop, {invalid_option, Key}},
            gen_smtp_server_session:init([make_ref(), ranch_tcp, Listen, ?CALLBACK, SessionOptions])
        )
    after
        gen_tcp:close(Listen)
    end.

%% The DATA receiver: the session's linked, plainly spawned process.
receivers(Session) ->
    case erlang:process_info(Session, links) of
        {links, Links} ->
            [
                P
             || P <- Links,
                is_pid(P),
                erlang:process_info(P, initial_call) =:= {initial_call, {erlang, apply, 2}}
            ];
        undefined ->
            []
    end.

wait_receivers(Session) ->
    wait_receivers(Session, 100).

wait_receivers(Session, 0) ->
    receivers(Session);
wait_receivers(Session, N) ->
    case receivers(Session) of
        [] ->
            timer:sleep(10),
            wait_receivers(Session, N - 1);
        Found ->
            Found
    end.

assert_gone(Pid) ->
    assert_gone(Pid, 200).

assert_gone(Pid, 0) ->
    ?assertNot(is_process_alive(Pid));
assert_gone(Pid, N) ->
    case is_process_alive(Pid) of
        false ->
            ok;
        true ->
            timer:sleep(10),
            assert_gone(Pid, N - 1)
    end.

%% Samples the bytes the session's DATA receiver retains (its heap plus every
%% off-heap binary it references) until stopped; returns the peak.
start_sampler(Session) ->
    Parent = self(),
    spawn_link(fun() -> sample(Parent, Session, 0) end).

stop_sampler(Sampler) ->
    Sampler ! {stop, self()},
    receive
        {peak, Sampler, Peak} -> Peak
    after 5000 -> error(sampler_timeout)
    end.

sample(Parent, Session, Peak) ->
    receive
        {stop, From} -> From ! {peak, self(), Peak}
    after 0 ->
        Retained = lists:sum([retained(R) || R <- receivers(Session)]),
        erlang:yield(),
        sample(Parent, Session, max(Peak, Retained))
    end.

retained(Pid) ->
    case erlang:process_info(Pid, [memory, binary]) of
        [{memory, Memory}, {binary, Binaries}] ->
            Unique = maps:from_list([{Id, Size} || {Id, Size, _Refs} <- Binaries]),
            Memory + lists:sum(maps:values(Unique));
        undefined ->
            0
    end.
