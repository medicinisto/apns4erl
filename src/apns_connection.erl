%%%-------------------------------------------------------------------
%%% @author Fernando Benavides <fernando.benavides@inakanetworks.com>
%%% @copyright (C) 2010 Fernando Benavides <fernando.benavides@inakanetworks.com>
%%% @doc apns4erl connection process
%%% @end
%%%-------------------------------------------------------------------
-module(apns_connection).
-author('Fernando Benavides <fernando.benavides@inakanetworks.com>').

-behaviour(gen_server).

-include("apns.hrl").
-include("localized.hrl").

-export([start_link/2, start_link/3, init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).
-export([send_message/2, stop/1]).
-export([build_payload/1]).
-export([test_connection/1]).

% for mocking
-export([ssl_connect/4, ssl_send/2, ssl_close/1]).

-record(state, {out_socket        :: tuple(),
                in_socket         :: tuple(),
                connection        :: #apns_connection{},
                in_buffer = <<>>  :: binary(),
                out_buffer = <<>> :: binary(),
                owner             :: undefined | pid()}).
-type state() :: #state{}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Public API
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%% @doc  Sends a message to apple through the connection
-spec send_message(apns:conn_id(), #apns_msg{}) -> ok.
send_message(ConnId, Msg) ->
  gen_server:cast(ConnId, Msg).

%% @doc  Stops the connection
-spec stop(apns:conn_id()) -> ok.
stop(ConnId) ->
  gen_server:cast(ConnId, stop).

%% @hidden
-spec start_link(atom(), #apns_connection{}, undefined | pid()) -> {ok, pid()} | {error, {already_started, pid()}}.
start_link(Name, Connection, Owner) ->
  gen_server:start_link({local, Name}, ?MODULE, {Connection, Owner}, []).
%% @hidden
-spec start_link(#apns_connection{}, undefined | pid()) -> {ok, pid()}.
start_link(Connection, Owner) ->
  gen_server:start_link(?MODULE, {Connection, Owner}, []).

-spec test_connection(#apns_connection{}) -> ok | {error, any()}.
test_connection(Connection) ->
    case open_out(Connection) of
        {ok, Socket} ->
            ssl_close(Socket),
            ok;

        {error, {tls_alert, "certificate revoked"}} -> 
             {error, certificate_revoked};
        {error, {tls_alert, R}} -> 
            {error, {invalid_certificate, R}};
        {error, Reason} -> 
            {error, {unknown, Reason}}
    end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Server implementation, a.k.a.: callbacks
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%% @hidden
-spec init({#apns_connection{}, undefined | pid()}) -> {ok, state(), non_neg_integer()}.
init({Connection, Owner}) ->
    {ok, #state{connection=Connection, owner = Owner}, 0}.

%% @hidden
open_out(Connection) ->
  KeyOpts = case key_opts(Connection) of
              undefined -> [];
              Other -> [Other]
            end,
  SslOpts = [cert_opts(Connection), KeyOpts, {mode, binary}],
  RealSslOpts = case Connection#apns_connection.cert_password of
    undefined -> SslOpts;
    Password -> [{password, Password} | SslOpts]
  end,
  ssl_connect(
    Connection#apns_connection.apple_host,
    Connection#apns_connection.apple_port,
    Connection#apns_connection.ssl_connect_options ++ RealSslOpts,
    Connection#apns_connection.timeout).
  
%% @hidden
key_opts(Connection) ->
  KeyType = Connection#apns_connection.key_type,
  KeyDer = Connection#apns_connection.key_der,
  case Connection#apns_connection.key_file of
    undefined -> case KeyDer of
                    undefined -> undefined;
                    _ -> {key, {KeyType, KeyDer}}
                 end;
    Filename -> {keyfile, filename:absname(Filename)}
  end.

%% @hidden
cert_opts(Connection) ->
  CertDer = Connection#apns_connection.cert_der,
  case Connection#apns_connection.cert_file of
    undefined -> case CertDer of
                    undefined -> undefined;
                    _ -> {cert, CertDer}
                 end;
    Filename -> {certfile, filename:absname(Filename)}
  end.


%% @hidden
open_feedback(Connection) ->
  KeyOpts = case key_opts(Connection) of
              undefined -> [];
              Other -> [Other]
            end,
  SslOpts = [cert_opts(Connection), KeyOpts, {mode, binary}],
  RealSslOpts = case Connection#apns_connection.cert_password of
    undefined -> SslOpts;
    Password -> [{password, Password} | SslOpts]
  end,
  case ssl_connect(
    Connection#apns_connection.feedback_host,
    Connection#apns_connection.feedback_port,
    RealSslOpts,
    Connection#apns_connection.timeout
  ) of
    {ok, InSocket} -> {ok, InSocket};
    {error, Reason} -> {error, Reason}
  end.

%% @hidden
-spec handle_call(X, reference(), state()) -> {stop, {unknown_request, X}, {unknown_request, X}, state()}.
handle_call(Request, _From, State) ->
    {stop, {unknown_request, Request}, {unknown_request, Request}, State}.

%% @hidden
-spec handle_cast(stop | #apns_msg{}, state()) -> {noreply, state()} | {stop, normal | {error, term()}, state()}.
handle_cast(Msg, State=#state{out_socket=undefined,connection=Connection}) ->
  try
    lager:info("Reconnecting to APNS..."),
    case open_out(Connection) of
      {ok, Socket} -> handle_cast(Msg, State#state{out_socket=Socket});
      {error, Reason} -> handle_error_and_stop(Msg, connect, Reason, State)
    end
  catch
    _:{error, Reason2} -> handle_error_and_stop(Msg, connect, Reason2, State)
  end;

handle_cast(Msg, State) when is_record(Msg, apns_msg) ->
  Socket = State#state.out_socket,
  Payload = build_payload(Msg),
  BinToken = hexstr_to_bin(Msg#apns_msg.device_token),
  try send_payload(Socket, Msg#apns_msg.id, Msg#apns_msg.expiry, BinToken, Payload) of
    ok ->
      {noreply, State};
    {error, Reason} ->
      handle_error_and_stop(Msg, send_payload, Reason, State)
  catch
      _:Reason ->
          handle_error_and_stop(Msg, send_payload, Reason, State)
  end;

handle_cast(stop, State) ->
  {stop, normal, State}.

%% @hidden
-spec handle_info({ssl, tuple(), binary()} | {ssl_closed, tuple()} | X, state()) -> {noreply, state()} | {stop, ssl_closed | {unknown_request, X}, state()}.
handle_info({ssl, SslSocket, Data}, State = #state{out_socket = SslSocket,
                                                   connection =
                                                     #apns_connection{error_fun = Error},
                                                   out_buffer = CurrentBuffer,
                                                   owner = Owner}) ->
  case <<CurrentBuffer/binary, Data/binary>> of
    <<Command:1/unit:8, StatusCode:1/unit:8, MsgId:4/binary, Rest/binary>> ->
      case Command of
        8 -> %% Error
          Status = parse_status(StatusCode),
          try Error({Owner, MsgId}, Status) of
            stop -> throw({stop, {msg_error, MsgId, Status}, State});
            _ -> noop
          catch
            _:ErrorResult ->
              lager:error("Error trying to inform error (~p) msg:~n\t~p", [Status, ErrorResult])
          end,
          case erlang:size(Rest) of
            0 -> {noreply, State#state{out_buffer = <<>>}}; %% It was a whole package
            _ -> handle_info({ssl, SslSocket, Rest}, State#state{out_buffer = <<>>})
          end;
        Command ->
          throw({stop, {unknown_command, Command}, State})
      end;
    NextBuffer -> %% We need to wait for the rest of the message
      {noreply, State#state{out_buffer = NextBuffer}}
  end;
handle_info({ssl, SslSocket, Data}, State = #state{in_socket  = SslSocket,
                                                   connection =
                                                     #apns_connection{feedback_fun = Feedback},
                                                   in_buffer  = CurrentBuffer,
                                                   owner = Owner
                                                  }) ->
  case <<CurrentBuffer/binary, Data/binary>> of
    <<TimeT:4/big-unsigned-integer-unit:8,
      Length:2/big-unsigned-integer-unit:8,
      Token:Length/binary,
      Rest/binary>> ->
      try Feedback({Owner, apns:timestamp(TimeT), bin_to_hexstr(Token)})
      catch
        _:Error ->
          lager:error("Error trying to inform feedback token ~p:~n\t~p", [Token, Error])
      end,
      case erlang:size(Rest) of
        0 -> {noreply, State#state{in_buffer = <<>>}}; %% It was a whole package
        _ -> handle_info({ssl, SslSocket, Rest}, State#state{in_buffer = <<>>})
      end;
    NextBuffer -> %% We need to wait for the rest of the message
      {noreply, State#state{in_buffer = NextBuffer}}
  end;

handle_info({ssl_closed, SslSocket}, State = #state{in_socket = SslSocket,
                                                    connection= Connection}) ->
  lager:info("Feedback server disconnected. Waiting ~p millis to connect again...",
                        [Connection#apns_connection.feedback_timeout]),
  _Timer = erlang:send_after(Connection#apns_connection.feedback_timeout, self(), reconnect),
  {noreply, State#state{in_socket = undefined}};

handle_info(reconnect, State = #state{connection = Connection}) ->
  lager:info("Reconnecting the Feedback server..."),
  case open_feedback(Connection) of
    {ok, InSocket} -> {noreply, State#state{in_socket = InSocket}};
    {error, Reason} -> {stop, {in_closed, Reason}, State}
  end;

handle_info({ssl_closed, SslSocket}, State = #state{out_socket = SslSocket}) ->
  lager:info("APNS disconnected"),
  {noreply, State#state{out_socket=undefined}};


handle_info(timeout, #state{connection = Connection}=State) ->
    case open_out(Connection) of
      {ok, Socket} -> 
            lager:debug("Opened connection"),
            case open_feedback(Connection) of
                {ok, InSocket} -> 
                    {noreply, State#state{out_socket=Socket, in_socket=InSocket}};
                {error, Reason} -> 
                    {stop, {error, Reason}, State}
            end;
      {error, Reason} -> 
            {stop, {error, Reason}, State}
    end;

 
handle_info(Request, State) ->
  {stop, {unknown_request, Request}, State}.

%% @hidden
-spec terminate(term(), state()) -> ok.
terminate(_Reason, _State) -> ok.

%% @hidden
-spec code_change(term(), state(), term()) -> {ok, state()}.
code_change(_OldVsn, State, _Extra) ->  {ok, State}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Private functions
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
build_payload(#apns_msg{alert = Alert,
                        badge = Badge,
                        sound = Sound,
                        apns_extra=Apns_Extra,
                        extra = Extra,
                        'content-available' = Content}) ->
  build_payload([{alert, Alert},
                 {badge, Badge},
                 {sound, Sound},
                 {'content-available', Content}] ++ Apns_Extra, Extra).

build_payload(Params, Extra) ->
  apns_mochijson2:encode(
    {[{<<"aps">>, do_build_payload(Params, [])} | Extra]}).

do_build_payload([{Key,Value}|Params], Payload) ->  
  case Value of
    Value when is_list(Value); is_binary(Value) ->
      do_build_payload(Params, [{atom_to_binary(Key, utf8), unicode:characters_to_binary(Value)} | Payload]);
    Value when is_integer(Value) ->
      do_build_payload(Params, [{atom_to_binary(Key, utf8), Value} | Payload]);
    #loc_alert{action = Action,
               args   = Args,
               body   = Body,
               image  = Image,
               key    = LocKey} ->
      Json = {case Body of
                none -> [];
                Body -> [{<<"body">>, unicode:characters_to_binary(Body)}]
              end ++ case Action of
                       none -> [];
                       Action -> [{<<"action-loc-key">>, unicode:characters_to_binary(Action)}]
                     end ++ case Image of
                              none -> [];
                              Image -> [{<<"launch-image">>, unicode:characters_to_binary(Image)}]
                            end ++
                  [{<<"loc-key">>, unicode:characters_to_binary(LocKey)},
                   {<<"loc-args">>, lists:map(fun unicode:characters_to_binary/1, Args)}]},
      do_build_payload(Params, [{atom_to_binary(Key, utf8), Json} | Payload]);
    _ ->
      do_build_payload(Params,Payload)
  end;
do_build_payload([], Payload) ->
  {Payload}.

-spec send_payload(tuple(), binary(), non_neg_integer(), binary(), iolist()) -> ok | {error, term()}.
send_payload(Socket, MsgId, Expiry, BinToken, Payload) ->
    BinPayload = list_to_binary(Payload),
    PayloadLength = erlang:size(BinPayload),
    Packet = [<<1:8, MsgId/binary, Expiry:4/big-unsigned-integer-unit:8,
                32:16/big,
                BinToken/binary,
                PayloadLength:16/big,
                BinPayload/binary>>],
    lager:info("Sending msg (expires on ~p)", [Expiry]),
    ssl_send(Socket, Packet).

hexstr_to_bin(S) ->
  hexstr_to_bin(S, []).
hexstr_to_bin([], Acc) ->
  list_to_binary(lists:reverse(Acc));
hexstr_to_bin([$ |T], Acc) ->
    hexstr_to_bin(T, Acc);
hexstr_to_bin([X,Y|T], Acc) ->
  {ok, [V], []} = io_lib:fread("~16u", [X,Y]),
  hexstr_to_bin(T, [V | Acc]).

bin_to_hexstr(Binary) ->
    L = size(Binary),
    Bits = L * 8,
    <<X:Bits/big-unsigned-integer>> = Binary,
    F = lists:flatten(io_lib:format("~~~B.16.0B", [L * 2])),
    lists:flatten(io_lib:format(F, [X])).

parse_status(0) -> no_errors;
parse_status(1) -> processing_error;
parse_status(2) -> missing_token;
parse_status(3) -> missing_topic;
parse_status(4) -> missing_payload;
parse_status(5) -> missing_token_size;
parse_status(6) -> missing_topic_size;
parse_status(7) -> missing_payload_size;
parse_status(8) -> invalid_token;
parse_status(10) -> shutdown;
parse_status(_) -> unknown.


ssl_send(Socket, Data) ->
    ssl:send(Socket, Data).

ssl_connect(Host, Port, Opts, Timeout) ->
    ssl:connect(Host, Port, Opts, Timeout).

ssl_close(Socket) ->
    ssl:close(Socket).

%% This is intended to be invoked from handle_cast.
%% Something really bad happened (i.e. connect failure, or packet send failure),
%% and we should assume that the connection is dead and should be stopped.
handle_error_and_stop(Msg, WhatFailed, Reason, State = #state{connection = #apns_connection{error_fun = ErrorFun}, owner = Owner}) ->
    case is_function(ErrorFun) of
        true ->
            try ErrorFun({Owner, Msg#apns_msg.id}, {error, WhatFailed, Reason}) of
                _ -> {stop, Reason, State}
            catch
                _:Err ->
                    lager:error("Error while invoking ~p for ~p: ~p",
                                [ErrorFun, WhatFailed, Err]),
                    {stop, Reason, State}
            end;
        false ->
            %% error_fun wasn't defined, so just log the error and stop
            lager:error("Error: ~p: ~p", [WhatFailed, Reason]),
            {stop, Reason, State}
    end.
