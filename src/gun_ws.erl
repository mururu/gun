%% Copyright (c) 2013-2014, Loïc Hoguin <essen@ninenines.eu>
%%
%% Permission to use, copy, modify, and/or distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.
%%
%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

-module(gun_ws).

-export([init/4]).
-export([handle/2]).
-export([send/2]).
-export([send_many/2]).

-record(ws_state, {
	owner :: pid(),
	socket :: inet:socket() | ssl:sslsocket(),
	transport :: module(),
	buffer = <<>> :: binary(),
  ws_key :: binary(),
  in_state = connecting :: connecting | open,
  %% TODO: deflate まわりの実装
	deflate_frame = false :: boolean(),
	inflate_state :: undefined | port(),
	deflate_state :: undefined | port()
}).

init(Owner, Socket, Transport, WsKey) ->
  #ws_state{owner=Owner, socket=Socket, transport=Transport, ws_key=WsKey}.

%% check handleshack response
handle(<<>>, State=#ws_state{in_state=connecting}) ->
  State;
handle(Data, State=#ws_state{in_state=connecting, owner=Owner, buffer=Buffer}) ->
  Data2 = << Buffer/binary, Data/binary >>,
	case binary:match(Data2, <<"\r\n\r\n">>) of
		nomatch ->
      State#ws_state{buffer=Data2};
		{_, _} ->
      %% TODO: これのエラー処理
      case validate_handshake(Data2, State#ws_state{buffer= <<>>}) of
        {ok, State2} ->
          Owner ! {gun_ws_upgrade, self(), ok},
          State2;
        E ->
          ct:pal(Data2),
          ct:pal("~p~n", [E]),
          error(fail_validate)
      end
	end;
%% handle WebSocket
handle(#ws_state{in_state = open}, Data) ->
  ct:pal("Data: ~p~n",[Data]).

validate_handshake(Data, State=#ws_state{ws_key=WsKey}) ->
  Challenge = base64:encode(crypto:hash(sha, <<WsKey/binary, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11">>)),
	{_, Status, _, Rest} = cow_http:parse_status_line(Data),
	{Headers, Rest2} = cow_http:parse_headers(Rest),
  case Status of
    101 ->
      case proplists:get_value(<<"upgrade">>, Headers) of
        %% TODO: 大小無視で一致
        <<"websocket">> ->
          case proplists:get_value(<<"connection">>, Headers) of
            %% TODO: 大小無視で一致
            <<"Upgrade">> ->
              case proplists:get_value(<<"sec-websocket-accept">>, Headers) of
                %% TODO: 前後の空白を無視しないといけない
                Challenge ->
                  %% TODO: Sec-WebSocket-Extensions, Sec-WebSocket-Protocol のバリデーション
                  {ok, State#ws_state{in_state=open, buffer=Rest2}};
                E ->
                  ct:pal("~p~n", [E]),
                  error(fail_sec_websocket_accept)
              end;
            E ->
              ct:pal("~p~n", [E]),
              error(fail_connection)
          end;
        E ->
          ct:pal("~p~n", [E]),
          error(fail_upgrade)
      end;
    E ->
      ct:pal("~p~n", [Data]),
      ct:pal("~p~n", [E]),
      error(fail_status)
  end.

%% -spec send(frame(), #ws_state{})
%% -> {ok, #ws_state{}} | {shutdown, #ws_state{}} | {{error, atom()}, #ws_state{}}.
send(Type, State=#ws_state{socket=Socket, transport=Transport})
		when Type =:= close ->
  MaskingKey = crypto:rand_bytes(4),
	Opcode = websocket_opcode(Type),
  case Transport:send(Socket, << 1:1, 0:3, Opcode:4, 1:1, 0:7, MaskingKey/binary >>) of
		ok -> {shutdown, State};
		Error -> {Error, State}
	end;
send(Type, State=#ws_state{socket=Socket, transport=Transport})
		when Type =:= ping; Type =:= pong ->
  MaskingKey = crypto:rand_bytes(4),
	Opcode = websocket_opcode(Type),
  MaskingKey = crypto:rand_bytes(4),
	{Transport:send(Socket, << 1:1, 0:3, Opcode:4, 1:1, 0:7, MaskingKey/binary >>), State};
send({close, Payload}, State) ->
	send({close, 1000, Payload}, State);
send({Type = close, StatusCode, Payload}, State=#ws_state{
		socket=Socket, transport=Transport}) ->
  MaskingKey = crypto:rand_bytes(4),
	Opcode = websocket_opcode(Type),
  Payload2 = mask_payload(MaskingKey, Payload),
	Len = 2 + iolist_size(Payload2),
	%% Control packets must not be > 125 in length.
	true = Len =< 125,
	BinLen = payload_length_to_binary(Len),
	Transport:send(Socket,
		[<< 1:1, 0:3, Opcode:4, 1:1, BinLen/bits, MaskingKey/binary, StatusCode:16 >>, Payload2]),
	{shutdown, State};
send({Type, Payload0}, State=#ws_state{socket=Socket, transport=Transport}) ->
  MaskingKey = crypto:rand_bytes(4),
	Opcode = websocket_opcode(Type),
	{Payload, Rsv, State2} = websocket_deflate_frame(Opcode, iolist_to_binary(Payload0), State),
  Payload2 = mask_payload(MaskingKey, Payload),
	Len = iolist_size(Payload2),
	%% Control packets must not be > 125 in length.
	true = if Type =:= ping; Type =:= pong ->
			Len =< 125;
		true ->
			true
	end,
	BinLen = payload_length_to_binary(Len),
	{Transport:send(Socket,
		[<< 1:1, Rsv/bits, Opcode:4, 1:1, BinLen/bits, MaskingKey/binary >>, Payload2]), State2}.

%% -spec websocket_send_many([frame()], #ws_state{})
%%   -> {ok, #ws_state{}} | {shutdown, #ws_state{}} | {{error, atom()}, #ws_state{}}.
send_many([], State) ->
	{ok, State};
send_many([Frame|Tail], State) ->
	case send(Frame, State) of
		{ok, State2} -> send_many(Tail, State2);
		{shutdown, State2} -> {shutdown, State2};
		{Error, State2} -> {Error, State2}
	end.

websocket_opcode(text) -> 1;
websocket_opcode(binary) -> 2;
websocket_opcode(close) -> 8;
websocket_opcode(ping) -> 9;
websocket_opcode(pong) -> 10.

%% -spec websocket_deflate_frame(opcode(), binary(), #state{}) ->
%%   {binary(), rsv(), #state{}}.
websocket_deflate_frame(Opcode, Payload,
		State=#ws_state{deflate_frame = DeflateFrame})
		when DeflateFrame =:= false orelse Opcode >= 8 ->
	{Payload, << 0:3 >>, State};
websocket_deflate_frame(_, Payload, State=#ws_state{deflate_state = Deflate}) ->
	Deflated = iolist_to_binary(zlib:deflate(Deflate, Payload, sync)),
	DeflatedBodyLength = erlang:size(Deflated) - 4,
	Deflated1 = case Deflated of
		<< Body:DeflatedBodyLength/binary, 0:8, 0:8, 255:8, 255:8 >> -> Body;
		_ -> Deflated
	end,
	{Deflated1, << 1:1, 0:2 >>, State}.

mask_payload(MaskingKeyBin, Payload) ->
  << MaskingKey:32 >> = MaskingKeyBin,
  mask_payload(MaskingKey, Payload, <<>>).
mask_payload(_, <<>>, Acc) ->
  Acc;
mask_payload(MaskingKey, << D:32, Rest/bits >>, Acc) ->
  T = D bxor MaskingKey,
  mask_payload(MaskingKey, Rest, << Acc/binary, T:32 >>);
mask_payload(MaskingKey, << D:24 >>, Acc) ->
  << MaskingKeyPart:24, _:8 >> = << MaskingKey:32 >>,
  T = D bxor MaskingKeyPart,
  << Acc/binary, T:24 >>;
mask_payload(MaskingKey, << D:16 >>, Acc) ->
  << MaskingKeyPart:16, _:16 >> = << MaskingKey:32 >>,
  T = D bxor MaskingKeyPart,
  << Acc/binary, T:16 >>;
mask_payload(MaskingKey, << D:8 >>, Acc) ->
  << MaskingKeyPart:8, _:24 >> = << MaskingKey:32 >>,
  T = D bxor MaskingKeyPart,
  << Acc/binary, T:8 >>.

-spec payload_length_to_binary(0..16#7fffffffffffffff)
	-> << _:7 >> | << _:23 >> | << _:71 >>.
payload_length_to_binary(N) ->
	case N of
		N when N =< 125 -> << N:7 >>;
		N when N =< 16#ffff -> << 126:7, N:16 >>;
		N when N =< 16#7fffffffffffffff -> << 127:7, N:64 >>
	end.
