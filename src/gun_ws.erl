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
	deflate_state :: undefined | port(),
  frag_state = undefined,
	utf8_state = <<>> :: binary(),
  payload_state :: undefined | tuple()
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
handle(Data, State=#ws_state{in_state=open, payload_state=undefined, buffer=Buffer}) ->
  websocket_data(State#ws_state{buffer = <<>>}, <<Buffer/bits, Data/bits>>);
handle(Data, State=#ws_state{in_state=open, payload_state={Opcode, Len, Unmasked, Rsv}, buffer=Buffer}) ->
  websocket_payload(State#ws_state{payload_state=undefined}, Opcode, Len, Unmasked, Data, Rsv).

%% All frames passing through this function are considered valid,
%% with the only exception of text and close frames with a payload
%% which may still contain errors.
%% -spec websocket_data(#state{}, Req, any(), binary())
%% 	-> {ok, Req, cowboy_middleware:env()}
%% 	| {suspend, module(), atom(), [any()]}
%% 	when Req::cowboy_req:req().
%% RSV bits MUST be 0 unless an extension is negotiated
%% that defines meanings for non-zero values.
websocket_data(State, << _:1, Rsv:3, _/bits >>)
		when Rsv =/= 0, State#ws_state.deflate_frame =:= false ->
	websocket_close(State, {error, badframe});
%% Invalid opcode. Note that these opcodes may be used by extensions.
websocket_data(State, << _:4, Opcode:4, _/bits >>)
		when Opcode > 2, Opcode =/= 8, Opcode =/= 9, Opcode =/= 10 ->
	websocket_close(State, {error, badframe});
%% Control frames MUST NOT be fragmented.
websocket_data(State, << 0:1, _:3, Opcode:4, _/bits >>)
		when Opcode >= 8 ->
	websocket_close(State, {error, badframe});
%% A frame MUST NOT use the zero opcode unless fragmentation was initiated.
websocket_data(State=#ws_state{frag_state=undefined}, << _:4, 0:4, _/bits >>) ->
	websocket_close(State, {error, badframe});
%% Non-control opcode when expecting control message or next fragment.
websocket_data(State=#ws_state{frag_state={nofin, _, _}}, << _:4, Opcode:4, _/bits >>)
		when Opcode =/= 0, Opcode < 8 ->
	websocket_close(State, {error, badframe});
%% Close control frame length MUST be 0 or >= 2.
websocket_data(State, << _:4, 8:4, _:1, 1:7, _/bits >>) ->
	websocket_close(State, {error, badframe});
%% Close control frame with incomplete close code. Need more data.
websocket_data(State, Data = << _:4, 8:4, 0:1, Len:7, _/bits >>)
		when Len > 1, byte_size(Data) < 8 ->
	State#ws_state{buffer=Data};
%% 7 bits payload length.
websocket_data(State, << Fin:1, Rsv:3/bits, Opcode:4, 0:1, Len:7, Rest/bits >>)
		when Len < 126 ->
	websocket_data(State, Opcode, Len, Rest, Rsv, Fin);
%% 16 bits payload length.
websocket_data(State, << Fin:1, Rsv:3/bits, Opcode:4, 0:1, 126:7, Len:16, Rest/bits >>)
		when Len > 125, Opcode < 8 ->
	websocket_data(State, Opcode, Len, Rest, Rsv, Fin);
%% 63 bits payload length.
websocket_data(State, << Fin:1, Rsv:3/bits, Opcode:4, 0:1, 127:7, 0:1, Len:63, Rest/bits >>)
		when Len > 16#ffff, Opcode < 8 ->
	websocket_data(State, Opcode, Len, Rest, Rsv, Fin);
%% When payload length is over 63 bits, the most significant bit MUST be 0.
websocket_data(State, << _:8, 0:1, 127:7, 1:1, _:7, _/bits >>) ->
	websocket_close(State, {error, badframe});
%% All frames sent from the client to the server are masked.
websocket_data(State, << _:8, 1:1, _/bits >>) ->
	websocket_close(State, {error, badframe});
%% For the next two clauses, it can be one of the following:
%%
%%  *  The minimal number of bytes MUST be used to encode the length
%%  *  All control frames MUST have a payload length of 125 bytes or less
websocket_data(State, << _:9, 126:7, _:16, _/bits >>) ->
	websocket_close(State, {error, badframe});
websocket_data(State, << _:9, 127:7, _:64, _/bits >>) ->
	websocket_close(State, {error, badframe});
%% Need more data.
websocket_data(State, Data) ->
  State#ws_state{buffer=Data}.

%% Initialize or update fragmentation state.
%% -spec websocket_data(#state{}, Req, any(),
%% 	opcode(), non_neg_integer(), mask_key(), binary(), rsv(), 0 | 1)
%% 	-> {ok, Req, cowboy_middleware:env()}
%% 	| {suspend, module(), atom(), [any()]}
%% 	when Req::cowboy_req:req().
%% The opcode is only included in the first frame fragment.
websocket_data(State=#ws_state{frag_state=undefined}, Opcode, Len, Data, Rsv, 0) ->
	websocket_payload(State#ws_state{frag_state={nofin, Opcode, <<>>}}, 0, Len, <<>>, Data, Rsv);
%% Subsequent frame fragments.
websocket_data(State=#ws_state{frag_state={nofin, _, _}}, 0, Len, Data, Rsv, 0) ->
	websocket_payload(State, 0, Len, <<>>, Data, Rsv);
%% Final frame fragment.
websocket_data(State=#ws_state{frag_state={nofin, Opcode, SoFar}}, 0, Len, Data, Rsv, 1) ->
	websocket_payload(State#ws_state{frag_state={fin, Opcode, SoFar}}, 0, Len, <<>>, Data, Rsv);
%% Unfragmented frame.
websocket_data(State, Opcode, Len, Data, Rsv, 1) ->
	websocket_payload(State, Opcode, Len, <<>>, Data, Rsv).

%% -spec websocket_payload(#state{}, Req, any(),
%% 	opcode(), non_neg_integer(), mask_key(), binary(), non_neg_integer(),
%% 	binary(), rsv())
%% 	-> {ok, Req, cowboy_middleware:env()}
%% 	| {suspend, module(), atom(), [any()]}
%% 	when Req::cowboy_req:req().
%% Close control frames with a payload MUST contain a valid close code.
websocket_payload(State,
		Opcode=8, Len,  <<>>,
		<< BinCode:2/binary, Rest/bits >>, Rsv) ->
	<< Code:16 >> = BinCode,
	if	Code < 1000; Code =:= 1004; Code =:= 1005; Code =:= 1006;
				(Code > 1011) and (Code < 3000); Code > 4999 ->
			websocket_close(State, {error, badframe});
		true ->
			websocket_payload(State,
				Opcode, Len - 2, BinCode, Rest, Rsv)
	end;
%% Text frames and close control frames MUST have a payload that is valid UTF-8.
websocket_payload(State=#ws_state{utf8_state=Incomplete},
		Opcode, Len, Unmasked, Data, Rsv)
		when (byte_size(Data) < Len) andalso ((Opcode =:= 1) orelse
			((Opcode =:= 8) andalso (Unmasked =/= <<>>))) ->
	{Unmasked2, State2} = websocket_inflate_frame(Data, Rsv, false, State),
	case is_utf8(<< Incomplete/binary, Unmasked2/binary >>) of
		false ->
			websocket_close(State2, {error, badencoding});
		Utf8State ->
			State2#ws_state{utf8_state=Utf8State, payload_state={Opcode, Len - byte_size(Data),
            << Unmasked/binary, Unmasked2/binary >>, Rsv}}
	end;
websocket_payload(State=#ws_state{utf8_state=Incomplete},
		Opcode, Len, Unmasked,
		Data, Rsv)
		when Opcode =:= 1; (Opcode =:= 8) and (Unmasked =/= <<>>) ->
	<< End:Len/binary, Rest/bits >> = Data,
	{Unmasked2, State2} = websocket_inflate_frame(End, Rsv, true, State),
	case is_utf8(<< Incomplete/binary, Unmasked2/binary >>) of
		<<>> ->
			websocket_dispatch(State2#ws_state{utf8_state= <<>>},
				Rest, Opcode,
				<< Unmasked/binary, Unmasked2/binary >>);
		_ ->
			websocket_close(State2, {error, badencoding})
	end;
%% Fragmented text frames may cut payload in the middle of UTF-8 codepoints.
websocket_payload(State=#ws_state{frag_state={_, 1, _}, utf8_state=Incomplete},
		Opcode=0, Len, Unmasked,
		Data, Rsv)
		when byte_size(Data) < Len ->
	{Unmasked2, State2} = websocket_inflate_frame(Data, Rsv, false, State),
	case is_utf8(<< Incomplete/binary, Unmasked2/binary >>) of
		false ->
			websocket_close(State2, {error, badencoding});
		Utf8State ->
			State2#ws_state{utf8_state=Utf8State, payload_state={
				Opcode, Len - byte_size(Data),
        << Unmasked/binary, Unmasked2/binary >>, Rsv}}
	end;
websocket_payload(State=#ws_state{frag_state={Fin, 1, _}, utf8_state=Incomplete},
		Opcode=0, Len, Unmasked,
		Data, Rsv) ->
	<< End:Len/binary, Rest/bits >> = Data,
	{Unmasked2, State2} = websocket_inflate_frame(End, Rsv, Fin =:= fin, State),
	case is_utf8(<< Incomplete/binary, Unmasked2/binary >>) of
		<<>> ->
			websocket_dispatch(State2#ws_state{utf8_state= <<>>},
				Rest, Opcode,
				<< Unmasked/binary, Unmasked2/binary >>);
		Utf8State when is_binary(Utf8State), Fin =:= nofin ->
			websocket_dispatch(State2#ws_state{utf8_state=Utf8State},
				Rest, Opcode,
				<< Unmasked/binary, Unmasked2/binary >>);
		_ ->
			websocket_close(State, {error, badencoding})
	end;
%% Other frames have a binary payload.
websocket_payload(State,
		Opcode, Len, Unmasked, Data, Rsv)
		when byte_size(Data) < Len ->
	{Unmasked2, State2} = websocket_inflate_frame(Data, Rsv, false, State),
	State2#ws_state{payload_state={
		Opcode, Len - byte_size(Data),
    << Unmasked/binary, Unmasked2/binary >>, Rsv}};
websocket_payload(State,
		Opcode, Len, Unmasked, Data, Rsv) ->
	<< End:Len/binary, Rest/bits >> = Data,
	{Unmasked2, State2} = websocket_inflate_frame(End, Rsv, true, State),
	websocket_dispatch(State2, Rest, Opcode,
		<< Unmasked/binary, Unmasked2/binary >>).

%% -spec websocket_inflate_frame(binary(), rsv(), boolean(), #state{}) ->
%% 		{binary(), #state{}}.
websocket_inflate_frame(Data, << Rsv1:1, _:2 >>, _,
		#ws_state{deflate_frame = DeflateFrame} = State)
		when DeflateFrame =:= false orelse Rsv1 =:= 0 ->
	{Data, State};
websocket_inflate_frame(Data, << 1:1, _:2 >>, false, State) ->
	Result = zlib:inflate(State#ws_state.inflate_state, Data),
	{iolist_to_binary(Result), State};
websocket_inflate_frame(Data, << 1:1, _:2 >>, true, State) ->
	Result = zlib:inflate(State#ws_state.inflate_state,
		<< Data/binary, 0:8, 0:8, 255:8, 255:8 >>),
	{iolist_to_binary(Result), State}.

%% -spec websocket_dispatch(#state{}, Req, any(), binary(), opcode(), binary())
%% 	-> {ok, Req, cowboy_middleware:env()}
%% 	| {suspend, module(), atom(), [any()]}
%% 	when Req::cowboy_req:req().
%% Continuation frame.
websocket_dispatch(State=#ws_state{frag_state={nofin, Opcode, SoFar}},
		RemainingData, 0, Payload) ->
	websocket_data(State#ws_state{frag_state={nofin, Opcode,
		<< SoFar/binary, Payload/binary >>}}, RemainingData);
%% Last continuation frame.
websocket_dispatch(State=#ws_state{frag_state={fin, Opcode, SoFar}},
		RemainingData, 0, Payload) ->
	websocket_dispatch(State#ws_state{frag_state=undefined},
		RemainingData, Opcode, << SoFar/binary, Payload/binary >>);
%% Text frame.
websocket_dispatch(State, RemainingData, 1, Payload) ->
  received(State, {text, Payload}, RemainingData);
%% Binary frame.
websocket_dispatch(State, RemainingData, 2, Payload) ->
  received(State, {binary, Payload}, RemainingData);
%% Close control frame.
websocket_dispatch(State, _RemainingData, 8, <<>>) ->
	websocket_close(State, remote);
websocket_dispatch(State, _RemainingData, 8,
		<< Code:16, Payload/bits >>) ->
	websocket_close(State, {remote, Code, Payload});
%% Ping control frame. Send a pong back and forward the ping to the handler.
websocket_dispatch(State=#ws_state{socket=_Socket, transport=_Transport},
		RemainingData, 9, Payload) ->
  %% TODO: reply Pong automatically
	%%Len = payload_length_to_binary(byte_size(Payload)),
	%% Transport:send(Socket, << 1:1, 0:3, 10:4, 0:1, Len/bits, Payload/binary >>),
  received(State, {ping, Payload}, RemainingData);
%% Pong control frame.
websocket_dispatch(State, RemainingData, 10, Payload) ->
  received(State, {pong, Payload}, RemainingData).

%% TODO: 名前
received(State=#ws_state{owner=Owner}, Frame, RemainingData) ->
  Owner ! {gun_ws, self(), Frame},
  websocket_data(State#ws_state{}, RemainingData).

websocket_close(_, _) ->
  ct:pal(close).

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

%% Returns <<>> if the argument is valid UTF-8, false if not,
%% or the incomplete part of the argument if we need more data.
-spec is_utf8(binary()) -> false | binary().
is_utf8(Valid = <<>>) ->
	Valid;
is_utf8(<< _/utf8, Rest/bits >>) ->
	is_utf8(Rest);
%% 2 bytes. Codepages C0 and C1 are invalid; fail early.
is_utf8(<< 2#1100000:7, _/bits >>) ->
	false;
is_utf8(Incomplete = << 2#110:3, _:5 >>) ->
	Incomplete;
%% 3 bytes.
is_utf8(Incomplete = << 2#1110:4, _:4 >>) ->
	Incomplete;
is_utf8(Incomplete = << 2#1110:4, _:4, 2#10:2, _:6 >>) ->
	Incomplete;
%% 4 bytes. Codepage F4 may have invalid values greater than 0x10FFFF.
is_utf8(<< 2#11110100:8, 2#10:2, High:6, _/bits >>) when High >= 2#10000 ->
	false;
is_utf8(Incomplete = << 2#11110:5, _:3 >>) ->
	Incomplete;
is_utf8(Incomplete = << 2#11110:5, _:3, 2#10:2, _:6 >>) ->
	Incomplete;
is_utf8(Incomplete = << 2#11110:5, _:3, 2#10:2, _:6, 2#10:2, _:6 >>) ->
	Incomplete;
%% Invalid.
is_utf8(_) ->
	false.
