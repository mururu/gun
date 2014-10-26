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

-record(ws_state, {
	owner :: pid(),
	socket :: inet:socket() | ssl:sslsocket(),
	transport :: module(),
	buffer = <<>> :: binary(),
  ws_key :: binary(),
  in_state = connecting :: connecting | open
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
          ct:pal("~p~n", [E]),
          error(fail_validate)
      end
	end;
%% handle WebSocket
handle(#ws_state{in_state = open}, Data) ->
  ct:pal("connected!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!~n").

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
      ct:pal("~p~n", [E]),
      error(fail_status)
  end.
