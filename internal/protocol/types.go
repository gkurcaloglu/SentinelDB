package protocol

import "fmt"

// MessageType, bir PostgreSQL wire protokolü mesajının etiket baytıdır.
// Aynı bayt değeri yöne (frontend/backend) göre farklı anlamlara gelebilir,
// bu yüzden isimlendirme messageName ile yön bazlı yapılır.
type MessageType byte

// Frontend (client -> server) mesaj tipleri.
const (
	MsgQuery           MessageType = 'Q'
	MsgParse           MessageType = 'P'
	MsgBind            MessageType = 'B'
	MsgExecute         MessageType = 'E'
	MsgDescribe        MessageType = 'D'
	MsgClose           MessageType = 'C'
	MsgSync            MessageType = 'S'
	MsgTerminate       MessageType = 'X'
	MsgPasswordMessage MessageType = 'p'
	MsgFunctionCall    MessageType = 'F'
	MsgCopyData        MessageType = 'd'
	MsgCopyDone        MessageType = 'c'
	MsgCopyFail        MessageType = 'f'
	MsgFlush           MessageType = 'H'
)

// Backend (server -> client) mesaj tipleri.
const (
	MsgAuthentication     MessageType = 'R'
	MsgParameterStatus    MessageType = 'S'
	MsgBackendKeyData     MessageType = 'K'
	MsgReadyForQuery      MessageType = 'Z'
	MsgRowDescription     MessageType = 'T'
	MsgDataRow            MessageType = 'D'
	MsgCommandComplete    MessageType = 'C'
	MsgErrorResponse      MessageType = 'E'
	MsgNoticeResponse     MessageType = 'N'
	MsgEmptyQueryResponse MessageType = 'I'
	MsgParseComplete      MessageType = '1'
	MsgBindComplete       MessageType = '2'
	MsgCloseComplete      MessageType = '3'
	MsgNoData             MessageType = 'n'
	MsgPortalSuspended    MessageType = 's'
	// COPY protokolünü başlatan backend mesajları. SentinelDB V1, COPY
	// protokolünü desteklemez (bkz. internal/masking.Transformer); bu
	// sabitler yalnızca bu mesajları tanıyıp güvenli şekilde
	// reddedebilmek için tanımlanmıştır.
	MsgCopyInResponse   MessageType = 'G'
	MsgCopyOutResponse  MessageType = 'H'
	MsgCopyBothResponse MessageType = 'W'
)

var frontendNames = map[MessageType]string{
	MsgQuery: "Query", MsgParse: "Parse", MsgBind: "Bind", MsgExecute: "Execute",
	MsgDescribe: "Describe", MsgClose: "Close", MsgSync: "Sync", MsgTerminate: "Terminate",
	MsgPasswordMessage: "PasswordMessage", MsgFunctionCall: "FunctionCall",
	MsgCopyData: "CopyData", MsgCopyDone: "CopyDone", MsgCopyFail: "CopyFail", MsgFlush: "Flush",
}

var backendNames = map[MessageType]string{
	MsgAuthentication: "Authentication", MsgParameterStatus: "ParameterStatus",
	MsgBackendKeyData: "BackendKeyData", MsgReadyForQuery: "ReadyForQuery",
	MsgRowDescription: "RowDescription", MsgDataRow: "DataRow",
	MsgCommandComplete: "CommandComplete", MsgErrorResponse: "ErrorResponse",
	MsgNoticeResponse: "NoticeResponse", MsgEmptyQueryResponse: "EmptyQueryResponse",
	MsgParseComplete: "ParseComplete", MsgBindComplete: "BindComplete",
	MsgCloseComplete: "CloseComplete", MsgNoData: "NoData", MsgPortalSuspended: "PortalSuspended",
	MsgCopyData: "CopyData", MsgCopyDone: "CopyDone",
	MsgCopyInResponse: "CopyInResponse", MsgCopyOutResponse: "CopyOutResponse", MsgCopyBothResponse: "CopyBothResponse",
}

func messageName(dir Direction, t MessageType) string {
	names := frontendNames
	if dir == Backend {
		names = backendNames
	}
	if name, ok := names[t]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(%q)", byte(t))
}
