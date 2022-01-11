
//MCTP
ENUM_START(MCTPMessageTypeEnum, uint8_t)
ENUM_VALUE(MCTPMessageTypeEnum, CONTROL,		0x00)
ENUM_VALUE(MCTPMessageTypeEnum, PLDM,			0x01)
ENUM_VALUE(MCTPMessageTypeEnum, SPDM,			0x05)
ENUM_VALUE(MCTPMessageTypeEnum, SECURED,		0x06)
ENUM_END()



ENUM_START(MessageVersionEnum, uint8_t)
ENUM_VALUE(MessageVersionEnum, UNKNOWN,		0)
ENUM_VALUE(MessageVersionEnum, SPDM_1_0,	0x10)
ENUM_VALUE(MessageVersionEnum, SPDM_1_1,	0x11)
ENUM_END()

//WARNING when changing REMEMBER to MODIFY is_request and is_response accordingly!
ENUM_START(RequestResponseEnum, uint8_t)
ENUM_VALUE(RequestResponseEnum, INVALID							,	0)	//TODO actually reserved but kindof useful to abuse?
/// SPDM request code (1.0)
ENUM_VALUE(RequestResponseEnum, REQUEST_GET_DIGESTS				,	0x81)
ENUM_VALUE(RequestResponseEnum, REQUEST_GET_CERTIFICATE			,	0x82)
ENUM_VALUE(RequestResponseEnum, REQUEST_CHALLENGE				,	0x83)
ENUM_VALUE(RequestResponseEnum, REQUEST_GET_VERSION				,	0x84)
ENUM_VALUE(RequestResponseEnum, REQUEST_GET_MEASUREMENTS		,	0xE0)
ENUM_VALUE(RequestResponseEnum, REQUEST_GET_CAPABILITIES		,	0xE1)
ENUM_VALUE(RequestResponseEnum, REQUEST_NEGOTIATE_ALGORITHMS	,	0xE3)
ENUM_VALUE(RequestResponseEnum, REQUEST_VENDOR_DEFINED_REQUEST	,	0xFE)
ENUM_VALUE(RequestResponseEnum, REQUEST_RESPOND_IF_READY		,	0xFF)
/// SPDM request code (1.1)
ENUM_VALUE(RequestResponseEnum, REQUEST_KEY_EXCHANGE			,	0xE4)
ENUM_VALUE(RequestResponseEnum, REQUEST_FINISH					,	0xE5)
ENUM_VALUE(RequestResponseEnum, REQUEST_PSK_EXCHANGE			,	0xE6)
ENUM_VALUE(RequestResponseEnum, REQUEST_PSK_FINISH				,	0xE7)
ENUM_VALUE(RequestResponseEnum, REQUEST_HEARTBEAT				,	0xE8)
ENUM_VALUE(RequestResponseEnum, REQUEST_KEY_UPDATE				,	0xE9)
ENUM_VALUE(RequestResponseEnum, REQUEST_GET_ENCAPSULATED_REQUEST		,	0xEA)
ENUM_VALUE(RequestResponseEnum, REQUEST_DELIVER_ENCAPSULATED_RESPONSE	,	0xEB)
ENUM_VALUE(RequestResponseEnum, REQUEST_END_SESSION				,	0xEC)
/// SPDM response code (1.0)
ENUM_VALUE(RequestResponseEnum, RESPONSE_DIGESTS				,	0x01)
ENUM_VALUE(RequestResponseEnum, RESPONSE_CERTIFICATE			,	0x02)
ENUM_VALUE(RequestResponseEnum, RESPONSE_CHALLENGE_AUTH			,	0x03)
ENUM_VALUE(RequestResponseEnum, RESPONSE_VERSION				,	0x04)
ENUM_VALUE(RequestResponseEnum, RESPONSE_MEASUREMENTS			,	0x60)
ENUM_VALUE(RequestResponseEnum, RESPONSE_CAPABILITIES			,	0x61)
ENUM_VALUE(RequestResponseEnum, RESPONSE_ALGORITHMS				,	0x63)
ENUM_VALUE(RequestResponseEnum, RESPONSE_VENDOR_DEFINED_RESPONSE	,	0x7E)
ENUM_VALUE(RequestResponseEnum, RESPONSE_ERROR					,	0x7F)
/// SPDM response code (1.1)
ENUM_VALUE(RequestResponseEnum, RESPONSE_KEY_EXCHANGE_RSP		,	0x64)
ENUM_VALUE(RequestResponseEnum, RESPONSE_FINISH_RSP				,	0x65)
ENUM_VALUE(RequestResponseEnum, RESPONSE_PSK_EXCHANGE_RSP		,	0x66)
ENUM_VALUE(RequestResponseEnum, RESPONSE_PSK_FINISH_RSP			,	0x67)
ENUM_VALUE(RequestResponseEnum, RESPONSE_HEARTBEAT_ACK			,	0x68)
ENUM_VALUE(RequestResponseEnum, RESPONSE_KEY_UPDATE_ACK			,	0x69)
ENUM_VALUE(RequestResponseEnum, RESPONSE_ENCAPSULATED_REQUEST	,	0x6A)
ENUM_VALUE(RequestResponseEnum, RESPONSE_ENCAPSULATED_RESPONSE_ACK	,	0x6B)
ENUM_VALUE(RequestResponseEnum, RESPONSE_END_SESSION_ACK		,	0x6C)
ENUM_END()
//WARNING when changing REMEMBER to MODIFY is_request and is_response accordingly!



ENUM_START(AlgTypeEnum, uint8_t)
ENUM_VALUE(AlgTypeEnum, UNKNOWN,			0)	//TODO actually reserved but kindof useful to abuse?
ENUM_VALUE(AlgTypeEnum, DHE,				2)
ENUM_VALUE(AlgTypeEnum, AEADCipherSuite,	3)
ENUM_VALUE(AlgTypeEnum, ReqBaseAsymAlg,		4)
ENUM_VALUE(AlgTypeEnum, KeySchedule,		5)
ENUM_END()


//API
ENUM_START(ConnectionInfoEnum, uint8_t)
ENUM_VALUE(ConnectionInfoEnum, SUPPORTED_VERSIONS,					0)
ENUM_VALUE(ConnectionInfoEnum, CHOOSEN_VERSION,						1)
ENUM_VALUE(ConnectionInfoEnum, CAPABILITIES,						2)
ENUM_VALUE(ConnectionInfoEnum, ALGORITHMS,							3)
ENUM_VALUE(ConnectionInfoEnum, DIGESTS,								4)
ENUM_VALUE(ConnectionInfoEnum, CERTIFICATES,						5)
ENUM_VALUE(ConnectionInfoEnum, NUM,									6)
ENUM_END()


