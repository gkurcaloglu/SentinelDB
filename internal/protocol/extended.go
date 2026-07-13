package protocol

import (
	"encoding/binary"
	"fmt"
	"unicode/utf8"
)

// TargetType, Describe ve Close mesajlarındaki hedef seçici baytıdır:
// 'S' (statement, hazırlanmış deyim) ya da 'P' (portal).
type TargetType byte

const (
	TargetStatement TargetType = 'S'
	TargetPortal    TargetType = 'P'
)

// ParseMessage, ayrıştırılmış bir Parse ('P') frontend mesajının gövdesidir.
// SQL metni yalnızca burada taşınır - Bind ve Execute'ta SQL metni yoktur.
type ParseMessage struct {
	StatementName string
	Query         string
	ParamOIDs     []uint32
}

// BindParam, Bind mesajındaki tek bir parametre değeridir. Null true ise
// Value geçersizdir/boştur; bu, PostgreSQL'in NULL (-1 uzunluk) ile boş
// string ("", 0 uzunluk) arasındaki ayrımını korur (bkz. DataCell ile aynı
// desen, internal/protocol/datarow.go).
type BindParam struct {
	Null  bool
	Value []byte
}

// BindMessage, ayrıştırılmış bir Bind ('B') frontend mesajının gövdesidir.
// ParamFormats/ResultFormats her biri 0 (metin) ya da 1 (ikili) olan format
// kodlarıdır.
type BindMessage struct {
	PortalName    string
	StatementName string
	ParamFormats  []int16
	Params        []BindParam
	ResultFormats []int16
}

// DescribeMessage, ayrıştırılmış bir Describe ('D') frontend mesajının
// gövdesidir.
type DescribeMessage struct {
	Target TargetType
	Name   string
}

// ExecuteMessage, ayrıştırılmış bir Execute ('E') frontend mesajının
// gövdesidir. MaxRows, protokolde belgelenen normal değer olarak 0 ise
// "sınır yok" anlamına gelir; PostgreSQL'in kendi backend uygulaması
// (bkz. backend/tcop/pquery.c, PortalRun: `count <= 0` ise `FETCH_ALL`)
// negatif değerleri de aynı şekilde "sınır yok" olarak yorumlar. Bu
// ayrıştırıcı, gerçek sunucuyla aynı davranışı yansıtabilmek için ham
// işaretli Int32 değerini olduğu gibi korur; hiçbir aralık daraltması
// yapmaz.
type ExecuteMessage struct {
	PortalName string
	MaxRows    int32
}

// CloseMessage, ayrıştırılmış bir Close ('C') frontend mesajının gövdesidir.
type CloseMessage struct {
	Target TargetType
	Name   string
}

// ExtendedParseErrorCategory, bir Extended Query frontend mesajının gövde
// doğrulamasının hangi kategoride başarısız olduğunu tanımlar. Sabit,
// sonlu bir küme olduğundan çağıranlar (ör. testler) hatayı string
// karşılaştırması yapmadan kategoriye göre ayırt edebilir.
type ExtendedParseErrorCategory string

const (
	CategoryTruncated            ExtendedParseErrorCategory = "truncated_payload"
	CategoryMissingTerminator    ExtendedParseErrorCategory = "missing_nul_terminator"
	CategoryInvalidLength        ExtendedParseErrorCategory = "invalid_length"
	CategoryLengthExceedsPayload ExtendedParseErrorCategory = "length_exceeds_payload"
	CategoryInvalidFormatCode    ExtendedParseErrorCategory = "invalid_format_code"
	CategoryInvalidFormatCount   ExtendedParseErrorCategory = "invalid_format_count"
	CategoryInvalidSelector      ExtendedParseErrorCategory = "invalid_selector"
	CategoryTrailingBytes        ExtendedParseErrorCategory = "trailing_bytes"
	CategoryInvalidUTF8          ExtendedParseErrorCategory = "invalid_utf8"
	CategoryNonEmptyPayload      ExtendedParseErrorCategory = "non_empty_payload"
)

// ExtendedParseError, bir Extended Query frontend mesajının gövdesi
// ayrıştırılırken oluşan bir doğrulama hatasıdır. Fail-closed işlenmeye
// uygun olacak şekilde YALNIZCA mesaj tipini ve doğrulama kategorisini
// taşır - ham payload baytlarını, parametre değerlerini ya da SQL metnini
// ASLA içermez (bkz. Decoder.fail, firewall.Gate.handleDecodeError - bu
// hatalar loglanabilir/istemciye yansıtılabilir).
type ExtendedParseError struct {
	MessageName string
	Category    ExtendedParseErrorCategory
}

func (e *ExtendedParseError) Error() string {
	return fmt.Sprintf("protocol: %s mesaji ayristirilamadi: kategori=%s", e.MessageName, e.Category)
}

func newExtendedParseError(msgName string, category ExtendedParseErrorCategory) *ExtendedParseError {
	return &ExtendedParseError{MessageName: msgName, Category: category}
}

// readExtendedCString, payload[offset:] içinden null sonlandırmalı bir
// string okur ve stringi ile null baytından sonraki offset'i döndürür.
// Sınır dışı offset ya da eksik null sonlandırıcı durumunda kategorize
// edilmiş bir *ExtendedParseError döner; hiçbir zaman panic etmez.
func readExtendedCString(msgName string, payload []byte, offset int) (string, int, error) {
	if offset < 0 || offset > len(payload) {
		return "", 0, newExtendedParseError(msgName, CategoryTruncated)
	}
	idx := -1
	for i := offset; i < len(payload); i++ {
		if payload[i] == 0 {
			idx = i
			break
		}
	}
	if idx == -1 {
		return "", 0, newExtendedParseError(msgName, CategoryMissingTerminator)
	}
	return string(payload[offset:idx]), idx + 1, nil
}

// ParseFrontendParse, bir Parse ('P') mesajının gövdesini (tag ve length
// alanları hariç) ayrıştırır. Güvenilmeyen "wire" verisi üzerinde çalışır:
// her adımda tampon sınırlarını doğrular, hiçbir girişte panic etmez.
//
// Wire format: String(statement adı) + String(sorgu metni) +
// Int16(parametre OID sayisi N) + N x Int32(parametre OID).
func ParseFrontendParse(payload []byte) (*ParseMessage, error) {
	const msgName = "Parse"

	stmt, offset, err := readExtendedCString(msgName, payload, 0)
	if err != nil {
		return nil, err
	}
	query, offset, err := readExtendedCString(msgName, payload, offset)
	if err != nil {
		return nil, err
	}

	if offset+2 > len(payload) {
		return nil, newExtendedParseError(msgName, CategoryTruncated)
	}
	count := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2

	if offset+count*4 > len(payload) {
		return nil, newExtendedParseError(msgName, CategoryTruncated)
	}
	oids := make([]uint32, 0, count)
	for i := 0; i < count; i++ {
		oids = append(oids, binary.BigEndian.Uint32(payload[offset:offset+4]))
		offset += 4
	}

	if offset != len(payload) {
		return nil, newExtendedParseError(msgName, CategoryTrailingBytes)
	}
	if !utf8.ValidString(stmt) || !utf8.ValidString(query) {
		return nil, newExtendedParseError(msgName, CategoryInvalidUTF8)
	}

	return &ParseMessage{StatementName: stmt, Query: query, ParamOIDs: oids}, nil
}

// readExtendedFormatCodes, count adet Int16 format kodu okur; her kodun
// 0 (metin) ya da 1 (ikili) olduğunu doğrular.
func readExtendedFormatCodes(msgName string, payload []byte, offset, count int) ([]int16, int, error) {
	codes := make([]int16, 0, count)
	for i := 0; i < count; i++ {
		if offset+2 > len(payload) {
			return nil, 0, newExtendedParseError(msgName, CategoryTruncated)
		}
		code := int16(binary.BigEndian.Uint16(payload[offset : offset+2]))
		if code != 0 && code != 1 {
			return nil, 0, newExtendedParseError(msgName, CategoryInvalidFormatCode)
		}
		codes = append(codes, code)
		offset += 2
	}
	return codes, offset, nil
}

// ParseFrontendBind, bir Bind ('B') mesajının gövdesini ayrıştırır.
//
// Wire format: String(portal adi) + String(statement adi) +
// Int16(format kodu sayisi C) + C x Int16(format kodu) +
// Int16(parametre sayisi M) + M x [Int32(uzunluk, -1=NULL) + uzunluk bayti] +
// Int16(sonuc format kodu sayisi R) + R x Int16(format kodu).
//
// Her parametre uzunluğu, ayırmadan (make) önce kalan payload'a sığdığı
// doğrulanır - bozuk/kötü niyetli bir uzunluk alanı kontrolsüz bellek
// ayırmaya yol açamaz.
func ParseFrontendBind(payload []byte) (*BindMessage, error) {
	const msgName = "Bind"

	portal, offset, err := readExtendedCString(msgName, payload, 0)
	if err != nil {
		return nil, err
	}
	stmt, offset, err := readExtendedCString(msgName, payload, offset)
	if err != nil {
		return nil, err
	}

	if offset+2 > len(payload) {
		return nil, newExtendedParseError(msgName, CategoryTruncated)
	}
	paramFormatCount := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2
	paramFormats, offset, err := readExtendedFormatCodes(msgName, payload, offset, paramFormatCount)
	if err != nil {
		return nil, err
	}

	if offset+2 > len(payload) {
		return nil, newExtendedParseError(msgName, CategoryTruncated)
	}
	paramCount := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2

	// PostgreSQL'in gerçek sunucu tarafı kuralı (bkz. backend/tcop/pquery.c,
	// exec_bind_message): paramFormatCount 0 ya da 1 her zaman geçerlidir
	// (0 = tüm parametreler varsayılan metin formatında, 1 = tek kod tüm
	// parametrelere uygulanır - paramCount sıfır olsa bile). 1'den büyük bir
	// sayı yalnızca paramCount'a tam olarak eşitse geçerlidir (parametre
	// basina bir format kodu).
	if paramFormatCount > 1 && paramFormatCount != paramCount {
		return nil, newExtendedParseError(msgName, CategoryInvalidFormatCount)
	}

	params := make([]BindParam, 0, paramCount)
	for i := 0; i < paramCount; i++ {
		if offset+4 > len(payload) {
			return nil, newExtendedParseError(msgName, CategoryTruncated)
		}
		length := int32(binary.BigEndian.Uint32(payload[offset : offset+4]))
		offset += 4

		if length == -1 {
			params = append(params, BindParam{Null: true})
			continue
		}
		if length < -1 {
			return nil, newExtendedParseError(msgName, CategoryInvalidLength)
		}
		// Toplama yerine cikarma kullanilir: length (kotu niyetli bir
		// gonderici tarafindan int32'nin ust siniri kadar buyuk olabilir)
		// offset'e eklenirse dar (32-bit) Go mimarilerinde int tasmasina yol
		// acabilir. remaining her zaman gecerli, negatif olmayan bir
		// degerdir (offset <= len(payload) yukarida zaten saglanmistir).
		remaining := len(payload) - offset
		if int(length) > remaining {
			return nil, newExtendedParseError(msgName, CategoryLengthExceedsPayload)
		}
		value := make([]byte, length)
		copy(value, payload[offset:offset+int(length)])
		params = append(params, BindParam{Value: value})
		offset += int(length)
	}

	if offset+2 > len(payload) {
		return nil, newExtendedParseError(msgName, CategoryTruncated)
	}
	resultFormatCount := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2
	resultFormats, offset, err := readExtendedFormatCodes(msgName, payload, offset, resultFormatCount)
	if err != nil {
		return nil, err
	}

	if offset != len(payload) {
		return nil, newExtendedParseError(msgName, CategoryTrailingBytes)
	}
	if !utf8.ValidString(portal) || !utf8.ValidString(stmt) {
		return nil, newExtendedParseError(msgName, CategoryInvalidUTF8)
	}

	return &BindMessage{
		PortalName:    portal,
		StatementName: stmt,
		ParamFormats:  paramFormats,
		Params:        params,
		ResultFormats: resultFormats,
	}, nil
}

// ParseFrontendDescribe, bir Describe ('D') mesajının gövdesini ayrıştırır.
//
// Wire format: Byte1(seçici, 'S' ya da 'P') + String(ad).
func ParseFrontendDescribe(payload []byte) (*DescribeMessage, error) {
	const msgName = "Describe"

	if len(payload) < 1 {
		return nil, newExtendedParseError(msgName, CategoryTruncated)
	}
	selector := TargetType(payload[0])
	if selector != TargetStatement && selector != TargetPortal {
		return nil, newExtendedParseError(msgName, CategoryInvalidSelector)
	}

	name, offset, err := readExtendedCString(msgName, payload, 1)
	if err != nil {
		return nil, err
	}
	if offset != len(payload) {
		return nil, newExtendedParseError(msgName, CategoryTrailingBytes)
	}
	if !utf8.ValidString(name) {
		return nil, newExtendedParseError(msgName, CategoryInvalidUTF8)
	}

	return &DescribeMessage{Target: selector, Name: name}, nil
}

// ParseFrontendExecute, bir Execute ('E') mesajının gövdesini ayrıştırır.
//
// Wire format: String(portal adi) + Int32(maksimum satir sayisi).
//
// maxRows, tam işaretli Int32 aralığıyla kabul edilir ve olduğu gibi
// korunur - PostgreSQL'in kendisi de negatif değerleri reddetmez, 0'la
// aynı şekilde "sınır yok" (FETCH_ALL) olarak işler (bkz. ExecuteMessage
// dokümantasyonu). Bu ayrıştırıcı, gerçek sunucunun kabul ettiği hiçbir
// değeri reddetmeyerek uyumluluğu korur.
func ParseFrontendExecute(payload []byte) (*ExecuteMessage, error) {
	const msgName = "Execute"

	portal, offset, err := readExtendedCString(msgName, payload, 0)
	if err != nil {
		return nil, err
	}

	if offset+4 > len(payload) {
		return nil, newExtendedParseError(msgName, CategoryTruncated)
	}
	maxRows := int32(binary.BigEndian.Uint32(payload[offset : offset+4]))
	offset += 4

	if offset != len(payload) {
		return nil, newExtendedParseError(msgName, CategoryTrailingBytes)
	}
	if !utf8.ValidString(portal) {
		return nil, newExtendedParseError(msgName, CategoryInvalidUTF8)
	}

	return &ExecuteMessage{PortalName: portal, MaxRows: maxRows}, nil
}

// ParseFrontendClose, bir Close ('C') mesajının gövdesini ayrıştırır.
//
// Wire format: Byte1(seçici, 'S' ya da 'P') + String(ad).
func ParseFrontendClose(payload []byte) (*CloseMessage, error) {
	const msgName = "Close"

	if len(payload) < 1 {
		return nil, newExtendedParseError(msgName, CategoryTruncated)
	}
	selector := TargetType(payload[0])
	if selector != TargetStatement && selector != TargetPortal {
		return nil, newExtendedParseError(msgName, CategoryInvalidSelector)
	}

	name, offset, err := readExtendedCString(msgName, payload, 1)
	if err != nil {
		return nil, err
	}
	if offset != len(payload) {
		return nil, newExtendedParseError(msgName, CategoryTrailingBytes)
	}
	if !utf8.ValidString(name) {
		return nil, newExtendedParseError(msgName, CategoryInvalidUTF8)
	}

	return &CloseMessage{Target: selector, Name: name}, nil
}

// ParseFrontendFlush, bir Flush ('H') mesajının gövdesini doğrular. Flush'ın
// hiçbir alanı yoktur; gövde boş olmalıdır.
func ParseFrontendFlush(payload []byte) error {
	if len(payload) != 0 {
		return newExtendedParseError("Flush", CategoryNonEmptyPayload)
	}
	return nil
}

// ParseFrontendSync, bir Sync ('S') mesajının gövdesini doğrular. Sync'in
// hiçbir alanı yoktur; gövde boş olmalıdır.
func ParseFrontendSync(payload []byte) error {
	if len(payload) != 0 {
		return newExtendedParseError("Sync", CategoryNonEmptyPayload)
	}
	return nil
}

// ParseFrontendTerminate, bir Terminate ('X') mesajının gövdesini doğrular.
// Terminate'in hiçbir alanı yoktur; gövde boş olmalıdır (bkz.
// ParseFrontendFlush/ParseFrontendSync ile aynı desen). Decoder.consumeNormal
// bu doğrulamayı BUGÜN otomatik olarak çağırmaz (Terminate akış-sonlandırma
// semantiği taşır, steady-state Extended Query mesajları arasında olağan bir
// "onaylanacak" işlem değildir) - bu fonksiyon, internal/firewall'daki opt-in
// frontend köprüsünün (bkz. Gate.RunExtended) kendi savunma amaçlı çerçeve
// doğrulaması için sağlanır.
func ParseFrontendTerminate(payload []byte) error {
	if len(payload) != 0 {
		return newExtendedParseError("Terminate", CategoryNonEmptyPayload)
	}
	return nil
}
