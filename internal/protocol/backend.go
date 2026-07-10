package protocol

import "encoding/binary"

// BuildErrorResponse, bir backend ErrorResponse ('E') mesajını ham
// baytlar olarak inşa eder. Bu, gateway'in bir isteği gerçek sunucuya hiç
// göndermeden, sanki sunucudan geliyormuş gibi bir hata döndürmesini sağlar
// (ör. politika tarafından engellenen sorgular için).
func BuildErrorResponse(severity, sqlState, message string) []byte {
	var body []byte
	addField := func(fieldType byte, value string) {
		body = append(body, fieldType)
		body = append(body, []byte(value)...)
		body = append(body, 0)
	}
	addField('S', severity) // önem derecesi (yerelleştirilmemiş, eski istemciler için)
	addField('V', severity) // önem derecesi (yerelleştirilmemiş, PG 9.6+)
	addField('C', sqlState)
	addField('M', message)
	body = append(body, 0) // alan listesi sonlandırıcı

	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(body)+4))

	out := make([]byte, 0, 1+len(length)+len(body))
	out = append(out, 'E')
	out = append(out, length...)
	out = append(out, body...)
	return out
}

// BuildReadyForQuery, bir backend ReadyForQuery ('Z') mesajını inşa eder.
// status 'I' (idle), 'T' (işlem içinde) ya da 'E' (başarısız işlem)
// olabilir. Bir ErrorResponse'un ardından gönderilmesi, istemcinin
// (libpq) senkron protokol durumunu kaybetmeden bir sonraki komutu
// gönderebilmesi için gereklidir.
func BuildReadyForQuery(status byte) []byte {
	return []byte{'Z', 0, 0, 0, 5, status}
}
