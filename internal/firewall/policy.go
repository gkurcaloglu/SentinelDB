// Package firewall, SentinelDB gateway'i içinden geçen sorguları
// değerlendirip izin verme/engelleme kararı veren politika motorunu
// ve bu kararları uygulayan aktif yönlendiriciyi (Gate) barındırır.
package firewall

import (
	"fmt"

	"github.com/gkurcaloglu/sentineldb/internal/protocol"
	"github.com/gkurcaloglu/sentineldb/internal/sqlmatch"
)

// Verdict, bir Policy'nin tek bir client mesajı hakkındaki kararıdır.
type Verdict int

const (
	Allow Verdict = iota
	Block
)

func (v Verdict) String() string {
	if v == Block {
		return "BLOCK"
	}
	return "ALLOW"
}

// Policy, tek bir client mesajını inceleyip Allow/Block kararı verir.
// Block durumunda dönen reason, istemciye gönderilecek ErrorResponse'un
// mesaj alanı olarak kullanılır.
type Policy interface {
	Evaluate(m protocol.Message) (Verdict, string)
}

// PolicyFunc, sade fonksiyonların Policy arayüzünü karşılamasını sağlar.
type PolicyFunc func(m protocol.Message) (Verdict, string)

// Evaluate, f'yi çağırır.
func (f PolicyFunc) Evaluate(m protocol.Message) (Verdict, string) {
	return f(m)
}

// DenyKeywords, Simple Query (MsgQuery) VE Extended Query Parse (MsgParse)
// metninde (büyük/küçük harf ve boşluk duyarsız) verilen ifadelerden biri
// geçen sorguları engelleyen, tamamen native (Wasm olmayan) bir Policy
// döndürür. Eşleştirme mantığı internal/sqlmatch'te tanımlıdır; firewall
// Wasm eklentisi de (bkz. internal/wasm, plugins/firewall) aynı paketi
// kullanır, böylece iki enforcement yolu birbirinden sapmaz.
//
// Yalnızca MsgQuery/MsgParse denetlenir - SQL şablonunu taşıyan TEK
// frontend mesaj türleri bunlardır (bkz. internal/firewall/extended_frontend.go,
// "Parse-time policy evaluation"): Bind/Describe/Execute/Close/Flush/Sync/
// Terminate hiçbir yeni SQL metni taşımaz, bu yüzden kasıtlı olarak
// denetlenmez (m.Query o mesaj türlerinde zaten boştur).
//
// Bu, gerçek bir SQL ayrıştırıcı değil, saf metin eşleştirmesidir: yorum
// satırları ya da string literalleri içindeki eşleşmeleri de yakalar
// (yanlış pozitif verebilir) ve göreli olarak kolay atlatılabilir (ör.
// "DR/**/OP TABLE", ya da ifadeyi çift tırnaklı bir tanımlayıcı içine
// gizlemek). Üretimde kullanmak için gerçek bir SQL ayrıştırıcıya
// dayanan bir Policy yazılmalı.
func DenyKeywords(phrases ...string) Policy {
	return PolicyFunc(func(m protocol.Message) (Verdict, string) {
		if m.Type != protocol.MsgQuery && m.Type != protocol.MsgParse {
			return Allow, ""
		}
		if matched := sqlmatch.MatchAny(m.Query, phrases); matched != "" {
			return Block, fmt.Sprintf("SentinelDB policy: query engellendi (yasaklı ifade: %q)", matched)
		}
		return Allow, ""
	})
}
