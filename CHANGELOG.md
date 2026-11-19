# Değişiklik günlüğü

Önemli değişiklikler bu dosyada sürüm bazında özetlenir. Biçim [Keep a Changelog](https://keepachangelog.com/tr/1.1.0/) yaklaşımını izler.

## [Yayınlanmamış]

### Eklendi

- Canlı demo kontrolü (`scripts/live_smoke.py`, `live-check.yml`): Vercel'deki demo her sabah otomatik doğrulanır. Servisin ayakta olduğu, depodaki sürümü çalıştırdığı (takılı kalmış dağıtım tespiti), dashboard CSP başlığı ve gizli etiketli verinin webhook'a gönderiminin `dataflow.sensitive-to-external` kuralıyla engellendiği kontrol edilir. Yalnızca standart kütüphane kullanır.
- Canlı kontrolün varsayımlarını uygulamanın kendisine karşı doğrulayan 5 test; uygulama değiştiğinde canlı kontrolün sessizce yanlış şeyi doğrulamaya başlaması önlenir.

## [1.1.0] - 2026-11-17

### Eklendi

- Parametreye bağlı, süreli, tek kullanımlık insan onayı: `approval_required` kararı bir onay isteği açar; onay oturuma, çağrının kanonik SHA-256 özetine ve süreye bağlıdır.
- Ajandan ayrı onaylayıcı kimliği (`AJAN_KALKANI_APPROVER_TOKEN`); jeton yoksa onay uçları `503` ile kapalı başarısız olur.
- `GET /api/gateway/approvals`, `GET /api/gateway/approvals/{id}` ve `POST /api/gateway/approvals/{id}/decision` uçları.
- İki yeni saldırı senaryosu: onaylı e-postada alıcı değiştirme ve onaylı ödemenin tekrar oynatılması; deterministik `payment.create` sahte aracı.
- Politika laboratuvarındaki gateway panelinde "ONAY BEKLİYOR" durumu ve onay kimliği.
- `examples/approval_flow.py` uçtan uca onay örneği; onay, eşzamanlılık ve süreçler arası özet testleriyle toplam 89 test.
- Public demoda yazma API’leri için IP başına rate limit.
- Vercel / `AJAN_KALKANI_PUBLIC_DEMO` ortamında Swagger, ReDoc ve OpenAPI keşfinin kapatılması.
- Dashboard hero notu: sentetik sandbox ve demo sınırları.
- Katkı rehberi, issue şablonları ve pull request güvenlik kontrol listesi.
- README üzerinde görünür CodeQL, Python ve test kanıtları.

### Düzeltildi

- `request_hash` artık `data_labels` kümesini sıralayarak hesaplanır. Önceden aynı çağrı farklı Python süreçlerinde farklı özet üretebiliyordu (hash randomization); bu, onayın özete bağlanmasını rastgele bozardı. Birden fazla etiketli eski karar kayıtlarındaki özetler yeni biçimle eşleşmeyebilir.
- Karşılaştırma ekranında iki moddaki bölgeler aynı erişilebilir adı taşıyordu (axe `landmark-unique`); bölge adlarına mod eklendi.

### Değişti

- Redaksiyon kuralları `redaction.py` modülünde toplandı; olay izleri ve onay önizlemeleri aynı kuralları kullanır.

## [1.0.0] - 2026-08-26

### Eklendi

- Capability sözleşmelerine dayalı varsayılan-ret politika motoru.
- Korumasız ve korumalı ajan koşularını karşılaştıran deterministik sandbox.
- Açıklanabilir karar izi, redaksiyon ve SQLite hash zinciri.
- Kalıcı runtime gateway oturumları ve politika laboratuvarı.
- 54 test, Agent CI güvenlik değerlendirmesi, wheel/Docker doğrulaması ve CodeQL.
- FastAPI dashboard ve sentetik verili canlı Vercel demosu.

[Yayınlanmamış]: https://github.com/Nurettin-Erdogan/ajan-kalkani/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/Nurettin-Erdogan/ajan-kalkani/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Nurettin-Erdogan/ajan-kalkani/tree/v1.0.0
