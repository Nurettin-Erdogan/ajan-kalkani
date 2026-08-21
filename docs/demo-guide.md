# 3 Dakikalık Demo Akışı

Bu senaryo Ajan Kalkanı'nın prompt injection'ı “çözdüğünü” iddia etmeden, zararlı araç çağrılarının etkisini çalışma zamanında nasıl sınırladığını gösterir.

## Hazırlık

- `start-ajan-kalkani.cmd` veya `python -m ajan_kalkani` ile dashboard'u aç.
- Demo yalnızca sahte e-posta, dosya, webhook ve takvim araçlarını kullanır; gerçek dış sistemlere yan etki oluşturmaz.
- Başlangıçta audit integrity sonucunun temiz olduğunu doğrula.

## 0:00–0:30 — Tehdit

“Bir e-postanın içindeki dolaylı talimat, modele gizli dosyayı okuyup webhook'a göndertebilir. Prompt seviyesinde ‘bunu yapma’ demek araç çağrısını teknik olarak durdurmaz.”

## 0:30–1:15 — Aynı saldırı, iki sonuç

1. Prompt injection senaryosunu `unprotected` modda çalıştır.
2. Hassas dosya okuma ve dış hedefe gönderme girişimini göster.
3. Aynı senaryoyu `guarded` modda çalıştır.
4. `file.read` ve `webhook.post` çağrılarının yürütülmeden engellendiğini göster.

Vurgu: karşılaştırma deterministiktir; iki mod aynı başlangıç durumu ve aynı çağrı planını kullanır.

## 1:15–2:05 — Açıklanabilir politika kararı

1. İzin verilen normal e-posta okuma ve taslak oluşturma çağrılarını göster.
2. Reddedilen çağrının hangi `deny` veya varsayılan-ret kuralına çarptığını aç.
3. `approval_required` kararının otomatik izin olmadığını belirt.
4. Politika laboratuvarında aşırı geniş joker veya kural çakışması uyarısını göster.

## 2:05–2:40 — Denetim izi

1. Redakte edilmiş karar geçmişini aç.
2. Hassas argümanların saklanmadığını belirt.
3. SQLite kayıtlarının sıralı hash zinciriyle birbirine bağlandığını göster.
4. Integrity endpoint'inin silme/değiştirme izini nasıl bulduğunu anlat.

Sınır: disk üzerinde tam yetkili saldırgana karşı merkezi, değiştirilemez log sistemi olduğu iddia edilmez.

## 2:40–3:00 — Kapanış

“Bu projede AI güvenliğini yalnızca model davranışına bırakmadım; en az yetki, varsayılan-ret, yürütme öncesi karar ve denetlenebilirlik ilkelerini uygulama katmanına taşıdım.”

## Görüşmede gelebilecek sorular

- Deny ve allow çakıştığında neden deny kazanıyor?
- Capability sözleşmesinin kendisine nasıl güveniyorsun?
- Hash zinciri neyi kanıtlar, neyi kanıtlamaz?
- Gerçek araç entegrasyonunda onay akışını nasıl tasarlardın?
