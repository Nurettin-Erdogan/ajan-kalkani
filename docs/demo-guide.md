# 3 dakikalık demo

Ajan Kalkanı’nın prompt injection’ı “çözdüğünü” iddia etmeden, zararlı araç çağrısının etkisini çalışma zamanında nasıl kestiğini gösterir.

## Hazırlık

- [Canlı demo](https://ajan-kalkani.vercel.app) veya `python -m ajan_kalkani`.
- Ortam yalnızca sahte e-posta, dosya, webhook ve takvim araçlarını kullanır; gerçek dış sisteme yan etki yoktur.
- Denetim bütünlüğünün başlangıçta temiz olduğunu doğrulayın. Politika laboratuvarında **Örnek sözleşmeyi yükle** hazır kısayoldur.

## 0:00–0:30 — Tehdit

Dolaylı talimat içeren bir e-posta, modele gizli dosyayı okutup dış adrese gönderebilir. Prompt’a “bunu yapma” yazmak araç çağrısını teknik olarak durdurmaz. Kontrol, yürütmeden önce yapılmalıdır.

## 0:30–1:15 — Aynı saldırı, iki sonuç

1. Prompt injection senaryosunu korumasız çalıştırın.
2. Hassas okuma ve dış gönderim girişimini gösterin.
3. Aynı senaryoyu korumalı çalıştırın.
4. `file.read` ve `webhook.post` çağrılarının yürütülmeden reddedildiğini gösterin.

Karşılaştırma deterministiktir: iki mod aynı başlangıç durumu ve aynı çağrı planını kullanır.

## 1:15–2:05 — Açıklanabilir karar

1. İzinli e-posta okuma ve taslak oluşturmayı gösterin.
2. Reddedilen çağrının `deny` veya varsayılan-ret kuralını açın.
3. `approval_required` kararının otomatik izin olmadığını belirtin.
4. Aşırı geniş joker veya kural çakışması uyarısını laboratuvarda gösterin.

Gateway oturumu, aynı lab çağrılarını `authorize` uçuna gönderip kararı yerinde üretir.

## 2:05–2:40 — Denetim izi

1. Redakte koşu listesinden bir kaydı açın.
2. Hassas argümanların saklanmadığını belirtin.
3. SQLite kayıtlarının sıralı hash zinciriyle bağlandığını gösterin.
4. Bütünlük uç noktasının kırık kaydı nasıl işaretlediğini anlatın.

Sınır: diskte tam yetkili bir saldırgana karşı değiştirilemez merkezi log iddiası yoktur.

## 2:40–3:00 — Kapanış

Ajan Kalkanı, model davranışına güvenmek yerine en az yetki, varsayılan-ret ve yürütme öncesi kararı uygulama katmanına koyar. Agent CI, korumalı saldırı başarısı ve yanlış bloğu eşikle karşılaştırır.

## Olası sorular

**Deny ve allow çakışınca neden deny kazanır?**  
Açık yasak, geniş izinden üstündür. Aksi halde bir `*` kuralı sözleşmeyi fiilen kaldırır.

**Sözleşmenin kendisine nasıl güveniyorsunuz?**  
Oturum açılırken sözleşme hash’lenir ve yetkilendirme boyunca değişmez. MVP, `task` metninden semantik yetki çıkarmaz.

**Hash zinciri neyi kanıtlar?**  
Yerel depoda kayıt sırasının bozulup bozulmadığını. Uzaktan bağımsız tanık veya WORM depolama iddiası taşımaz.

**Gerçek araçta onayı nasıl tasarlarsınız?**  
`approval_required` şu an sandbox kararıdır. Üretimde insan onayı, süre ve tekrar-oynatma koruması ayrı bir iş akışı olur.
