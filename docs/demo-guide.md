# Canlı tur

[Ajan Kalkanı](https://ajan-kalkani.vercel.app) AI ajanının araç çağrılarını, operatörün yazdığı capability sözleşmesine göre yürütmeden önce değerlendirir. Ortam sahte e-posta, dosya, webhook ve takvim araçları kullanır; gerçek dış sisteme yan etki yoktur.

## Karşılaştırma

1. Prompt injection senaryosunu **korumasız** çalıştırın: hassas okuma ve dış gönderim denemesi görünür.
2. Aynı senaryoyu **korumalı** çalıştırın: `file.read` ve `webhook.post` yürütülmeden reddedilir.
3. Karar izinde hangi kuralın devreye girdiğini açın.

İki koşu aynı başlangıç durumu ve aynı çağrı planını kullanır.

## Politika ve denetim

1. **Örnek sözleşmeyi yükle** ile e-posta taslağı sözleşmesini forma alın.
2. Sözleşmeyi değerlendirin; ardından gateway oturumu ile lab çağrılarını yetkilendirin.
3. Denetim listesinden bir kayda tıklayın. Argümanlar redakte tutulur; kayıtlar hash zinciriyle bağlanır.

Ajan Kalkanı prompt injection’ı “çözdüğünü” iddia etmez. Amaç, en az yetki ve varsayılan-ret ile zararlı çağrının etkisini sınırlamaktır.
