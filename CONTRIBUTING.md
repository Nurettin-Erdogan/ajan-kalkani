# Katkı rehberi

Ajan Kalkanı'na yapılacak yeni saldırı senaryoları, politika testleri, güvenlik düzeltmeleri ve dokümantasyon katkıları memnuniyetle karşılanır. Büyük özellikler için uygulamaya başlamadan önce bir issue açarak güvenlik varsayımını ve kapsamı netleştirin.

## Geliştirme ortamı

Python 3.11 veya üzeri gerekir.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
pytest
python -m ajan_kalkani --evaluate --report evaluation-report.json
```

Paket ve konteyner değişikliklerinde ayrıca şu kontrolleri çalıştırın:

```powershell
python -m build
docker build --tag ajan-kalkani-local .
```

## Değişiklik ilkeleri

1. Yeni politika davranışını en az bir olumlu ve bir olumsuz testle kanıtlayın.
2. Saldırı senaryolarını deterministik ve gerçek sistemlere yan etkisiz tutun.
3. Olay izlerine gizli değer, araç argümanı veya kişisel veri eklemeyin.
4. Mimari ya da tehdit varsayımı değişiyorsa `docs/ARCHITECTURE.md` ve `docs/THREAT_MODEL.md` belgelerini güncelleyin.
5. Pull request açıklamasında tehdit, alınan karar ve doğrulama sonucunu yazın.

## Güvenlik bildirimleri

Güvenlik açıklarını herkese açık issue olarak paylaşmayın. Bildirim yolu için [SECURITY.md](SECURITY.md) dosyasını kullanın.

