# DEEPIFYS / VELORAIFY — Cloudflare sürümü

Bu sürüm Netlify Blobs/Functions kullanmaz. Cloudflare Pages Functions + D1 + R2 kullanır.

## Cloudflare kurulumu

1. Pages projesini Git üzerinden bağla. Pages Functions içeren projeler dashboard Direct Upload ile deploy edilemez.
2. Cloudflare D1'de bir veritabanı oluştur.
3. `schema.sql` dosyasını D1'e uygula.
4. Pages projesi > Settings > Functions > Bindings bölümünden D1 binding ekle:
   - Variable name: `DB`
   - Database: oluşturduğun D1
5. R2'de bir bucket oluştur.
6. Aynı Bindings bölümünden R2 binding ekle:
   - Variable name: `MEDIA`
   - Bucket: oluşturduğun R2
7. Environment Variables/Secrets bölümünde `ADMIN_KEY` oluştur.
8. Yeniden deploy et.

## API

- `/api/social-auth`
- `/api/social-profile`
- `/api/social-posts`
- `/api/admin`
- `/api/presence`
- `/api/reviews`
- `/media/...`

## Özellikler

Kayıt/giriş, profil, profil fotoğrafı, takip, görselli gönderi, beğeni, yorum, arama, keşfet, popüler, admin ve aktif kullanıcı sayacı Cloudflare altyapısına taşındı.

### Önemli veri notu

Eski Netlify Blobs verileri otomatik olarak D1/R2'ye taşınmaz. Eski kullanıcıların ve gönderilerin korunması isteniyorsa ayrıca bir migration yapılmalıdır.
