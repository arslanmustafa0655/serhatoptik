


const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const { createClient } = require('@supabase/supabase-js'); // Supabase dahil edildi

const app = express();
const port = 3000;




// ==========================================
// 🔗 SUPABASE BULUT BAĞLANTI AYARLARI
// ==========================================
const SUPABASE_URL = 'https://ldhnqfosvhbntocoloyg.supabase.co'; // KENDİ SUPABASE URL'İNİ YAZ KRAL
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImxkaG5xZm9zdmhibnRvY29sb3lnIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODE3MDQ5ODQsImV4cCI6MjA5NzI4MDk4NH0.Hd1Vb6qeSK7nD4_iFHY11FH47e9jN1rbPAzc4RhjB9M'; // KENDİ ANON KEY'İNİ YAZ KRAL

const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
// ... diğer require'lar (bcrypt, supabase, vs.) ...

// Postacıyı global olarak tanımlıyoruz
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'arslanmustafa0655@gmail.com',
        pass: 'adum qntz fksj dqpe'
    }
});


// ==========================================
// 💳 IYZICO TEST (SANDBOX) AYARLARI
// ==========================================

// Chrome CSP hatasını engelleyen güvenlik vizesi
app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:; connect-src * 'unsafe-inline' ws://localhost:* http://localhost:*; img-src * data: blob:;"
  );
  next();
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(__dirname));

// SAYFA YÖNLENDİRMELERİ
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/sepet', (req, res) => res.sendFile(path.join(__dirname, 'sepet.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/profil', (req, res) => res.sendFile(path.join(__dirname, 'profil.html')));
app.get('/siparislerim', (req, res) => res.sendFile(path.join(__dirname, 'siparislerim.html')));



// ==========================================
// SUNUCU TABANLI ADMİN GÜVENLİK KALKANI
// ==========================================
// ==========================================
// SUNUCU TABANLI + VERİTABANI BAĞLANTILI ADMİN KALKANI
// ==========================================
// 1. ADIM: E-posta/Kullanıcı Adı ve Şifre Kontrolü -> Kayıtlı Maile Kod Gönder
app.post('/auth/admin-login', async (req, res) => {
    const { giris_kimlik, sifre } = req.body;
    const temizKimlik = giris_kimlik.toLowerCase().trim();

    // 1. Admini bul
    const { data: kullanicilar, error } = await supabase
        .from('kullanicilar')
        .select('*')
        .or(`eposta.eq.${temizKimlik},kullanici_adi.eq.${temizKimlik}`);

    if (error || !kullanicilar || kullanicilar.length === 0 || kullanicilar[0].rol !== 'admin') {
        return res.json({ success: false, message: "Kral, yetkin yok veya hesap hatalı!" });
    }

    const kullanici = kullanicilar[0];
    const sifreDogruMu = await bcrypt.compare(sifre, kullanici.sifre);
    if (!sifreDogruMu) return res.json({ success: false, message: "Şifre yanlış!" });

    // 2. Kodu üret (100000 - 999999 arası)
    const kod = Math.floor(100000 + Math.random() * 900000);
    const kriptoluKod = await bcrypt.hash(kod.toString(), 10);

    // 3. DB'ye yaz (kendi çalışan mantığınla aynı)
    await supabase.from('kullanicilar')
        .update({ reset_kodu: kriptoluKod }) // Mevcut sütunu kullandık
        .eq('id', kullanici.id);

    // 4. Mail at
    const mailOptions = {
        from: 'arslanmustafa0655@gmail.com',
        to: kullanici.eposta,
        subject: 'Admin Giriş Doğrulama',
        text: `Admin panel giriş doğrulama kodu: ${kod}`
    };

    transporter.sendMail(mailOptions, (error) => {
        if (error) return res.json({ success: false, message: "Mail gitmedi." });
        res.json({ success: true, gercekEposta: kullanici.eposta });
    });
});
// 2. ADIM: E-posta Doğrulama Kodunu Kontrol Et ve İçeri Al



// 1. SAYFA YÖNLENDİRMELERİ (Kalkansız, direkt dosyayı veriyoruz)
app.get('/admin-giris', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin-giris.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

app.post('/auth/admin-verify', async (req, res) => {
    try {
        const { eposta, kod } = req.body;
        
        // 1. Veriler eksikse anında şutla
        if (!eposta || !kod) {
            return res.json({ success: false, message: "Bağlantı koptu, e-posta veya kod eksik!" });
        }

        // 2. Veritabanından şifrelenmiş kodu çek
        const { data: k, error } = await supabase
            .from('kullanicilar')
            .select('reset_kodu')
            .eq('eposta', eposta.toLowerCase().trim())
            .single();

        // 3. Hesap yoksa veya hata varsa şutla
        if (error || !k) {
            return res.json({ success: false, message: "Kullanıcı bulunamadı veya veritabanı hatası!" });
        }

        // 4. Veritabanında kod yoksa (süresi dolmuşsa vs.) şutla
        if (!k.reset_kodu) {
            return res.json({ success: false, message: "Doğrulama kodu geçersiz veya süresi dolmuş!" });
        }

        // 5. Kodları karşılaştır
        const kodDogruMu = await bcrypt.compare(kod.toString(), k.reset_kodu);

        if (!kodDogruMu) {
            return res.json({ success: false, message: "Hatalı kod girdiniz!" });
        }

        // 6. Başarılı! DB'den kodu sil ve KESİN CEVAP dön
        await supabase.from('kullanicilar').update({ reset_kodu: null }).eq('eposta', eposta.toLowerCase().trim());
        
        return res.json({ success: true });

    } catch (e) {
        // 7. Kod çökse bile havada kalmasın, catch'e düşüp KESİN CEVAP dönsün
        return res.json({ success: false, message: "Sunucu hatası: İşlem tamamlanamadı." });
    }
});
// Ürün Listeleme API (Supabase Versiyonu)
app.get('/api/urunler', async (req, res) => {
  const { data, error } = await supabase.from('urunler').select('*');
  if (error) return res.status(500).json({ error: "Veri çekme hatası." });
  res.json(data);
});

// ==========================================
// 1. SUPABASE UYUMLU KAYIT MOTORU
// ==========================================
app.post('/auth/register', async (req, res) => {
  const { ad_soyad, kullanici_adi, eposta, sifre } = req.body;

  if (!sifre || sifre.length < 8 || !/[0-9]/.test(sifre) || !/[a-zA-Z]/.test(sifre)) {
    return res.send("<script>alert('Güvenlik İhlali: Şifre kurallara uymuyor!'); window.location.href='/login';</script>");
  }

  try {
    const kriptoluSifre = await bcrypt.hash(sifre, 10);
    
    // Supabase Insert Mantığı
    const { error } = await supabase.from('kullanicilar').insert([
      { 
        ad_soyad, 
        kullanici_adi: kullanici_adi.toLowerCase().trim(), 
        eposta: eposta.toLowerCase().trim(), 
        sifre: kriptoluSifre 
      }
    ]);

    // ==========================================
    // 🚨 AJAN BURADA: GERÇEK HATAYI TERMİNALE YAZDIRACAK
    console.log("SUPABASE KAYIT HATASI DETAYI:", error); 
    // ==========================================

    if (error) {
      // PostgreSQL benzersizlik hatası kodu 23505'tir
      if (error.code === '23505') {
        return res.send("<script>alert('Kullanıcı Adı veya E-posta zaten alınmış!'); window.location.href='/login';</script>");
      }
      return res.status(500).send("Kayıt esnasında bir hata oluştu.");
    }

    res.send("<script>alert('Hesap başarıyla bulutta oluşturuldu! Giriş yapabilirsiniz.'); window.location.href='/login';</script>");
  } catch {
    res.status(500).send("Sistemsel hata.");
  }
});

// ==========================================
// 2. SUPABASE UYUMLU ÇİFT YÖNLÜ GİRİŞ MOTORU
// ==========================================
app.post('/auth/login', async (req, res) => {
  const { giris_kimlik, sifre } = req.body;
  const temizKimlik = giris_kimlik.toLowerCase().trim();
  const hataMesaji = "<script>alert('Hatalı kullanıcı adı, e-posta veya şifre girdiniz!'); window.location.href='/login';</script>";

  // Supabase OR sorgusu: E-posta VEYA kullanıcı adı eşleşen satırı getir
  const { data: kullanicilar, error } = await supabase
    .from('kullanicilar')
    .select('*')
    .or(`eposta.eq.${temizKimlik},kullanici_adi.eq.${temizKimlik}`);

  if (error || !kullanicilar || kullanicilar.length === 0) {
    return res.send(hataMesaji);
  }

  const kullanici = kullanicilar[0];
  const sifreDogruMu = await bcrypt.compare(sifre, kullanici.sifre);

  if (sifreDogruMu) {
    res.send(`
      <script>
        localStorage.setItem('serhat_optik_kullanici', JSON.stringify({
          ad_soyad: "${kullanici.ad_soyad}",
          kullanici_adi: "${kullanici.kullanici_adi}",
          eposta: "${kullanici.eposta}",
          rol: "${kullanici.rol}" // İŞTE KRALIN YETKİ BELGESİ BURADA!
        }));
        window.location.href = '/';
      </script>
    `);
  } else {
    res.send(hataMesaji);
  }
});

// ==========================================
// 3. KRİPTOLU OTP KODU ÜRETİP MAİL ATAN MOTOR
// ==========================================
app.post('/auth/sifre-unuttum-kod-gonder', async (req, res) => {
  const { eposta } = req.body;
  const temizEposta = eposta.toLowerCase().trim();

  const { data: kullanicilar, error: searchError } = await supabase
    .from('kullanicilar')
    .select('*')
    .eq('eposta', temizEposta);

  if (searchError || !kullanicilar || kullanicilar.length === 0) {
    return res.json({ success: false, message: "Kullanıcı bulunamadı!" });
  }

  const onayKodu = Math.floor(100000 + Math.random() * 900000);
  const besDakikaSonra = new Date(Date.now() + 5 * 60000).toISOString(); // Postgres ISO formatı sever

  try {
    const kriptoluOTP = await bcrypt.hash(onayKodu.toString(), 10);

    // Supabase Güncelleme (Update) Mantığı
    const { error: updateError } = await supabase
      .from('kullanicilar')
      .update({ reset_kodu: kriptoluOTP, kod_suresi: besDakikaSonra })
      .eq('eposta', temizEposta);

    if (updateError) return res.json({ success: false, message: "Veri tabanı güncelleme hatası." });

    // NODEMAILER GMAIL SERVİSİ
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: 'arslanmustafa0655@gmail.com', // Kendi Gmail adresini yaz kral
        pass: 'adum qntz fksj dqpe'     // Google Uygulama Şifren
      }
    });

    const mailOptions = {
      from: '"Serhat Optik" <senin_epostan@gmail.com>',
      to: temizEposta,
      subject: 'Şifre Sıfırlama Doğrulama Kodu',
      html: `<h2>Serhat Optik</h2><p>Doğrulama kodunuz: <b style="font-size:24px;">${onayKodu}</b></p><p>Süre: 5 Dakika</p>`
    };

    transporter.sendMail(mailOptions, (error) => {
      if (error) return res.json({ success: false, message: "Mail fırlatılamadı." });
      res.json({ success: true });
    });

  } catch {
    res.json({ success: false, message: "Kripto hatası." });
  }
});

// ==========================================
// 4. KODU DOĞRULAYIP ŞİFREYİ SIFIRLAMA MOTORU
// ==========================================
app.post('/auth/kod-ile-sifre-guncelle', async (req, res) => {
  const { eposta, onay_kodu, yeni_sifre } = req.body;
  const temizEposta = eposta.toLowerCase().trim();

  if (!yeni_sifre || yeni_sifre.length < 8) {
    return res.send("<script>alert('Yeni şifre en az 8 karakter olmalıdır!'); window.location.href='/login';</script>");
  }

  // Süresi geçmemiş (kod_suresi > şu anki zaman) olan satırı çekiyoruz
  const { data: kullanicilar, error } = await supabase
    .from('kullanicilar')
    .select('*')
    .eq('eposta', temizEposta)
    .gt('kod_suresi', new Date().toISOString());

  if (error || !kullanicilar || kullanicilar.length === 0 || !kullanicilar[0].reset_kodu) {
    return res.send("<script>alert('Doğrulama kodunun süresi dolmuş veya hatalı istek!'); window.location.href='/login';</script>");
  }

  const kodDogruMu = await bcrypt.compare(onay_kodu.toString(), kullanicilar[0].reset_kodu);

  if (!kodDogruMu) {
    return res.send("<script>alert('Girdiğiniz 6 haneli kod hatalı!'); window.location.href='/login';</script>");
  }

  try {
    const yeniKriptoluSifre = await bcrypt.hash(yeni_sifre, 10);

    // Yeni şifreyi yaz ve kod alanlarını sıfırla (NULL yap)
    const { error: finalError } = await supabase
      .from('kullanicilar')
      .update({ sifre: yeniKriptoluSifre, reset_kodu: null, kod_suresi: null })
      .eq('id', kullanicilar[0].id);

    if (finalError) return res.status(500).send("Güncellenemedi.");
    res.send("<script>alert('Şifreniz bulutta başarıyla güncellendi! Giriş yapabilirsiniz.'); window.location.href='/login';</script>");
  } catch {
    res.status(500).send("Sistemsel hata.");
  }
});

// ==========================================
// PROFİL VE SEPET API'LERİ
// ==========================================
app.post('/auth/profil-guncelle', async (req, res) => {
  const { eski_eposta, yeni_ad_soyad, yeni_sifre } = req.body;
  
  if (yeni_sifre && yeni_sifre.trim().length > 0) {
    if (yeni_sifre.length < 8) return res.send("<script>alert('Şifre en az 8 karakter olmalı!'); window.location.href='/profil';</script>");
    const kriptoluSifre = await bcrypt.hash(yeni_sifre, 10);
    
    await supabase.from('kullanicilar').update({ ad_soyad: yeni_ad_soyad, sifre: kriptoluSifre }).eq('eposta', eski_eposta);
  } else {
    await supabase.from('kullanicilar').update({ ad_soyad: yeni_ad_soyad }).eq('eposta', eski_eposta);
  }
  res.send("<script>alert('Profil güncellendi. Yeniden giriş yapın.'); window.location.href='/login';</script>");
});

app.get('/api/sepet/:eposta', async (req, res) => {
  // İlişkili tablodan (urunler) veri çekme (INNER JOIN muadili)
  const { data, error } = await supabase
    .from('sepetler')
    .select('id, adet, urun_id, urunler(urun_adi,kategori, fiyat, resim_url)')
    .eq('kullanici_eposta', req.params.eposta);

  if (error || !data) return res.json([]);
  
  // Ön yüzün eski koda uyumlu çalışması için veriyi düzeltip gönderiyoruz
  const temizSepet = data.map(item => ({
    id: item.urun_id,
    adet: item.adet,
    urun_adi: item.urunler.urun_adi,
    kategori:item.urunler.kategori,
    fiyat: item.urunler.fiyat,
    resim_url: item.urunler.resim_url
  }));
  res.json(temizSepet);
});

app.post('/api/sepet/ekle', async (req, res) => {
  const { eposta, urun_id, adet } = req.body;

  const { data: mevcut } = await supabase.from('sepetler').select('*').eq('kullanici_eposta', eposta).eq('urun_id', urun_id);

  if (mevcut && mevcut.length > 0) {
    const yeniAdet = adet === 1 ? mevcut[0].adet + 1 : adet;
    await supabase.from('sepetler').update({ adet: yeniAdet }).eq('id', mevcut[0].id);
  } else {
    await supabase.from('sepetler').insert([{ kullanici_eposta: eposta, urun_id, adet }]);
  }
  res.json({ success: true });
});

app.post('/api/sepet/sil', async (req, res) => {
  await supabase.from('sepetler').delete().eq('kullanici_eposta', req.body.eposta).eq('urun_id', req.body.urun_id);
  res.json({ success: true });
});

app.post('/api/siparis-ver', async (req, res) => {
    // 1. FRONTEND'DEN GELEN ADRESİ BURADA YAKALIYORUZ
    const { eposta, adres } = req.body; 

    try {
        const { data: sepetVerisi, error: sepetHata } = await supabase
            .from('sepetler')
            .select('urun_id, adet, urunler(urun_adi, fiyat, stok)')
            .eq('kullanici_eposta', eposta);

        if (sepetHata) throw sepetHata;
        
        if (!sepetVerisi || sepetVerisi.length === 0) {
            return res.json({ success: false, message: "Sepetiniz boş!" });
        }

        // Stok Kontrolü
        for (let item of sepetVerisi) {
            if (item.urunler.stok < item.adet) {
                return res.json({ 
                    success: false, 
                    message: `Stok yetersiz! ${item.urunler.urun_adi} ürününden sadece ${item.urunler.stok} adet kaldı.` 
                });
            }
        }

        // 2. SİPARİŞ LİSTESİNE ADRESİ EKLİYORUZ (Veritabanına gidecek olan kısım)
        const siparisListesi = sepetVerisi.map(item => ({
            siparis_no: 'ORD-' + Date.now(),
            kullanici_eposta: eposta,
            urun_adi: item.urunler.urun_adi,
            fiyat: item.urunler.fiyat,
            adet: item.adet,
            durum: 'Hazırlanıyor',
            adres: adres  // İŞTE BURASI!
        }));

        // Siparişleri Kaydet
        await supabase.from('siparisler').insert(siparisListesi);

        // Stokları Düş
        for (let item of sepetVerisi) {
            const yeniStok = item.urunler.stok - item.adet;
            await supabase
                .from('urunler')
                .update({ stok: yeniStok })
                .eq('id', item.urun_id);
        }

        // Sepeti Boşalt
        await supabase.from('sepetler').delete().eq('kullanici_eposta', eposta);

        res.json({ success: true, message: "Siparişin alındı!" });
    } catch (e) {
        console.error("Hata Detayı:", e);
        res.json({ success: false, message: "Sipariş işlenirken bir hata oluştu." });
    }
});
async function siparisleriGetir() {
    const k = JSON.parse(localStorage.getItem('serhat_optik_kullanici'));
    const res = await fetch(`/api/siparislerim/${k.eposta}`);
    const siparisler = await res.json();

    const tbody = document.getElementById('siparisListesi');
    
    tbody.innerHTML = siparisler.map(s => {
        // Duruma göre renk seçimi
        let badgeClass = 'bg-warning'; // Hazırlanıyor
        if (s.durum === 'Kargolandı') badgeClass = 'bg-primary';
        if (s.durum === 'Teslim Edildi') badgeClass = 'bg-success';

        return `
            <tr>
                <td><small class="text-muted">${s.siparis_no}</small></td>
                <td>${s.urun_adi}</td>
                <td>${s.adet}</td>
                <td><strong>${s.fiyat} TL</strong></td>
                <td><span class="badge ${badgeClass}">${s.durum}</span></td>
            </tr>
        `;
    }).join('');
}
    // Siparişleri çeken API rotası
app.get('/api/siparislerim/:eposta', async (req, res) => {
    try {
        const { eposta } = req.params;
        const { data, error } = await supabase
            .from('siparisler')
            .select('*')
            .eq('kullanici_eposta', eposta)
            .order('siparis_tarihi', { ascending: false });

        if (error) {
            console.error("Supabase Hatası:", error);
            return res.status(500).json({ error: error.message });
        }
        
        res.json(data);
    } catch (err) {
        console.error("Sunucu Hatası:", err);
        res.status(500).json({ error: "Sunucu hatası oluştu." });
    }
});


// ==========================================
// ADMIN PANELİ - CRUD İŞLEMLERİ
// ==========================================

// 1. Yeni Ürün Ekleme (POST)
app.post('/api/admin/urunler', async (req, res) => {
    try {
        const { error } = await supabase.from('urunler').insert([req.body]);
        if (error) throw error;
        res.json({ success: true, message: "Ürün başarıyla eklendi." });
    } catch (e) {
        console.error(e);
        res.json({ success: false, message: e.message });
    }
});

// 2. Mevcut Ürünü Güncelleme (PUT)
app.put('/api/admin/urunler/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { error } = await supabase.from('urunler').update(req.body).eq('id', id);
        if (error) throw error;
        res.json({ success: true, message: "Ürün başarıyla güncellendi." });
    } catch (e) {
        console.error(e);
        res.json({ success: false, message: e.message });
    }
});

// 3. Ürün Silme (DELETE)
app.delete('/api/admin/urunler/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { error } = await supabase.from('urunler').delete().eq('id', id);
        if (error) throw error;
        res.json({ success: true, message: "Ürün başarıyla silindi." });
    } catch (e) {
        console.error(e);
        res.json({ success: false, message: e.message });
    }
});

// ==========================================
// ADMIN - TÜM SİPARİŞLERİ YÖNETME
// ==========================================

// 1. Tüm Müşteri Siparişlerini Getir
app.get('/api/admin/siparisler', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('siparisler')
            .select('*')
            .order('siparis_tarihi', { ascending: false }); // En yeni sipariş en üstte

        if (error) throw error;
        res.json({ success: true, siparisler: data });
    } catch (e) {
        console.error("Sipariş çekme hatası:", e);
        res.json({ success: false, message: "Siparişler getirilemedi." });
    }
});

// 2. Sipariş Durumunu Güncelle (Hazırlanıyor -> Kargolandı)
app.put('/api/admin/siparisler/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { durum } = req.body;
        
        const { error } = await supabase
            .from('siparisler')
            .update({ durum })
            .eq('id', id);
            
        if (error) throw error;
        res.json({ success: true });
    } catch (e) {
        res.json({ success: false, message: "Durum güncellenemedi." });
    }
});


app.put('/api/admin/siparisler/grup/:siparis_no', async (req, res) => {
    try {
        const { siparis_no } = req.params;
        const { durum } = req.body;
        console.log(`[TOPLU GÜNCELLEME] Sipariş No: ${siparis_no} için yeni durum: ${durum}`);
        const { error } = await supabase
            .from('siparisler')
            .update({ durum })
            .eq('siparis_no', siparis_no);
        if (error) throw error;
        return res.json({ success: true });
    } catch (e) {
        console.error("Toplu durum güncelleme hatası:", e);
        return res.json({ success: false, message: "Sipariş grubu güncellenemedi." });
    }
});
// Admin Paneline Yönlendirme (Sayfa Yönlendirmeleri arasına ekle)
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));


app.listen(port, () => console.log(`🚀 Sunucu Frankfurt Bulut Veri Tabanına Bağlandı: http://localhost:{port}`));