const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const { createClient } = require('@supabase/supabase-js');
const { Resend } = require('resend'); // Nodemailer gitti, Resend geldi!
const nodemailer = require('nodemailer');
const app = express();
const port = 3000;

// ==========================================
// 🔗 SUPABASE VE RESEND BULUT BAĞLANTI AYARLARI
// ==========================================
const SUPABASE_URL = process.env.SUPABASE_URL; 
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// Resend Postacısını Kuruyoruz
const resend = new Resend(process.env.RESEND_API_KEY);

// ==========================================
// 💳 GÜVENLİK VE AYARLAR
// ==========================================
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

app.get('/admin-giris', (req, res) => res.sendFile(path.join(__dirname, 'admin-giris.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));

// ==========================================
// 1. SUNUCU TABANLI DİREKT ADMİN GİRİŞİ (MAİLSİZ)
// ==========================================
app.post('/auth/admin-login', async (req, res) => {
    const { giris_kimlik, sifre } = req.body;
    const temizKimlik = giris_kimlik.toLowerCase().trim();

    const { data: kullanicilar, error } = await supabase
        .from('kullanicilar')
        .select('*')
        .or(`eposta.eq.${temizKimlik},kullanici_adi.eq.${temizKimlik}`);

    if (error || !kullanicilar || kullanicilar.length === 0 || kullanicilar[0].rol !== 'admin') {
        return res.json({ success: false, message: "Kral, yetkin yok veya hesap hatalı!" });
    }

    const kullanici = kullanicilar[0];
    const sifreDogruMu = await bcrypt.compare(sifre, kullanici.sifre);
    
    if (!sifreDogruMu) {
        return res.json({ success: false, message: "Şifre yanlış!" });
    }

    // ŞİFRE DOĞRUYSA DİREKT İÇERİ AL! (Mail yok, kod yok)
    return res.json({ 
        success: true, 
        message: "Giriş başarılı, yönlendiriliyorsunuz...",
        kullanici: {
            ad_soyad: kullanici.ad_soyad,
            kullanici_adi: kullanici.kullanici_adi,
            eposta: kullanici.eposta,
            rol: kullanici.rol
        }
    });
});

// ==========================================
// 2. SUPABASE UYUMLU KAYIT MOTORU
// ==========================================
app.post('/auth/register', async (req, res) => {
  const { ad_soyad, kullanici_adi, eposta, sifre } = req.body;

  if (!sifre || sifre.length < 8 || !/[0-9]/.test(sifre) || !/[a-zA-Z]/.test(sifre)) {
    return res.send("<script>alert('Güvenlik İhlali: Şifre kurallara uymuyor!'); window.location.href='/login';</script>");
  }

  try {
    const kriptoluSifre = await bcrypt.hash(sifre, 10);
    const { error } = await supabase.from('kullanicilar').insert([
      { ad_soyad, kullanici_adi: kullanici_adi.toLowerCase().trim(), eposta: eposta.toLowerCase().trim(), sifre: kriptoluSifre }
    ]);

    if (error) {
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

app.post('/auth/login', async (req, res) => {
  const { giris_kimlik, sifre } = req.body;
  const temizKimlik = giris_kimlik.toLowerCase().trim();
  const hataMesaji = "<script>alert('Hatalı kullanıcı adı, e-posta veya şifre girdiniz!'); window.location.href='/login';</script>";

  const { data: kullanicilar, error } = await supabase
    .from('kullanicilar')
    .select('*')
    .or(`eposta.eq.${temizKimlik},kullanici_adi.eq.${temizKimlik}`);

  if (error || !kullanicilar || kullanicilar.length === 0) return res.send(hataMesaji);

  const kullanici = kullanicilar[0];
  const sifreDogruMu = await bcrypt.compare(sifre, kullanici.sifre);

  if (sifreDogruMu) {
    res.send(`
      <script>
        localStorage.setItem('serhat_optik_kullanici', JSON.stringify({
          ad_soyad: "${kullanici.ad_soyad}",
          kullanici_adi: "${kullanici.kullanici_adi}",
          eposta: "${kullanici.eposta}",
          rol: "${kullanici.rol}" 
        }));
        window.location.href = '/';
      </script>
    `);
  } else {
    res.send(hataMesaji);
  }
});

// ==========================================
// 3. KRİPTOLU OTP KODU ÜRETİP MAİL ATAN MOTOR (Şifremi Unuttum)
// ==========================================
// ==========================================
// 3. KRİPTOLU OTP KODU ÜRETİP MAİL ATAN MOTOR (Şifremi Unuttum)
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
  const besDakikaSonra = new Date(Date.now() + 5 * 60000).toISOString(); 

  try {
    const kriptoluOTP = await bcrypt.hash(onayKodu.toString(), 10);
    const { error: updateError } = await supabase
      .from('kullanicilar')
      .update({ reset_kodu: kriptoluOTP, kod_suresi: besDakikaSonra })
      .eq('eposta', temizEposta);

    if (updateError) return res.json({ success: false, message: "Veri tabanı güncelleme hatası." });

    // YENİLMEZ NODEMAILER ZIRHI (Render'ın Timeout Hatasını Çözen Kısım)
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        host: 'smtp.gmail.com',
        port: 587,
        secure: false,
        requireTLS: true,
        family: 4, // İŞTE BÜYÜ BURADA! Sunucuyu IPv4 kullanmaya zorlar, timeout hatasını yok eder!
        auth: {
            user: process.env.GMAIL_USER,
            pass: process.env.GMAIL_PASS
        },
        tls: {
            rejectUnauthorized: false
        }
    });

    const mailOptions = {
        from: '"Serhat Optik" <' + process.env.GMAIL_USER + '>',
        to: temizEposta, // Artık herkese gidecek!
        subject: 'Şifre Sıfırlama Doğrulama Kodu',
        html: `<h2>Serhat Optik</h2><p>Doğrulama kodunuz: <b style="font-size:24px;">${onayKodu}</b></p><p>Süre: 5 Dakika</p>`
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log("🚨 GMAIL GÖNDERME HATASI:", error);
            return res.json({ success: false, message: "Mail fırlatılamadı." });
        }
        console.log("✅ Şifre Sıfırlama Maili Herkese Gitti:", info.response);
        res.json({ success: true });
    });

  } catch {
    res.json({ success: false, message: "Kripto hatası." });
  }
});

app.post('/auth/kod-ile-sifre-guncelle', async (req, res) => {
  const { eposta, onay_kodu, yeni_sifre } = req.body;
  const temizEposta = eposta.toLowerCase().trim();

  if (!yeni_sifre || yeni_sifre.length < 8) {
    return res.send("<script>alert('Yeni şifre en az 8 karakter olmalıdır!'); window.location.href='/login';</script>");
  }

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
// PROFİL, SEPET VE SİPARİŞ API'LERİ
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

app.get('/api/urunler', async (req, res) => {
  const { data, error } = await supabase.from('urunler').select('*');
  if (error) return res.status(500).json({ error: "Veri çekme hatası." });
  res.json(data);
});

app.get('/api/sepet/:eposta', async (req, res) => {
  const { data, error } = await supabase
    .from('sepetler')
    .select('id, adet, urun_id, urunler(urun_adi,kategori, fiyat, resim_url)')
    .eq('kullanici_eposta', req.params.eposta);

  if (error || !data) return res.json([]);
  
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
    const { eposta, adres } = req.body; 

    try {
        const { data: sepetVerisi, error: sepetHata } = await supabase
            .from('sepetler')
            .select('urun_id, adet, urunler(urun_adi, fiyat, stok)')
            .eq('kullanici_eposta', eposta);

        if (sepetHata) throw sepetHata;
        if (!sepetVerisi || sepetVerisi.length === 0) return res.json({ success: false, message: "Sepetiniz boş!" });

        for (let item of sepetVerisi) {
            if (item.urunler.stok < item.adet) {
                return res.json({ success: false, message: `Stok yetersiz! ${item.urunler.urun_adi} ürününden sadece ${item.urunler.stok} adet kaldı.` });
            }
        }

        const siparisListesi = sepetVerisi.map(item => ({
            siparis_no: 'ORD-' + Date.now(),
            kullanici_eposta: eposta,
            urun_adi: item.urunler.urun_adi,
            fiyat: item.urunler.fiyat,
            adet: item.adet,
            durum: 'Hazırlanıyor',
            adres: adres 
        }));

        await supabase.from('siparisler').insert(siparisListesi);

        for (let item of sepetVerisi) {
            const yeniStok = item.urunler.stok - item.adet;
            await supabase.from('urunler').update({ stok: yeniStok }).eq('id', item.urun_id);
        }

        await supabase.from('sepetler').delete().eq('kullanici_eposta', eposta);
        res.json({ success: true, message: "Siparişin alındı!" });
    } catch (e) {
        console.error("Hata Detayı:", e);
        res.json({ success: false, message: "Sipariş işlenirken bir hata oluştu." });
    }
});

app.get('/api/siparislerim/:eposta', async (req, res) => {
    try {
        const { eposta } = req.params;
        const { data, error } = await supabase
            .from('siparisler')
            .select('*')
            .eq('kullanici_eposta', eposta)
            .order('siparis_tarihi', { ascending: false });

        if (error) return res.status(500).json({ error: error.message });
        res.json(data);
    } catch (err) {
        res.status(500).json({ error: "Sunucu hatası oluştu." });
    }
});

// ==========================================
// ADMIN PANELİ - CRUD İŞLEMLERİ
// ==========================================
app.post('/api/admin/urunler', async (req, res) => {
    try {
        const { error } = await supabase.from('urunler').insert([req.body]);
        if (error) throw error;
        res.json({ success: true, message: "Ürün başarıyla eklendi." });
    } catch (e) {
        res.json({ success: false, message: e.message });
    }
});

app.put('/api/admin/urunler/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { error } = await supabase.from('urunler').update(req.body).eq('id', id);
        if (error) throw error;
        res.json({ success: true, message: "Ürün başarıyla güncellendi." });
    } catch (e) {
        res.json({ success: false, message: e.message });
    }
});

app.delete('/api/admin/urunler/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { error } = await supabase.from('urunler').delete().eq('id', id);
        if (error) throw error;
        res.json({ success: true, message: "Ürün başarıyla silindi." });
    } catch (e) {
        res.json({ success: false, message: e.message });
    }
});

app.get('/api/admin/siparisler', async (req, res) => {
    try {
        const { data, error } = await supabase.from('siparisler').select('*').order('siparis_tarihi', { ascending: false });
        if (error) throw error;
        res.json({ success: true, siparisler: data });
    } catch (e) {
        res.json({ success: false, message: "Siparişler getirilemedi." });
    }
});

app.put('/api/admin/siparisler/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { durum } = req.body;
        const { error } = await supabase.from('siparisler').update({ durum }).eq('id', id);
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
        const { error } = await supabase.from('siparisler').update({ durum }).eq('siparis_no', siparis_no);
        if (error) throw error;
        return res.json({ success: true });
    } catch (e) {
        return res.json({ success: false, message: "Sipariş grubu güncellenemedi." });
    }
});

app.listen(port, () => console.log(`🚀 Sunucu Bulut Veri Tabanına Bağlandı: http://localhost:${port}`));