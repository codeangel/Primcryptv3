import hashlib
import random
from collections import OrderedDict

# --- Temel Bileşenler ve Veri Yapıları ---

# Türkçe alfabe (desteklenen karakter kümesi)
turkce_alfabe = ['a', 'b', 'c', 'ç', 'd', 'e', 'f', 'g', 'ğ', 'h',
                  'ı', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'ö', 'p',
                  'r', 's', 'ş', 't', 'u', 'ü', 'v', 'y', 'z']

# Her bir alfabe karakterine karşılık gelen asal sayılar
# Bu sayılar, alfabetik sıraya göre atanmıştır ve benzersizdir.
asal_sayilar = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
                  31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
                  73, 79, 83, 89, 97, 101, 103, 107, 109]

# Harften asal sayıya kolay dönüşüm için sözlük
harf_asal_esleme = dict(zip(turkce_alfabe, asal_sayilar))

# Asal sayıdan harfe kolay dönüşüm için ters sözlük (çözümlemede kullanılır)
asal_esleme_harf = dict(zip(asal_sayilar, turkce_alfabe))

# --- Kişiye Özel Permütasyon Tablosu (P-Kutu) Oluşturma ---
# Bu fonksiyon, verilen anahtardan deterministik olarak bir P-Kutu oluşturur.
# P-Kutu, 0-65535 arasındaki tüm 16-bit değerlerini karıştırır.
def ozel_p_kutu_olustur(anahtar):
    # Anahtarın SHA256 karma değeri alınır ve hexadecimal (16'lık) formata dönüştürülür.
    anahtar_karma = hashlib.sha256(anahtar.encode()).hexdigest()
    
    # Karma değerin ilk 16 karakteri (hexadecimal) alınır ve bir tamsayıya çevrilerek
    # rastgele sayı üreteci için tohum (seed) olarak kullanılır.
    # Bu, aynı anahtarla her zaman aynı P-Kutu'nun oluşmasını sağlar.
    p_kutu_tohumu = int(anahtar_karma[0:16], 16)

    # 0'dan 65535'e kadar (16 bitlik tüm olası değerler) bir liste oluşturulur.
    p_kutu_degerleri = list(range(65536))
    
    # Oluşturulan tohum ile yeni bir rastgele sayı üreteci (RNG) başlatılır.
    # Bu RNG, her zaman aynı tohumla aynı sırayı üretir.
    p_kutu_rng = random.Random(p_kutu_tohumu)
    
    # P-Kutu değerleri listesi, RNG kullanılarak karıştırılır.
    p_kutu_rng.shuffle(p_kutu_degerleri)
    
    # Orijinal indeksleri (0-65535) anahtar, karıştırılmış değerleri ise değer olarak
    # içeren sıralı bir sözlük (OrderedDict) oluşturulur.
    p_kutu = OrderedDict(zip(range(65536), p_kutu_degerleri))
    return p_kutu

# --- Ters P-Kutu Oluşturma ---
# Bu fonksiyon, verilen bir P-Kutu'nun anahtarları ve değerlerini yer değiştirerek
# tersini oluşturur. Çözümleme işleminde permütasyonu geri almak için kullanılır.
def ters_p_kutu(p_kutu):
    # Sözlük anlayışı kullanılarak anahtar-değer çiftleri tersine çevrilir.
    return {deger: anahtar for anahtar, deger in p_kutu.items()}

# --- Şifreleme Fonksiyonu ---
# Düz metni ve anahtar kelimeyi alır, şifreli metni ve kullanılan P-Kutu'yu döndürür.
def sifrele(duz_metin, anahtar_kelime):
    # Anahtar kelimeye özel P-Kutu oluşturulur.
    p_kutu = ozel_p_kutu_olustur(anahtar_kelime)
    sifreli_metin = ""

    # Düz metin üzerinde karakter karakter ilerlenir.
    for i in range(len(duz_metin)):
        # Düz metin ve anahtar kelime karakterleri alınır, küçük harfe çevrilir.
        # Anahtar kelime düz metin uzunluğuna göre döngüsel olarak tekrar eder.
        m_harf = duz_metin[i].lower()
        k_harf = anahtar_kelime[i % len(anahtar_kelime)].lower()

        # Eğer karakterler desteklenen alfabede yoksa, hata placeholder'ı eklenir.
        if m_harf not in harf_asal_esleme or k_harf not in harf_asal_esleme:
            sifreli_metin += "??" 
            continue

        # Harfler asal sayı karşılıklarına dönüştürülür.
        m_asal = harf_asal_esleme[m_harf]
        k_asal = harf_asal_esleme[k_harf]

        # Düz metin asal değeri 8 bit sola kaydırılır (yüksek 8 bit olur).
        # Anahtar asal değeri ile bitwise OR işlemi yapılarak tek bir 16-bit değer elde edilir.
        # Örneğin, m_asal = 2 (00000010), k_asal = 3 (00000011) ise:
        # (2 << 8) -> 00000010 00000000
        # | 3      -> 00000010 00000011 (yani 515)
        birlesik_deger = (m_asal << 8) | k_asal
        
        # Birleşik değer, oluşturulan P-Kutu kullanılarak permüte edilir.
        # Eğer bir nedenden dolayı değer P-Kutu'da bulunamazsa (normalde olmaz),
        # değeri olduğu gibi bırakılır.
        permute_edilmis_deger = p_kutu.get(birlesik_deger, birlesik_deger)

        # Permüte edilmiş 16-bit değer ikiye ayrılır:
        # index_1: Üst 8 bit alınır ve alfabenin boyutuna göre modüler aritmetik uygulanır.
        # index_2: Alt 8 bit alınır (0xFF ile AND işlemi) ve alfabenin boyutuna göre modüler aritmetik uygulanır.
        index_1 = (permute_edilmis_deger >> 8) % len(turkce_alfabe)
        index_2 = (permute_edilmis_deger & 0xFF) % len(turkce_alfabe)
        
        # Elde edilen indekslere karşılık gelen alfabe karakterleri şifreli metne eklenir.
        # Her orijinal karakter için 2 şifreli karakter oluşur.
        sifreli_metin += turkce_alfabe[index_1]
        sifreli_metin += turkce_alfabe[index_2]

    return sifreli_metin, p_kutu # Şifreli metin ve kullanılan P-Kutu döndürülür

# --- Çözümleme Fonksiyonu ---
# Şifreli metni, anahtar kelimeyi ve şifrelemede kullanılan P-Kutu'yu alır, çözülmüş metni döndürür.
def cozumle(sifreli_metin, anahtar_kelime, kullanilan_p_kutu):
    # Ters P-Kutu oluşturulur.
    ters_p_kutu_harita = ters_p_kutu(kullanilan_p_kutu)
    cozulmus_metin = ""

    # Şifreli metin 2 karakterlik bloklar halinde işlenir (her orijinal karakter 2 şifreli karaktere dönüşmüştü).
    for i in range(0, len(sifreli_metin), 2):
        # Şifreli blok alınır, dizin dışı hataları önlemek için güvenli bir şekilde dilimlenir.
        sifreli_blok = sifreli_metin[i : i+2].lower()

        # Eğer blok "?? " placeholder'ı ise, çözülmüş metne "?" eklenir.
        if sifreli_blok == "??":
            cozulmus_metin += "?"
            continue
        
        # Bloğun 2 karakterden kısa olması (metin sonu veya bozuk metin) durumu.
        if len(sifreli_blok) < 2:
            cozulmus_metin += "?" 
            continue

        # Şifreli bloğun ilk ve ikinci karakterleri ayrılır.
        sifreli_karakter_1 = sifreli_blok[0]
        sifreli_karakter_2 = sifreli_blok[1]

        try:
            # Şifreli karakterlerin alfabedeki indeksleri bulunur.
            karakter_indeks_1 = turkce_alfabe.index(sifreli_karakter_1)
            karakter_indeks_2 = turkce_alfabe.index(sifreli_karakter_2)
        except ValueError:
            # Geçersiz bir şifreli karakter varsa (alfabede yok), "?" eklenir.
            cozulmus_metin += "?"
            continue

        # Orijinal anahtar kelimeden beklenen anahtar karakteri ve asal değeri bulunur.
        beklenen_k_harf = anahtar_kelime[(i // 2) % len(anahtar_kelime)].lower()
        beklenen_k_asal = harf_asal_esleme.get(beklenen_k_harf, None)

        if beklenen_k_asal is None:
            cozulmus_metin += "?"
            continue

        found_m_harf = "?" # Bulunan düz metin karakteri için başlangıç değeri

        # --- Lokal Kaba Kuvvet Arama (Brute-Force) ---
        # Şifreleme sırasında uygulanan modüler aritmetik (%29) nedeniyle bilgi kaybı olur.
        # Bu kaybı telafi etmek için, 0-65535 arasındaki tüm olası permütasyon sonrası değerleri deneriz.
        for gecerli_permute_edilmis_deger in range(65536):
            # Aday permütasyon değerinden 2 indeks geri çıkarılır.
            test_indeks_1 = (gecerli_permute_edilmis_deger >> 8) % len(turkce_alfabe)
            test_indeks_2 = (gecerli_permute_edilmis_deger & 0xFF) % len(turkce_alfabe)

            # Eğer çıkarılan indeksler, şifreli bloktan elde ettiğimiz indekslerle eşleşiyorsa...
            if test_indeks_1 == karakter_indeks_1 and test_indeks_2 == karakter_indeks_2:
                # Bu 'gecerli_permute_edilmis_deger' potansiyel olarak doğru olan permüte edilmiş değerdir.
                # Şimdi bunu ters P-Kutu'dan geçirerek orijinal birleşik değeri (combined_val) bulalım.
                birlesik_deger_adayi = ters_p_kutu_harita.get(gecerli_permute_edilmis_deger, None)

                if birlesik_deger_adayi is None:
                    continue 
                
                # Birleşik değer adayından anahtar asal değeri (alt 8 bit) ve düz metin asal değeri (üst 8 bit) ayrılır.
                cikarilan_k_asal = birlesik_deger_adayi & 0xFF
                cikarilan_m_asal = (birlesik_deger_adayi >> 8) & 0xFF
                
                # Anahtar asal değerinin beklenen anahtar asal değeriyle eşleşip eşleşmediği kontrol edilir.
                # Ayrıca çıkarılan düz metin asal değerinin geçerli bir asal karşılığı olup olmadığına bakılır.
                if cikarilan_k_asal == beklenen_k_asal and cikarilan_m_asal in asal_esleme_harf:
                    # Eğer tüm koşullar sağlanırsa, doğru düz metin karakteri bulunur.
                    found_m_harf = asal_esleme_harf[cikarilan_m_asal]
                    break # Doğru değer bulunduğunda iç döngüden çıkılır.
        
        # Bulunan düz metin karakteri çözülmüş metne eklenir.
        cozulmus_metin += found_m_harf

    return cozulmus_metin

# --- Ana İşlem Bloğu ve Testler ---
# Bu kısım, program çalıştırıldığında kullanıcıdan girdi alır, şifreleme ve çözümleme yapar
# ve ardından bir doğrulama testi gerçekleştirir.
if __name__ == "__main__":
    # Kullanıcıdan düz metin ve anahtar kelime girdisi alınır.
    asli = input("Lütfen şifrelemek istediğiniz kelimeyi girin: ")
    anahtar = input("Lütfen şifreleme anahtarını girin: ")

    # Şifreleme işlemi yapılır.
    sifreli_metin, p_kutu_kullanildi = sifrele(asli, anahtar)
    print(f"Şifreli metin: {sifreli_metin}")

    # Çözümleme işlemi yapılır.
    cozulmus_metin = cozumle(sifreli_metin, anahtar, p_kutu_kullanildi)
    print(f"Çözülmüş metin: {cozulmus_metin}")

    # --- Şifreleme ve Çözümleme Doğrulama Testi ---
    # Orijinal ve çözülmüş metinlerin küçük harf halleri alınır.
    asli_norm = asli.lower()
    cozulmus_norm = cozulmus_metin.lower()

    # Uzunluklar kontrol edilir. Eğer farklıysa, bir sorun vardır.
    if len(asli_norm) == len(cozulmus_norm):
        test_basarili = True
        # Karakter karakter karşılaştırma yapılır.
        for char_idx in range(len(asli_norm)):
            # Eğer orijinal karakter desteklenen alfabede ise, çözülmüş haliyle aynı olmalıdır.
            if asli_norm[char_idx] in turkce_alfabe:
                if asli_norm[char_idx] != cozulmus_norm[char_idx]:
                    test_basarili = False
                    break
            # Eğer orijinal karakter desteklenmiyorsa (çözülmüş hali "??" veya "?" olmalıydı),
            # çözülmüş hali "?" olmalıdır.
            else:
                if cozulmus_norm[char_idx] != '?':
                    test_basarili = False
                    break
        
        if test_basarili:
            print("Şifreleme ve çözümleme başarıyla tamamlandı! ✅")
        else:
            print("Şifreleme ve çözümlemede bir hata oluştu. ❌")
            print(f"Orijinal: {asli_norm}, Çözülmüş: {cozulmus_norm}")
    else:
        print("Şifreleme ve çözümlemede bir hata oluştu (uzunluk farkı var). ❌")
        print(f"Orijinal: {asli_norm}, Çözülmüş: {cozulmus_norm}")

