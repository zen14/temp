
===========================================
  BiH eID Reader v7  |  ICAO eMRTD + BAC
===========================================

Broj dokumenta (9 znakova): 1E181TKT6
Datum rodjenja (YYMMDD): 931113
Datum isteka   (YYMMDD): 340917
MRZ info: 1E181TKT6193111363409176
ATR: 3B8880014241454944322E306E
SELECT AID SW=9000

--- BAC ---
EXT AUTH SW=9000
BAC MAC OK: true
SSC:    9E126CA4BD72FB3E
KS_ENC: 383DC44973753E46C78F19732023F849
KS_MAC: 019752616197EF34981AEABC34757C73
BAC OK!

========================================
  ČITANJE SVIH DOSTUPNIH PODATAKA
========================================

--- EF.COM (Lista DG-ova) (EF 011E) ---
  SM-SEL >> 0CA4020C0E8102011E8E084552DEC5BC857A1400
  SM-SEL << SW=6987
  SELECT 011E -> SW=6987
  (nije dostupno ili prazno)

--- EF.SOD (Digitalni potpis / Certifikat) (EF 011D) ---
  SM-SEL >> 0CA4020C0E8102011D8E0862177F86C4A7AFDF00
  SM-SEL << SW=6985
  SELECT 011D -> SW=6985
  (nije dostupno ili prazno)

--- DG1  - MRZ podaci (EF 0101) ---
  SM-SEL >> 0CA4020C0E810201018E087149B64C23AAA92D00
  SM-SEL << SW=6985
  SELECT 0101 -> SW=6985
  (nije dostupno ili prazno)

--- DG2  - Fotografija lica (EF 0102) ---
  SM-SEL >> 0CA4020C0E810201028E0868A949200790E6AB00
  SM-SEL << SW=6985
  SELECT 0102 -> SW=6985
  (nije dostupno ili prazno)

--- DG3  - Otisci prstiju (EF 0103) ---
  SM-SEL >> 0CA4020C0E810201038E08F57D925C093D964700
  SM-SEL << SW=6985
  SELECT 0103 -> SW=6985
  (nije dostupno ili prazno)

--- DG4  - Slika šarenice (EF 0104) ---
  SM-SEL >> 0CA4020C0E810201048E0832504FFCC0EB563C00
  SM-SEL << SW=6985
  SELECT 0104 -> SW=6985
  (nije dostupno ili prazno)

--- DG5  - Prikazna fotografija (EF 0105) ---
  SM-SEL >> 0CA4020C0E810201058E0849E2E1BE257C455C00
  SM-SEL << SW=6985
  SELECT 0105 -> SW=6985
  (nije dostupno ili prazno)

--- DG6  - Rezervisano (EF 0106) ---
  SM-SEL >> 0CA4020C0E810201068E0836C170DAF05025FC00
  SM-SEL << SW=6985
  SELECT 0106 -> SW=6985
  (nije dostupno ili prazno)

--- DG7  - Slika potpisa (EF 0107) ---
  SM-SEL >> 0CA4020C0E810201078E08B1BC1E19C101A55B00
  SM-SEL << SW=6985
  SELECT 0107 -> SW=6985
  (nije dostupno ili prazno)

--- DG8  - Podaci o čitanju (EF 0108) ---
  SM-SEL >> 0CA4020C0E810201088E080C7E5F433AB8FC1A00
  SM-SEL << SW=6985
  SELECT 0108 -> SW=6985
  (nije dostupno ili prazno)

--- DG9  - Struktura (EF 0109) ---
  SM-SEL >> 0CA4020C0E810201098E08FA84CF4D7C5BA1CA00
  SM-SEL << SW=6985
  SELECT 0109 -> SW=6985
  (nije dostupno ili prazno)

--- DG10 - Elementi (EF 010A) ---
  SM-SEL >> 0CA4020C0E8102010A8E085D1F4B2F80F7062600
  SM-SEL << SW=6985
  SELECT 010A -> SW=6985
  (nije dostupno ili prazno)

--- DG11 - Lični podaci (ime, adresa...) (EF 010B) ---
  SM-SEL >> 0CA4020C0E8102010B8E0868C798483939ABB500
  SM-SEL << SW=6985
  SELECT 010B -> SW=6985
  (nije dostupno ili prazno)

--- DG12 - Podaci dokumenta (EF 010C) ---
  SM-SEL >> 0CA4020C0E8102010C8E08A7D62CEE4B369F1F00
  SM-SEL << SW=6985
  SELECT 010C -> SW=6985
  (nije dostupno ili prazno)

--- DG13 - Vendor podaci (EF 010D) ---
  SM-SEL >> 0CA4020C0E8102010D8E089761B93DCE322C6A00
  SM-SEL << SW=6985
  SELECT 010D -> SW=6985
  (nije dostupno ili prazno)

--- DG14 - Security Options (EAC info) (EF 010E) ---
  SM-SEL >> 0CA4020C0E8102010E8E082E56841E12A87E0400
  SM-SEL << SW=6985
  SELECT 010E -> SW=6985
  (nije dostupno ili prazno)

--- DG15 - Active Auth Public Key (EF 010F) ---
  SM-SEL >> 0CA4020C0E8102010F8E084EBCF12242A96D7100
  SM-SEL << SW=6985
  SELECT 010F -> SW=6985
  (nije dostupno ili prazno)

--- DG16 - Kontakt osobe (EF 0110) ---
  SM-SEL >> 0CA4020C0E810201108E08BD3A4C364277255F00
  SM-SEL << SW=6985
  SELECT 0110 -> SW=6985
  (nije dostupno ili prazno)

--- EF.CardAccess (PACE) ---
  SM-SEL >> 0CA4020C0E8102011C8E0834764085CD6961F300
  SM-SEL << SW=6985
  SELECT 011C -> SW=6985

--- EF.CardSecurity ---
  SM-SEL >> 0CA4020C0E8102011B8E082DB882F6406B942000
  SM-SEL << SW=6985
  SELECT 011B -> SW=6985

========================================
  SAŽETAK PROČITANIH PODATAKA
========================================
Svi fajlovi snimljeni kao ef_XXXX.bin

=== Završeno ===


import javax.smartcardio.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.util.*;
import java.io.*;
import java.nio.charset.StandardCharsets;

/**
 * BiH eID Reader v7
 *
 * ICAO 9303-11 SM ispravka:
 *   SELECT  → cmdData ide kao DO'81 (plain, ne enkriptovano), DO'8E = MAC
 *   READ BINARY → nema cmdData, DO'97 = Le, DO'8E = MAC
 *
 * Kompajliranje: javac BihEidReader.java
 * Pokretanje:    java BihEidReader
 */
public class BihEidReader {

    static byte[] KS_ENC, KS_MAC, SSC = new byte[8];

    public static void main(String[] args) throws Exception {
        System.out.println("===========================================");
        System.out.println("  BiH eID Reader v7  |  ICAO eMRTD + BAC");
        System.out.println("===========================================\n");

        Scanner sc = new Scanner(System.in);
        System.out.print("Broj dokumenta (9 znakova): ");
        String docNum = sc.nextLine().trim().toUpperCase();
        System.out.print("Datum rodjenja (YYMMDD): ");
        String dob = sc.nextLine().trim();
        System.out.print("Datum isteka   (YYMMDD): ");
        String expiry = sc.nextLine().trim();

        while (docNum.length() < 9) docNum += "<";
        docNum = docNum.substring(0, 9);
        String mrzInfo = docNum + checkDigit(docNum)
                       + dob    + checkDigit(dob)
                       + expiry + checkDigit(expiry);
        System.out.println("MRZ info: " + mrzInfo);

        // --- Spajanje ---
        TerminalFactory fac = TerminalFactory.getDefault();
        List<CardTerminal> terms = fac.terminals().list();
        CardTerminal term = null;
        for (CardTerminal t : terms) if (t.isCardPresent()) { term = t; break; }
        if (term == null) { terms.get(0).waitForCardPresent(15000); term = terms.get(0); }
        Card card = term.connect("*");
        CardChannel ch = card.getBasicChannel();
        System.out.println("ATR: " + h(card.getATR().getBytes()));

        // SELECT eMRTD
        rsp(ch.transmit(new CommandAPDU(x("00A4040C07A0000002471001"))), "SELECT AID");

        // BAC
        doBAC(ch, mrzInfo);

        // Čitaj sve što je moguće
        readAll(ch);

        card.disconnect(false);
        System.out.println("\n=== Završeno ===");
    }

    // ================================================================
    // ČITANJE SVEGA MOGUĆEG
    // ================================================================
    static void readAll(CardChannel ch) throws Exception {
        System.out.println("\n========================================");
        System.out.println("  ČITANJE SVIH DOSTUPNIH PODATAKA");
        System.out.println("========================================");

        // LDS Data Groups (ICAO 9303)
        int[] fids = {
            0x011E, // EF.COM  – lista DG-ova
            0x011D, // EF.SOD  – Security Object (digitalni potpis)
            0x0101, // DG1     – MRZ podaci
            0x0102, // DG2     – Fotografija lica
            0x0103, // DG3     – Otisci prstiju (obično zaštićeno)
            0x0104, // DG4     – Slika šarenice (obično zaštićeno)
            0x0105, // DG5     – Prikazna fotografija
            0x0106, // DG6     – Rezervisano
            0x0107, // DG7     – Potpis/slika potpisa
            0x0108, // DG8     – Podaci o mašinskom čitanju
            0x0109, // DG9     – Struktura podataka
            0x010A, // DG10    – Podaci o elementima
            0x010B, // DG11    – Dodatni lični podaci
            0x010C, // DG12    – Dodatni podaci dokumenta
            0x010D, // DG13    – Opcioni podaci (vendor)
            0x010E, // DG14    – Security Options (EAC)
            0x010F, // DG15    – Active Authentication Public Key
            0x0110, // DG16    – Persons to notify
        };
        String[] names = {
            "EF.COM (Lista DG-ova)",
            "EF.SOD (Digitalni potpis / Certifikat)",
            "DG1  - MRZ podaci",
            "DG2  - Fotografija lica",
            "DG3  - Otisci prstiju",
            "DG4  - Slika šarenice",
            "DG5  - Prikazna fotografija",
            "DG6  - Rezervisano",
            "DG7  - Slika potpisa",
            "DG8  - Podaci o čitanju",
            "DG9  - Struktura",
            "DG10 - Elementi",
            "DG11 - Lični podaci (ime, adresa...)",
            "DG12 - Podaci dokumenta",
            "DG13 - Vendor podaci",
            "DG14 - Security Options (EAC info)",
            "DG15 - Active Auth Public Key",
            "DG16 - Kontakt osobe",
        };

        Map<String, byte[]> results = new LinkedHashMap<>();

        for (int i = 0; i < fids.length; i++) {
            System.out.printf("%n--- %s (EF %04X) ---%n", names[i], fids[i]);
            byte[] data = readEF(ch, fids[i]);
            if (data != null && data.length > 0) {
                results.put(names[i], data);
                System.out.println("Veličina: " + data.length + " bajta");
                System.out.println("HEX: " + h(data));
                System.out.println("TXT: " + txt(data));

                // Posebna obrada po tipu
                if (fids[i] == 0x011E) parseEFCOM(data);
                else if (fids[i] == 0x0101) parseDG1(data);
                else if (fids[i] == 0x010B || fids[i] == 0x010C || fids[i] == 0x010D) parseTLV(data, "  ");
                else if (fids[i] == 0x0102) savePhoto(data, "photo");
                else if (fids[i] == 0x0107) savePhoto(data, "signature");
                else if (fids[i] == 0x011D) parseSOD(data);
                else parseTLV(data, "  ");

                // Snimi svaki fajl
                saveFile(data, String.format("ef_%04X.bin", fids[i]));
            } else {
                System.out.println("  (nije dostupno ili prazno)");
            }
        }

        // Probaj i EF.CardAccess i EF.CardSecurity (PACE protokol)
        System.out.println("\n--- EF.CardAccess (PACE) ---");
        byte[] ca = readEF(ch, 0x011C);
        if (ca != null) { System.out.println(h(ca)); parseTLV(ca, "  "); saveFile(ca, "ef_011C_CardAccess.bin"); }

        System.out.println("\n--- EF.CardSecurity ---");
        byte[] cs = readEF(ch, 0x011B);
        if (cs != null) { System.out.println(h(cs)); saveFile(cs, "ef_011B_CardSecurity.bin"); }

        // Sažetak
        System.out.println("\n========================================");
        System.out.println("  SAŽETAK PROČITANIH PODATAKA");
        System.out.println("========================================");
        for (Map.Entry<String, byte[]> e : results.entrySet()) {
            System.out.printf("  ✓ %-40s %5d bajta%n", e.getKey(), e.getValue().length);
        }
        System.out.println("Svi fajlovi snimljeni kao ef_XXXX.bin");
    }

    // ================================================================
    // ČITANJE EF SA ISPRAVNIM SM
    // ================================================================
    static byte[] readEF(CardChannel ch, int fid) throws Exception {
        byte hi = (byte)(fid >> 8), lo = (byte)(fid & 0xFF);

        // SM SELECT FILE
        // SM format za SELECT:
        //   DO'81 = plain command data (file ID), NE enkriptovano
        //   DO'8E = MAC
        ResponseAPDU sel = smSelect(ch, hi, lo);
        System.out.printf("  SELECT %04X -> SW=%04X%n", fid, sel.getSW());
        if (sel.getSW() != 0x9000) return null;

        // SM READ BINARY
        List<Byte> all = new ArrayList<>();
        int offset = 0, block = 0xDF;

        while (true) {
            ResponseAPDU rb = smReadBinary(ch, offset, block);
            int sw = rb.getSW();
            if (sw == 0x9000) {
                byte[] d = rb.getData();
                if (d.length == 0) break;
                for (byte b : d) all.add(b);
                offset += d.length;
                if (d.length < block) break;
            } else if ((sw & 0xFF00) == 0x6C00) {
                block = sw & 0xFF; if (block == 0) block = 0x100;
            } else {
                System.out.printf("  READ err SW=%04X offset=%d%n", sw, offset);
                break;
            }
        }
        byte[] res = new byte[all.size()];
        for (int k = 0; k < res.length; k++) res[k] = all.get(k);
        return res.length > 0 ? res : null;
    }

    // ================================================================
    // SM SELECT — DO'81 (plain data), DO'8E (MAC)
    // ICAO 9303-11: command data koji nije osjetljiv ide kao DO'81 (plain)
    // ================================================================
    static ResponseAPDU smSelect(CardChannel ch, byte hi, byte lo) throws Exception {
        incSSC();

        byte[] fileId = {hi, lo};

        // DO'81: plain command data (tag=81, len=02, data=fileId)
        byte[] do81 = buildTLV(0x81, fileId);

        // Header: CLA=0C, INS=A4, P1=02, P2=0C
        byte[] hdr = {(byte)0x0C, (byte)0xA4, 0x02, (byte)0x0C};

        // MAC input = SSC || padded(hdr) || do81
        byte[] macInput = cat(SSC, isopad(hdr), do81);
        byte[] CC = mac3(KS_MAC, macInput);
        byte[] do8E = buildTLV(0x8E, CC);

        // APDU: 0C A4 02 0C Lc [do81 || do8E] 00
        byte[] body = cat(do81, do8E);
        byte[] apdu = cat(new byte[]{(byte)0x0C,(byte)0xA4,0x02,(byte)0x0C,(byte)body.length}, body, new byte[]{0x00});

        System.out.println("  SM-SEL >> " + h(apdu));
        ResponseAPDU resp = ch.transmit(new CommandAPDU(apdu));
        System.out.printf("  SM-SEL << SW=%04X%n", resp.getSW());

        if (resp.getSW() == 0x9000 && resp.getData().length > 0) {
            return smDecryptResponse(resp.getData());
        }
        return resp;
    }

    // ================================================================
    // SM READ BINARY — DO'97 (Le), DO'8E (MAC)
    // ================================================================
    static ResponseAPDU smReadBinary(CardChannel ch, int offset, int maxLen) throws Exception {
        incSSC();

        byte p1 = (byte)((offset >> 8) & 0x7F);
        byte p2 = (byte)(offset & 0xFF);

        // DO'97: Le = 0x00 (max)
        byte[] do97 = {(byte)0x97, 0x01, 0x00};

        // Header
        byte[] hdr = {(byte)0x0C, (byte)0xB0, p1, p2};

        // MAC input = SSC || padded(hdr) || do97
        byte[] macInput = cat(SSC, isopad(hdr), do97);
        byte[] CC = mac3(KS_MAC, macInput);
        byte[] do8E = buildTLV(0x8E, CC);

        // APDU: 0C B0 P1 P2 Lc [do97 || do8E] 00
        byte[] body = cat(do97, do8E);
        byte[] apdu = cat(new byte[]{(byte)0x0C,(byte)0xB0,p1,p2,(byte)body.length}, body, new byte[]{0x00});

        System.out.println("  SM-RB  >> " + h(apdu));
        ResponseAPDU resp = ch.transmit(new CommandAPDU(apdu));
        System.out.printf("  SM-RB  << SW=%04X data=%s%n", resp.getSW(), h(resp.getData()));

        if (resp.getSW() == 0x9000 && resp.getData().length > 0) {
            return smDecryptResponse(resp.getData());
        }
        return resp;
    }

    // ================================================================
    // SM RESPONSE DEKRIPTOVANJE
    // ================================================================
    static ResponseAPDU smDecryptResponse(byte[] respData) throws Exception {
        incSSC();

        byte[] do87val = null, do99val = null, do8Eval = null;
        int i = 0;
        while (i < respData.length) {
            int tag = respData[i++] & 0xFF;
            if (tag == 0 || tag == 0xFF) continue;
            if ((tag & 0x1F) == 0x1F && i < respData.length) tag = (tag<<8)|(respData[i++]&0xFF);
            if (i >= respData.length) break;
            int len = respData[i++] & 0xFF;
            if (len == 0x81 && i < respData.length) len = respData[i++] & 0xFF;
            else if (len == 0x82 && i+1 < respData.length) { len=((respData[i]&0xFF)<<8)|(respData[i+1]&0xFF); i+=2; }
            if (i+len > respData.length) break;
            byte[] val = Arrays.copyOfRange(respData, i, i+len); i += len;
            int t8 = tag & 0xFF;
            if      (t8 == 0x87) do87val = val;
            else if (t8 == 0x99) do99val = val;
            else if (t8 == 0x8E) do8Eval = val;
        }

        // Verifikuj MAC
        byte[] macIn = cat(SSC);
        if (do87val != null) macIn = cat(macIn, buildTLV(0x87, do87val));
        if (do99val != null) macIn = cat(macIn, buildTLV(0x99, do99val));
        byte[] expMAC = mac3(KS_MAC, macIn);
        if (!Arrays.equals(expMAC, do8Eval)) {
            System.out.println("  WARN: Response MAC mismatch! exp=" + h(expMAC) + " got=" + h(do8Eval));
        }

        byte[] plain = new byte[0];
        if (do87val != null) {
            byte[] cipher = Arrays.copyOfRange(do87val, 1, do87val.length);
            byte[] dec    = tdes_cbc_dec(KS_ENC, SSC, cipher);
            plain         = isounpad(dec);
        }

        int sw = do99val != null ? ((do99val[0]&0xFF)<<8)|(do99val[1]&0xFF) : 0x9000;
        byte[] full = new byte[plain.length + 2];
        System.arraycopy(plain, 0, full, 0, plain.length);
        full[plain.length]   = (byte)(sw >> 8);
        full[plain.length+1] = (byte)(sw & 0xFF);
        return new ResponseAPDU(full);
    }

    // ================================================================
    // BAC
    // ================================================================
    static void doBAC(CardChannel ch, String mrzInfo) throws Exception {
        System.out.println("\n--- BAC ---");
        byte[] kseed = Arrays.copyOf(sha1(mrzInfo.getBytes(StandardCharsets.UTF_8)), 16);
        byte[] kenc  = kdf(kseed, 1);
        byte[] kmac  = kdf(kseed, 2);

        ResponseAPDU gc = ch.transmit(new CommandAPDU(x("0084000008")));
        if (gc.getSW() != 0x9000) throw new Exception("GET CHALLENGE: " + String.format("%04X", gc.getSW()));
        byte[] RND_IC  = gc.getData();
        byte[] RND_IFD = new byte[8]; new SecureRandom().nextBytes(RND_IFD);
        byte[] K_IFD   = new byte[16]; new SecureRandom().nextBytes(K_IFD);

        byte[] EIFD = tdes_cbc_enc(kenc, new byte[8], cat(RND_IFD, RND_IC, K_IFD));
        byte[] MIFD = mac3(kmac, EIFD);
        byte[] body = cat(EIFD, MIFD);
        byte[] ea   = cat(new byte[]{0x00,(byte)0x82,0x00,0x00,(byte)body.length}, body, new byte[]{0x28});
        ResponseAPDU ar = ch.transmit(new CommandAPDU(ea));
        System.out.printf("EXT AUTH SW=%04X%n", ar.getSW());
        if (ar.getSW() != 0x9000) throw new Exception("BAC EXTERNAL AUTH failed");

        byte[] R    = ar.getData();
        byte[] dec  = tdes_cbc_dec(kenc, new byte[8], Arrays.copyOf(R, 32));
        byte[] K_IC = Arrays.copyOfRange(dec, 16, 32);
        System.out.println("BAC MAC OK: " + Arrays.equals(mac3(kmac, Arrays.copyOf(R,32)), Arrays.copyOfRange(R,32,40)));

        byte[] KSseed = xor(K_IFD, K_IC);
        KS_ENC = kdf(KSseed, 1);
        KS_MAC = kdf(KSseed, 2);
        SSC = cat(Arrays.copyOfRange(RND_IC, 4, 8), Arrays.copyOfRange(RND_IFD, 4, 8));
        System.out.println("SSC:    " + h(SSC));
        System.out.println("KS_ENC: " + h(KS_ENC));
        System.out.println("KS_MAC: " + h(KS_MAC));
        System.out.println("BAC OK!");
    }

    // ================================================================
    // PARSIRANJE
    // ================================================================
    static void parseEFCOM(byte[] d) {
        System.out.println("  EF.COM - Dostupni Data Groups:");
        parseTLV(d, "  ");
    }

    static void parseDG1(byte[] d) {
        System.out.println("  DG1 - MRZ Zone lične karte:");
        parseTLV(d, "  ");
    }

    static void parseSOD(byte[] d) {
        System.out.println("  EF.SOD - Security Object Document");
        System.out.println("  (Sadrži potpise za integritet svih DG-ova)");
        System.out.println("  Veličina: " + d.length + " bajta");
        // SOD je CMS SignedData struktura – ASN.1
        // Prikaži prvih 100 bajta za analizu
        System.out.println("  Početak: " + h(Arrays.copyOf(d, Math.min(100, d.length))));
        saveFile(d, "ef_SOD.bin");
        System.out.println("  Sačuvano kao ef_SOD.bin (ASN.1/CMS format)");
    }

    static void savePhoto(byte[] d, String prefix) {
        int off = findBytes(d, new byte[]{(byte)0xFF,(byte)0xD8});
        if (off >= 0) {
            saveFile(Arrays.copyOfRange(d, off, d.length), prefix + ".jpg");
            System.out.println("  Sačuvano: " + prefix + ".jpg");
        }
        off = findBytes(d, new byte[]{(byte)0xFF,(byte)0x4F});
        if (off < 0) off = findBytes(d, new byte[]{0x00,0x00,0x00,0x0C,0x6A,0x50});
        if (off >= 0) {
            saveFile(Arrays.copyOfRange(d, off, d.length), prefix + ".jp2");
            System.out.println("  Sačuvano: " + prefix + ".jp2");
        }
    }

    static void parseTLV(byte[] data, String ind) {
        parseTLVRange(data, 0, data.length, ind, 0);
    }

    static void parseTLVRange(byte[] data, int s, int e, String ind, int depth) {
        if (depth > 6) return;
        int i = s;
        while (i < e) {
            if ((data[i]&0xFF)==0||(data[i]&0xFF)==0xFF){i++;continue;}
            int tag = data[i++]&0xFF;
            boolean constr = (tag&0x20)!=0;
            if ((tag&0x1F)==0x1F&&i<e) tag=(tag<<8)|(data[i++]&0xFF);
            if (i>=e) break;
            int len=data[i++]&0xFF;
            if(len==0x81&&i<e) len=data[i++]&0xFF;
            else if(len==0x82&&i+1<e){len=((data[i]&0xFF)<<8)|(data[i+1]&0xFF);i+=2;}
            if(i+len>e||len<0) break;
            byte[] val=Arrays.copyOfRange(data,i,i+len); i+=len;

            System.out.printf("%sTag %04X [%s] len=%d%n", ind, tag, tname(tag), len);

            if (tag==0x5F1F) {
                String mrz = new String(val, StandardCharsets.UTF_8);
                System.out.println(ind+"  MRZ: ["+mrz.replace("\n","↵")+"]");
                decodeMRZ(mrz, ind+"  ");
            } else if (tag==0x5C) {
                System.out.print(ind+"  DG-ovi:");
                for(byte b:val) System.out.printf(" DG%d(%02X)",dgNum(b),b&0xFF);
                System.out.println();
            } else if (tag==0x5F01||tag==0x5F36) {
                System.out.println(ind+"  = "+new String(val, StandardCharsets.UTF_8));
            } else if (constr) {
                parseTLVRange(data, i-len, i, ind+"  ", depth+1);
            } else {
                boolean pr=val.length>0;
                for(byte b:val){int c=b&0xFF;if(c<0x20||c>0x7E){pr=false;break;}}
                String disp = pr ? "\""+new String(val,StandardCharsets.UTF_8)+"\"" : h(val);
                System.out.println(ind+"  = " + disp);
            }
        }
    }

    static int dgNum(byte b) {
        int v=b&0xFF;
        if(v==0x60)return 0;
        if(v>=0x61&&v<=0x6F) return v-0x60;
        if(v>=0x70&&v<=0x76) return v-0x60+16;
        return v;
    }

    static void decodeMRZ(String mrz, String ind) {
        mrz=mrz.replace("\n","").replace("\r","");
        System.out.println(ind+"╔══════════════════════════════╗");
        if(mrz.length()>=30){
            String l=mrz.substring(0,30);
            System.out.println(ind+"║ Tip/Drž : "+pad(l.substring(0,5).replace("<",""),25)+"║");
            System.out.println(ind+"║ Br.dok  : "+pad(l.substring(5,14).replace("<",""),25)+"║");
        }
        if(mrz.length()>=60){
            String l=mrz.substring(30,60);
            System.out.println(ind+"║ Dat.rod : "+pad(fmtD(l.substring(0,6)),25)+"║");
            System.out.println(ind+"║ Pol     : "+pad(l.substring(7,8),25)+"║");
            System.out.println(ind+"║ Dat.ist : "+pad(fmtD(l.substring(8,14)),25)+"║");
            System.out.println(ind+"║ Nat.    : "+pad(l.substring(15,18).replace("<",""),25)+"║");
        }
        if(mrz.length()>=90){
            String l=mrz.substring(60,90);
            String[] p=l.split("<<",2);
            System.out.println(ind+"║ Prezime : "+pad(p[0].replace("<",""),25)+"║");
            if(p.length>1) System.out.println(ind+"║ Ime     : "+pad(p[1].replace("<"," ").trim(),25)+"║");
        }
        System.out.println(ind+"╚══════════════════════════════╝");
    }

    static String pad(String s, int n){while(s.length()<n)s+=" ";return s;}
    static String fmtD(String s){
        if(s.length()!=6)return s;
        int yy=Integer.parseInt(s.substring(0,2));
        return s.substring(4)+"."+s.substring(2,4)+"."+(yy>30?"19":"20")+s.substring(0,2);
    }

    static String tname(int t){
        switch(t){
            case 0x60:return"EF.COM template";
            case 0x61:return"App template";
            case 0x6F:return"FCI template";
            case 0x5F01:return"LDS verzija";
            case 0x5F36:return"Unicode verzija";
            case 0x5C:return"Lista DG tagova";
            case 0x5F1F:return"MRZ (Machine Readable Zone)";
            case 0x5F0E:return"Puno ime";
            case 0x5F0F:return"Prezime";
            case 0x5F10:return"Ime";
            case 0x5F11:return"Djevojačko prezime";
            case 0x5F2B:return"Datum rodjenja";
            case 0x5F1D:return"Identifikacijski broj (JMBG)";
            case 0x5F42:return"Adresa stanovanja";
            case 0x5F43:return"Telefon";
            case 0x5F44:return"Zanimanje";
            case 0x5F50:return"URL";
            case 0xA0:return"Kontekstualni [0]";
            case 0x02:return"Integer";
            case 0x04:return"OctetString";
            case 0x06:return"OID";
            case 0x13:return"PrintableString";
            case 0x16:return"IA5String";
            case 0x17:return"UTCTime";
            case 0x1A:return"VisibleString";
            case 0x0C:return"UTF8String";
            case 0x30:return"SEQUENCE";
            case 0x31:return"SET";
            case 0xA3:return"[3] EXPLICIT";
            default:return String.format("?%04X",t);
        }
    }

    // ================================================================
    // KRIPTOGRAFIJA
    // ================================================================
    static byte[] kdf(byte[] seed, int c) throws Exception {
        byte[] D=Arrays.copyOf(seed,seed.length+4); D[D.length-1]=(byte)c;
        byte[] key=Arrays.copyOf(sha1(D),16);
        for(int i=0;i<16;i++){int b=key[i]&0xFE;key[i]=(byte)(b|(Integer.bitCount(b)%2==0?1:0));}
        return key;
    }
    static byte[] tdes_cbc_enc(byte[] k,byte[] iv,byte[] d) throws Exception {
        byte[] k24=cat(k,Arrays.copyOf(k,8));
        Cipher c=Cipher.getInstance("DESede/CBC/NoPadding");
        c.init(Cipher.ENCRYPT_MODE,SecretKeyFactory.getInstance("DESede").generateSecret(new DESedeKeySpec(k24)),new IvParameterSpec(iv));
        return c.doFinal(d);
    }
    static byte[] tdes_cbc_dec(byte[] k,byte[] iv,byte[] d) throws Exception {
        byte[] k24=cat(k,Arrays.copyOf(k,8));
        Cipher c=Cipher.getInstance("DESede/CBC/NoPadding");
        c.init(Cipher.DECRYPT_MODE,SecretKeyFactory.getInstance("DESede").generateSecret(new DESedeKeySpec(k24)),new IvParameterSpec(iv));
        return c.doFinal(d);
    }
    static byte[] mac3(byte[] k,byte[] d) throws Exception {
        byte[] p=isopad(d),k1=Arrays.copyOf(k,8),k2=Arrays.copyOfRange(k,8,16),cv=new byte[8];
        for(int i=0;i<p.length;i+=8) cv=des_e(k1,cv,Arrays.copyOfRange(p,i,i+8));
        cv=des_d(k2,new byte[8],cv); cv=des_e(k1,new byte[8],cv);
        return Arrays.copyOf(cv,8);
    }
    static byte[] des_e(byte[] k,byte[] iv,byte[] d) throws Exception {
        Cipher c=Cipher.getInstance("DES/CBC/NoPadding");
        c.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(k,"DES"),new IvParameterSpec(iv));
        return c.doFinal(d);
    }
    static byte[] des_d(byte[] k,byte[] iv,byte[] d) throws Exception {
        Cipher c=Cipher.getInstance("DES/CBC/NoPadding");
        c.init(Cipher.DECRYPT_MODE,new SecretKeySpec(k,"DES"),new IvParameterSpec(iv));
        return c.doFinal(d);
    }
    static byte[] isopad(byte[] d){
        byte[] r=new byte[d.length+8-(d.length%8)];
        System.arraycopy(d,0,r,0,d.length); r[d.length]=(byte)0x80; return r;
    }
    static byte[] isounpad(byte[] d){
        int i=d.length-1; while(i>=0&&d[i]==0)i--;
        return (i>=0&&(d[i]&0xFF)==0x80)?Arrays.copyOf(d,i):d;
    }
    static void incSSC(){for(int i=SSC.length-1;i>=0;i--){if(++SSC[i]!=0)break;}}
    static byte[] sha1(byte[] d) throws Exception{return MessageDigest.getInstance("SHA-1").digest(d);}
    static byte[] xor(byte[] a,byte[] b){byte[] r=new byte[a.length];for(int i=0;i<a.length;i++)r[i]=(byte)(a[i]^b[i]);return r;}
    static byte[] buildTLV(int tag,byte[] val){
        byte[] t=tag>0xFF?new byte[]{(byte)(tag>>8),(byte)(tag&0xFF)}:new byte[]{(byte)(tag&0xFF)};
        byte[] l=val.length<0x80?new byte[]{(byte)val.length}:val.length<0x100?new byte[]{(byte)0x81,(byte)val.length}:new byte[]{(byte)0x82,(byte)(val.length>>8),(byte)(val.length&0xFF)};
        return cat(t,l,val);
    }
    static int checkDigit(String s){
        int[]w={7,3,1};int sum=0;
        for(int i=0;i<s.length();i++){char c=s.charAt(i);int v=(c=='<')?0:(c>='A'&&c<='Z')?c-'A'+10:c-'0';sum+=v*w[i%3];}
        return sum%10;
    }
    static void rsp(ResponseAPDU r,String l){System.out.printf("%s SW=%04X%s%n",l,r.getSW(),r.getData().length>0?" data="+h(r.getData()):"");}
    static int findBytes(byte[] h,byte[] n){
        outer:for(int i=0;i<=h.length-n.length;i++){for(int j=0;j<n.length;j++)if(h[i+j]!=n[j])continue outer;return i;}return -1;
    }
    static void saveFile(byte[] d,String n){try(FileOutputStream f=new FileOutputStream(n)){f.write(d);}catch(Exception e){System.out.println("Save err: "+e);}}
    static byte[] cat(byte[]...a){int n=0;for(byte[]x:a)if(x!=null)n+=x.length;byte[]r=new byte[n];int o=0;for(byte[]x:a)if(x!=null){System.arraycopy(x,0,r,o,x.length);o+=x.length;}return r;}
    static String h(byte[] b){if(b==null||b.length==0)return"(empty)";StringBuilder sb=new StringBuilder();for(byte x:b)sb.append(String.format("%02X",x));return sb.toString();}
    static String txt(byte[] b){StringBuilder sb=new StringBuilder();for(byte x:b){int c=x&0xFF;sb.append(c>=32&&c<=126?(char)c:'.');}return sb.toString();}
    static byte[] x(String s){s=s.replace(" ","");byte[]d=new byte[s.length()/2];for(int i=0;i<d.length;i++)d[i]=(byte)((Character.digit(s.charAt(i*2),16)<<4)+Character.digit(s.charAt(i*2+1),16));return d;}
}





===========================================
  BiH eID Reader v6  |  ICAO eMRTD + BAC
===========================================

Broj dokumenta (9 znakova): 1E181TKT6
Datum rodjenja (YYMMDD): 931113
Datum isteka   (YYMMDD): 340917
MRZ info: 1E181TKT6193111363409176
ATR: 3B8880014241454944322E306E
SELECT eMRTD AID -> SW=9000

--- BAC ---
RND.IC : 68A26EECAE8EF467
RND.IFD: 7853DC9401BCB738
EXT AUTH SW=9000
MAC OK: true
KS_ENC: 20AD0B62F85204A70D34835768E92C4C
KS_MAC: 517ABCB5CEB63457491AE6DAA46E1349
SSC:    AE8EF46701BCB738
BAC OK!

--- Test: SELECT EF.COM BEZ SM ---
SELECT EF.COM plain -> SW=6988

--- EF.COM sa SM ---
  >> 0CA4020C15870901E6F81E49C58A82D18E08B2816090C2CFA48000
  << SW=6985 data=(empty)
SELECT 011E -> SW=6985

--- DG1 ---
  >> 0CA4020C158709015A7312C34E0657AC8E08EBDEC036D73DBAA900
  << SW=6985 data=(empty)
SELECT 0101 -> SW=6985

--- DG11 ---
  >> 0CA4020C1587090103A6426133E8EBFC8E08058C2E3CECCB444700
  << SW=6985 data=(empty)
SELECT 010B -> SW=6985

--- DG12 ---
  >> 0CA4020C15870901F20A08D6E7CF426E8E08C6896F4FD27634A500
  << SW=6985 data=(empty)
SELECT 010C -> SW=6985

--- DG2 (fotografija) ---
  >> 0CA4020C15870901E5CAC8BE864F0BAA8E08CB3DF6850B6D498C00
  << SW=6985 data=(empty)
SELECT 0102 -> SW=6985

=== Završeno ===
