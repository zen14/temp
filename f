===========================================
  BiH eID Explorer v3  |  BAEID2.0
===========================================

Čitač: HID Global OMNIKEY 5422CL Smartcard Reader 0
ATR: 3B 88 80 01 42 41 45 49 44 32 2E 30 6E

========== TEST 1: SELECT MF ==========
SELECT MF P2=00 -> SW=9000 data=[]
SELECT MF P2=04 -> SW=9000 data=[]
SELECT MF P2=0C -> SW=9000 data=[]
SELECT MF bez Lc -> SW=6A80

========== TEST 2: BRUTE-FORCE FILE IDs ==========
  *** EF 2F00 P1=02 P2=00 -> SW=9000 []
      DATA(18): 61 10 4F 07 A0 00 00 02 47 10 01 50 05 65 4D 52 54 44
      TEXT: a.O.....G..P.eMRTD
      TLV Tag=0061 [?]: 4F 07 A0 00 00 02 47 10 01 50 05 65 4D 52 54 44
      Snimljeno: ef_2F00.bin
  *** EF 2F00 P1=02 P2=0C -> SW=9000 []
      DATA(18): 61 10 4F 07 A0 00 00 02 47 10 01 50 05 65 4D 52 54 44
      TEXT: a.O.....G..P.eMRTD
      TLV Tag=0061 [?]: 4F 07 A0 00 00 02 47 10 01 50 05 65 4D 52 54 44
      Snimljeno: ef_2F00.bin
  *** EF 2F00 P1=00 P2=00 -> SW=9000 []
      DATA(18): 61 10 4F 07 A0 00 00 02 47 10 01 50 05 65 4D 52 54 44
      TEXT: a.O.....G..P.eMRTD
      TLV Tag=0061 [?]: 4F 07 A0 00 00 02 47 10 01 50 05 65 4D 52 54 44
      Snimljeno: ef_2F00.bin
  *** EF 2F00 P1=00 P2=0C -> SW=9000 []
      DATA(18): 61 10 4F 07 A0 00 00 02 47 10 01 50 05 65 4D 52 54 44
      TEXT: a.O.....G..P.eMRTD
      TLV Tag=0061 [?]: 4F 07 A0 00 00 02 47 10 01 50 05 65 4D 52 54 44
      Snimljeno: ef_2F00.bin
  *** EF 2F01 P1=02 P2=00 -> SW=9000 []
      DATA(26): 43 01 99 44 05 00 B0 2F 01 00 47 03 84 21 E0 7F 66 08 02 02 02 40 02 02 02 40
      TEXT: C..D.../..G..!..f....@...@
      TLV Tag=0043 [?]: 99
      TLV Tag=0044 [?]: 00 B0 2F 01 00
      TLV Tag=0047 [?]: 84 21 E0
      TLV Tag=7F66 [?]: 02 02 02 40 02 02 02 40
      Snimljeno: ef_2F01.bin
  *** EF 2F01 P1=02 P2=0C -> SW=9000 []
      DATA(26): 43 01 99 44 05 00 B0 2F 01 00 47 03 84 21 E0 7F 66 08 02 02 02 40 02 02 02 40
      TEXT: C..D.../..G..!..f....@...@
      TLV Tag=0043 [?]: 99
      TLV Tag=0044 [?]: 00 B0 2F 01 00
      TLV Tag=0047 [?]: 84 21 E0
      TLV Tag=7F66 [?]: 02 02 02 40 02 02 02 40
      Snimljeno: ef_2F01.bin
  *** EF 2F01 P1=00 P2=00 -> SW=9000 []
      DATA(26): 43 01 99 44 05 00 B0 2F 01 00 47 03 84 21 E0 7F 66 08 02 02 02 40 02 02 02 40
      TEXT: C..D.../..G..!..f....@...@
      TLV Tag=0043 [?]: 99
      TLV Tag=0044 [?]: 00 B0 2F 01 00
      TLV Tag=0047 [?]: 84 21 E0
      TLV Tag=7F66 [?]: 02 02 02 40 02 02 02 40
      Snimljeno: ef_2F01.bin
  *** EF 2F01 P1=00 P2=0C -> SW=9000 []
      DATA(26): 43 01 99 44 05 00 B0 2F 01 00 47 03 84 21 E0 7F 66 08 02 02 02 40 02 02 02 40
      TEXT: C..D.../..G..!..f....@...@
      TLV Tag=0043 [?]: 99
      TLV Tag=0044 [?]: 00 B0 2F 01 00
      TLV Tag=0047 [?]: 84 21 E0
      TLV Tag=7F66 [?]: 02 02 02 40 02 02 02 40
      Snimljeno: ef_2F01.bin

========== TEST 3: READ RECORD ==========

========== TEST 4: PROPRIETARY (CLA=80) ==========

========== TEST 5: AID sa Le=00 ==========
SELECT AID BAEID2 sa Le=00 -> SW=6A82 []
SELECT null AID -> SW=9000 [6F 10 84 08 A0 00 00 01 51 00 00 00 A5 04 9F 65 01 FF]
  Null AID uspio! Čitam fajlove...

=== Završeno - pošalji output! ===

Process finished with exit code 0





import javax.smartcardio.*;
import java.util.*;
import java.io.*;

/**
 * BiH eID Explorer v3 - Sistematsko istraživanje kartice
 *
 * Kompajliranje: javac BihEidReader.java
 * Pokretanje:    java BihEidReader
 */
public class BihEidReader {

    public static void main(String[] args) {
        System.out.println("===========================================");
        System.out.println("  BiH eID Explorer v3  |  BAEID2.0");
        System.out.println("===========================================\n");

        try {
            TerminalFactory factory = TerminalFactory.getDefault();
            List<CardTerminal> terminals = factory.terminals().list();

            CardTerminal terminal = null;
            for (CardTerminal t : terminals) {
                if (t.isCardPresent()) { terminal = t; break; }
            }
            if (terminal == null) {
                terminals.get(0).waitForCardPresent(15000);
                terminal = terminals.get(0);
            }

            System.out.println("Čitač: " + terminal.getName());
            Card card = terminal.connect("*");
            CardChannel ch = card.getBasicChannel();
            System.out.println("ATR: " + hex(card.getATR().getBytes()) + "\n");

            // ===================================================
            // TEST 1: SELECT MF razne kombinacije
            // ===================================================
            System.out.println("========== TEST 1: SELECT MF ==========");
            for (byte p2 : new byte[]{0x00, 0x04, 0x0C}) {
                ResponseAPDU r = ch.transmit(new CommandAPDU(
                    new byte[]{0x00,(byte)0xA4,0x00,p2,0x02,(byte)0x3F,(byte)0x00}));
                System.out.printf("SELECT MF P2=%02X -> SW=%04X data=[%s]%n",
                    p2 & 0xFF, r.getSW(), hex(r.getData()));
            }
            // SELECT MF bez Lc (samo 2 bajta)
            ResponseAPDU r0 = ch.transmit(new CommandAPDU(new byte[]{0x00,(byte)0xA4,0x00,0x00}));
            System.out.printf("SELECT MF bez Lc -> SW=%04X%n", r0.getSW());

            // ===================================================
            // TEST 2: Brute-force File ID-ovi (nakon MF reset)
            // ===================================================
            System.out.println("\n========== TEST 2: BRUTE-FORCE FILE IDs ==========");
            ch.transmit(new CommandAPDU(hexToBytes("00A4000C023F00")));

            // Svaki (hiB, loB) par, probaj P1=02 (by file ID) i P1=00
            int[][] tries = {
                {0x00,0x01},{0x00,0x02},{0x00,0x03},{0x00,0x04},{0x00,0x05},
                {0x01,0x01},{0x01,0x02},{0x01,0x03},{0x01,0x04},{0x01,0x05},
                {0x02,0x01},{0x02,0x02},{0x02,0x03},{0x02,0x04},{0x02,0x05},
                {0x03,0x01},{0x03,0x02},{0x03,0x03},
                {0x10,0x01},{0x10,0x02},{0x10,0x03},
                {0x20,0x01},{0x20,0x02},{0x20,0x03},
                {0x50,0x01},{0x50,0x02},{0x50,0x03},
                {0xD0,0x01},{0xD0,0x02},{0xD0,0x03},{0xD0,0x04},
                {0xEF,0x01},{0xEF,0x02},{0xEF,0x03},
                {0x3F,0x01},{0x3F,0x02},
                {0x2F,0x00},{0x2F,0x01},{0x2F,0x02},  // standard EFs
            };

            for (int[] fid : tries) {
                byte hi = (byte)fid[0], lo = (byte)fid[1];
                for (byte p1 : new byte[]{0x02, 0x00}) {
                    for (byte p2 : new byte[]{0x00, 0x0C}) {
                        byte[] sel = {0x00,(byte)0xA4,p1,p2,0x02,hi,lo};
                        ResponseAPDU r = ch.transmit(new CommandAPDU(sel));
                        int sw = r.getSW();
                        if (sw != 0x6A82 && sw != 0x6D00 && sw != 0x6E00 && sw != 0x6700 && sw != 0x6800) {
                            System.out.printf("  *** EF %02X%02X P1=%02X P2=%02X -> SW=%04X [%s]%n",
                                hi&0xFF, lo&0xFF, p1&0xFF, p2&0xFF, sw, hex(r.getData()));
                            if (sw == 0x9000 || (sw & 0xFF00) == 0x6100) {
                                byte[] data = readBinary(ch);
                                if (data.length > 0) {
                                    System.out.println("      DATA(" + data.length + "): " + hex(data));
                                    System.out.println("      TEXT: " + toText(data));
                                    parseTLV(data);
                                    // Sačuvaj fajl
                                    String fname = String.format("ef_%02X%02X.bin", hi&0xFF, lo&0xFF);
                                    saveFile(data, fname);
                                    System.out.println("      Snimljeno: " + fname);
                                }
                            }
                        }
                    }
                }
            }

            // ===================================================
            // TEST 3: READ RECORD (EMV stil)
            // ===================================================
            System.out.println("\n========== TEST 3: READ RECORD ==========");
            ch.transmit(new CommandAPDU(hexToBytes("00A4000C023F00")));
            for (int sfi = 1; sfi <= 30; sfi++) {
                for (int rec = 1; rec <= 5; rec++) {
                    byte p2 = (byte)((sfi << 3) | 0x04);
                    byte[] apdu = {0x00,(byte)0xB2,(byte)rec,p2,0x00};
                    ResponseAPDU r = ch.transmit(new CommandAPDU(apdu));
                    int sw = r.getSW();
                    if (sw == 0x9000 && r.getData().length > 0) {
                        System.out.printf("  READ RECORD SFI=%d REC=%d -> SW=%04X DATA: %s%n",
                            sfi, rec, sw, hex(r.getData()));
                        System.out.println("  TEXT: " + toText(r.getData()));
                        parseTLV(r.getData());
                    } else if ((sw & 0xFF00) == 0x6C00) {
                        // Ponovi sa tačnom dužinom
                        byte[] apdu2 = {0x00,(byte)0xB2,(byte)rec,p2,(byte)(sw&0xFF)};
                        ResponseAPDU r2 = ch.transmit(new CommandAPDU(apdu2));
                        if (r2.getSW() == 0x9000) {
                            System.out.printf("  READ RECORD SFI=%d REC=%d (retry): %s%n",
                                sfi, rec, hex(r2.getData()));
                        }
                    }
                }
            }

            // ===================================================
            // TEST 4: Proprietarne CLA=80 komande
            // ===================================================
            System.out.println("\n========== TEST 4: PROPRIETARY (CLA=80) ==========");
            String[] cmds80 = {
                "80 CA 00 01 00", "80 CA 00 02 00", "80 CA 00 03 00",
                "80 CA 9F 17 00", "80 CA 9F 36 00",
                "80 B0 00 00 00", "80 B2 01 0C 00",
                "80 A4 00 00 02 3F 00",
                "80 30 00 00 00",  // GET CHALLENGE style
                "80 E2 00 00 00",
            };
            for (String cmd : cmds80) {
                ResponseAPDU r = ch.transmit(new CommandAPDU(hexToBytes(cmd.replace(" ",""))));
                int sw = r.getSW();
                if (sw != 0x6D00 && sw != 0x6E00 && sw != 0x6700 && sw != 0x6800) {
                    System.out.printf("  %s -> SW=%04X [%s]%n", cmd, sw, hex(r.getData()));
                }
            }

            // ===================================================
            // TEST 5: IDDEEA specifični AID sa Le=00 na kraju
            // ===================================================
            System.out.println("\n========== TEST 5: AID sa Le=00 ==========");
            // Neke kartice zahtijevaju Le bajt na SELECT AID
            byte[] aidBytes = hexToBytes("F34549445F424945494432");
            byte[] selAidLe = new byte[6 + aidBytes.length];
            selAidLe[0]=0x00; selAidLe[1]=(byte)0xA4;
            selAidLe[2]=0x04; selAidLe[3]=0x00;
            selAidLe[4]=(byte)aidBytes.length;
            System.arraycopy(aidBytes, 0, selAidLe, 5, aidBytes.length);
            selAidLe[5+aidBytes.length]=0x00; // Le

            ResponseAPDU rAid = ch.transmit(new CommandAPDU(selAidLe));
            System.out.printf("SELECT AID BAEID2 sa Le=00 -> SW=%04X [%s]%n",
                rAid.getSW(), hex(rAid.getData()));

            // AID sa prvim bajtom = 00 (null AID - select first)
            ResponseAPDU rNull = ch.transmit(new CommandAPDU(
                new byte[]{0x00,(byte)0xA4,0x04,0x00,0x00}));
            System.out.printf("SELECT null AID -> SW=%04X [%s]%n",
                rNull.getSW(), hex(rNull.getData()));

            if (rNull.getSW() == 0x9000 || (rNull.getSW() & 0xFF00) == 0x6100) {
                System.out.println("  Null AID uspio! Čitam fajlove...");
                tryReadAllFiles(ch);
            }

            card.disconnect(false);
            System.out.println("\n=== Završeno - pošalji output! ===");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void tryReadAllFiles(CardChannel ch) throws CardException {
        int[][] fids = {
            {0x01,0x01},{0x01,0x02},{0x01,0x03},
            {0x02,0x01},{0x02,0x02},{0x02,0x03},
            {0xD0,0x01},{0xD0,0x02},{0xD0,0x03},
        };
        for (int[] fid : fids) {
            byte[] sel = {0x00,(byte)0xA4,0x02,0x0C,0x02,(byte)fid[0],(byte)fid[1]};
            ResponseAPDU r = ch.transmit(new CommandAPDU(sel));
            if (r.getSW() == 0x9000) {
                byte[] data = readBinary(ch);
                if (data.length > 0) {
                    System.out.printf("  EF %02X%02X: %s%n", fid[0], fid[1], hex(data));
                    System.out.println("  TEXT: " + toText(data));
                    parseTLV(data);
                }
            }
        }
    }

    private static byte[] readBinary(CardChannel ch) throws CardException {
        List<Byte> all = new ArrayList<>();
        int offset = 0, block = 0xEF;
        while (true) {
            byte[] apdu = {0x00,(byte)0xB0,
                (byte)((offset>>8)&0x7F),(byte)(offset&0xFF),(byte)block};
            ResponseAPDU r = ch.transmit(new CommandAPDU(apdu));
            int sw = r.getSW();
            if (sw == 0x9000) {
                byte[] d = r.getData();
                if (d.length == 0) break;
                for (byte b : d) all.add(b);
                offset += d.length;
                if (d.length < block) break;
            } else if ((sw & 0xFF00) == 0x6C00) {
                block = sw & 0xFF; if (block == 0) block = 0x100;
            } else if ((sw & 0xFF00) == 0x6100) {
                int n = sw & 0xFF; if (n == 0) n = 0xFF;
                ResponseAPDU gr = ch.transmit(new CommandAPDU(
                    new byte[]{0x00,(byte)0xC0,0x00,0x00,(byte)n}));
                if (gr.getSW() == 0x9000) for (byte b : gr.getData()) all.add(b);
                break;
            } else break;
        }
        byte[] res = new byte[all.size()];
        for (int i = 0; i < res.length; i++) res[i] = all.get(i);
        return res;
    }

    private static void parseTLV(byte[] data) {
        if (data.length < 2) return;
        int i = 0;
        while (i < data.length - 1) {
            int tag = data[i] & 0xFF;
            if (tag == 0x00 || tag == 0xFF) { i++; continue; }
            if ((tag & 0x1F) == 0x1F && i+1 < data.length) {
                tag = (tag<<8)|(data[i+1]&0xFF); i+=2;
            } else i++;
            if (i >= data.length) break;
            int len = data[i] & 0xFF; i++;
            if (len == 0x81 && i < data.length) { len = data[i]&0xFF; i++; }
            else if (len == 0x82 && i+1 < data.length) {
                len = ((data[i]&0xFF)<<8)|(data[i+1]&0xFF); i+=2;
            }
            if (i+len > data.length || len <= 0) break;
            byte[] val = Arrays.copyOfRange(data, i, i+len); i+=len;
            boolean print = val.length > 0;
            for (byte b : val) { int c=b&0xFF; if(c<0x20||c>0x7E){print=false;break;} }
            System.out.printf("      TLV Tag=%04X [%s]: %s%n", tag, tagName(tag),
                print ? new String(val).trim() : hex(val));
        }
    }

    private static String tagName(int t) {
        switch(t) {
            case 0x5F01: return "Ime";         case 0x5F02: return "Prezime";
            case 0x5F03: return "Srednje";     case 0x5F04: return "Datum rod.";
            case 0x5F05: return "Pol";         case 0x5F06: return "JMBG";
            case 0x5F07: return "Broj LK";     case 0x5F08: return "Izdat";
            case 0x5F09: return "Istice";      case 0x5F0A: return "Organ";
            case 0x5F0B: return "Mj.rod.";     case 0x5F0C: return "Ulica";
            case 0x5F0D: return "Kuc.br.";     case 0x5F0E: return "Grad";
            case 0x5F0F: return "Opcina";      case 0x5F10: return "PTT";
            case 0x5F20: return "MRZ";         case 0x5F24: return "Expiry";
            case 0x5F28: return "Zemlja";      case 0x5F2C: return "Nat.";
            default: return "?";
        }
    }

    private static void saveFile(byte[] data, String name) {
        try (FileOutputStream fos = new FileOutputStream(name)) { fos.write(data); }
        catch (Exception e) { System.out.println("Greška snimanja: " + e.getMessage()); }
    }

    private static String toText(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            int c = b&0xFF;
            sb.append((c>=0x20&&c<=0x7E) ? (char)c : '.');
        }
        return sb.toString();
    }

    private static String hex(byte[] b) {
        if (b==null||b.length==0) return "";
        StringBuilder sb=new StringBuilder();
        for (byte x:b) sb.append(String.format("%02X ",x));
        return sb.toString().trim();
    }

    private static byte[] hexToBytes(String s) {
        s=s.replace(" ","");
        byte[] d=new byte[s.length()/2];
        for (int i=0;i<d.length;i++)
            d[i]=(byte)((Character.digit(s.charAt(i*2),16)<<4)+Character.digit(s.charAt(i*2+1),16));
        return d;
    }
}


import javax.smartcardio.*;
import java.util.*;
import java.io.*;
import java.nio.charset.StandardCharsets;

/**
 * BiH eID Reader v2 – kompatibilno sa BAEID2.0 (IDDEEA gen2)
 *
 * Kompajliranje: javac BihEidReader.java
 * Pokretanje:    java BihEidReader
 */
public class BihEidReader {

    // AID kandidati za BiH eID
    private static final byte[][] AID_CANDIDATES = {
        hexToBytes("F34549445F424945494432"),   // BAEID2 standardni
        hexToBytes("A000000367455349474E"),      // eSign
        hexToBytes("A0000000183003"),            // generički eID
        hexToBytes("F3454944"),                  // kratki BAEID
        hexToBytes("A00000018830030000"),        // varijanta
    };

    public static void main(String[] args) {
        System.out.println("===========================================");
        System.out.println("  BiH eID Reader v2  |  BAEID2.0");
        System.out.println("===========================================\n");

        try {
            TerminalFactory factory = TerminalFactory.getDefault();
            List<CardTerminal> terminals = factory.terminals().list();

            if (terminals.isEmpty()) {
                System.out.println("[GREŠKA] Nije pronađen nijedan čitač!");
                return;
            }

            CardTerminal terminal = null;
            for (CardTerminal t : terminals) {
                System.out.println("Čitač: " + t.getName() + " | kartica: " + t.isCardPresent());
                if (t.isCardPresent()) terminal = t;
            }

            if (terminal == null) {
                System.out.println("Ubaci karticu...");
                terminals.get(0).waitForCardPresent(30000);
                terminal = terminals.get(0);
            }

            System.out.println("\nSpajam se na: " + terminal.getName());
            Card card = terminal.connect("*");
            CardChannel ch = card.getBasicChannel();

            byte[] atr = card.getATR().getBytes();
            System.out.println("ATR: " + bytesToHex(atr));
            System.out.println("ATR string: " + atrToString(atr));
            System.out.println();

            // KORAK 1: SELECT MF
            System.out.println("--- SELECT MF ---");
            ResponseAPDU mfResp = ch.transmit(new CommandAPDU(hexToBytes("00A40004023F00")));
            System.out.println("MF SW: " + swHex(mfResp));
            if (mfResp.getData().length > 0)
                System.out.println("MF Data: " + bytesToHex(mfResp.getData()));

            // KORAK 2: Probaj sve AID kandidate
            System.out.println("\n--- TRAŽIM AID APLIKACIJE ---");
            boolean aidFound = false;
            for (byte[] aid : AID_CANDIDATES) {
                byte[] selectAid = buildSelectAid(aid);
                ResponseAPDU r = ch.transmit(new CommandAPDU(selectAid));
                System.out.printf("AID %s -> SW=%s%n", bytesToHex(aid), swHex(r));
                if (r.getSW() == 0x9000 || (r.getSW() & 0xFF00) == 0x6100) {
                    System.out.println("  ✓ AID pronađen! Response: " + bytesToHex(r.getData()));
                    aidFound = true;
                    System.out.println("\n  Probam EF fajlove...");
                    tryReadAllFiles(ch);
                    break;
                }
            }

            if (!aidFound) {
                System.out.println("\nNijedan AID nije prihvaćen. Probam direktno čitanje...");
                tryDirectRead(ch);
            }

            // KORAK 3: GET DATA
            System.out.println("\n--- POKUŠAJ GET DATA ---");
            tryGetData(ch);

            card.disconnect(false);
            System.out.println("\n=== Završeno ===");

        } catch (Exception e) {
            System.out.println("[GREŠKA] " + e.getMessage());
            e.printStackTrace();
        }
    }

    // -------------------------------------------------------
    private static void tryReadAllFiles(CardChannel ch) throws CardException {
        int[][] fileIds = {
            {0x01, 0x01}, {0x01, 0x02}, {0x01, 0x03}, {0x01, 0x04},
            {0x02, 0x01}, {0x02, 0x02}, {0x02, 0x03},
            {0x00, 0x01}, {0x00, 0x02}, {0x00, 0x03},
            {0xD0, 0x01}, {0xD0, 0x02}, {0xD0, 0x03},
        };

        for (int[] fid : fileIds) {
            byte[] sel = {0x00, (byte)0xA4, 0x02, 0x0C, 0x02, (byte)fid[0], (byte)fid[1]};
            ResponseAPDU r = ch.transmit(new CommandAPDU(sel));
            if (r.getSW() == 0x9000 || (r.getSW() & 0xFF00) == 0x6100) {
                System.out.printf("  EF %02X%02X -> SELECT OK%n", fid[0], fid[1]);
                byte[] data = readBinary(ch);
                if (data != null && data.length > 0) {
                    System.out.println("    Data (" + data.length + "b): " + bytesToHex(data));
                    String txt = extractReadableText(data);
                    if (!txt.isEmpty()) System.out.println("    Tekst: " + txt);
                    parseTLV(data, "    ");
                }
            }
        }
    }

    private static void tryDirectRead(CardChannel ch) throws CardException {
        System.out.println("Direktno READ BINARY:");
        byte[] data = readBinary(ch);
        if (data != null && data.length > 0) {
            System.out.println("Data: " + bytesToHex(data));
            System.out.println("Tekst: " + extractReadableText(data));
            parseTLV(data, "  ");
        } else {
            System.out.println("Nema podataka.");
        }
    }

    private static void tryGetData(CardChannel ch) throws CardException {
        int[] tags = {0x9F01, 0x9F07, 0x9F08, 0x9F0D, 0x9F0E, 0x9F0F,
                      0x5F24, 0x5F20, 0x5F2C, 0x5F28, 0x9F49, 0x9F69};
        for (int tag : tags) {
            byte[] apdu = {0x00, (byte)0xCA, (byte)((tag>>8)&0xFF), (byte)(tag&0xFF), 0x00};
            ResponseAPDU r = ch.transmit(new CommandAPDU(apdu));
            if (r.getSW() == 0x9000 && r.getData().length > 0) {
                System.out.printf("  GET DATA %04X: %s%n", tag, bytesToHex(r.getData()));
            }
        }
    }

    private static byte[] readBinary(CardChannel ch) throws CardException {
        List<Byte> all = new ArrayList<>();
        int offset = 0;
        int block = 0xEF;

        while (true) {
            byte[] apdu = {
                0x00, (byte)0xB0,
                (byte)((offset >> 8) & 0x7F),
                (byte)(offset & 0xFF),
                (byte)block
            };
            ResponseAPDU r = ch.transmit(new CommandAPDU(apdu));
            int sw = r.getSW();

            if (sw == 0x9000) {
                byte[] d = r.getData();
                if (d.length == 0) break;
                for (byte b : d) all.add(b);
                offset += d.length;
                if (d.length < block) break;
            } else if ((sw & 0xFF00) == 0x6C00) {
                block = sw & 0xFF;
                if (block == 0) block = 0x100;
                continue;
            } else if ((sw & 0xFF00) == 0x6100) {
                int respLen = sw & 0xFF;
                if (respLen == 0) respLen = 0xFF;
                ResponseAPDU gr = ch.transmit(new CommandAPDU(
                    new byte[]{0x00, (byte)0xC0, 0x00, 0x00, (byte)respLen}));
                if (gr.getSW() == 0x9000) {
                    for (byte b : gr.getData()) all.add(b);
                }
                break;
            } else {
                break;
            }
        }

        byte[] res = new byte[all.size()];
        for (int i = 0; i < res.length; i++) res[i] = all.get(i);
        return res;
    }

    // -------------------------------------------------------
    private static void parseTLV(byte[] data, String indent) {
        if (data.length < 2) return;
        int i = 0;
        while (i < data.length - 1) {
            int tag = data[i] & 0xFF;
            if (tag == 0x00 || tag == 0xFF) { i++; continue; }
            if ((tag & 0x1F) == 0x1F && i + 1 < data.length) {
                tag = (tag << 8) | (data[i+1] & 0xFF);
                i += 2;
            } else {
                i++;
            }
            if (i >= data.length) break;
            int len = data[i] & 0xFF;
            i++;
            if (len == 0x81 && i < data.length) { len = data[i] & 0xFF; i++; }
            else if (len == 0x82 && i + 1 < data.length) {
                len = ((data[i]&0xFF)<<8)|(data[i+1]&0xFF); i+=2;
            }
            if (i + len > data.length) break;
            byte[] val = Arrays.copyOfRange(data, i, i + len);
            i += len;
            String valStr = isPrintable(val) ? new String(val).trim() : bytesToHex(val);
            System.out.printf("%sTag=0x%X [%s]: %s%n", indent, tag, getTagName(tag), valStr);
        }
    }

    // -------------------------------------------------------
    private static byte[] buildSelectAid(byte[] aid) {
        byte[] apdu = new byte[5 + aid.length];
        apdu[0] = 0x00; apdu[1] = (byte)0xA4;
        apdu[2] = 0x04; apdu[3] = 0x00;
        apdu[4] = (byte)aid.length;
        System.arraycopy(aid, 0, apdu, 5, aid.length);
        return apdu;
    }

    private static String extractReadableText(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            int c = b & 0xFF;
            if (c >= 0x20 && c <= 0x7E) sb.append((char)c);
            else if (sb.length() > 0 && sb.charAt(sb.length()-1) != ' ') sb.append(' ');
        }
        return sb.toString().replaceAll("\\s+", " ").trim();
    }

    private static String atrToString(byte[] atr) {
        StringBuilder sb = new StringBuilder();
        for (byte b : atr) {
            int c = b & 0xFF;
            if (c >= 0x20 && c <= 0x7E) sb.append((char)c);
        }
        return sb.toString();
    }

    private static String getTagName(int tag) {
        switch (tag) {
            case 0x5F01: return "Ime";
            case 0x5F02: return "Prezime";
            case 0x5F03: return "Srednje ime";
            case 0x5F04: return "Datum rodjenja";
            case 0x5F05: return "Pol";
            case 0x5F06: return "JMBG";
            case 0x5F07: return "Broj LK";
            case 0x5F08: return "Datum izdavanja";
            case 0x5F09: return "Datum isteka";
            case 0x5F0A: return "Organ izdavanja";
            case 0x5F0B: return "Mjesto rodjenja";
            case 0x5F0C: return "Ulica";
            case 0x5F0D: return "Kucni broj";
            case 0x5F0E: return "Grad";
            case 0x5F0F: return "Opcina";
            case 0x5F10: return "Postanski broj";
            case 0x5F20: return "MRZ ime";
            case 0x5F24: return "Datum isteka";
            case 0x5F28: return "Zemlja";
            case 0x5F2C: return "Nacionalnost";
            case 0x5F35: return "Pol ICAO";
            default: return "?";
        }
    }

    private static boolean isPrintable(byte[] data) {
        if (data.length == 0) return false;
        for (byte b : data) {
            int c = b & 0xFF;
            if (c < 0x20 && c != 0x0A && c != 0x0D) return false;
            if (c > 0x7E && c < 0xA0) return false;
        }
        return true;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02X ", b));
        return sb.toString().trim();
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2)
            data[i/2] = (byte)((Character.digit(hex.charAt(i),16)<<4)
                              + Character.digit(hex.charAt(i+1),16));
        return data;
    }

    private static String swHex(ResponseAPDU r) {
        return String.format("%04X", r.getSW());
    }
}



import javax.smartcardio.*;
import java.util.*;

/**
 * BiH eID Card Reader
 * Čita podatke sa BiH lične karte putem PC/SC interfejsa
 * Kompatibilno sa IDDEEA middlewareom i OmniKey čitačem
 *
 * Kompajliranje: javac BihEidReader.java
 * Pokretanje:    java BihEidReader
 */
public class BihEidReader {

    // -------------------------------------------------------
    // BiH eID APDUs i File IDevi
    // -------------------------------------------------------

    // SELECT aplikacije po AID-u (BiH eID)
    private static final byte[] SELECT_MF          = hexToBytes("00A40004023F00");
    private static final byte[] SELECT_EF_ID       = hexToBytes("00A4000402D001"); // Lični podaci
    private static final byte[] SELECT_EF_ADDRESS  = hexToBytes("00A4000402D002"); // Adresa
    private static final byte[] SELECT_EF_PHOTO    = hexToBytes("00A4000402D003"); // Fotografija (binary)

    // READ BINARY – čita do 256 bajtova (Le=0x00 → 256)
    private static final byte[] READ_BINARY_BASE   = {0x00, (byte)0xB0, 0x00, 0x00, 0x00};

    // -------------------------------------------------------
    // Glavni program
    // -------------------------------------------------------
    public static void main(String[] args) {
        System.out.println("===========================================");
        System.out.println("  BiH eID Reader  |  IDDEEA + OmniKey");
        System.out.println("===========================================\n");

        try {
            // 1) Nabavi TerminalFactory (koristi sistemski PC/SC)
            TerminalFactory factory = TerminalFactory.getDefault();
            List<CardTerminal> terminals = factory.terminals().list();

            if (terminals.isEmpty()) {
                System.out.println("[GREŠKA] Nije pronađen nijedan čitač kartica!");
                System.out.println("Provjeri da li je OmniKey čitač priključen i driveri instalirani.");
                return;
            }

            System.out.println("Pronađeni čitači:");
            for (int i = 0; i < terminals.size(); i++) {
                System.out.println("  [" + i + "] " + terminals.get(i).getName());
            }
            System.out.println();

            // 2) Odaberi prvi čitač (ili onaj koji ima karticu)
            CardTerminal terminal = null;
            for (CardTerminal t : terminals) {
                if (t.isCardPresent()) {
                    terminal = t;
                    break;
                }
            }

            if (terminal == null) {
                System.out.println("[ČEKANJE] Ubaci ličnu kartu u čitač...");
                terminals.get(0).waitForCardPresent(30000);
                terminal = terminals.get(0);
            }

            System.out.println("Koristim čitač: " + terminal.getName());
            System.out.println("Kartica ubačena. Uspostavljam vezu...\n");

            // 3) Spoji se na karticu (T=0 ili T=1 automatski)
            Card card = terminal.connect("*");
            CardChannel channel = card.getBasicChannel();

            System.out.println("ATR: " + bytesToHex(card.getATR().getBytes()));
            System.out.println();

            // 4) Čitanje ličnih podataka
            System.out.println("--- LIČNI PODACI ---");
            readAndParseFile(channel, SELECT_EF_ID, true);

            // 5) Čitanje adrese
            System.out.println("\n--- ADRESA ---");
            readAndParseFile(channel, SELECT_EF_ADDRESS, true);

            // 6) Fotografija (samo veličina, ne ispisujemo binary)
            System.out.println("\n--- FOTOGRAFIJA ---");
            byte[] photo = readBinaryFile(channel, SELECT_EF_PHOTO);
            if (photo != null) {
                System.out.println("Fotografija pročitana, veličina: " + photo.length + " bajtova");
                System.out.println("(JPEG/BMP data – sačuvaj u fajl po potrebi)");
                // Opciono: sačuvaj u fajl
                saveToFile(photo, "photo.jpg");
                System.out.println("Sačuvana kao: photo.jpg");
            }

            card.disconnect(false);
            System.out.println("\n=== Čitanje završeno ===");

        } catch (CardException e) {
            System.out.println("[GREŠKA PC/SC] " + e.getMessage());
            e.printStackTrace();
        } catch (Exception e) {
            System.out.println("[GREŠKA] " + e.getMessage());
            e.printStackTrace();
        }
    }

    // -------------------------------------------------------
    // Odabir fajla i parsiranje TLV podataka
    // -------------------------------------------------------
    private static void readAndParseFile(CardChannel channel, byte[] selectApdu, boolean parseTlv)
            throws CardException {

        byte[] data = readBinaryFile(channel, selectApdu);
        if (data == null) return;

        System.out.println("Raw hex: " + bytesToHex(data));
        System.out.println();

        if (parseTlv) {
            parseTLV(data);
        }
    }

    private static byte[] readBinaryFile(CardChannel channel, byte[] selectApdu) throws CardException {
        // SELECT fajl
        ResponseAPDU selectResp = channel.transmit(new CommandAPDU(selectApdu));
        if (selectResp.getSW() != 0x9000) {
            System.out.println("[UPOZORENJE] SELECT nije uspio, SW=" +
                    String.format("%04X", selectResp.getSW()));
            return null;
        }

        // Čitaj binarne podatke u blokovima
        List<Byte> allData = new ArrayList<>();
        int offset = 0;
        int blockSize = 0xEF; // siguran blok za većinu čitača

        while (true) {
            byte[] readApdu = {
                0x00, (byte)0xB0,
                (byte)((offset >> 8) & 0x7F),
                (byte)(offset & 0xFF),
                (byte)blockSize
            };

            ResponseAPDU resp = channel.transmit(new CommandAPDU(readApdu));
            int sw = resp.getSW();

            if (sw == 0x9000 || (sw & 0xFF00) == 0x6200) {
                byte[] chunk = resp.getData();
                if (chunk.length == 0) break;
                for (byte b : chunk) allData.add(b);
                offset += chunk.length;
                if (chunk.length < blockSize) break; // zadnji blok
            } else if ((sw & 0xFF00) == 0x6C00) {
                // 6CXX – ponovi sa tačnom dužinom
                blockSize = sw & 0x00FF;
                continue;
            } else if (sw == 0x6B00 || sw == 0x6982 || sw == 0x6A82) {
                break; // kraj fajla ili pristup odbijen
            } else {
                break;
            }
        }

        byte[] result = new byte[allData.size()];
        for (int i = 0; i < result.length; i++) result[i] = allData.get(i);
        return result;
    }

    // -------------------------------------------------------
    // TLV Parser – BiH eID koristi BER-TLV kodiranje
    // -------------------------------------------------------
    private static void parseTLV(byte[] data) {
        int i = 0;
        while (i < data.length - 1) {
            int tag = data[i] & 0xFF;
            if (tag == 0x00 || tag == 0xFF) { i++; continue; }

            // Dvo-bajtni tag?
            if ((tag & 0x1F) == 0x1F && i + 1 < data.length) {
                tag = (tag << 8) | (data[i+1] & 0xFF);
                i += 2;
            } else {
                i++;
            }

            if (i >= data.length) break;

            // Dužina
            int len = data[i] & 0xFF;
            i++;
            if (len == 0x81 && i < data.length) {
                len = data[i] & 0xFF; i++;
            } else if (len == 0x82 && i + 1 < data.length) {
                len = ((data[i] & 0xFF) << 8) | (data[i+1] & 0xFF); i += 2;
            }

            if (i + len > data.length) break;

            byte[] value = Arrays.copyOfRange(data, i, i + len);
            i += len;

            String tagName = getTagName(tag);
            String valueStr = isPrintable(value) ?
                    new String(value).trim() :
                    bytesToHex(value);

            System.out.printf("  Tag 0x%X %-30s : %s%n", tag, "(" + tagName + ")", valueStr);
        }
    }

    private static String getTagName(int tag) {
        // BiH eID poznati tagovi (ICAO + IDDEEA specifični)
        switch (tag) {
            case 0x61: return "Aplikacijska predloška";
            case 0x5F01: return "Ime";
            case 0x5F02: return "Prezime";
            case 0x5F03: return "Srednje ime";
            case 0x5F04: return "Datum rođenja";
            case 0x5F05: return "Pol";
            case 0x5F06: return "JMBG";
            case 0x5F07: return "Broj lične karte";
            case 0x5F08: return "Datum izdavanja";
            case 0x5F09: return "Datum isteka";
            case 0x5F0A: return "Organ izdavanja";
            case 0x5F0B: return "Mjesto rođenja";
            case 0x5F0C: return "Ulica";
            case 0x5F0D: return "Kućni broj";
            case 0x5F0E: return "Grad";
            case 0x5F0F: return "Općina";
            case 0x5F10: return "Poštanski broj";
            case 0x5F11: return "Kanton/Entitet";
            case 0x5F12: return "Državljanstvo";
            case 0x5F1F: return "MRZ red 1";
            case 0x5F20: return "MRZ red 2";
            case 0x5F2C: return "Nacionalnost";
            case 0x5F35: return "Pol (ICAO)";
            case 0x80:   return "Kontekstualni podatak";
            case 0x9F0E: return "Broj dokumenta";
            default:     return "Nepoznat";
        }
    }

    // -------------------------------------------------------
    // Pomoćne metode
    // -------------------------------------------------------
    private static boolean isPrintable(byte[] data) {
        for (byte b : data) {
            int c = b & 0xFF;
            if (c < 0x20 && c != 0x0A && c != 0x0D) return false;
            if (c > 0x7E && c < 0xA0) return false;
        }
        return data.length > 0;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02X ", b));
        return sb.toString().trim();
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2)
            data[i / 2] = (byte)((Character.digit(hex.charAt(i), 16) << 4)
                                + Character.digit(hex.charAt(i+1), 16));
        return data;
    }

    private static void saveToFile(byte[] data, String filename) {
        try {
            java.io.FileOutputStream fos = new java.io.FileOutputStream(filename);
            fos.write(data);
            fos.close();
        } catch (Exception e) {
            System.out.println("[GREŠKA] Nije moguće sačuvati fajl: " + e.getMessage());
        }
    }
}



import javax.smartcardio.*;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.*;

public class EidNfcFullFinal {

    private static final String DLL_PATH =
            "C:\\Users\\w881348\\Desktop\\ocr\\New folder\\opensc_pkcs11.dll";

    public static void main(String[] args) throws Exception {

        System.out.println("=================================");
        System.out.println("📡 Čekam NFC karticu...");
        System.out.println("=================================\n");

        TerminalFactory factory = TerminalFactory.getDefault();
        List<CardTerminal> terminals = factory.terminals().list();

        if (terminals.isEmpty()) {
            System.out.println("❌ Nema čitača");
            return;
        }

        // -----------------------------------
        // NAĐI NFC (CL) READER
        // -----------------------------------
        CardTerminal terminal = null;

        for (CardTerminal t : terminals) {
            System.out.println("Reader: " + t.getName());

            if (t.getName().toLowerCase().contains("cl")) {
                terminal = t;
            }
        }

        if (terminal == null) {
            terminal = terminals.get(0);
        }

        System.out.println("\n✔ Koristim: " + terminal.getName());

        // -----------------------------------
        // LOOP
        // -----------------------------------
        while (true) {

            terminal.waitForCardPresent(0);
            System.out.println("\n📇 Kartica detektovana!");

            try {
                readCard();
            } catch (Exception e) {
                System.out.println("❌ Greška:");
                e.printStackTrace();
            }

            terminal.waitForCardAbsent(0);
            System.out.println("\n📤 Kartica uklonjena");
            System.out.println("\n📡 Čekam novu...");
        }
    }

    // -----------------------------------
    // GLAVNO ČITANJE
    // -----------------------------------
    private static void readCard() {

        for (int slot = 0; slot < 5; slot++) {

            try {

                System.out.println("\n🔍 Testiram slot: " + slot);

                String config =
                        "name=SmartCard\n" +
                        "library=" + DLL_PATH + "\n" +
                        "slotListIndex=" + slot + "\n";

                File cfg = File.createTempFile("pkcs11", ".cfg");

                try (FileOutputStream fos = new FileOutputStream(cfg)) {
                    fos.write(config.getBytes(StandardCharsets.UTF_8));
                }

                sun.security.pkcs11.SunPKCS11 provider =
                        new sun.security.pkcs11.SunPKCS11(cfg.getAbsolutePath());

                Security.addProvider(provider);

                KeyStore ks = KeyStore.getInstance("PKCS11", provider);
                ks.load(null, null);

                Enumeration<String> aliases = ks.aliases();

                if (!aliases.hasMoreElements()) {
                    System.out.println("❌ Nema certifikata");
                    continue;
                }

                while (aliases.hasMoreElements()) {

                    String alias = aliases.nextElement();

                    X509Certificate cert =
                            (X509Certificate) ks.getCertificate(alias);

                    if (cert == null) continue;

                    if (!isEid(cert)) continue;

                    System.out.println("\n=================================");
                    System.out.println("📇 eID SA NFC KARTICE");
                    System.out.println("=================================");

                    Map<String, String> user = parseUser(cert);

                    System.out.println("Ime: " + user.get("2.5.4.42"));
                    System.out.println("Prezime: " + user.get("2.5.4.4"));

                    System.out.println("\nSubject:");
                    System.out.println(cert.getSubjectX500Principal().getName());

                    System.out.println("\n✔ SLOT RADI: " + slot);

                    return; // prekini kad nađe pravi slot
                }

            } catch (Exception e) {
                System.out.println("❌ Slot " + slot + " ne radi");
            }
        }

        System.out.println("❌ NIJEDAN SLOT NIJE RADIO");
    }

    // -----------------------------------
    // FILTER ZA BIH eID
    // -----------------------------------
    private static boolean isEid(X509Certificate cert) {

        String issuer = cert.getIssuerX500Principal().getName();

        return issuer.contains("IDDEEA") || issuer.contains("iddeea");
    }

    // -----------------------------------
    // PARSER OID + HEX
    // -----------------------------------
    private static Map<String, String> parseUser(X509Certificate cert) {

        Map<String, String> map = new HashMap<>();

        String dn = cert.getSubjectX500Principal().getName();

        String[] parts = dn.split(",");

        for (String part : parts) {

            part = part.trim();

            if (part.contains("#")) {

                String[] kv = part.split("=");

                if (kv.length == 2) {
                    map.put(kv[0], decodeHex(kv[1].replace("#", "")));
                }

            } else {

                String[] kv = part.split("=");

                if (kv.length == 2) {
                    map.put(kv[0], kv[1]);
                }
            }
        }

        return map;
    }

    // -----------------------------------
    // HEX → STRING
    // -----------------------------------
    private static String decodeHex(String hex) {

        try {

            byte[] data = new byte[hex.length() / 2];

            for (int i = 0; i < data.length; i++) {
                data[i] = (byte) Integer.parseInt(
                        hex.substring(i * 2, i * 2 + 2), 16);
            }

            if (data.length > 2 && data[0] == 0x0C) {
                byte[] real = new byte[data.length - 2];
                System.arraycopy(data, 2, real, 0, real.length);
                return new String(real, "UTF-8");
            }

            return new String(data, "UTF-8");

        } catch (Exception e) {
            return "DECODE_ERROR";
        }
    }
}




import javax.smartcardio.*;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.List;

public class EidCardOnlyPKCS11 {

    public static void main(String[] args) throws Exception {

        System.out.println("📡 Čekam karticu...");

        TerminalFactory factory = TerminalFactory.getDefault();
        List<CardTerminal> terminals = factory.terminals().list();

        CardTerminal terminal = terminals.get(0);

        while (true) {

            terminal.waitForCardPresent(0);
            System.out.println("\n📇 Kartica detektovana!");

            try {
                readFromCard();
            } catch (Exception e) {
                e.printStackTrace();
            }

            terminal.waitForCardAbsent(0);
            System.out.println("📤 Kartica uklonjena\n");
        }
    }

    private static void readFromCard() throws Exception {

        // -----------------------------------
        // 1. PKCS#11 CONFIG
        // -----------------------------------
        String dllPath = "C:\\Users\\w881348\\Desktop\\ocr\\New folder\\opensc_pkcs11.dll";

        String config =
                "name=SmartCard\n" +
                "library=" + dllPath + "\n" +
                "slotListIndex=0\n";

        File cfg = File.createTempFile("pkcs11", ".cfg");

        try (FileOutputStream fos = new FileOutputStream(cfg)) {
            fos.write(config.getBytes(StandardCharsets.UTF_8));
        }

        // -----------------------------------
        // 2. LOAD PROVIDER
        // -----------------------------------
        sun.security.pkcs11.SunPKCS11 provider =
                new sun.security.pkcs11.SunPKCS11(cfg.getAbsolutePath());

        Security.addProvider(provider);

        // -----------------------------------
        // 3. KEYSTORE (SAMO KARTICA!)
        // -----------------------------------
        KeyStore ks = KeyStore.getInstance("PKCS11", provider);

        ks.load(null, null); // PIN popup ako treba

        Enumeration<String> aliases = ks.aliases();

        if (!aliases.hasMoreElements()) {
            System.out.println("❌ Nema certifikata na kartici");
            return;
        }

        while (aliases.hasMoreElements()) {

            String alias = aliases.nextElement();

            X509Certificate cert =
                    (X509Certificate) ks.getCertificate(alias);

            if (cert == null) continue;

            System.out.println("=================================");
            System.out.println("📇 CERT SA KARTICE");
            System.out.println("=================================");

            System.out.println("Alias: " + alias);

            String subject = cert.getSubjectX500Principal().getName();

            System.out.println("Subject: " + subject);

            System.out.println("Ime: " + extractName(subject));
        }
    }

    // -----------------------------------
    // DECODE IMENA (HEX)
    // -----------------------------------
    private static String extractName(String dn) {

        try {

            if (dn.contains("#")) {

                String hex = dn.split("#")[1];

                byte[] data = new byte[hex.length() / 2];

                for (int i = 0; i < data.length; i++) {
                    data[i] = (byte) Integer.parseInt(
                            hex.substring(i * 2, i * 2 + 2), 16);
                }

                if (data[0] == 0x0C) {
                    byte[] real = new byte[data.length - 2];
                    System.arraycopy(data, 2, real, 0, real.length);
                    return new String(real, "UTF-8");
                }

                return new String(data, "UTF-8");
            }

        } catch (Exception ignored) {}

        return "UNKNOWN";
    }
}





import javax.smartcardio.*;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.*;

public class EidNfcReader {

    public static void main(String[] args) throws Exception {

        System.out.println("=================================");
        System.out.println("📡 Čekam NFC ličnu kartu...");
        System.out.println("=================================\n");

        TerminalFactory factory = TerminalFactory.getDefault();
        List<CardTerminal> terminals = factory.terminals().list();

        if (terminals.isEmpty()) {
            System.out.println("❌ NEMA ČITAČA");
            return;
        }

        CardTerminal terminal = null;

        // -----------------------------------
        // NAĐI OMNIKEY (ili prvi dostupni)
        // -----------------------------------
        for (CardTerminal t : terminals) {
            System.out.println("Reader: " + t.getName());

            if (t.getName().toLowerCase().contains("omnikey")) {
                terminal = t;
            }
        }

        if (terminal == null) {
            terminal = terminals.get(0);
        }

        System.out.println("\n✔ Koristim: " + terminal.getName());

        // -----------------------------------
        // LOOP - ČEKA KARTICU
        // -----------------------------------
        while (true) {

            terminal.waitForCardPresent(0);

            System.out.println("\n📇 Kartica detektovana!");

            try {
                readEidFromWindowsStore();
            } catch (Exception e) {
                System.out.println("❌ Greška:");
                e.printStackTrace();
            }

            // čekaj da se kartica ukloni
            terminal.waitForCardAbsent(0);

            System.out.println("\n📤 Kartica uklonjena");
            System.out.println("\n📡 Čekam novu karticu...");
        }
    }

    // -----------------------------------
    // ČITANJE CERTA (SAMO KAD JE KARTICA PRISUTNA)
    // -----------------------------------
    private static void readEidFromWindowsStore() throws Exception {

        KeyStore ks = KeyStore.getInstance("Windows-MY");
        ks.load(null, null);

        Enumeration<String> aliases = ks.aliases();

        boolean found = false;

        while (aliases.hasMoreElements()) {

            String alias = aliases.nextElement();

            X509Certificate cert =
                    (X509Certificate) ks.getCertificate(alias);

            if (cert == null) continue;

            if (!isEid(cert)) continue;

            found = true;

            System.out.println("=================================");
            System.out.println("📇 eID CERT (SA KARTICE)");
            System.out.println("=================================");

            Map<String, String> user = parseUser(cert);

            System.out.println("Ime: " + user.get("2.5.4.42"));
            System.out.println("Prezime: " + user.get("2.5.4.4"));

            System.out.println("\nSubject:");
            System.out.println(cert.getSubjectX500Principal().getName());
        }

        if (!found) {
            System.out.println("⚠ Nije pronađen eID cert (provjeri PIN / middleware)");
        }
    }

    // -----------------------------------
    // FILTER ZA BIH eID
    // -----------------------------------
    private static boolean isEid(X509Certificate cert) {

        String issuer = cert.getIssuerX500Principal().getName();

        return issuer.contains("IDDEEA") || issuer.contains("iddeea");
    }

    // -----------------------------------
    // PARSER (OID + HEX)
    // -----------------------------------
    private static Map<String, String> parseUser(X509Certificate cert) {

        Map<String, String> map = new HashMap<>();

        String dn = cert.getSubjectX500Principal().getName();

        String[] parts = dn.split(",");

        for (String part : parts) {

            part = part.trim();

            if (part.contains("#")) {

                String[] kv = part.split("=");

                if (kv.length == 2) {
                    map.put(kv[0], decodeHex(kv[1].replace("#", "")));
                }

            } else {

                String[] kv = part.split("=");

                if (kv.length == 2) {
                    map.put(kv[0], kv[1]);
                }
            }
        }

        return map;
    }

    // -----------------------------------
    // HEX → STRING
    // -----------------------------------
    private static String decodeHex(String hex) {

        try {

            byte[] data = new byte[hex.length() / 2];

            for (int i = 0; i < data.length; i++) {
                data[i] = (byte) Integer.parseInt(
                        hex.substring(i * 2, i * 2 + 2), 16);
            }

            if (data.length > 2 && data[0] == 0x0C) {
                byte[] real = new byte[data.length - 2];
                System.arraycopy(data, 2, real, 0, real.length);
                return new String(real, "UTF-8");
            }

            return new String(data, "UTF-8");

        } catch (Exception e) {
            return "DECODE_ERROR";
        }
    }
}




import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

public class EidFullReader {

    public static void main(String[] args) throws Exception {

        System.out.println("=================================");
        System.out.println("🔵 BIH eID USER READER");
        System.out.println("=================================\n");

        // -----------------------------------
        // 1. UČITAJ WINDOWS CERT STORE
        // -----------------------------------
        KeyStore ks = KeyStore.getInstance("Windows-MY");
        ks.load(null, null);

        Enumeration<String> aliases = ks.aliases();

        boolean found = false;

        while (aliases.hasMoreElements()) {

            String alias = aliases.nextElement();

            X509Certificate cert =
                    (X509Certificate) ks.getCertificate(alias);

            if (cert == null) continue;

            // -----------------------------------
            // 2. FILTER ZA BIH eID
            // -----------------------------------
            if (!isEID(cert)) continue;

            found = true;

            System.out.println("=================================");
            System.out.println("📇 eID CERT PRONAĐEN");
            System.out.println("=================================");

            System.out.println("Alias: " + alias);

            // -----------------------------------
            // 3. PARSIRAJ USER PODATKE
            // -----------------------------------
            Map<String, String> user = parseUser(cert);

            String ime = user.get("2.5.4.42");   // ime
            String prezime = user.get("2.5.4.4"); // prezime

            System.out.println("\n👤 USER:");
            System.out.println("Ime: " + ime);
            System.out.println("Prezime: " + prezime);

            // fallback ako nema OID-a
            if (ime == null && prezime == null) {
                System.out.println("Fallback CN: " +
                        extractCN(cert.getSubjectX500Principal().getName()));
            }

            // -----------------------------------
            // 4. OSTALI PODACI
            // -----------------------------------
            System.out.println("\n📄 SUBJECT:");
            System.out.println(cert.getSubjectX500Principal().getName());

            System.out.println("\n🏢 ISSUER:");
            System.out.println(cert.getIssuerX500Principal().getName());

            System.out.println("\n🔢 SERIAL:");
            System.out.println(cert.getSerialNumber());

            System.out.println("\n📅 VALID:");
            System.out.println(cert.getNotBefore() + " -> " + cert.getNotAfter());

            // -----------------------------------
            // 5. SVI OID PODACI (DEBUG)
            // -----------------------------------
            System.out.println("\n🔍 SVI PODACI:");
            for (String key : user.keySet()) {
                System.out.println(key + " = " + user.get(key));
            }
        }

        if (!found) {
            System.out.println("❌ NIJE PRONAĐEN eID CERT");
        }
    }

    // -----------------------------------
    // PREPOZNAJ BIH eID
    // -----------------------------------
    private static boolean isEID(X509Certificate cert) {

        String issuer = cert.getIssuerX500Principal().getName();

        return issuer.contains("IDDEEA") || issuer.contains("iddeea");
    }

    // -----------------------------------
    // PARSE SUBJECT (OID + HEX)
    // -----------------------------------
    private static Map<String, String> parseUser(X509Certificate cert) {

        Map<String, String> user = new HashMap<>();

        String dn = cert.getSubjectX500Principal().getName();

        String[] parts = dn.split(",");

        for (String part : parts) {

            part = part.trim();

            if (part.contains("#")) {

                String[] kv = part.split("=");

                if (kv.length == 2) {
                    String key = kv[0];
                    String value = decodeHex(kv[1].replace("#", ""));
                    user.put(key, value);
                }

            } else {

                String[] kv = part.split("=");

                if (kv.length == 2) {
                    user.put(kv[0], kv[1]);
                }
            }
        }

        return user;
    }

    // -----------------------------------
    // HEX → STRING (ASN.1 UTF8)
    // -----------------------------------
    private static String decodeHex(String hex) {

        try {

            byte[] data = new byte[hex.length() / 2];

            for (int i = 0; i < data.length; i++) {
                data[i] = (byte) Integer.parseInt(
                        hex.substring(i * 2, i * 2 + 2), 16);
            }

            // skip ASN.1 UTF8 header (0C)
            if (data.length > 2 && data[0] == 0x0C) {
                byte[] real = new byte[data.length - 2];
                System.arraycopy(data, 2, real, 0, real.length);
                return new String(real, "UTF-8");
            }

            return new String(data, "UTF-8");

        } catch (Exception e) {
            return "DECODE_ERROR";
        }
    }

    // -----------------------------------
    // FALLBACK CN
    // -----------------------------------
    private static String extractCN(String dn) {

        for (String part : dn.split(",")) {
            part = part.trim();
            if (part.startsWith("CN=")) {
                return part.substring(3);
            }
        }

        return "UNKNOWN";
    }
}



import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class EidCardOnly {

    public static void main(String[] args) throws Exception {

        KeyStore ks = KeyStore.getInstance("Windows-MY");
        ks.load(null, null);

        Enumeration<String> aliases = ks.aliases();

        while (aliases.hasMoreElements()) {

            String alias = aliases.nextElement();

            X509Certificate cert =
                    (X509Certificate) ks.getCertificate(alias);

            if (cert == null) continue;

            String subject = cert.getSubjectX500Principal().getName();

            // 🔴 FILTER ZA LIČNU KARTU
            if (isEID(cert)) {

                System.out.println("=================================");
                System.out.println("📇 eID CERT PRONAĐEN");
                System.out.println("=================================");

                System.out.println("Alias: " + alias);
                System.out.println("Ime: " + extractCN(subject));
                System.out.println("Subject: " + subject);
                System.out.println("Issuer: " + cert.getIssuerX500Principal().getName());
                System.out.println("Serial: " + cert.getSerialNumber());
                System.out.println("Valid from: " + cert.getNotBefore());
                System.out.println("Valid to: " + cert.getNotAfter());
            }
        }
    }

    // -----------------------------------
    // PREPOZNAJ eID CERT (BITNO)
    // -----------------------------------
    private static boolean isEID(X509Certificate cert) {

        String issuer = cert.getIssuerX500Principal().getName();
        String subject = cert.getSubjectX500Principal().getName();

        return issuer.contains("IDDEEA") ||
               issuer.contains("Bosnia") ||
               subject.contains("BA");
    }

    // -----------------------------------
    // IZVLAČENJE IMENA
    // -----------------------------------
    private static String extractCN(String dn) {

        for (String part : dn.split(",")) {
            part = part.trim();
            if (part.startsWith("CN=")) {
                return part.substring(3);
            }
        }

        return "UNKNOWN";
    }
}





import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class EidWindows {

    public static void main(String[] args) throws Exception {

        KeyStore ks = KeyStore.getInstance("Windows-MY");
        ks.load(null, null);

        Enumeration<String> aliases = ks.aliases();

        while (aliases.hasMoreElements()) {

            String alias = aliases.nextElement();

            X509Certificate cert =
                    (X509Certificate) ks.getCertificate(alias);

            if (cert != null) {

                System.out.println("SUBJECT: " +
                        cert.getSubjectX500Principal().getName());
            }
        }
    }
}


import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class EidFinal {

    public static void main(String[] args) {

        System.out.println("==== eID START ====\n");

        try {

            // -----------------------------------
            // 1. TAČAN DLL PATH (PRILAGODI!)
            // -----------------------------------
            String dllPath = "C:\\Users\\w881348\\Desktop\\ocr\\New folder\\opensc_pkcs11.dll";

            File dll = new File(dllPath);

            if (!dll.exists()) {
                System.out.println("❌ DLL NOT FOUND:");
                System.out.println(dllPath);
                return;
            }

            System.out.println("✔ DLL FOUND");

            // -----------------------------------
            // 2. ISPRAVAN CONFIG
            // -----------------------------------
            String config =
                    "name=OpenSC\n" +
                    "library=" + dllPath + "\n" +
                    "slotListIndex=0\n";

            File cfg = File.createTempFile("pkcs11", ".cfg");

            FileOutputStream fos = new FileOutputStream(cfg);
            fos.write(config.getBytes(StandardCharsets.UTF_8));
            fos.close();

            System.out.println("\nCONFIG:");
            System.out.println(config);

            // -----------------------------------
            // 3. LOAD PROVIDER
            // -----------------------------------
            sun.security.pkcs11.SunPKCS11 provider =
                    new sun.security.pkcs11.SunPKCS11(cfg.getAbsolutePath());

            Security.addProvider(provider);

            System.out.println("✔ PROVIDER LOADED");

            // -----------------------------------
            // 4. KEYSTORE
            // -----------------------------------
            KeyStore ks = KeyStore.getInstance("PKCS11", provider);

            try {
                ks.load(null, null);
                System.out.println("✔ KEYSTORE LOADED");
            } catch (Exception e) {
                System.out.println("⚠ PIN REQUIRED ili kartica problem");
                System.out.println(e.getMessage());
            }

            // -----------------------------------
            // 5. CERTS
            // -----------------------------------
            Enumeration<String> aliases = ks.aliases();

            if (!aliases.hasMoreElements()) {
                System.out.println("❌ NEMA CERTIFIKATA");
                System.out.println("👉 Probaj slotListIndex=1");
                return;
            }

            while (aliases.hasMoreElements()) {

                String alias = aliases.nextElement();

                System.out.println("\nALIAS: " + alias);

                X509Certificate cert =
                        (X509Certificate) ks.getCertificate(alias);

                if (cert == null) {
                    System.out.println("❌ CERT NULL");
                    continue;
                }

                String subject = cert.getSubjectX500Principal().getName();

                System.out.println("SUBJECT: " + subject);
                System.out.println("IME: " + extractCN(subject));
            }

        } catch (Exception e) {
            System.out.println("\n❌ FATAL:");
            e.printStackTrace();
        }
    }

    private static String extractCN(String dn) {

        if (dn == null) return "UNKNOWN";

        for (String part : dn.split(",")) {
            part = part.trim();
            if (part.startsWith("CN=")) {
                return part.substring(3);
            }
        }

        return "UNKNOWN";
    }
}




import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class EidPkcs11FullDebug {

    public static void main(String[] args) {

        System.out.println("====================================");
        System.out.println("🔵 BIH eID PKCS#11 DEBUG START");
        System.out.println("====================================\n");

        try {

            // -----------------------------------
            // 1. JAVA INFO
            // -----------------------------------
            System.out.println("✔ Java version: " + System.getProperty("java.version"));

            // -----------------------------------
            // 2. PKCS#11 DLL (CHANGE THIS!)
            // -----------------------------------
            String pkcs11Lib =
                    "C:\\Program Files\\OpenSC Project\\OpenSC\\pkcs11\\opensc_pkcs11.dll";

            File lib = new File(pkcs11Lib);

            System.out.println("\n🔍 Checking PKCS#11 library...");
            if (!lib.exists()) {
                System.out.println("❌ DLL NOT FOUND:");
                System.out.println(pkcs11Lib);
                return;
            }

            System.out.println("✔ DLL FOUND");

            // -----------------------------------
            // 3. CONFIG (CRITICAL FIXED FORMAT)
            // -----------------------------------
            String config =
                    "name=eID\n" +
                    "library=" + pkcs11Lib + "\n" +
                    "slotListIndex=0\n";

            File cfg = File.createTempFile("pkcs11", ".cfg");

            try (FileOutputStream fos = new FileOutputStream(cfg)) {
                fos.write(config.getBytes(StandardCharsets.UTF_8));
            }

            System.out.println("\n📄 CONFIG FILE:");
            System.out.println(cfg.getAbsolutePath());
            System.out.println("\n----- CONFIG -----");
            System.out.println(config);
            System.out.println("------------------");

            // -----------------------------------
            // 4. LOAD PROVIDER
            // -----------------------------------
            System.out.println("\n🔵 Loading PKCS#11 provider...");

            sun.security.pkcs11.SunPKCS11 provider =
                    new sun.security.pkcs11.SunPKCS11(cfg.getAbsolutePath());

            Security.addProvider(provider);

            System.out.println("✔ Provider loaded: " + provider.getName());

            // -----------------------------------
            // 5. KEYSTORE INIT (MOST IMPORTANT PART)
            // -----------------------------------
            System.out.println("\n🔵 Initializing PKCS#11 KeyStore...");

            KeyStore ks = KeyStore.getInstance("PKCS11", provider);

            try {
                ks.load(null, null);
                System.out.println("✔ KeyStore loaded WITHOUT PIN (token visible)");
            } catch (Exception e) {
                System.out.println("⚠ KeyStore requires PIN or token issue:");
                System.out.println("👉 " + e.getMessage());
            }

            // -----------------------------------
            // 6. SLOT / CERT DEBUG
            // -----------------------------------
            System.out.println("\n🔵 Reading certificates...");

            Enumeration<String> aliases = ks.aliases();

            if (!aliases.hasMoreElements()) {
                System.out.println("❌ NO CERTIFICATES FOUND");
                System.out.println("👉 Possible causes:");
                System.out.println("   - wrong slot");
                System.out.println("   - card not inserted");
                System.out.println("   - wrong PKCS#11 DLL");
                return;
            }

            while (aliases.hasMoreElements()) {

                String alias = aliases.nextElement();

                System.out.println("\n----------------------------------");
                System.out.println("🔑 ALIAS: " + alias);

                try {

                    X509Certificate cert =
                            (X509Certificate) ks.getCertificate(alias);

                    if (cert == null) {
                        System.out.println("❌ CERT NULL");
                        continue;
                    }

                    System.out.println("✔ CERT FOUND");

                    System.out.println("📄 SUBJECT: " +
                            cert.getSubjectX500Principal().getName());

                    System.out.println("🏢 ISSUER: " +
                            cert.getIssuerX500Principal().getName());

                    System.out.println("🔢 SERIAL: " +
                            cert.getSerialNumber());

                    System.out.println("📅 VALID FROM: " + cert.getNotBefore());
                    System.out.println("📅 VALID TO:   " + cert.getNotAfter());

                } catch (Exception ex) {
                    System.out.println("❌ ERROR reading cert:");
                    ex.printStackTrace();
                }
            }

            System.out.println("\n====================================");
            System.out.println("✔ DEBUG FINISHED");
            System.out.println("====================================");

        } catch (Exception e) {

            System.out.println("\n❌ FATAL ERROR:");
            e.printStackTrace();
        }
    }
}



import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class EidDebugOpenSC {

    public static void main(String[] args) {

        System.out.println("=================================");
        System.out.println("🔵 eID DEBUG START");
        System.out.println("=================================\n");

        try {

            // -----------------------------------
            // 1. CHECK JAVA VERSION
            // -----------------------------------
            System.out.println("✔ Java version: " + System.getProperty("java.version"));

            // -----------------------------------
            // 2. CONFIG PATH (IMPORTANT DEBUG)
            // -----------------------------------
            String dllPath = "C:\\Program Files\\OpenSC Project\\OpenSC\\pkcs11\\opensc_pkcs11.dll";

            System.out.println("🔍 Checking PKCS#11 DLL...");
            File dll = new File(dllPath);

            if (!dll.exists()) {
                System.out.println("❌ DLL NOT FOUND: " + dllPath);
                return;
            }

            System.out.println("✔ DLL FOUND: " + dllPath);

            // -----------------------------------
            // 3. CREATE PKCS11 CONFIG FILE
            // -----------------------------------
            String config =
                    "name=OpenSC\n" +
                    "library=" + dllPath + "\n" +
                    "slotListIndex=0\n";

            File cfg = File.createTempFile("pkcs11", ".cfg");
            FileOutputStream fos = new FileOutputStream(cfg);
            fos.write(config.getBytes(StandardCharsets.UTF_8));
            fos.close();

            System.out.println("✔ Config file: " + cfg.getAbsolutePath());
            System.out.println("📄 CONFIG CONTENT:\n" + config);

            // -----------------------------------
            // 4. LOAD PKCS11 PROVIDER
            // -----------------------------------
            System.out.println("\n🔵 Loading PKCS#11 provider...");

            sun.security.pkcs11.SunPKCS11 provider =
                    new sun.security.pkcs11.SunPKCS11(cfg.getAbsolutePath());

            Security.addProvider(provider);

            System.out.println("✔ Provider loaded: " + provider.getName());

            // -----------------------------------
            // 5. KEYSTORE INIT
            // -----------------------------------
            System.out.println("\n🔵 Initializing KeyStore...");

            KeyStore ks = KeyStore.getInstance("PKCS11", provider);

            try {
                ks.load(null, null);
                System.out.println("✔ KeyStore loaded (no PIN)");
            } catch (Exception e) {
                System.out.println("⚠ KeyStore load failed (PIN required or card issue)");
                System.out.println("👉 " + e.getMessage());
            }

            // -----------------------------------
            // 6. LIST ALIASES
            // -----------------------------------
            System.out.println("\n🔵 Reading aliases...");

            Enumeration<String> aliases = ks.aliases();

            if (!aliases.hasMoreElements()) {
                System.out.println("❌ NO CERTIFICATES FOUND");
                return;
            }

            while (aliases.hasMoreElements()) {

                String alias = aliases.nextElement();

                System.out.println("\n---------------------------------");
                System.out.println("🔑 ALIAS: " + alias);

                try {
                    X509Certificate cert =
                            (X509Certificate) ks.getCertificate(alias);

                    if (cert == null) {
                        System.out.println("❌ Certificate is NULL");
                        continue;
                    }

                    System.out.println("✔ Certificate loaded");

                    // SUBJECT
                    String subject = cert.getSubjectX500Principal().getName();
                    System.out.println("📄 SUBJECT: " + subject);

                    // ISSUER
                    System.out.println("🏢 ISSUER: " + cert.getIssuerX500Principal().getName());

                    // SERIAL
                    System.out.println("🔢 SERIAL: " + cert.getSerialNumber());

                    // VALIDITY
                    System.out.println("📅 VALID FROM: " + cert.getNotBefore());
                    System.out.println("📅 VALID TO:   " + cert.getNotAfter());

                    // EXTRACT NAME
                    String name = extractCN(subject);
                    System.out.println("👤 NAME: " + name);

                } catch (Exception ex) {
                    System.out.println("❌ ERROR reading cert:");
                    ex.printStackTrace();
                }
            }

            System.out.println("\n=================================");
            System.out.println("✔ DEBUG FINISHED");
            System.out.println("=================================");

        } catch (Exception e) {

            System.out.println("\n❌ FATAL ERROR:");
            e.printStackTrace();
        }
    }

    // -----------------------------------
    // CN EXTRACTOR (IME PREZIME)
    // -----------------------------------
    private static String extractCN(String dn) {

        if (dn == null) return "UNKNOWN";

        String[] parts = dn.split(",");

        for (String p : parts) {
            p = p.trim();
            if (p.startsWith("CN=")) {
                return p.substring(3);
            }
        }

        return "UNKNOWN";
    }
}




import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class EidOpenSC {

    public static void main(String[] args) {

        try {

            // -------------------------
            // PKCS#11 CONFIG (OpenSC)
            // -------------------------
            String config =
                    "name=OpenSC\n" +
                    "library=C:\\Program Files\\OpenSC Project\\OpenSC\\pkcs11\\opensc_pkcs11.dll\n" +
                    "slotListIndex=0";

            File cfg = File.createTempFile("pkcs11", ".cfg");

            FileOutputStream fos = new FileOutputStream(cfg);
            fos.write(config.getBytes(StandardCharsets.UTF_8));
            fos.close();

            // -------------------------
            // LOAD PROVIDER
            // -------------------------
            sun.security.pkcs11.SunPKCS11 provider =
                    new sun.security.pkcs11.SunPKCS11(cfg.getAbsolutePath());

            Security.addProvider(provider);

            // -------------------------
            // KEYSTORE
            // -------------------------
            KeyStore ks = KeyStore.getInstance("PKCS11", provider);

            ks.load(null, null); // PIN ako treba

            System.out.println("✔ Kartica učitana!\n");

            // -------------------------
            // READ CERTS
            // -------------------------
            Enumeration<String> aliases = ks.aliases();

            while (aliases.hasMoreElements()) {

                String alias = aliases.nextElement();

                X509Certificate cert =
                        (X509Certificate) ks.getCertificate(alias);

                if (cert != null) {

                    String subject = cert.getSubjectX500Principal().getName();

                    System.out.println("📄 SUBJECT:");
                    System.out.println(subject);

                    System.out.println("\n👤 IME:");
                    System.out.println(extractCN(subject));

                    System.out.println("----------------------");
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String extractCN(String dn) {

        for (String part : dn.split(",")) {
            if (part.trim().startsWith("CN=")) {
                return part.trim().substring(3);
            }
        }

        return "Nepoznato";
    }
}



import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class EidJava8HID {

    public static void main(String[] args) {

        try {

            // --------------------------------------
            // 1. PKCS#11 CONFIG (HID DRIVER)
            // --------------------------------------
            String config =
                    "name=HIDeID\n" +
                    "library=C:\\Windows\\System32\\eps2003csp11.dll\n" +
                    "slotListIndex=0";

            File cfg = File.createTempFile("pkcs11", ".cfg");

            FileOutputStream fos = new FileOutputStream(cfg);
            fos.write(config.getBytes(StandardCharsets.UTF_8));
            fos.close();

            // --------------------------------------
            // 2. LOAD PROVIDER (Java 8 compatible)
            // --------------------------------------
            sun.security.pkcs11.SunPKCS11 provider =
                    new sun.security.pkcs11.SunPKCS11(cfg.getAbsolutePath());

            Security.addProvider(provider);

            // --------------------------------------
            // 3. KEYSTORE INIT
            // --------------------------------------
            KeyStore ks = KeyStore.getInstance("PKCS11", provider);

            // ako kartica traži PIN:
            // ks.load(null, "1234".toCharArray());
            ks.load(null, null);

            System.out.println("✔ Kartica uspješno učitana\n");

            // --------------------------------------
            // 4. READ CERTIFICATES
            // --------------------------------------
            Enumeration<String> aliases = ks.aliases();

            while (aliases.hasMoreElements()) {

                String alias = aliases.nextElement();

                X509Certificate cert =
                        (X509Certificate) ks.getCertificate(alias);

                if (cert != null) {

                    String subject = cert.getSubjectX500Principal().getName();

                    System.out.println("📄 SUBJECT:");
                    System.out.println(subject);

                    String ime = extractCN(subject);

                    System.out.println("\n👤 IME I PREZIME:");
                    System.out.println(ime);

                    System.out.println("----------------------------");
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // --------------------------------------
    // EXTRACT CN (IME PREZIME)
    // --------------------------------------
    private static String extractCN(String dn) {

        if (dn == null) return "Nepoznato";

        String[] parts = dn.split(",");

        for (String p : parts) {
            p = p.trim();
            if (p.startsWith("CN=")) {
                return p.substring(3);
            }
        }

        return "Nepoznato";
    }
}
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class EidNameReader {

    public static void main(String[] args) {

        try {

            // -----------------------------
            // PKCS#11 CONFIG (HID)
            // -----------------------------
            String config =
                    "name=HIDeID\n" +
                    "library=C:\\Windows\\System32\\eps2003csp11.dll\n" +
                    "slotListIndex=0";

            java.io.File cfg = java.io.File.createTempFile("pkcs11", ".cfg");
            java.nio.file.Files.writeString(cfg.toPath(), config);

            java.security.Provider provider =
                    new sun.security.pkcs11.SunPKCS11(cfg.getAbsolutePath());

            Security.addProvider(provider);

            // -----------------------------
            // KEYSTORE LOAD
            // -----------------------------
            KeyStore ks = KeyStore.getInstance("PKCS11", provider);
            ks.load(null, null); // PIN ako treba

            System.out.println("✔ Kartica učitana\n");

            // -----------------------------
            // READ CERTS
            // -----------------------------
            Enumeration<String> aliases = ks.aliases();

            while (aliases.hasMoreElements()) {

                String alias = aliases.nextElement();

                X509Certificate cert =
                        (X509Certificate) ks.getCertificate(alias);

                if (cert != null) {

                    String subject = cert.getSubjectX500Principal().getName();

                    System.out.println("📄 SUBJECT:");
                    System.out.println(subject);

                    // -----------------------------
                    // EXTREME SIMPLE NAME EXTRACTION
                    // -----------------------------
                    String name = extractCN(subject);

                    System.out.println("\n👤 IME I PREZIME:");
                    System.out.println(name);
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // ---------------------------------
    // EXTRACT CN=NAME SURNAME
    // ---------------------------------
    private static String extractCN(String dn) {

        for (String part : dn.split(",")) {
            if (part.trim().startsWith("CN=")) {
                return part.trim().substring(3);
            }
        }

        return "Nepoznato";
    }
}




import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.Security;
import java.util.Enumeration;
import sun.security.pkcs11.SunPKCS11;

public class EidPKCS11 {

    public static void main(String[] args) {

        try {

            // -------------------------
            // PKCS11 CONFIG
            // -------------------------
            String config =
                    "name=BiHEID\n" +
                    "library=C:\\\\Windows\\\\System32\\\\eps2003csp11.dll\n" +
                    "slotListIndex=0";

            // -------------------------
            // LOAD PROVIDER (JAVA 17 FIX)
            // -------------------------
            SunPKCS11 provider =
                    new SunPKCS11(new ByteArrayInputStream(config.getBytes()));

            Security.addProvider(provider);

            // -------------------------
            // KEYSTORE
            // -------------------------
            KeyStore ks = KeyStore.getInstance("PKCS11", provider);
            ks.load(null, null);

            System.out.println("✔ Kartica učitana");

            // -------------------------
            // LIST CERTS
            // -------------------------
            Enumeration<String> aliases = ks.aliases();

            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                System.out.println("Alias: " + alias);
                System.out.println(ks.getCertificate(alias));
                System.out.println("-------------------");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}




import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class EIDJava17Fixed {

    public static void main(String[] args) {

        try {

            // -----------------------------
            // 1. PKCS#11 CONFIG FILE
            // -----------------------------
            String cfg =
                    "name=BiHEID\n" +
                    "library=C:\\Windows\\System32\\eps2003csp11.dll\n" +
                    "slotListIndex=0";

            java.nio.file.Path cfgPath =
                    java.nio.file.Files.createTempFile("pkcs11", ".cfg");

            java.nio.file.Files.writeString(cfgPath, cfg);

            // -----------------------------
            // 2. LOAD PROVIDER (NO sun.*)
            // -----------------------------
            java.security.Provider provider =
                    new sun.security.pkcs11.SunPKCS11(cfgPath.toString());

            Security.addProvider(provider);

            // -----------------------------
            // 3. KEYSTORE LOAD
            // -----------------------------
            KeyStore ks = KeyStore.getInstance("PKCS11", provider);
            ks.load(null, null); // PIN prompt

            System.out.println("✅ eID učitan\n");

            // -----------------------------
            // 4. READ CERTIFICATES
            // -----------------------------
            Enumeration<String> aliases = ks.aliases();

            while (aliases.hasMoreElements()) {

                String alias = aliases.nextElement();

                X509Certificate cert =
                        (X509Certificate) ks.getCertificate(alias);

                if (cert != null) {
                    System.out.println("🔑 " + alias);
                    System.out.println("👤 " + cert.getSubjectDN());
                    System.out.println("----------------------");
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}



import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class BiHEID_Java17 {

    public static void main(String[] args) {

        try {

            // --------------------------------------------------
            // 1. PKCS#11 CONFIG FILE
            // --------------------------------------------------

            String cfg =
                    "name=BiHEID\n" +
                    "library=C:\\Windows\\System32\\eps2003csp11.dll\n" +
                    "slotListIndex=0";

            java.nio.file.Path cfgPath =
                    java.nio.file.Files.createTempFile("pkcs11", ".cfg");

            java.nio.file.Files.writeString(cfgPath, cfg);

            // --------------------------------------------------
            // 2. LOAD PROVIDER (JAVA 17 SAFE WAY)
            // --------------------------------------------------

            java.security.Provider p = new sun.security.pkcs11.SunPKCS11(
                    cfgPath.toString()
            );

            Security.addProvider(p);

            // --------------------------------------------------
            // 3. LOAD KEYSTORE
            // --------------------------------------------------

            KeyStore ks = KeyStore.getInstance("PKCS11", p);
            ks.load(null, null); // PIN prompt ide ovdje

            System.out.println("\n✅ eID uspješno učitan!\n");

            // --------------------------------------------------
            // 4. LIST CERTS
            // --------------------------------------------------

            Enumeration<String> aliases = ks.aliases();

            while (aliases.hasMoreElements()) {

                String alias = aliases.nextElement();

                X509Certificate cert =
                        (X509Certificate) ks.getCertificate(alias);

                if (cert != null) {

                    System.out.println("🔑 Alias: " + alias);
                    System.out.println("👤 Subject: " + cert.getSubjectDN());
                    System.out.println("🏢 Issuer: " + cert.getIssuerDN());
                    System.out.println("📅 Valid until: " + cert.getNotAfter());
                    System.out.println("---------------------------");
                }
            }

        } catch (Exception e) {
            System.out.println("❌ Greška:");
            e.printStackTrace();
        }
    }
}







import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class BiHEID_PKCS11_Full {

    public static void main(String[] args) {

        try {

            // --------------------------------------------------
            // 1. REGISTRUJ PKCS#11 PROVIDER (bez SunPKCS11 klase)
            // --------------------------------------------------

            String pkcs11Config =
                    "name=BiHEID\n" +
                    "library=C:\\Windows\\System32\\eps2003csp11.dll\n" +
                    "slotListIndex=0";

            java.io.File configFile = java.io.File.createTempFile("pkcs11", ".cfg");
            java.io.FileWriter fw = new java.io.FileWriter(configFile);
            fw.write(pkcs11Config);
            fw.close();

            // Java PKCS#11 provider (standardni način)
            sun.security.pkcs11.SunPKCS11 provider =
                    new sun.security.pkcs11.SunPKCS11(configFile.getAbsolutePath());

            Security.addProvider(provider);

            // --------------------------------------------------
            // 2. OTVORI KEYSTORE (traži PIN automatski)
            // --------------------------------------------------

            KeyStore ks = KeyStore.getInstance("PKCS11");
            ks.load(null, null);

            System.out.println("\n✅ eID kartica uspješno učitana!\n");

            // --------------------------------------------------
            // 3. ČITANJE CERTIFIKATA
            // --------------------------------------------------

            Enumeration<String> aliases = ks.aliases();

            while (aliases.hasMoreElements()) {

                String alias = aliases.nextElement();

                System.out.println("🔑 Alias: " + alias);

                X509Certificate cert =
                        (X509Certificate) ks.getCertificate(alias);

                if (cert != null) {
                    System.out.println("👤 Subject: " + cert.getSubjectDN());
                    System.out.println("🏢 Issuer: " + cert.getIssuerDN());
                    System.out.println("📅 Valid from: " + cert.getNotBefore());
                    System.out.println("📅 Valid to: " + cert.getNotAfter());
                    System.out.println("--------------------------------------");
                }
            }

            System.out.println("\n🎉 Gotovo!");

        } catch (Exception e) {
            System.out.println("❌ Greška:");
            e.printStackTrace();
        }
    }
}



import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class BiHEIDWorking {

    public static void main(String[] args) {

        try {

            // 🔥 PUTANJA DO PKCS11 LIB
            String config =
                    "name=eID\n" +
                    "library=C:\\Windows\\System32\\eps2003csp11.dll\n" +
                    "slotListIndex=0";

            sun.security.pkcs11.SunPKCS11 provider =
                    new sun.security.pkcs11.SunPKCS11(
                            new java.io.ByteArrayInputStream(config.getBytes())
                    );

            Security.addProvider(provider);

            // 🔐 KEYSTORE (traži PIN automatski)
            KeyStore ks = KeyStore.getInstance("PKCS11", provider);
            ks.load(null, null);

            System.out.println("✅ Kartica učitana!\n");

            Enumeration<String> aliases = ks.aliases();

            while (aliases.hasMoreElements()) {

                String alias = aliases.nextElement();

                System.out.println("🔑 Alias: " + alias);

                X509Certificate cert = (X509Certificate) ks.getCertificate(alias);

                System.out.println("📄 Subject: " + cert.getSubjectDN());
                System.out.println("📄 Valid until: " + cert.getNotAfter());

            }

        } catch (Exception e) {
            System.out.println("❌ Greška:");
            e.printStackTrace();
        }
    }
}



import java.security.KeyStore;
import java.security.Security;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class BiHEID_PKCS11 {

    public static void main(String[] args) {
        try {

            // 🔥 PATH DO PKCS#11 LIBRARY
            String pkcs11Path = "C:\\Windows\\System32\\eps2003csp11.dll"; 
            // ili opensc-pkcs11.so na Linuxu

            // ----------------------------------------
            // 1. LOAD PKCS#11 PROVIDER
            // ----------------------------------------
            String config =
                    "name=BiHEID\n" +
                    "library=" + pkcs11Path + "\n" +
                    "slotListIndex=0";

            java.io.ByteArrayInputStream configStream =
                    new java.io.ByteArrayInputStream(config.getBytes());

            sun.security.pkcs11.SunPKCS11 provider =
                    new sun.security.pkcs11.SunPKCS11(configStream);

            Security.addProvider(provider);

            // ----------------------------------------
            // 2. LOAD KEYSTORE FROM CARD
            // ----------------------------------------
            KeyStore ks = KeyStore.getInstance("PKCS11", provider);
            ks.load(null, null); // PIN će se tražiti

            // ----------------------------------------
            // 3. LIST CERTIFICATES
            // ----------------------------------------
            Enumeration<String> aliases = ks.aliases();

            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();

                System.out.println("🔑 Alias: " + alias);

                X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
                System.out.println("📄 Subject: " + cert.getSubjectDN());
                System.out.println("📄 Issuer: " + cert.getIssuerDN());
                System.out.println("📄 Serial: " + cert.getSerialNumber());

                PrivateKey key = (PrivateKey) ks.getKey(alias, null);
                System.out.println("🔐 Private key available: " + (key != null));
            }

            System.out.println("\n✅ eID uspješno očitan!");

        } catch (Exception e) {
            System.out.println("❌ Greška:");
            e.printStackTrace();
        }
    }
}


<dependencies>
    <dependency>
        <groupId>org.bouncycastle</groupId>
        <artifactId>bcprov-jdk18on</artifactId>
        <version>1.78</version>
    </dependency>
</dependencies>

import javax.smartcardio.*;
import java.util.List;

public class BiHEIDReader {

    public static void main(String[] args) {
        new BiHEIDReader().start();
    }

    public void start() {
        try {
            TerminalFactory factory = TerminalFactory.getDefault();

            System.out.println("⏳ Čekam NFC karticu...");

            while (true) {

                List<CardTerminal> terminals = factory.terminals().list();

                for (CardTerminal terminal : terminals) {

                    if (terminal.isCardPresent()) {

                        System.out.println("\n📇 Kartica detektovana na: " + terminal.getName());

                        try {
                            readCard(terminal);
                        } catch (Exception e) {
                            System.out.println("❌ Greška pri čitanju:");
                            e.printStackTrace();
                        }

                        while (terminal.isCardPresent()) {
                            Thread.sleep(500);
                        }

                        System.out.println("📤 Kartica uklonjena\n");
                    }
                }

                Thread.sleep(500);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void readCard(CardTerminal terminal) throws Exception {

        // ⚠️ KLJUČNO: T=CL (NFC / contactless)
        Card card = terminal.connect("*");

        System.out.println("🔗 Connected: " + card.getProtocol());

        CardChannel channel = card.getBasicChannel();

        byte[] atr = card.getATR().getBytes();
        System.out.print("📡 ATR: ");
        for (byte b : atr) {
            System.out.printf("%02X ", b);
        }
        System.out.println();

        // -----------------------------------------
        // 1. PROBA SELECT AID (BAEID / eID applet)
        // -----------------------------------------

        byte[] selectAID = new byte[]{
                (byte) 0x00, (byte) 0xA4, 0x04, 0x00,
                0x0A,
                (byte) 0xA0, 0x00, 0x00, 0x01, 0x67, 0x45, 0x53, 0x49, 0x42, 0x00
        };

        ResponseAPDU response = channel.transmit(new CommandAPDU(selectAID));

        System.out.printf("📦 SELECT AID SW: %04X\n", response.getSW());

        if (response.getSW() != 0x9000) {
            System.out.println("⚠️ AID nije prihvaćen (kartica koristi drugi applet ili treba PIN/PACE)");
        } else {
            System.out.println("✅ AID prihvaćen!");
        }

        // -----------------------------------------
        // 2. PROBA SIGURNOSNE KOMANDE (opciono)
        // -----------------------------------------

        // NE koristi GET CHALLENGE – BiH eID često ga blokira
        // Zato ga NE šaljemo

        // -----------------------------------------
        // 3. PROBA READ BINARY (ako ima otvoren file)
        // -----------------------------------------

        byte[] readBinary = new byte[]{
                (byte) 0x00, (byte) 0xB0, 0x00, 0x00, 0x10
        };

        ResponseAPDU readResp = channel.transmit(new CommandAPDU(readBinary));

        System.out.printf("📄 READ SW: %04X\n", readResp.getSW());

        if (readResp.getSW() == 0x9000) {
            byte[] data = readResp.getData();
            System.out.println("📦 DATA:");
            for (byte b : data) {
                System.out.printf("%02X ", b);
            }
            System.out.println();
        } else {
            System.out.println("⚠️ READ nije dozvoljen bez autentikacije (PIN/PACE/secure channel)");
        }

        card.disconnect(false);
    }
}



import javax.smartcardio.*;
import java.util.List;

public class NFCReaderFull {

    public static void main(String[] args) {

        try {

            TerminalFactory factory = TerminalFactory.getDefault();
            List<CardTerminal> terminals = factory.terminals().list();

            if (terminals.isEmpty()) {
                System.out.println("❌ Nema readera!");
                return;
            }

            System.out.println("📡 Svi readeri:");

            CardTerminal nfcTerminal = null;

            // 🔍 Pronađi NFC reader
            for (CardTerminal t : terminals) {
                System.out.println(" - " + t.getName());

                String name = t.getName().toLowerCase();

                if (name.contains("cl") || name.contains("contactless") || name.contains("nfc")) {
                    nfcTerminal = t;
                }
            }

            // fallback ako nije pronađen
            if (nfcTerminal == null) {
                System.out.println("⚠️ NFC nije jasno označen → koristim prvi");
                nfcTerminal = terminals.get(0);
            }

            System.out.println("\n👉 Koristim: " + nfcTerminal.getName());
            System.out.println("📥 Čekam NFC karticu...");

            while (true) {

                if (nfcTerminal.waitForCardPresent(1000)) {

                    try {
                        System.out.println("📶 NFC DETEKTOVAN!");

                        // 🔥 KLJUČNO: koristi "*" (NE T=CL)
                        Card card = nfcTerminal.connect("*");

                        System.out.println("📇 ATR: " + bytesToHex(card.getATR().getBytes()));

                        CardChannel channel = card.getBasicChannel();

                        // =========================
                        // 🔐 TEST APDU (GET CHALLENGE)
                        // =========================
                        CommandAPDU cmd = new CommandAPDU(
                                0x00, 0x84, 0x00, 0x00, 0x08
                        );

                        ResponseAPDU resp = channel.transmit(cmd);

                        System.out.println("📤 SW: " + Integer.toHexString(resp.getSW()));
                        System.out.println("📄 DATA: " + bytesToHex(resp.getData()));

                        card.disconnect(false);

                    } catch (Exception e) {
                        System.out.println("❌ Greška:");
                        e.printStackTrace();
                    }

                    // čekaj da se kartica ukloni
                    while (nfcTerminal.isCardPresent()) {
                        Thread.sleep(500);
                    }

                    System.out.println("\n📤 Kartica uklonjena");
                    System.out.println("📥 Čekam NFC karticu...");
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // HEX helper
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }
}



import javax.smartcardio.*;
import java.util.List;

public class NFCFix {

    public static void main(String[] args) throws Exception {

        TerminalFactory factory = TerminalFactory.getDefault();
        List<CardTerminal> terminals = factory.terminals().list();

        if (terminals.isEmpty()) {
            System.out.println("❌ Nema readera");
            return;
        }

        System.out.println("📡 Svi readeri:");

        CardTerminal nfcTerminal = null;

        for (CardTerminal t : terminals) {
            System.out.println(" - " + t.getName());

            // 🔥 KLJUČNO: tražimo contactless / CL / NFC
            String name = t.getName().toLowerCase();

            if (name.contains("cl") || name.contains("contactless") || name.contains("nfc")) {
                nfcTerminal = t;
            }
        }

        // fallback ako nije našao
        if (nfcTerminal == null) {
            System.out.println("⚠️ NFC reader nije jasno označen → uzimam prvi");
            nfcTerminal = terminals.get(0);
        }

        System.out.println("\n👉 Koristim: " + nfcTerminal.getName());
        System.out.println("📥 Čekam NFC karticu...");

        while (true) {

            if (nfcTerminal.waitForCardPresent(1000)) {

                try {
                    System.out.println("📶 NFC DETEKTOVAN!");

                    // 🔥 OBAVEZNO
                    Card card = nfcTerminal.connect("T=CL");

                    System.out.println("ATR: " + bytesToHex(card.getATR().getBytes()));

                    card.disconnect(false);

                } catch (Exception e) {
                    System.out.println("❌ Greška:");
                    e.printStackTrace();
                }

                while (nfcTerminal.isCardPresent()) {
                    Thread.sleep(500);
                }

                System.out.println("\n📤 Kartica uklonjena");
                System.out.println("📥 Čekam NFC karticu...");
            }
        }
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }
}




import javax.smartcardio.*;
import java.util.List;

public class NFCReader {

    public static void main(String[] args) throws Exception {

        TerminalFactory factory = TerminalFactory.getDefault();
        List<CardTerminal> terminals = factory.terminals().list();

        if (terminals.isEmpty()) {
            System.out.println("❌ Nema readera");
            return;
        }

        CardTerminal terminal = terminals.get(0);

        System.out.println("📡 Reader: " + terminal.getName());
        System.out.println("📥 Čekam NFC karticu...");

        while (true) {

            if (terminal.waitForCardPresent(1000)) {

                try {
                    System.out.println("📶 NFC kartica detektovana!");

                    // 🔥 KLJUČNO: T=CL
                    Card card = terminal.connect("T=CL");

                    System.out.println("ATR: " + bytesToHex(card.getATR().getBytes()));

                    CardChannel channel = card.getBasicChannel();

                    // TEST APDU
                    CommandAPDU cmd = new CommandAPDU(
                            0x00, 0x84, 0x00, 0x00, 0x08
                    );

                    ResponseAPDU resp = channel.transmit(cmd);

                    System.out.println("SW: " + Integer.toHexString(resp.getSW()));
                    System.out.println("DATA: " + bytesToHex(resp.getData()));

                    card.disconnect(false);

                } catch (Exception e) {
                    System.out.println("❌ NFC greška:");
                    e.printStackTrace();
                }

                while (terminal.isCardPresent()) {
                    Thread.sleep(500);
                }

                System.out.println("\n📤 Kartica uklonjena");
                System.out.println("📥 Čekam NFC karticu...");
            }
        }
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }
}





import javax.smartcardio.*;
import java.util.List;

public class ReadBosniaEID {

    public static void main(String[] args) {

        try {

            TerminalFactory factory = TerminalFactory.getDefault();
            List<CardTerminal> terminals = factory.terminals().list();

            if (terminals.isEmpty()) {
                System.out.println("❌ Nema dostupnih readera!");
                return;
            }

            System.out.println("📡 Dostupni readeri:");
            for (CardTerminal t : terminals) {
                System.out.println(" - " + t.getName());
            }

            CardTerminal terminal = terminals.get(0);

            System.out.println("\n📥 Čekam karticu...");

            // LOOP čekanje (radi bolje nego waitForCardPresent(0))
            while (true) {
                if (terminal.waitForCardPresent(1000)) {
                    System.out.println("✅ Kartica detektovana!");
                    break;
                }
            }

            // CONNECT (BITNO: koristi "*")
            Card card = terminal.connect("*");

            System.out.println("📇 ATR: " + bytesToHex(card.getATR().getBytes()));

            CardChannel channel = card.getBasicChannel();

            // =========================
            // 🔐 SELECT AID (probni)
            // =========================
            byte[] AID = new byte[]{
                    (byte) 0xA0, 0x00, 0x00, 0x00,
                    0x77, 0x01, 0x08, 0x00
            };

            CommandAPDU select = new CommandAPDU(
                    0x00, 0xA4, 0x04, 0x00, AID
            );

            ResponseAPDU selectResp = channel.transmit(select);

            System.out.println("📤 SELECT SW: " + Integer.toHexString(selectResp.getSW()));

            // =========================
            // 📄 READ BINARY (test)
            // =========================
            CommandAPDU read = new CommandAPDU(
                    0x00, 0xB0, 0x00, 0x00, 0xFF
            );

            ResponseAPDU readResp = channel.transmit(read);

            System.out.println("📤 READ SW: " + Integer.toHexString(readResp.getSW()));
            System.out.println("📄 DATA: " + bytesToHex(readResp.getData()));

            card.disconnect(false);

        } catch (Exception e) {
            System.out.println("❌ Greška:");
            e.printStackTrace();
        }
    }

    // HEX helper
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }
}





import javax.smartcardio.*;
import java.util.List;

public class ReadBosniaEID {

    public static void main(String[] args) throws Exception {

        TerminalFactory factory = TerminalFactory.getDefault();
        List<CardTerminal> terminals = factory.terminals().list();

        if (terminals.isEmpty()) {
            System.out.println("Nema readera");
            return;
        }

        CardTerminal terminal = terminals.get(0);

        System.out.println("Čekam karticu...");

        terminal.waitForCardPresent(0);

        Card card = terminal.connect("*");
        CardChannel channel = card.getBasicChannel();

        System.out.println("ATR: " + bytesToHex(card.getATR().getBytes()));

        // 🔐 SELECT AID (ovo moraš pogoditi tačan AID)
        byte[] AID = new byte[] {
                (byte)0xA0, 0x00, 0x00, 0x00, 0x77, 0x01, 0x08, 0x00
        };

        CommandAPDU select = new CommandAPDU(
                0x00, 0xA4, 0x04, 0x00, AID
        );

        ResponseAPDU response = channel.transmit(select);

        System.out.println("SELECT SW: " + Integer.toHexString(response.getSW()));

        // primjer READ (vjerovatno će biti zaštićen)
        CommandAPDU read = new CommandAPDU(
                0x00, 0xB0, 0x00, 0x00, 0xFF
        );

        ResponseAPDU readResp = channel.transmit(read);

        System.out.println("READ SW: " + Integer.toHexString(readResp.getSW()));
        System.out.println("DATA: " + bytesToHex(readResp.getData()));

        card.disconnect(false);
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }
}



import org.jmrtd.*;
import org.jmrtd.lds.icao.DG1File;
import org.jmrtd.lds.icao.MRZInfo;

import javax.smartcardio.*;
import java.io.InputStream;
import java.security.Security;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import net.sf.scuba.smartcards.*;

public class ReadEIDFixed {

    private static final String CAN = "123456";

    private static final String DOC_NUMBER = "XXXXXXXX";
    private static final String DOB = "YYMMDD";
    private static final String DOE = "YYMMDD";

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        new ReadEIDFixed().start();
    }

    public void start() {
        try {

            TerminalFactory factory = TerminalFactory.getDefault();

            while (true) {

                for (CardTerminal terminal : factory.terminals().list()) {

                    if (terminal.isCardPresent()) {
                        System.out.println("📇 Kartica: " + terminal.getName());
                        readCard(terminal);
                    }
                }

                Thread.sleep(500);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void readCard(CardTerminal terminal) {

        try {

            CardService cs = CardService.getInstance(terminal);
            cs.open();

            PassportService ps = new PassportService(
                    cs,
                    PassportService.NORMAL_MAX_TRANCEIVE_LENGTH,
                    PassportService.DEFAULT_MAX_BLOCKSIZE,
                    false,
                    false
            );

            ps.open();

            boolean ok = false;

            // 🔐 PACE
            try {
                System.out.println("🔐 PACE...");

                PACEKeySpec key = PACEKeySpec.createCANKey(CAN);

                ps.doPACE(key, 12);

                System.out.println("✅ PACE OK");
                ok = true;

            } catch (Exception e) {
                System.out.println("⚠️ PACE FAIL → BAC");
            }

            // 🔐 BAC (FIXED IMPORT)
            if (!ok) {

                BACKey bacKey = new BACKey(DOC_NUMBER, DOB, DOE);

                ps.doBAC(bacKey);

                System.out.println("✅ BAC OK");
            }

            ps.sendSelectApplet(false);

            InputStream dg1Stream = ps.getInputStream(PassportService.EF_DG1);

            DG1File dg1 = new DG1File(dg1Stream);

            MRZInfo mrz = dg1.getMRZInfo();

            System.out.println("📄 MRZ:");
            System.out.println(mrz);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}





import org.jmrtd.*;
import org.jmrtd.lds.icao.DG1File;
import org.jmrtd.lds.icao.MRZInfo;

import javax.smartcardio.*;
import java.io.InputStream;
import java.security.Security;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import net.sf.scuba.smartcards.*;

public class ReadEIDFixed {

    private static final String CAN = "123456";

    private static final String DOC_NUMBER = "XXXXXXXX";
    private static final String DOB = "YYMMDD";
    private static final String DOE = "YYMMDD";

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        new ReadEIDFixed().start();
    }

    public void start() {
        try {

            TerminalFactory factory = TerminalFactory.getDefault();

            while (true) {

                for (CardTerminal terminal : factory.terminals().list()) {

                    if (terminal.isCardPresent()) {
                        System.out.println("📇 Kartica: " + terminal.getName());
                        readCard(terminal);
                    }
                }

                Thread.sleep(500);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void readCard(CardTerminal terminal) {

        try {

            CardService cs = CardService.getInstance(terminal);
            cs.open();

            PassportService ps = new PassportService(
                    cs,
                    PassportService.NORMAL_MAX_TRANCEIVE_LENGTH,
                    PassportService.DEFAULT_MAX_BLOCKSIZE,
                    false,
                    false
            );

            ps.open();

            boolean ok = false;

            // =========================
            // 🔐 PACE (TVOJA VERZIJA)
            // =========================
            try {
                System.out.println("🔐 PACE...");

                ps.doPACE(PACEKeySpec.createCANKey(CAN));

                System.out.println("✅ PACE OK");
                ok = true;

            } catch (Exception e) {
                System.out.println("⚠️ PACE fail → BAC");
            }

            // =========================
            // 🔐 BAC (FIXED - NE BACKeySpec)
            // =========================
            if (!ok) {

                import org.jmrtd.BACKey;

                BACKey bacKey = new BACKey(DOC_NUMBER, DOB, DOE);

                ps.doBAC(bacKey);

                System.out.println("✅ BAC OK");
            }

            ps.sendSelectApplet(false);

            InputStream dg1Stream = ps.getInputStream(PassportService.EF_DG1);

            DG1File dg1 = new DG1File(dg1Stream);

            MRZInfo mrz = dg1.getMRZInfo();

            System.out.println("📄 MRZ:");
            System.out.println(mrz);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}




import org.jmrtd.*;
import org.jmrtd.lds.icao.DG1File;
import org.jmrtd.lds.icao.MRZInfo;

import javax.smartcardio.*;
import java.io.InputStream;
import java.security.Security;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import net.sf.scuba.smartcards.*;

public class ReadEIDFixed {

    // 🔑 CAN (za PACE)
    private static final String CAN = "123456";

    // 📄 BAC fallback (OBAVEZNO popuni)
    private static final String DOC_NUMBER = "XXXXXXXX";
    private static final String DOB = "YYMMDD";
    private static final String DOE = "YYMMDD";

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        new ReadEIDFixed().start();
    }

    public void start() {
        try {
            TerminalFactory factory = TerminalFactory.getDefault();

            while (true) {

                List<CardTerminal> terminals = factory.terminals().list();

                for (CardTerminal terminal : terminals) {

                    if (terminal.isCardPresent()) {

                        System.out.println("📇 Kartica: " + terminal.getName());

                        readCard(terminal);

                        while (terminal.isCardPresent()) {
                            Thread.sleep(500);
                        }

                        System.out.println("📤 Kartica uklonjena\n");
                    }
                }

                Thread.sleep(500);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void readCard(CardTerminal terminal) {

        try {

            // 1. CONNECT
            Card card = terminal.connect("T=CL");

            System.out.println("ATR: " + card.getATR());

            // 2. WRAP CARD
            CardService cs = CardService.getInstance(terminal);
            cs.open();

            PassportService ps = new PassportService(
                    cs,
                    PassportService.NORMAL_MAX_TRANCEIVE_LENGTH,
                    PassportService.DEFAULT_MAX_BLOCKSIZE,
                    false,
                    false
            );

            ps.open();

            boolean ok = false;

            // =========================
            // 🔐 PACE (TVOJA VERZIJA)
            // =========================
            try {
                System.out.println("🔐 PACE pokušaj...");

                PACEKeySpec paceKey = PACEKeySpec.createCANKey(CAN);

                // ✔ TVOJ API: PARAM_ID = 12 (NIST P-256)
                ps.doPACE(paceKey, 12);

                System.out.println("✅ PACE OK");
                ok = true;

            } catch (Exception e) {
                System.out.println("⚠️ PACE fail → BAC");
            }

            // =========================
            // 🔐 BAC FALLBACK
            // =========================
            if (!ok) {

                BACKeySpec bacKey = new BACKeySpec(
                        DOC_NUMBER,
                        DOB,
                        DOE
                );

                ps.doBAC(bacKey);

                System.out.println("✅ BAC OK");
            }

            // 3. SELECT APPLET
            ps.sendSelectApplet(false);

            // 4. READ DG1 (MRZ)
            InputStream dg1Stream = ps.getInputStream(PassportService.EF_DG1);

            DG1File dg1 = new DG1File(dg1Stream);

            MRZInfo mrz = dg1.getMRZInfo();

            System.out.println("\n📄 MRZ PODACI:");
            System.out.println("Document: " + mrz.getDocumentNumber());
            System.out.println("DOB: " + mrz.getDateOfBirth());
            System.out.println("DOE: " + mrz.getDateOfExpiry());
            System.out.println("Nationality: " + mrz.getNationality());
            System.out.println("Names: " + mrz.getNames());

        } catch (Exception e) {
            System.out.println("❌ Greška:");
            e.printStackTrace();
        }
    }
}


import org.jmrtd.*;
import org.jmrtd.lds.icao.DG1File;
import org.jmrtd.lds.icao.MRZInfo;

import javax.smartcardio.*;
import java.io.InputStream;
import java.security.Security;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import net.sf.scuba.smartcards.*;

public class ReadEIDFixed {

    // 🔑 CAN (ako PACE radi)
    private static final String CAN = "123456";

    // 📄 BAC fallback podaci (OBAVEZNO popuniti)
    private static final String DOC_NUMBER = "XXXXXXXX";
    private static final String DOB = "YYMMDD";
    private static final String DOE = "YYMMDD";

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        new ReadEIDFixed().start();
    }

    public void start() {
        try {
            TerminalFactory factory = TerminalFactory.getDefault();

            while (true) {

                List<CardTerminal> terminals = factory.terminals().list();

                for (CardTerminal terminal : terminals) {

                    if (terminal.isCardPresent()) {

                        System.out.println("📇 Kartica detektovana: " + terminal.getName());

                        readCard(terminal);

                        while (terminal.isCardPresent()) {
                            Thread.sleep(500);
                        }

                        System.out.println("📤 Kartica uklonjena\n");
                    }
                }

                Thread.sleep(500);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void readCard(CardTerminal terminal) {

        try {

            // 1. CONNECT
            Card card = terminal.connect("T=CL");

            System.out.println("ATR: " + card.getATR());

            // 2. WRAP U CARD SERVICE (ISPRAVNO ZA TVOJU VERZIJU)
            CardService cs = CardService.getInstance(terminal);
            cs.open();

            PassportService ps = new PassportService(
                    cs,
                    PassportService.NORMAL_MAX_TRANCEIVE_LENGTH,
                    PassportService.DEFAULT_MAX_BLOCKSIZE,
                    false,
                    false
            );

            ps.open();

            boolean authenticated = false;

            // =========================
            // 🔐 PACE (TRY)
            // =========================
            try {
                System.out.println("🔐 Pokušavam PACE...");

                PACEKeySpec paceKey = PACEKeySpec.createCANKey(CAN);

                ps.doPACE(paceKey, null); // ✔ FIX (bez PACE_MODE)

                System.out.println("✅ PACE uspješan");
                authenticated = true;

            } catch (Exception e) {
                System.out.println("⚠️ PACE ne radi → prelazim na BAC");
            }

            // =========================
            // 🔐 BAC FALLBACK
            // =========================
            if (!authenticated) {

                BACKeySpec bacKey = new BACKeySpec(
                        DOC_NUMBER,
                        DOB,
                        DOE
                );

                ps.doBAC(bacKey);

                System.out.println("✅ BAC uspješan");
            }

            // 3. SELECT APPLET
            ps.sendSelectApplet(false);

            // 4. READ DG1 (MRZ)
            InputStream dg1Stream = ps.getInputStream(PassportService.EF_DG1);

            DG1File dg1 = new DG1File(dg1Stream);

            MRZInfo mrz = dg1.getMRZInfo();

            System.out.println("\n📄 MRZ PODACI:");
            System.out.println("Document: " + mrz.getDocumentNumber());
            System.out.println("DOB: " + mrz.getDateOfBirth());
            System.out.println("DOE: " + mrz.getDateOfExpiry());
            System.out.println("Nationality: " + mrz.getNationality());
            System.out.println("Names: " + mrz.getNames());

        } catch (Exception e) {
            System.out.println("❌ Greška pri čitanju kartice:");
            e.printStackTrace();
        }
    }
}






import org.jmrtd.*;
import org.jmrtd.lds.icao.DG1File;
import org.jmrtd.lds.icao.MRZInfo;

import javax.smartcardio.*;
import java.io.InputStream;
import java.security.Security;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import net.sf.scuba.smartcards.*;

public class ReadEIDFixed {

    private static final String CAN = "123456"; // <- tvoj CAN

    // Ako PACE faila, BAC treba MRZ podatke:
    private static final String DOC_NUMBER = "XXXXXXXX"; // <- upiši broj dokumenta
    private static final String DOB = "YYMMDD";          // <- datum rođenja
    private static final String DOE = "YYMMDD";          // <- datum isteka

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        new ReadEIDFixed().start();
    }

    public void start() {
        try {
            TerminalFactory factory = TerminalFactory.getDefault();

            while (true) {

                List<CardTerminal> terminals = factory.terminals().list();

                for (CardTerminal terminal : terminals) {

                    if (terminal.isCardPresent()) {

                        System.out.println("📇 Kartica: " + terminal.getName());

                        readCard(terminal);

                        while (terminal.isCardPresent()) {
                            Thread.sleep(500);
                        }

                        System.out.println("📤 Kartica uklonjena\n");
                    }
                }

                Thread.sleep(500);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void readCard(CardTerminal terminal) {

        try {
            // 1. CONNECT
            Card card = terminal.connect("T=CL");

            System.out.println("ATR: " + card.getATR());

            // 2. WRAP CARD -> CardService (ISPRAVNO)
            CardService cs = CardService.getInstance(terminal);
            cs.open();

            PassportService ps = new PassportService(
                    cs,
                    PassportService.NORMAL_MAX_TRANCEIVE_LENGTH,
                    PassportService.DEFAULT_MAX_BLOCKSIZE,
                    false,
                    false
            );

            ps.open();

            boolean success = false;

            // =========================
            // 🔐 3. PACE ATTEMPT
            // =========================
            try {
                System.out.println("🔐 Pokušavam PACE...");

                PACEKeySpec paceKey = PACEKeySpec.createCANKey(CAN);

                ps.doPACE(
                        paceKey,
                        null,
                        PassportService.PACE_MODE
                );

                System.out.println("✅ PACE uspješan");
                success = true;

            } catch (Exception e) {
                System.out.println("⚠️ PACE ne radi → prelazim na BAC");
            }

            // =========================
            // 🔐 4. BAC FALLBACK
            // =========================
            if (!success) {

                BACKeySpec bacKey = new BACKeySpec(
                        DOC_NUMBER,
                        DOB,
                        DOE
                );

                ps.doBAC(bacKey);

                System.out.println("✅ BAC uspješan");
            }

            // 5. SELECT APPLET
            ps.sendSelectApplet(false);

            // 6. READ DG1
            InputStream dg1Stream = ps.getInputStream(PassportService.EF_DG1);

            DG1File dg1 = new DG1File(dg1Stream);

            MRZInfo mrz = dg1.getMRZInfo();

            System.out.println("📄 MRZ:");
            System.out.println("Document: " + mrz.getDocumentNumber());
            System.out.println("DOB: " + mrz.getDateOfBirth());
            System.out.println("DOE: " + mrz.getDateOfExpiry());
            System.out.println("Nationality: " + mrz.getNationality());
            System.out.println("Name: " + mrz.getNames());

        } catch (Exception e) {
            System.out.println("❌ Greška:");
            e.printStackTrace();
        }
    }
}





private void readCard(CardTerminal terminal) {
    try {

        CardService cs = CardService.getInstance(terminal);
        cs.open();

        PassportService ps = new PassportService(
                cs,
                PassportService.NORMAL_MAX_TRANCEIVE_LENGTH,
                PassportService.DEFAULT_MAX_BLOCKSIZE,
                false,
                false
        );

        ps.open();

        System.out.println("🔐 Pokrećem PACE...");

        PACEKeySpec paceKey = PACEKeySpec.createCANKey(CAN);

        ps.doPACE(
                paceKey,
                null,
                PassportService.PACE_MODE
        );

        System.out.println("✅ PACE uspješan");

        ps.sendSelectApplet(false);

        InputStream dg1Stream = ps.getInputStream(PassportService.EF_DG1);
        DG1File dg1 = new DG1File(dg1Stream);

        MRZInfo mrz = dg1.getMRZInfo();

        System.out.println("📄 MRZ:");
        System.out.println(mrz);

    } catch (Exception e) {
        e.printStackTrace();
    }
}




private void readCard(CardTerminal terminal) {
    try {

        Card card = terminal.connect("T=CL");

        CardService cs = new TerminalCardService(card);
        cs.open();

        PassportService ps = new PassportService(
                cs,
                PassportService.NORMAL_MAX_TRANCEIVE_LENGTH,
                PassportService.DEFAULT_MAX_BLOCKSIZE,
                false,
                false
        );

        ps.open();

        System.out.println("🔐 Pokrećem PACE...");

        PACEKeySpec paceKey = PACEKeySpec.createCANKey(CAN);

        ps.doPACE(
                paceKey,
                null,
                PassportService.PACE_MODE
        );

        System.out.println("✅ PACE uspješan");

        ps.sendSelectApplet(false);

        InputStream dg1Stream = ps.getInputStream(PassportService.EF_DG1);
        DG1File dg1 = new DG1File(dg1Stream);

        MRZInfo mrz = dg1.getMRZInfo();

        System.out.println("📄 MRZ:");
        System.out.println(mrz.toString());

    } catch (Exception e) {
        System.out.println("❌ Greška:");
        e.printStackTrace();
    }
}


import org.jmrtd.*;
import org.jmrtd.lds.icao.DG1File;
import org.jmrtd.lds.MRZInfo;

import javax.smartcardio.*;
import java.io.InputStream;
import java.security.Security;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import net.sf.scuba.smartcards.*;

public class ReadEIDFixed {

    private static final String CAN = "123456"; // <-- stavi svoj CAN

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        new ReadEIDFixed().start();
    }

    public void start() {
        try {
            TerminalFactory factory = TerminalFactory.getDefault();

            while (true) {
                List<CardTerminal> terminals = factory.terminals().list();

                for (CardTerminal terminal : terminals) {

                    if (terminal.isCardPresent()) {
                        System.out.println("📇 Kartica: " + terminal.getName());

                        readCard(terminal);

                        while (terminal.isCardPresent()) {
                            Thread.sleep(500);
                        }

                        System.out.println("📤 Kartica uklonjena\n");
                    }
                }

                Thread.sleep(500);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void readCard(CardTerminal terminal) {
        try {
            Card card = terminal.connect("T=CL");

            // Wrap u Scuba CardService
            CardService cs = CardService.getInstance(card);
            cs.open();

            PassportService ps = new PassportService(
                    cs,
                    PassportService.NORMAL_MAX_TRANCEIVE_LENGTH,
                    PassportService.DEFAULT_MAX_BLOCKSIZE,
                    false,
                    false
            );

            ps.open();

            System.out.println("🔐 Pokrećem PACE...");

            // PACE key sa CAN
            PACEKeySpec paceKey = PACEKeySpec.createCANKey(CAN);

            // PACE (novi API)
            ps.doPACE(
                    paceKey,
                    null,
                    PassportService.PACE_MODE
            );

            System.out.println("✅ PACE uspješan");

            ps.sendSelectApplet(false);

            // DG1 čitanje
            InputStream dg1Stream = ps.getInputStream(PassportService.EF_DG1);
            DG1File dg1 = new DG1File(dg1Stream);

            MRZInfo mrz = dg1.getMRZInfo();

            System.out.println("📄 MRZ:");
            System.out.println(mrz.toString());

        } catch (Exception e) {
            System.out.println("❌ Greška:");
            e.printStackTrace();
        }
    }
}






import org.jmrtd.*;
import org.jmrtd.lds.*;
import org.jmrtd.lds.icao.DG1File;

import javax.smartcardio.*;
import java.io.InputStream;
import java.security.Security;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ReadEID {

    private static final String CAN = "123456"; // <-- OVDJE STAVI SVOJ CAN

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        new ReadEID().start();
    }

    public void start() {
        try {
            TerminalFactory factory = TerminalFactory.getDefault();

            while (true) {
                List<CardTerminal> terminals = factory.terminals().list();

                for (CardTerminal terminal : terminals) {

                    if (terminal.isCardPresent()) {
                        System.out.println("📇 Kartica detektovana: " + terminal.getName());

                        readCard(terminal);

                        while (terminal.isCardPresent()) {
                            Thread.sleep(500);
                        }

                        System.out.println("📤 Kartica uklonjena\n");
                    }
                }

                Thread.sleep(500);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void readCard(CardTerminal terminal) {
        try {
            Card card = terminal.connect("T=CL");
            CardService service = CardService.getInstance(card);
            service.open();

            PassportService ps = new PassportService(service);
            ps.open();

            System.out.println("🔐 Pokrećem PACE...");

            // PACE sa CAN
            BACKeySpec paceKey = new BACKey(CAN, "", "");

            ps.doPACE(paceKey, null);

            System.out.println("✅ PACE uspješan!");

            ps.sendSelectApplet(false);

            // Čitanje DG1 (osnovni podaci)
            InputStream dg1Stream = ps.getInputStream(PassportService.EF_DG1);
            DG1File dg1 = new DG1File(dg1Stream);

            System.out.println("📄 DG1 sadržaj:");
            System.out.println(dg1.getMRZInfo().toString());

        } catch (Exception e) {
            System.out.println("❌ Greška pri čitanju kartice");
            e.printStackTrace();
        }
    }
}


import javax.smartcardio.*;
import java.util.List;

public class SmartCardFullListener {

    public static void main(String[] args) {
        new SmartCardFullListener().start();
    }

    public void start() {
        try {
            TerminalFactory factory = TerminalFactory.getDefault();

            while (true) {

                List<CardTerminal> terminals = factory.terminals().list();

                if (terminals.isEmpty()) {
                    System.out.println("❌ Nema readera...");
                    Thread.sleep(2000);
                    continue;
                }

                // Ispiši sve readere
                System.out.println("\n📡 Dostupni readeri:");
                for (int i = 0; i < terminals.size(); i++) {
                    System.out.println(i + ": " + terminals.get(i).getName());
                }

                // Prođi kroz sve readere (kontakt + NFC)
                for (CardTerminal terminal : terminals) {

                    try {
                        if (terminal.isCardPresent()) {
                            System.out.println("\n📇 Kartica detektovana na: " + terminal.getName());

                            processCard(terminal);

                            // čekaj da se kartica makne
                            while (terminal.isCardPresent()) {
                                Thread.sleep(500);
                            }

                            System.out.println("📤 Kartica uklonjena\n");
                        }

                    } catch (Exception e) {
                        System.out.println("⚠️ Greška na readeru: " + terminal.getName());
                    }
                }

                Thread.sleep(500);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void processCard(CardTerminal terminal) {
        Card card = null;

        try {
            // pokušaj različite protokole (bitno za NFC!)
            String[] protocols = {"T=0", "T=1", "T=CL", "*"};

            for (String protocol : protocols) {
                try {
                    card = terminal.connect(protocol);
                    System.out.println("🔗 Spojen preko protokola: " + protocol);
                    break;
                } catch (Exception ignored) {}
            }

            if (card == null) {
                System.out.println("❌ Ne mogu se spojiti na karticu");
                return;
            }

            CardChannel channel = card.getBasicChannel();

            System.out.println("📨 Slanje test APDU komande...");

            byte[] command = new byte[]{
                    (byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, (byte) 0x00
            };

            ResponseAPDU response = channel.transmit(new CommandAPDU(command));

            System.out.println("📥 Response: " + bytesToHex(response.getBytes()));

        } catch (Exception e) {
            System.out.println("❌ Greška pri radu s karticom");
            e.printStackTrace();
        } finally {
            try {
                if (card != null) {
                    card.disconnect(false);
                }
            } catch (Exception ignored) {}
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }
}
<dependencies>
    <dependency>
        <groupId>org.jmrtd</groupId>
        <artifactId>jmrtd</artifactId>
        <version>0.7.42</version>
    </dependency>
</dependencies>
<dependencies>
    <dependency>
        <groupId>org.jmrtd</groupId>
        <artifactId>jmrtd</artifactId>
        <version>0.7.42</version>
    </dependency>

    <dependency>
        <groupId>org.bouncycastle</groupId>
        <artifactId>bcprov-jdk18on</artifactId>
        <version>1.78</version>
    </dependency>
</dependencies>

import javax.smartcardio.*;
import java.util.List;

public class SmartCardListener {

    public static void main(String[] args) {
        new SmartCardListener().start();
    }

    public void start() {
        try {
            TerminalFactory factory = TerminalFactory.getDefault();
            List<CardTerminal> terminals = factory.terminals().list();

            if (terminals.isEmpty()) {
                System.out.println("❌ Nema dostupnih čitača kartica.");
                return;
            }

            CardTerminal terminal = terminals.get(0);
            System.out.println("✅ Reader pronađen: " + terminal.getName());

            while (true) {
                System.out.println("⏳ Čekam karticu...");

                // BLOKIRA dok se kartica ne prisloni
                terminal.waitForCardPresent(0);

                System.out.println("📇 Kartica detektovana!");

                processCard(terminal);

                // Čekaj da korisnik makne karticu
                terminal.waitForCardAbsent(0);
                System.out.println("📤 Kartica uklonjena\n");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void processCard(CardTerminal terminal) {
        Card card = null;

        try {
            card = terminal.connect("*");
            CardChannel channel = card.getBasicChannel();

            System.out.println("🔗 Povezan sa karticom");

            // TODO: Ovdje ide prava logika (BAC/PACE + čitanje podataka)
            byte[] command = new byte[] {
                (byte)0x00, (byte)0xA4, (byte)0x04, (byte)0x00, (byte)0x00
            };

            ResponseAPDU response = channel.transmit(new CommandAPDU(command));

            System.out.println("📥 Response: " + bytesToHex(response.getBytes()));

        } catch (Exception e) {
            System.out.println("❌ Greška pri radu s karticom");
            e.printStackTrace();
        } finally {
            try {
                if (card != null) {
                    card.disconnect(false);
                }
            } catch (Exception ignored) {}
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }
}
