
import javax.smartcardio.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.util.*;
import java.io.*;
import java.nio.charset.StandardCharsets;

/**
 * BiH eID Reader v11
 * Testira 4 SM varijante + READ BINARY sa SFI (bez SELECT)
 *
 * Kompajliranje: javac BihEidReader.java
 * Pokretanje:    java BihEidReader
 */
public class BihEidReader {

    static byte[] KS_ENC, KS_MAC, SSC = new byte[8];

    public static void main(String[] args) throws Exception {
        System.out.println("===========================================");
        System.out.println("  BiH eID Reader v11 |  SM Variant Test");
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
        String mrzInfo = docNum + cd(docNum) + dob + cd(dob) + expiry + cd(expiry);
        System.out.println("MRZ: " + mrzInfo);

        TerminalFactory fac = TerminalFactory.getDefault();
        List<CardTerminal> terms = fac.terminals().list();
        CardTerminal term = null;
        for (CardTerminal t : terms) if (t.isCardPresent()) { term = t; break; }
        if (term == null) { terms.get(0).waitForCardPresent(15000); term = terms.get(0); }
        Card card = term.connect("*");
        CardChannel ch = card.getBasicChannel();
        System.out.println("ATR: " + h(card.getATR().getBytes()));

        // =====================================================
        // Test svake varijante (svaki put restart BAC)
        // =====================================================
        String[] varLabels = {
            "A: IV=E(KSenc,SSC), MAC=SSC+pad(hdr)+DOs",
            "B: IV=E(KSenc,SSC), MAC=pad(SSC)+pad(hdr)+DOs",
            "C: IV=zeros,         MAC=SSC+pad(hdr)+DOs",
            "D: IV=zeros,         MAC=pad(SSC)+pad(hdr)+DOs",
        };

        for (int variant = 0; variant < 4; variant++) {
            System.out.println("\n========================================");
            System.out.println("  VARIJANTA " + varLabels[variant]);
            System.out.println("========================================");

            // Restart
            send(ch, "00A4040C07A0000002471001", "SELECT AID");
            doBAC(ch, mrzInfo);

            // Test SELECT EF.COM (011E) sa ovom varijantom
            int sw = testSelectVariant(ch, (byte)0x01, (byte)0x1E, variant);
            System.out.printf("  EF.COM SELECT -> SW=%04X  %s%n",
                sw, sw == 0x9000 ? "*** USPJEH! ***" : getSWMeaning(sw));

            if (sw == 0x9000) {
                System.out.println("  Varijanta " + (char)('A'+variant) + " radi! Čitam sve...");
                readAll(ch, variant, mrzInfo);
                break;
            }
        }

        // =====================================================
        // Test READ BINARY sa Short File Identifier (SFI)
        // (zaobilazi SELECT – bira i čita u jednoj komandi)
        // =====================================================
        System.out.println("\n========================================");
        System.out.println("  VARIJANTA E: READ BINARY sa SFI");
        System.out.println("  (bez prethodnog SELECT)");
        System.out.println("========================================");
        send(ch, "00A4040C07A0000002471001", "Re-SELECT AID");
        doBAC(ch, mrzInfo);

        // ICAO SFI assignments: DG1=0x01, DG2=0x02, EF.COM=0x1E, EF.SOD=0x1D
        int[] sfis    = { 0x1E, 0x01, 0x02, 0x0B, 0x0C, 0x1D, 0x0F };
        String[] sfiN = { "EF.COM","DG1","DG2","DG11","DG12","EF.SOD","DG15" };

        for (int i = 0; i < sfis.length; i++) {
            // P1 = 0x80 | SFI  → selektuje i čita datoteku po SFI
            byte p1 = (byte)(0x80 | sfis[i]);
            System.out.printf("%n  SM READ BINARY SFI=%02X (%s) P1=%02X%n",
                sfis[i], sfiN[i], p1 & 0xFF);

            // Probaj varijante C (IV=0, SSC raw) i A
            for (int v : new int[]{2, 0}) {
                incSSC();
                byte[] IV = (v <= 1) ? tdes_ecb(KS_ENC, SSC) : new byte[8]; // A,B: E(Kenc,SSC); C,D: zeros
                byte[] do97 = {(byte)0x97, 0x01, 0x00};
                byte[] hdr  = {(byte)0x0C, (byte)0xB0, p1, 0x00};
                byte[] sscMac = (v == 1 || v == 3) ? isopad(SSC) : SSC;
                byte[] M   = cat(sscMac, isopad(hdr), do97);
                byte[] CC  = mac3(KS_MAC, M);
                byte[] do8E = tlv(0x8E, CC);
                byte[] body = cat(do97, do8E);
                byte[] apdu = cat(new byte[]{(byte)0x0C,(byte)0xB0,p1,0x00,(byte)body.length},
                                  body, new byte[]{0x00});
                System.out.printf("    var%c APDU: %s%n", (char)('A'+v), h(apdu));
                ResponseAPDU r = ch.transmit(new CommandAPDU(apdu));
                System.out.printf("    var%c -> SW=%04X  %s%n",
                    (char)('A'+v), r.getSW(), getSWMeaning(r.getSW()));
                if (r.getSW() == 0x9000 && r.getData().length > 0) {
                    System.out.println("    *** USPJEH! data=" + h(r.getData()));
                }
            }
        }

        // =====================================================
        // Varijanta F: SM bez DO'87 u SELECT (samo MAC zaštita)
        // Neke kartice traže da se SELECT izvrši bez šifriranja
        // (samo autentičnost, ne povjerljivost)
        // =====================================================
        System.out.println("\n========================================");
        System.out.println("  VARIJANTA F: SELECT bez DO'87 (samo MAC)");
        System.out.println("========================================");
        send(ch, "00A4040C07A0000002471001", "Re-SELECT AID");
        doBAC(ch, mrzInfo);

        // Ovakav SELECT: CLA=0C, nema cmdData, samo DO'8E
        // Ali file ID mora negdje biti - koristi P1/P2 ili kratki SFI
        for (int sfi : new int[]{0x1E, 0x01, 0x02, 0x0B}) {
            incSSC();
            // SELECT FILE BY SHORT EF ID: A4 02 0C 00 (bez Lc)
            // P2=SFI kao "short file identifier"
            byte[] hdr = {(byte)0x0C, (byte)0xA4, 0x02, (byte)sfi};
            byte[] M   = cat(SSC, isopad(hdr));
            byte[] CC  = mac3(KS_MAC, M);
            byte[] do8E = tlv(0x8E, CC);
            byte[] apdu = cat(new byte[]{(byte)0x0C,(byte)0xA4,0x02,(byte)sfi,(byte)do8E.length},
                              do8E, new byte[]{0x00});
            System.out.printf("  SM SELECT SFI=%02X APDU: %s%n", sfi, h(apdu));
            ResponseAPDU r = ch.transmit(new CommandAPDU(apdu));
            System.out.printf("  SW=%04X  %s%n", r.getSW(), getSWMeaning(r.getSW()));
            if (r.getSW() == 0x9000) {
                System.out.println("  *** USPJEH! Čitam...");
                // READ BINARY
                ResponseAPDU rb = smRB_var(ch, (byte)0x00, (byte)0x00, 0); // var A
                System.out.printf("  READ -> SW=%04X data=%s%n", rb.getSW(), h(rb.getData()));
            }
        }

        card.disconnect(false);
        System.out.println("\n=== Završeno ===");
    }

    // ================================================================
    // TEST SELECT VARIJANTE (0=A, 1=B, 2=C, 3=D)
    // ================================================================
    static int testSelectVariant(CardChannel ch, byte hi, byte lo, int variant) throws Exception {
        incSSC();

        // IV za enkriptovanje
        byte[] IV = (variant <= 1) ? tdes_ecb(KS_ENC, SSC) : new byte[8];

        // Enkriptuj file ID
        byte[] enc  = tdes_cbc(KS_ENC, IV, isopad(new byte[]{hi, lo}));
        byte[] do87 = tlv(0x87, cat(new byte[]{0x01}, enc));

        // MAC input: SSC ili pad(SSC)
        byte[] sscMac = (variant == 1 || variant == 3) ? isopad(SSC) : SSC;
        byte[] hdr   = {(byte)0x0C, (byte)0xA4, 0x02, (byte)0x0C};
        byte[] M     = cat(sscMac, isopad(hdr), do87);
        byte[] CC    = mac3(KS_MAC, M);
        byte[] do8E  = tlv(0x8E, CC);

        byte[] body = cat(do87, do8E);
        byte[] apdu = cat(new byte[]{(byte)0x0C,(byte)0xA4,0x02,(byte)0x0C,(byte)body.length},
                          body, new byte[]{0x00});
        System.out.println("  APDU: " + h(apdu));
        ResponseAPDU r = ch.transmit(new CommandAPDU(apdu));
        return r.getSW();
    }

    // ================================================================
    // READ BINARY varijanta
    // ================================================================
    static ResponseAPDU smRB_var(CardChannel ch, byte p1, byte p2, int variant) throws Exception {
        incSSC();
        byte[] IV = (variant <= 1) ? tdes_ecb(KS_ENC, SSC) : new byte[8];
        byte[] do97 = {(byte)0x97, 0x01, 0x00};
        byte[] hdr  = {(byte)0x0C, (byte)0xB0, p1, p2};
        byte[] sscM = (variant==1||variant==3) ? isopad(SSC) : SSC;
        byte[] M    = cat(sscM, isopad(hdr), do97);
        byte[] CC   = mac3(KS_MAC, M);
        byte[] do8E = tlv(0x8E, CC);
        byte[] body = cat(do97, do8E);
        byte[] apdu = cat(new byte[]{(byte)0x0C,(byte)0xB0,p1,p2,(byte)body.length},
                          body, new byte[]{0x00});
        ResponseAPDU r = ch.transmit(new CommandAPDU(apdu));
        if (r.getSW() == 0x9000 && r.getData().length > 0) {
            return smDecrypt(r.getData(), variant);
        }
        return r;
    }

    // ================================================================
    // ČITANJE SVEGA (kad nađemo radnu varijantu)
    // ================================================================
    static void readAll(CardChannel ch, int variant, String mrzInfo) throws Exception {
        int[] fids   = { 0x011E, 0x0101, 0x010B, 0x010C, 0x0102, 0x011D, 0x010F };
        String[] names = { "EF.COM","DG1 MRZ","DG11 Lični","DG12 Dok","DG2 Foto","EF.SOD","DG15" };
        for (int i = 0; i < fids.length; i++) {
            System.out.println("\n--- " + names[i] + " ---");
            byte[] data = readEF(ch, fids[i], variant);
            if (data != null && data.length > 0) {
                System.out.printf("  ✓ %d bajta%n", data.length);
                saveFile(data, String.format("ef_%04X.bin", fids[i]));
                switch (fids[i]) {
                    case 0x011E: parseTLV(data,"  "); break;
                    case 0x0101: parseDG1(data); break;
                    case 0x010B: case 0x010C: parseTLV(data,"  "); break;
                    case 0x0102: savePhoto(data,"face"); break;
                }
            }
        }
    }

    static byte[] readEF(CardChannel ch, int fid, int variant) throws Exception {
        byte hi=(byte)(fid>>8), lo=(byte)(fid&0xFF);
        int sw = testSelectVariant(ch, hi, lo, variant);
        System.out.printf("  SELECT %04X SW=%04X%n", fid, sw);
        if (sw != 0x9000) return null;
        List<Byte> all=new ArrayList<>();
        int off=0;
        while(true) {
            ResponseAPDU rb = smRB_var(ch,(byte)((off>>8)&0x7F),(byte)(off&0xFF),variant);
            int rsw=rb.getSW();
            if(rsw==0x9000){byte[] d=rb.getData();if(d.length==0)break;for(byte b:d)all.add(b);off+=d.length;if(d.length<0xDF)break;}
            else break;
        }
        byte[] res=new byte[all.size()];for(int k=0;k<res.length;k++)res[k]=all.get(k);
        return res.length>0?res:null;
    }

    // ================================================================
    // SM RESPONSE DEKRIPTOVANJE
    // ================================================================
    static ResponseAPDU smDecrypt(byte[] resp, int variant) throws Exception {
        incSSC();
        byte[] IV=(variant<=1)?tdes_ecb(KS_ENC,SSC):new byte[8];
        byte[] v87=null,v99=null,v8E=null;
        int i=0;
        while(i<resp.length){
            int tag=resp[i++]&0xFF; if(tag==0||tag==0xFF) continue;
            if((tag&0x1F)==0x1F&&i<resp.length) tag=(tag<<8)|(resp[i++]&0xFF);
            if(i>=resp.length) break;
            int len=resp[i++]&0xFF;
            if(len==0x81&&i<resp.length)len=resp[i++]&0xFF;
            else if(len==0x82&&i+1<resp.length){len=((resp[i]&0xFF)<<8)|(resp[i+1]&0xFF);i+=2;}
            if(i+len>resp.length) break;
            byte[] val=Arrays.copyOfRange(resp,i,i+len);i+=len;
            int t=tag&0xFF;
            if(t==0x87)v87=val; else if(t==0x99)v99=val; else if(t==0x8E)v8E=val;
        }
        byte[] sscM=(variant==1||variant==3)?isopad(SSC):SSC;
        byte[] macIn=sscM;
        if(v87!=null) macIn=cat(macIn,tlv(0x87,v87));
        if(v99!=null) macIn=cat(macIn,tlv(0x99,v99));
        if(!Arrays.equals(mac3(KS_MAC,macIn),v8E))
            System.out.println("  WARN: response MAC mismatch");
        byte[] plain=new byte[0];
        if(v87!=null){byte[] c=Arrays.copyOfRange(v87,1,v87.length);plain=isounpad(tdes_cbc_dec(KS_ENC,IV,c));}
        int sw=v99!=null?((v99[0]&0xFF)<<8)|(v99[1]&0xFF):0x9000;
        byte[] full=new byte[plain.length+2];System.arraycopy(plain,0,full,0,plain.length);
        full[plain.length]=(byte)(sw>>8);full[plain.length+1]=(byte)(sw&0xFF);
        return new ResponseAPDU(full);
    }

    // ================================================================
    // BAC
    // ================================================================
    static void doBAC(CardChannel ch, String mrzInfo) throws Exception {
        System.out.println("--- BAC ---");
        byte[] kseed=Arrays.copyOf(sha1(mrzInfo.getBytes(StandardCharsets.UTF_8)),16);
        byte[] kenc=kdf(kseed,1), kmac=kdf(kseed,2);
        ResponseAPDU gc=ch.transmit(new CommandAPDU(x("0084000008")));
        if(gc.getSW()!=0x9000) throw new Exception("GET CHALLENGE: "+sw(gc));
        byte[] RND_IC=gc.getData();
        byte[] RND_IFD=new byte[8];new SecureRandom().nextBytes(RND_IFD);
        byte[] K_IFD=new byte[16];new SecureRandom().nextBytes(K_IFD);
        byte[] EIFD=tdes_cbc(kenc,new byte[8],cat(RND_IFD,RND_IC,K_IFD));
        byte[] MIFD=mac3(kmac,EIFD);
        byte[] body=cat(EIFD,MIFD);
        byte[] ea=cat(new byte[]{0x00,(byte)0x82,0x00,0x00,0x28},body,new byte[]{0x28});
        ResponseAPDU ar=ch.transmit(new CommandAPDU(ea));
        System.out.printf("EXT AUTH SW=%04X%n",ar.getSW());
        if(ar.getSW()!=0x9000) throw new Exception("BAC failed");
        byte[] R=ar.getData();
        byte[] dec=tdes_cbc_dec(kenc,new byte[8],Arrays.copyOf(R,32));
        byte[] K_IC=Arrays.copyOfRange(dec,16,32);
        boolean macOk=Arrays.equals(mac3(kmac,Arrays.copyOf(R,32)),Arrays.copyOfRange(R,32,40));
        System.out.println("MAC OK: "+macOk);
        byte[] seed=xor(K_IFD,K_IC);
        KS_ENC=kdf(seed,1); KS_MAC=kdf(seed,2);
        SSC=cat(Arrays.copyOfRange(RND_IC,4,8),Arrays.copyOfRange(RND_IFD,4,8));
        System.out.println("KS_ENC: "+h(KS_ENC));
        System.out.println("KS_MAC: "+h(KS_MAC));
        System.out.println("SSC:    "+h(SSC));
        System.out.println("BAC OK!");
    }

    // ================================================================
    // PARSIRANJE
    // ================================================================
    static void parseDG1(byte[] d){System.out.println("DG1 MRZ:");parseTLV(d,"  ");}
    static void parseTLV(byte[] d,String ind){doTLV(d,0,d.length,ind,0);}
    static void doTLV(byte[] d,int s,int e,String ind,int depth){
        if(depth>8)return;int i=s;
        while(i<e){
            if((d[i]&0xFF)==0||(d[i]&0xFF)==0xFF){i++;continue;}
            int tag=d[i++]&0xFF;boolean con=(tag&0x20)!=0;
            if((tag&0x1F)==0x1F&&i<e) tag=(tag<<8)|(d[i++]&0xFF);
            if(i>=e) break;int len=d[i++]&0xFF;
            if(len==0x81&&i<e)len=d[i++]&0xFF;
            else if(len==0x82&&i+1<e){len=((d[i]&0xFF)<<8)|(d[i+1]&0xFF);i+=2;}
            if(i+len>e||len<0) break;byte[] val=Arrays.copyOfRange(d,i,i+len);i+=len;
            System.out.printf("%s%04X [%s] len=%d%n",ind,tag,tn(tag),len);
            if(tag==0x5F1F){String mrz=new String(val,StandardCharsets.UTF_8);System.out.println(ind+"  ["+mrz.replace("\n","↵")+"]");mrzBox(mrz,ind+"  ");}
            else if(tag==0x5C){System.out.print(ind+"  DG:");for(byte b:val)System.out.printf(" %d",dgN(b&0xFF));System.out.println();}
            else if(con) doTLV(d,i-len,i,ind+"  ",depth+1);
            else{boolean pr=val.length>0;for(byte b:val){int c=b&0xFF;if(c<0x20||c>0x7E){pr=false;break;}}
                System.out.println(ind+"  = "+(pr?"\""+new String(val,StandardCharsets.UTF_8)+"\"":h(val)));}
        }
    }
    static void mrzBox(String mrz,String ind){
        mrz=mrz.replace("\n","").replace("\r","");
        if(mrz.length()<60) return;
        System.out.println(ind+"╔══════════════════════════════╗");
        String l1=mrz.substring(0,30);
        System.out.println(ind+"║ Br.dok  : "+p(l1.substring(5,14).replace("<",""),21)+"║");
        String l2=mrz.substring(30,60);
        System.out.println(ind+"║ Dat.rod : "+p(fD(l2.substring(0,6)),21)+"║");
        System.out.println(ind+"║ Pol     : "+p(l2.substring(7,8).equals("M")?"Muški":"Ženski",21)+"║");
        System.out.println(ind+"║ Dat.ist : "+p(fD(l2.substring(8,14)),21)+"║");
        if(mrz.length()>=90){String l3=mrz.substring(60,90);String[]ps=l3.split("<<",2);
            System.out.println(ind+"║ Prezime : "+p(ps[0].replace("<",""),21)+"║");
            if(ps.length>1) System.out.println(ind+"║ Ime     : "+p(ps[1].replace("<"," ").trim(),21)+"║");}
        System.out.println(ind+"╚══════════════════════════════╝");
    }
    static void savePhoto(byte[] d,String pfx){
        int off=findB(d,new byte[]{(byte)0xFF,(byte)0xD8});
        if(off>=0){saveFile(Arrays.copyOfRange(d,off,d.length),pfx+".jpg");System.out.println("  "+pfx+".jpg saved");}
    }
    static String getSWMeaning(int sw){
        switch(sw){
            case 0x9000:return"OK";case 0x6988:return"SM crypto wrong";
            case 0x6987:return"SM missing";case 0x6985:return"Conditions not met";
            case 0x6982:return"Security status not satisfied";case 0x6A82:return"File not found";
            default:return String.format("SW=%04X",sw);
        }
    }
    static String fD(String s){if(s.length()!=6)return s;int y=Integer.parseInt(s.substring(0,2));return s.substring(4)+"."+s.substring(2,4)+"."+(y>30?"19":"20")+s.substring(0,2);}
    static String p(String s,int n){while(s.length()<n)s+=" ";return s;}
    static int dgN(int b){if(b==0x60)return 0;if(b>=0x61&&b<=0x6F)return b-0x60;return b;}
    static String tn(int t){switch(t){case 0x60:return"EF.COM";case 0x5F01:return"LDS ver";case 0x5F36:return"Unicode ver";case 0x5C:return"DG lista";case 0x5F1F:return"MRZ";case 0x5F0E:return"Ime";case 0x5F1D:return"JMBG";case 0x5F42:return"Adresa";case 0x30:return"SEQ";default:return String.format("?%04X",t);}}

    // ================================================================
    // KRIPTO
    // ================================================================
    static byte[] tdes_ecb(byte[] k16,byte[] d8) throws Exception{
        byte[] k24=cat(k16,Arrays.copyOf(k16,8));
        Cipher c=Cipher.getInstance("DESede/ECB/NoPadding");
        c.init(Cipher.ENCRYPT_MODE,SecretKeyFactory.getInstance("DESede").generateSecret(new DESedeKeySpec(k24)));
        return c.doFinal(d8);
    }
    static byte[] tdes_cbc(byte[] k16,byte[] iv,byte[] d) throws Exception{
        byte[] k24=cat(k16,Arrays.copyOf(k16,8));
        Cipher c=Cipher.getInstance("DESede/CBC/NoPadding");
        c.init(Cipher.ENCRYPT_MODE,SecretKeyFactory.getInstance("DESede").generateSecret(new DESedeKeySpec(k24)),new IvParameterSpec(iv));
        return c.doFinal(d);
    }
    static byte[] tdes_cbc_dec(byte[] k16,byte[] iv,byte[] d) throws Exception{
        byte[] k24=cat(k16,Arrays.copyOf(k16,8));
        Cipher c=Cipher.getInstance("DESede/CBC/NoPadding");
        c.init(Cipher.DECRYPT_MODE,SecretKeyFactory.getInstance("DESede").generateSecret(new DESedeKeySpec(k24)),new IvParameterSpec(iv));
        return c.doFinal(d);
    }
    static byte[] mac3(byte[] k16,byte[] d) throws Exception{
        byte[] p=isopad(d),k1=Arrays.copyOf(k16,8),k2=Arrays.copyOfRange(k16,8,16),cv=new byte[8];
        for(int i=0;i<p.length;i+=8) cv=des_e(k1,cv,Arrays.copyOfRange(p,i,i+8));
        return Arrays.copyOf(des_e(k1,new byte[8],des_d(k2,new byte[8],cv)),8);
    }
    static byte[] des_e(byte[] k,byte[] iv,byte[] d) throws Exception{Cipher c=Cipher.getInstance("DES/CBC/NoPadding");c.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(k,"DES"),new IvParameterSpec(iv));return c.doFinal(d);}
    static byte[] des_d(byte[] k,byte[] iv,byte[] d) throws Exception{Cipher c=Cipher.getInstance("DES/CBC/NoPadding");c.init(Cipher.DECRYPT_MODE,new SecretKeySpec(k,"DES"),new IvParameterSpec(iv));return c.doFinal(d);}
    static byte[] kdf(byte[] s,int c) throws Exception{
        byte[] D=Arrays.copyOf(s,s.length+4);D[D.length-1]=(byte)c;
        byte[] k=Arrays.copyOf(sha1(D),16);
        for(int i=0;i<16;i++){int b=k[i]&0xFE;k[i]=(byte)(b|(Integer.bitCount(b)%2==0?1:0));}
        return k;
    }
    static byte[] isopad(byte[] d){byte[] r=new byte[d.length+8-(d.length%8)];System.arraycopy(d,0,r,0,d.length);r[d.length]=(byte)0x80;return r;}
    static byte[] isounpad(byte[] d){int i=d.length-1;while(i>=0&&d[i]==0)i--;return(i>=0&&(d[i]&0xFF)==0x80)?Arrays.copyOf(d,i):d;}
    static void incSSC(){for(int i=SSC.length-1;i>=0;i--){if(++SSC[i]!=0)break;}}
    static byte[] sha1(byte[] d) throws Exception{return MessageDigest.getInstance("SHA-1").digest(d);}
    static byte[] xor(byte[] a,byte[] b){byte[] r=new byte[a.length];for(int i=0;i<a.length;i++)r[i]=(byte)(a[i]^b[i]);return r;}
    static byte[] tlv(int tag,byte[] val){byte[] t=tag>0xFF?new byte[]{(byte)(tag>>8),(byte)(tag&0xFF)}:new byte[]{(byte)(tag&0xFF)};byte[] l=val.length<0x80?new byte[]{(byte)val.length}:val.length<0x100?new byte[]{(byte)0x81,(byte)val.length}:new byte[]{(byte)0x82,(byte)(val.length>>8),(byte)(val.length&0xFF)};return cat(t,l,val);}
    static int cd(String s){int[]w={7,3,1};int sum=0;for(int i=0;i<s.length();i++){char c=s.charAt(i);int v=(c=='<')?0:(c>='A'&&c<='Z')?c-'A'+10:c-'0';sum+=v*w[i%3];}return sum%10;}
    static ResponseAPDU send(CardChannel ch,String hex,String l) throws CardException{ResponseAPDU r=ch.transmit(new CommandAPDU(x(hex)));System.out.printf("%s SW=%04X%s%n",l,r.getSW(),r.getData().length>0?" data="+h(r.getData()):"");return r;}
    static int findB(byte[] h,byte[] n){outer:for(int i=0;i<=h.length-n.length;i++){for(int j=0;j<n.length;j++)if(h[i+j]!=n[j])continue outer;return i;}return -1;}
    static void saveFile(byte[] d,String n){try(FileOutputStream f=new FileOutputStream(n)){f.write(d);}catch(Exception e){System.out.println("Save: "+e);}}
    static byte[] cat(byte[]...a){int n=0;for(byte[]x:a)if(x!=null)n+=x.length;byte[]r=new byte[n];int o=0;for(byte[]x:a)if(x!=null){System.arraycopy(x,0,r,o,x.length);o+=x.length;}return r;}
    static String h(byte[] b){if(b==null||b.length==0)return"(empty)";StringBuilder s=new StringBuilder();for(byte x:b)s.append(String.format("%02X",x));return s.toString();}
    static String sw(ResponseAPDU r){return String.format("%04X",r.getSW());}
    static byte[] x(String s){s=s.replace(" ","");byte[]d=new byte[s.length()/2];for(int i=0;i<d.length;i++)d[i]=(byte)((Character.digit(s.charAt(i*2),16)<<4)+Character.digit(s.charAt(i*2+1),16));return d;}
}



import javax.smartcardio.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.util.*;
import java.io.*;
import java.nio.charset.StandardCharsets;

/**
 * BiH eID Reader v11
 * Testira 4 SM varijante + READ BINARY sa SFI (bez SELECT)
 *
 * Kompajliranje: javac BihEidReader.java
 * Pokretanje:    java BihEidReader
 */
public class BihEidReader {

    static byte[] KS_ENC, KS_MAC, SSC = new byte[8];

    public static void main(String[] args) throws Exception {
        System.out.println("===========================================");
        System.out.println("  BiH eID Reader v11 |  SM Variant Test");
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
        String mrzInfo = docNum + cd(docNum) + dob + cd(dob) + expiry + cd(expiry);
        System.out.println("MRZ: " + mrzInfo);

        TerminalFactory fac = TerminalFactory.getDefault();
        List<CardTerminal> terms = fac.terminals().list();
        CardTerminal term = null;
        for (CardTerminal t : terms) if (t.isCardPresent()) { term = t; break; }
        if (term == null) { terms.get(0).waitForCardPresent(15000); term = terms.get(0); }
        Card card = term.connect("*");
        CardChannel ch = card.getBasicChannel();
        System.out.println("ATR: " + h(card.getATR().getBytes()));

        // =====================================================
        // Test svake varijante (svaki put restart BAC)
        // =====================================================
        String[] varLabels = {
            "A: IV=E(KSenc,SSC), MAC=SSC+pad(hdr)+DOs",
            "B: IV=E(KSenc,SSC), MAC=pad(SSC)+pad(hdr)+DOs",
            "C: IV=zeros,         MAC=SSC+pad(hdr)+DOs",
            "D: IV=zeros,         MAC=pad(SSC)+pad(hdr)+DOs",
        };

        for (int variant = 0; variant < 4; variant++) {
            System.out.println("\n========================================");
            System.out.println("  VARIJANTA " + varLabels[variant]);
            System.out.println("========================================");

            // Restart
            send(ch, "00A4040C07A0000002471001", "SELECT AID");
            doBAC(ch, mrzInfo);

            // Test SELECT EF.COM (011E) sa ovom varijantom
            int sw = testSelectVariant(ch, (byte)0x01, (byte)0x1E, variant);
            System.out.printf("  EF.COM SELECT -> SW=%04X  %s%n",
                sw, sw == 0x9000 ? "*** USPJEH! ***" : getSWMeaning(sw));

            if (sw == 0x9000) {
                System.out.println("  Varijanta " + (char)('A'+variant) + " radi! Čitam sve...");
                readAll(ch, variant, mrzInfo);
                break;
            }
        }

        // =====================================================
        // Test READ BINARY sa Short File Identifier (SFI)
        // (zaobilazi SELECT – bira i čita u jednoj komandi)
        // =====================================================
        System.out.println("\n========================================");
        System.out.println("  VARIJANTA E: READ BINARY sa SFI");
        System.out.println("  (bez prethodnog SELECT)");
        System.out.println("========================================");
        send(ch, "00A4040C07A0000002471001", "Re-SELECT AID");
        doBAC(ch, mrzInfo);

        // ICAO SFI assignments: DG1=0x01, DG2=0x02, EF.COM=0x1E, EF.SOD=0x1D
        int[] sfis    = { 0x1E, 0x01, 0x02, 0x0B, 0x0C, 0x1D, 0x0F };
        String[] sfiN = { "EF.COM","DG1","DG2","DG11","DG12","EF.SOD","DG15" };

        for (int i = 0; i < sfis.length; i++) {
            // P1 = 0x80 | SFI  → selektuje i čita datoteku po SFI
            byte p1 = (byte)(0x80 | sfis[i]);
            System.out.printf("%n  SM READ BINARY SFI=%02X (%s) P1=%02X%n",
                sfis[i], sfiN[i], p1 & 0xFF);

            // Probaj varijante C (IV=0, SSC raw) i A
            for (int v : new int[]{2, 0}) {
                incSSC();
                byte[] IV = (v <= 1) ? tdes_ecb(KS_ENC, SSC) : new byte[8]; // A,B: E(Kenc,SSC); C,D: zeros
                byte[] do97 = {(byte)0x97, 0x01, 0x00};
                byte[] hdr  = {(byte)0x0C, (byte)0xB0, p1, 0x00};
                byte[] sscMac = (v == 1 || v == 3) ? isopad(SSC) : SSC;
                byte[] M   = cat(sscMac, isopad(hdr), do97);
                byte[] CC  = mac3(KS_MAC, M);
                byte[] do8E = tlv(0x8E, CC);
                byte[] body = cat(do97, do8E);
                byte[] apdu = cat(new byte[]{(byte)0x0C,(byte)0xB0,p1,0x00,(byte)body.length},
                                  body, new byte[]{0x00});
                System.out.printf("    var%c APDU: %s%n", (char)('A'+v), h(apdu));
                ResponseAPDU r = ch.transmit(new CommandAPDU(apdu));
                System.out.printf("    var%c -> SW=%04X  %s%n",
                    (char)('A'+v), r.getSW(), getSWMeaning(r.getSW()));
                if (r.getSW() == 0x9000 && r.getData().length > 0) {
                    System.out.println("    *** USPJEH! data=" + h(r.getData()));
                }
            }
        }

        // =====================================================
        // Varijanta F: SM bez DO'87 u SELECT (samo MAC zaštita)
        // Neke kartice traže da se SELECT izvrši bez šifriranja
        // (samo autentičnost, ne povjerljivost)
        // =====================================================
        System.out.println("\n========================================");
        System.out.println("  VARIJANTA F: SELECT bez DO'87 (samo MAC)");
        System.out.println("========================================");
        send(ch, "00A4040C07A0000002471001", "Re-SELECT AID");
        doBAC(ch, mrzInfo);

        // Ovakav SELECT: CLA=0C, nema cmdData, samo DO'8E
        // Ali file ID mora negdje biti - koristi P1/P2 ili kratki SFI
        for (int sfi : new int[]{0x1E, 0x01, 0x02, 0x0B}) {
            incSSC();
            // SELECT FILE BY SHORT EF ID: A4 02 0C 00 (bez Lc)
            // P2=SFI kao "short file identifier"
            byte[] hdr = {(byte)0x0C, (byte)0xA4, 0x02, (byte)sfi};
            byte[] M   = cat(SSC, isopad(hdr));
            byte[] CC  = mac3(KS_MAC, M);
            byte[] do8E = tlv(0x8E, CC);
            byte[] apdu = cat(new byte[]{(byte)0x0C,(byte)0xA4,0x02,(byte)sfi,(byte)do8E.length},
                              do8E, new byte[]{0x00});
            System.out.printf("  SM SELECT SFI=%02X APDU: %s%n", sfi, h(apdu));
            ResponseAPDU r = ch.transmit(new CommandAPDU(apdu));
            System.out.printf("  SW=%04X  %s%n", r.getSW(), getSWMeaning(r.getSW()));
            if (r.getSW() == 0x9000) {
                System.out.println("  *** USPJEH! Čitam...");
                // READ BINARY
                ResponseAPDU rb = smRB_var(ch, (byte)0x00, (byte)0x00, 0); // var A
                System.out.printf("  READ -> SW=%04X data=%s%n", rb.getSW(), h(rb.getData()));
            }
        }

        card.disconnect(false);
        System.out.println("\n=== Završeno ===");
    }

    // ================================================================
    // TEST SELECT VARIJANTE (0=A, 1=B, 2=C, 3=D)
    // ================================================================
    static int testSelectVariant(CardChannel ch, byte hi, byte lo, int variant) throws Exception {
        incSSC();

        // IV za enkriptovanje
        byte[] IV = (variant <= 1) ? tdes_ecb(KS_ENC, SSC) : new byte[8];

        // Enkriptuj file ID
        byte[] enc  = tdes_cbc(KS_ENC, IV, isopad(new byte[]{hi, lo}));
        byte[] do87 = tlv(0x87, cat(new byte[]{0x01}, enc));

        // MAC input: SSC ili pad(SSC)
        byte[] sscMac = (variant == 1 || variant == 3) ? isopad(SSC) : SSC;
        byte[] hdr   = {(byte)0x0C, (byte)0xA4, 0x02, (byte)0x0C};
        byte[] M     = cat(sscMac, isopad(hdr), do87);
        byte[] CC    = mac3(KS_MAC, M);
        byte[] do8E  = tlv(0x8E, CC);

        byte[] body = cat(do87, do8E);
        byte[] apdu = cat(new byte[]{(byte)0x0C,(byte)0xA4,0x02,(byte)0x0C,(byte)body.length},
                          body, new byte[]{0x00});
        System.out.println("  APDU: " + h(apdu));
        ResponseAPDU r = ch.transmit(new CommandAPDU(apdu));
        return r.getSW();
    }

    // ================================================================
    // READ BINARY varijanta
    // ================================================================
    static ResponseAPDU smRB_var(CardChannel ch, byte p1, byte p2, int variant) throws Exception {
        incSSC();
        byte[] IV = (variant <= 1) ? tdes_ecb(KS_ENC, SSC) : new byte[8];
        byte[] do97 = {(byte)0x97, 0x01, 0x00};
        byte[] hdr  = {(byte)0x0C, (byte)0xB0, p1, p2};
        byte[] sscM = (variant==1||variant==3) ? isopad(SSC) : SSC;
        byte[] M    = cat(sscM, isopad(hdr), do97);
        byte[] CC   = mac3(KS_MAC, M);
        byte[] do8E = tlv(0x8E, CC);
        byte[] body = cat(do97, do8E);
        byte[] apdu = cat(new byte[]{(byte)0x0C,(byte)0xB0,p1,p2,(byte)body.length},
                          body, new byte[]{0x00});
        ResponseAPDU r = ch.transmit(new CommandAPDU(apdu));
        if (r.getSW() == 0x9000 && r.getData().length > 0) {
            return smDecrypt(r.getData(), variant);
        }
        return r;
    }

    // ================================================================
    // ČITANJE SVEGA (kad nađemo radnu varijantu)
    // ================================================================
    static void readAll(CardChannel ch, int variant, String mrzInfo) throws Exception {
        int[] fids   = { 0x011E, 0x0101, 0x010B, 0x010C, 0x0102, 0x011D, 0x010F };
        String[] names = { "EF.COM","DG1 MRZ","DG11 Lični","DG12 Dok","DG2 Foto","EF.SOD","DG15" };
        for (int i = 0; i < fids.length; i++) {
            System.out.println("\n--- " + names[i] + " ---");
            byte[] data = readEF(ch, fids[i], variant);
            if (data != null && data.length > 0) {
                System.out.printf("  ✓ %d bajta%n", data.length);
                saveFile(data, String.format("ef_%04X.bin", fids[i]));
                switch (fids[i]) {
                    case 0x011E: parseTLV(data,"  "); break;
                    case 0x0101: parseDG1(data); break;
                    case 0x010B: case 0x010C: parseTLV(data,"  "); break;
                    case 0x0102: savePhoto(data,"face"); break;
                }
            }
        }
    }

    static byte[] readEF(CardChannel ch, int fid, int variant) throws Exception {
        byte hi=(byte)(fid>>8), lo=(byte)(fid&0xFF);
        int sw = testSelectVariant(ch, hi, lo, variant);
        System.out.printf("  SELECT %04X SW=%04X%n", fid, sw);
        if (sw != 0x9000) return null;
        List<Byte> all=new ArrayList<>();
        int off=0;
        while(true) {
            ResponseAPDU rb = smRB_var(ch,(byte)((off>>8)&0x7F),(byte)(off&0xFF),variant);
            int rsw=rb.getSW();
            if(rsw==0x9000){byte[] d=rb.getData();if(d.length==0)break;for(byte b:d)all.add(b);off+=d.length;if(d.length<0xDF)break;}
            else break;
        }
        byte[] res=new byte[all.size()];for(int k=0;k<res.length;k++)res[k]=all.get(k);
        return res.length>0?res:null;
    }

    // ================================================================
    // SM RESPONSE DEKRIPTOVANJE
    // ================================================================
    static ResponseAPDU smDecrypt(byte[] resp, int variant) throws Exception {
        incSSC();
        byte[] IV=(variant<=1)?tdes_ecb(KS_ENC,SSC):new byte[8];
        byte[] v87=null,v99=null,v8E=null;
        int i=0;
        while(i<resp.length){
            int tag=resp[i++]&0xFF; if(tag==0||tag==0xFF) continue;
            if((tag&0x1F)==0x1F&&i<resp.length) tag=(tag<<8)|(resp[i++]&0xFF);
            if(i>=resp.length) break;
            int len=resp[i++]&0xFF;
            if(len==0x81&&i<resp.length)len=resp[i++]&0xFF;
            else if(len==0x82&&i+1<resp.length){len=((resp[i]&0xFF)<<8)|(resp[i+1]&0xFF);i+=2;}
            if(i+len>resp.length) break;
            byte[] val=Arrays.copyOfRange(resp,i,i+len);i+=len;
            int t=tag&0xFF;
            if(t==0x87)v87=val; else if(t==0x99)v99=val; else if(t==0x8E)v8E=val;
        }
        byte[] sscM=(variant==1||variant==3)?isopad(SSC):SSC;
        byte[] macIn=sscM;
        if(v87!=null) macIn=cat(macIn,tlv(0x87,v87));
        if(v99!=null) macIn=cat(macIn,tlv(0x99,v99));
        if(!Arrays.equals(mac3(KS_MAC,macIn),v8E))
            System.out.println("  WARN: response MAC mismatch");
        byte[] plain=new byte[0];
        if(v87!=null){byte[] c=Arrays.copyOfRange(v87,1,v87.length);plain=isounpad(tdes_cbc_dec(KS_ENC,IV,c));}
        int sw=v99!=null?((v99[0]&0xFF)<<8)|(v99[1]&0xFF):0x9000;
        byte[] full=new byte[plain.length+2];System.arraycopy(plain,0,full,0,plain.length);
        full[plain.length]=(byte)(sw>>8);full[plain.length+1]=(byte)(sw&0xFF);
        return new ResponseAPDU(full);
    }

    // ================================================================
    // BAC
    // ================================================================
    static void doBAC(CardChannel ch, String mrzInfo) throws Exception {
        System.out.println("--- BAC ---");
        byte[] kseed=Arrays.copyOf(sha1(mrzInfo.getBytes(StandardCharsets.UTF_8)),16);
        byte[] kenc=kdf(kseed,1), kmac=kdf(kseed,2);
        ResponseAPDU gc=ch.transmit(new CommandAPDU(x("0084000008")));
        if(gc.getSW()!=0x9000) throw new Exception("GET CHALLENGE: "+sw(gc));
        byte[] RND_IC=gc.getData();
        byte[] RND_IFD=new byte[8];new SecureRandom().nextBytes(RND_IFD);
        byte[] K_IFD=new byte[16];new SecureRandom().nextBytes(K_IFD);
        byte[] EIFD=tdes_cbc(kenc,new byte[8],cat(RND_IFD,RND_IC,K_IFD));
        byte[] MIFD=mac3(kmac,EIFD);
        byte[] body=cat(EIFD,MIFD);
        byte[] ea=cat(new byte[]{0x00,(byte)0x82,0x00,0x00,0x28},body,new byte[]{0x28});
        ResponseAPDU ar=ch.transmit(new CommandAPDU(ea));
        System.out.printf("EXT AUTH SW=%04X%n",ar.getSW());
        if(ar.getSW()!=0x9000) throw new Exception("BAC failed");
        byte[] R=ar.getData();
        byte[] dec=tdes_cbc_dec(kenc,new byte[8],Arrays.copyOf(R,32));
        byte[] K_IC=Arrays.copyOfRange(dec,16,32);
        boolean macOk=Arrays.equals(mac3(kmac,Arrays.copyOf(R,32)),Arrays.copyOfRange(R,32,40));
        System.out.println("MAC OK: "+macOk);
        byte[] seed=xor(K_IFD,K_IC);
        KS_ENC=kdf(seed,1); KS_MAC=kdf(seed,2);
        SSC=cat(Arrays.copyOfRange(RND_IC,4,8),Arrays.copyOfRange(RND_IFD,4,8));
        System.out.println("KS_ENC: "+h(KS_ENC));
        System.out.println("KS_MAC: "+h(KS_MAC));
        System.out.println("SSC:    "+h(SSC));
        System.out.println("BAC OK!");
    }

    // ================================================================
    // PARSIRANJE
    // ================================================================
    static void parseDG1(byte[] d){System.out.println("DG1 MRZ:");parseTLV(d,"  ");}
    static void parseTLV(byte[] d,String ind){doTLV(d,0,d.length,ind,0);}
    static void doTLV(byte[] d,int s,int e,String ind,int depth){
        if(depth>8)return;int i=s;
        while(i<e){
            if((d[i]&0xFF)==0||(d[i]&0xFF)==0xFF){i++;continue;}
            int tag=d[i++]&0xFF;boolean con=(tag&0x20)!=0;
            if((tag&0x1F)==0x1F&&i<e) tag=(tag<<8)|(d[i++]&0xFF);
            if(i>=e) break;int len=d[i++]&0xFF;
            if(len==0x81&&i<e)len=d[i++]&0xFF;
            else if(len==0x82&&i+1<e){len=((d[i]&0xFF)<<8)|(d[i+1]&0xFF);i+=2;}
            if(i+len>e||len<0) break;byte[] val=Arrays.copyOfRange(d,i,i+len);i+=len;
            System.out.printf("%s%04X [%s] len=%d%n",ind,tag,tn(tag),len);
            if(tag==0x5F1F){String mrz=new String(val,StandardCharsets.UTF_8);System.out.println(ind+"  ["+mrz.replace("\n","↵")+"]");mrzBox(mrz,ind+"  ");}
            else if(tag==0x5C){System.out.print(ind+"  DG:");for(byte b:val)System.out.printf(" %d",dgN(b&0xFF));System.out.println();}
            else if(con) doTLV(d,i-len,i,ind+"  ",depth+1);
            else{boolean pr=val.length>0;for(byte b:val){int c=b&0xFF;if(c<0x20||c>0x7E){pr=false;break;}}
                System.out.println(ind+"  = "+(pr?"\""+new String(val,StandardCharsets.UTF_8)+"\"":h(val)));}
        }
    }
    static void mrzBox(String mrz,String ind){
        mrz=mrz.replace("\n","").replace("\r","");
        if(mrz.length()<60) return;
        System.out.println(ind+"╔══════════════════════════════╗");
        String l1=mrz.substring(0,30);
        System.out.println(ind+"║ Br.dok  : "+p(l1.substring(5,14).replace("<",""),21)+"║");
        String l2=mrz.substring(30,60);
        System.out.println(ind+"║ Dat.rod : "+p(fD(l2.substring(0,6)),21)+"║");
        System.out.println(ind+"║ Pol     : "+p(l2.substring(7,8).equals("M")?"Muški":"Ženski",21)+"║");
        System.out.println(ind+"║ Dat.ist : "+p(fD(l2.substring(8,14)),21)+"║");
        if(mrz.length()>=90){String l3=mrz.substring(60,90);String[]ps=l3.split("<<",2);
            System.out.println(ind+"║ Prezime : "+p(ps[0].replace("<",""),21)+"║");
            if(ps.length>1) System.out.println(ind+"║ Ime     : "+p(ps[1].replace("<"," ").trim(),21)+"║");}
        System.out.println(ind+"╚══════════════════════════════╝");
    }
    static void savePhoto(byte[] d,String pfx){
        int off=findB(d,new byte[]{(byte)0xFF,(byte)0xD8});
        if(off>=0){saveFile(Arrays.copyOfRange(d,off,d.length),pfx+".jpg");System.out.println("  "+pfx+".jpg saved");}
    }
    static String getSWMeaning(int sw){
        switch(sw){
            case 0x9000:return"OK";case 0x6988:return"SM crypto wrong";
            case 0x6987:return"SM missing";case 0x6985:return"Conditions not met";
            case 0x6982:return"Security status not satisfied";case 0x6A82:return"File not found";
            default:return String.format("SW=%04X",sw);
        }
    }
    static String fD(String s){if(s.length()!=6)return s;int y=Integer.parseInt(s.substring(0,2));return s.substring(4)+"."+s.substring(2,4)+"."+(y>30?"19":"20")+s.substring(0,2);}
    static String p(String s,int n){while(s.length()<n)s+=" ";return s;}
    static int dgN(int b){if(b==0x60)return 0;if(b>=0x61&&b<=0x6F)return b-0x60;return b;}
    static String tn(int t){switch(t){case 0x60:return"EF.COM";case 0x5F01:return"LDS ver";case 0x5F36:return"Unicode ver";case 0x5C:return"DG lista";case 0x5F1F:return"MRZ";case 0x5F0E:return"Ime";case 0x5F1D:return"JMBG";case 0x5F42:return"Adresa";case 0x30:return"SEQ";default:return String.format("?%04X",t);}}

    // ================================================================
    // KRIPTO
    // ================================================================
    static byte[] tdes_ecb(byte[] k16,byte[] d8) throws Exception{
        byte[] k24=cat(k16,Arrays.copyOf(k16,8));
        Cipher c=Cipher.getInstance("DESede/ECB/NoPadding");
        c.init(Cipher.ENCRYPT_MODE,SecretKeyFactory.getInstance("DESede").generateSecret(new DESedeKeySpec(k24)));
        return c.doFinal(d8);
    }
    static byte[] tdes_cbc(byte[] k16,byte[] iv,byte[] d) throws Exception{
        byte[] k24=cat(k16,Arrays.copyOf(k16,8));
        Cipher c=Cipher.getInstance("DESede/CBC/NoPadding");
        c.init(Cipher.ENCRYPT_MODE,SecretKeyFactory.getInstance("DESede").generateSecret(new DESedeKeySpec(k24)),new IvParameterSpec(iv));
        return c.doFinal(d);
    }
    static byte[] tdes_cbc_dec(byte[] k16,byte[] iv,byte[] d) throws Exception{
        byte[] k24=cat(k16,Arrays.copyOf(k16,8));
        Cipher c=Cipher.getInstance("DESede/CBC/NoPadding");
        c.init(Cipher.DECRYPT_MODE,SecretKeyFactory.getInstance("DESede").generateSecret(new DESedeKeySpec(k24)),new IvParameterSpec(iv));
        return c.doFinal(d);
    }
    static byte[] mac3(byte[] k16,byte[] d) throws Exception{
        byte[] p=isopad(d),k1=Arrays.copyOf(k16,8),k2=Arrays.copyOfRange(k16,8,16),cv=new byte[8];
        for(int i=0;i<p.length;i+=8) cv=des_e(k1,cv,Arrays.copyOfRange(p,i,i+8));
        return Arrays.copyOf(des_e(k1,new byte[8],des_d(k2,new byte[8],cv)),8);
    }
    static byte[] des_e(byte[] k,byte[] iv,byte[] d) throws Exception{Cipher c=Cipher.getInstance("DES/CBC/NoPadding");c.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(k,"DES"),new IvParameterSpec(iv));return c.doFinal(d);}
    static byte[] des_d(byte[] k,byte[] iv,byte[] d) throws Exception{Cipher c=Cipher.getInstance("DES/CBC/NoPadding");c.init(Cipher.DECRYPT_MODE,new SecretKeySpec(k,"DES"),new IvParameterSpec(iv));return c.doFinal(d);}
    static byte[] kdf(byte[] s,int c) throws Exception{
        byte[] D=Arrays.copyOf(s,s.length+4);D[D.length-1]=(byte)c;
        byte[] k=Arrays.copyOf(sha1(D),16);
        for(int i=0;i<16;i++){int b=k[i]&0xFE;k[i]=(byte)(b|(Integer.bitCount(b)%2==0?1:0));}
        return k;
    }
    static byte[] isopad(byte[] d){byte[] r=new byte[d.length+8-(d.length%8)];System.arraycopy(d,0,r,0,d.length);r[d.length]=(byte)0x80;return r;}
    static byte[] isounpad(byte[] d){int i=d.length-1;while(i>=0&&d[i]==0)i--;return(i>=0&&(d[i]&0xFF)==0x80)?Arrays.copyOf(d,i):d;}
    static void incSSC(){for(int i=SSC.length-1;i>=0;i--){if(++SSC[i]!=0)break;}}
    static byte[] sha1(byte[] d) throws Exception{return MessageDigest.getInstance("SHA-1").digest(d);}
    static byte[] xor(byte[] a,byte[] b){byte[] r=new byte[a.length];for(int i=0;i<a.length;i++)r[i]=(byte)(a[i]^b[i]);return r;}
    static byte[] tlv(int tag,byte[] val){byte[] t=tag>0xFF?new byte[]{(byte)(tag>>8),(byte)(tag&0xFF)}:new byte[]{(byte)(tag&0xFF)};byte[] l=val.length<0x80?new byte[]{(byte)val.length}:val.length<0x100?new byte[]{(byte)0x81,(byte)val.length}:new byte[]{(byte)0x82,(byte)(val.length>>8),(byte)(val.length&0xFF)};return cat(t,l,val);}
    static int cd(String s){int[]w={7,3,1};int sum=0;for(int i=0;i<s.length();i++){char c=s.charAt(i);int v=(c=='<')?0:(c>='A'&&c<='Z')?c-'A'+10:c-'0';sum+=v*w[i%3];}return sum%10;}
    static ResponseAPDU send(CardChannel ch,String hex,String l) throws CardException{ResponseAPDU r=ch.transmit(new CommandAPDU(x(hex)));System.out.printf("%s SW=%04X%s%n",l,r.getSW(),r.getData().length>0?" data="+h(r.getData()):"");return r;}
    static int findB(byte[] h,byte[] n){outer:for(int i=0;i<=h.length-n.length;i++){for(int j=0;j<n.length;j++)if(h[i+j]!=n[j])continue outer;return i;}return -1;}
    static void saveFile(byte[] d,String n){try(FileOutputStream f=new FileOutputStream(n)){f.write(d);}catch(Exception e){System.out.println("Save: "+e);}}
    static byte[] cat(byte[]...a){int n=0;for(byte[]x:a)if(x!=null)n+=x.length;byte[]r=new byte[n];int o=0;for(byte[]x:a)if(x!=null){System.arraycopy(x,0,r,o,x.length);o+=x.length;}return r;}
    static String h(byte[] b){if(b==null||b.length==0)return"(empty)";StringBuilder s=new StringBuilder();for(byte x:b)s.append(String.format("%02X",x));return s.toString();}
    static String sw(ResponseAPDU r){return String.format("%04X",r.getSW());}
    static byte[] x(String s){s=s.replace(" ","");byte[]d=new byte[s.length()/2];for(int i=0;i<d.length;i++)d[i]=(byte)((Character.digit(s.charAt(i*2),16)<<4)+Character.digit(s.charAt(i*2+1),16));return d;}
}






import javax.smartcardio.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.util.*;
import java.io.*;
import java.nio.charset.StandardCharsets;

/**
 * BiH eID Reader v11
 * Testira 4 SM varijante + READ BINARY sa SFI (bez SELECT)
 *
 * Kompajliranje: javac BihEidReader.java
 * Pokretanje:    java BihEidReader
 */
public class BihEidReader {

    static byte[] KS_ENC, KS_MAC, SSC = new byte[8];

    public static void main(String[] args) throws Exception {
        System.out.println("===========================================");
        System.out.println("  BiH eID Reader v11 |  SM Variant Test");
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
        String mrzInfo = docNum + cd(docNum) + dob + cd(dob) + expiry + cd(expiry);
        System.out.println("MRZ: " + mrzInfo);

        TerminalFactory fac = TerminalFactory.getDefault();
        List<CardTerminal> terms = fac.terminals().list();
        CardTerminal term = null;
        for (CardTerminal t : terms) if (t.isCardPresent()) { term = t; break; }
        if (term == null) { terms.get(0).waitForCardPresent(15000); term = terms.get(0); }
        Card card = term.connect("*");
        CardChannel ch = card.getBasicChannel();
        System.out.println("ATR: " + h(card.getATR().getBytes()));

        // =====================================================
        // Test svake varijante (svaki put restart BAC)
        // =====================================================
        String[] varLabels = {
            "A: IV=E(KSenc,SSC), MAC=SSC+pad(hdr)+DOs",
            "B: IV=E(KSenc,SSC), MAC=pad(SSC)+pad(hdr)+DOs",
            "C: IV=zeros,         MAC=SSC+pad(hdr)+DOs",
            "D: IV=zeros,         MAC=pad(SSC)+pad(hdr)+DOs",
        };

        for (int variant = 0; variant < 4; variant++) {
            System.out.println("\n========================================");
            System.out.println("  VARIJANTA " + varLabels[variant]);
            System.out.println("========================================");

            // Restart
            send(ch, "00A4040C07A0000002471001", "SELECT AID");
            doBAC(ch, mrzInfo);

            // Test SELECT EF.COM (011E) sa ovom varijantom
            int sw = testSelectVariant(ch, (byte)0x01, (byte)0x1E, variant);
            System.out.printf("  EF.COM SELECT -> SW=%04X  %s%n",
                sw, sw == 0x9000 ? "*** USPJEH! ***" : getSWMeaning(sw));

            if (sw == 0x9000) {
                System.out.println("  Varijanta " + (char)('A'+variant) + " radi! Čitam sve...");
                readAll(ch, variant, mrzInfo);
                break;
            }
        }

        // =====================================================
        // Test READ BINARY sa Short File Identifier (SFI)
        // (zaobilazi SELECT – bira i čita u jednoj komandi)
        // =====================================================
        System.out.println("\n========================================");
        System.out.println("  VARIJANTA E: READ BINARY sa SFI");
        System.out.println("  (bez prethodnog SELECT)");
        System.out.println("========================================");
        send(ch, "00A4040C07A0000002471001", "Re-SELECT AID");
        doBAC(ch, mrzInfo);

        // ICAO SFI assignments: DG1=0x01, DG2=0x02, EF.COM=0x1E, EF.SOD=0x1D
        int[] sfis    = { 0x1E, 0x01, 0x02, 0x0B, 0x0C, 0x1D, 0x0F };
        String[] sfiN = { "EF.COM","DG1","DG2","DG11","DG12","EF.SOD","DG15" };

        for (int i = 0; i < sfis.length; i++) {
            // P1 = 0x80 | SFI  → selektuje i čita datoteku po SFI
            byte p1 = (byte)(0x80 | sfis[i]);
            System.out.printf("%n  SM READ BINARY SFI=%02X (%s) P1=%02X%n",
                sfis[i], sfiN[i], p1 & 0xFF);

            // Probaj varijante C (IV=0, SSC raw) i A
            for (int v : new int[]{2, 0}) {
                incSSC();
                byte[] IV = (v <= 1) ? tdes_ecb(KS_ENC, SSC) : new byte[8]; // A,B: E(Kenc,SSC); C,D: zeros
                byte[] do97 = {(byte)0x97, 0x01, 0x00};
                byte[] hdr  = {(byte)0x0C, (byte)0xB0, p1, 0x00};
                byte[] sscMac = (v == 1 || v == 3) ? isopad(SSC) : SSC;
                byte[] M   = cat(sscMac, isopad(hdr), do97);
                byte[] CC  = mac3(KS_MAC, M);
                byte[] do8E = tlv(0x8E, CC);
                byte[] body = cat(do97, do8E);
                byte[] apdu = cat(new byte[]{(byte)0x0C,(byte)0xB0,p1,0x00,(byte)body.length},
                                  body, new byte[]{0x00});
                System.out.printf("    var%c APDU: %s%n", (char)('A'+v), h(apdu));
                ResponseAPDU r = ch.transmit(new CommandAPDU(apdu));
                System.out.printf("    var%c -> SW=%04X  %s%n",
                    (char)('A'+v), r.getSW(), getSWMeaning(r.getSW()));
                if (r.getSW() == 0x9000 && r.getData().length > 0) {
                    System.out.println("    *** USPJEH! data=" + h(r.getData()));
                }
            }
        }

        // =====================================================
        // Varijanta F: SM bez DO'87 u SELECT (samo MAC zaštita)
        // Neke kartice traže da se SELECT izvrši bez šifriranja
        // (samo autentičnost, ne povjerljivost)
        // =====================================================
        System.out.println("\n========================================");
        System.out.println("  VARIJANTA F: SELECT bez DO'87 (samo MAC)");
        System.out.println("========================================");
        send(ch, "00A4040C07A0000002471001", "Re-SELECT AID");
        doBAC(ch, mrzInfo);

        // Ovakav SELECT: CLA=0C, nema cmdData, samo DO'8E
        // Ali file ID mora negdje biti - koristi P1/P2 ili kratki SFI
        for (int sfi : new int[]{0x1E, 0x01, 0x02, 0x0B}) {
            incSSC();
            // SELECT FILE BY SHORT EF ID: A4 02 0C 00 (bez Lc)
            // P2=SFI kao "short file identifier"
            byte[] hdr = {(byte)0x0C, (byte)0xA4, 0x02, (byte)sfi};
            byte[] M   = cat(SSC, isopad(hdr));
            byte[] CC  = mac3(KS_MAC, M);
            byte[] do8E = tlv(0x8E, CC);
            byte[] apdu = cat(new byte[]{(byte)0x0C,(byte)0xA4,0x02,(byte)sfi,(byte)do8E.length},
                              do8E, new byte[]{0x00});
            System.out.printf("  SM SELECT SFI=%02X APDU: %s%n", sfi, h(apdu));
            ResponseAPDU r = ch.transmit(new CommandAPDU(apdu));
            System.out.printf("  SW=%04X  %s%n", r.getSW(), getSWMeaning(r.getSW()));
            if (r.getSW() == 0x9000) {
                System.out.println("  *** USPJEH! Čitam...");
                // READ BINARY
                ResponseAPDU rb = smRB_var(ch, (byte)0x00, (byte)0x00, 0); // var A
                System.out.printf("  READ -> SW=%04X data=%s%n", rb.getSW(), h(rb.getData()));
            }
        }

        card.disconnect(false);
        System.out.println("\n=== Završeno ===");
    }

    // ================================================================
    // TEST SELECT VARIJANTE (0=A, 1=B, 2=C, 3=D)
    // ================================================================
    static int testSelectVariant(CardChannel ch, byte hi, byte lo, int variant) throws Exception {
        incSSC();

        // IV za enkriptovanje
        byte[] IV = (variant <= 1) ? tdes_ecb(KS_ENC, SSC) : new byte[8];

        // Enkriptuj file ID
        byte[] enc  = tdes_cbc(KS_ENC, IV, isopad(new byte[]{hi, lo}));
        byte[] do87 = tlv(0x87, cat(new byte[]{0x01}, enc));

        // MAC input: SSC ili pad(SSC)
        byte[] sscMac = (variant == 1 || variant == 3) ? isopad(SSC) : SSC;
        byte[] hdr   = {(byte)0x0C, (byte)0xA4, 0x02, (byte)0x0C};
        byte[] M     = cat(sscMac, isopad(hdr), do87);
        byte[] CC    = mac3(KS_MAC, M);
        byte[] do8E  = tlv(0x8E, CC);

        byte[] body = cat(do87, do8E);
        byte[] apdu = cat(new byte[]{(byte)0x0C,(byte)0xA4,0x02,(byte)0x0C,(byte)body.length},
                          body, new byte[]{0x00});
        System.out.println("  APDU: " + h(apdu));
        ResponseAPDU r = ch.transmit(new CommandAPDU(apdu));
        return r.getSW();
    }

    // ================================================================
    // READ BINARY varijanta
    // ================================================================
    static ResponseAPDU smRB_var(CardChannel ch, byte p1, byte p2, int variant) throws Exception {
        incSSC();
        byte[] IV = (variant <= 1) ? tdes_ecb(KS_ENC, SSC) : new byte[8];
        byte[] do97 = {(byte)0x97, 0x01, 0x00};
        byte[] hdr  = {(byte)0x0C, (byte)0xB0, p1, p2};
        byte[] sscM = (variant==1||variant==3) ? isopad(SSC) : SSC;
        byte[] M    = cat(sscM, isopad(hdr), do97);
        byte[] CC   = mac3(KS_MAC, M);
        byte[] do8E = tlv(0x8E, CC);
        byte[] body = cat(do97, do8E);
        byte[] apdu = cat(new byte[]{(byte)0x0C,(byte)0xB0,p1,p2,(byte)body.length},
                          body, new byte[]{0x00});
        ResponseAPDU r = ch.transmit(new CommandAPDU(apdu));
        if (r.getSW() == 0x9000 && r.getData().length > 0) {
            return smDecrypt(r.getData(), variant);
        }
        return r;
    }

    // ================================================================
    // ČITANJE SVEGA (kad nađemo radnu varijantu)
    // ================================================================
    static void readAll(CardChannel ch, int variant, String mrzInfo) throws Exception {
        int[] fids   = { 0x011E, 0x0101, 0x010B, 0x010C, 0x0102, 0x011D, 0x010F };
        String[] names = { "EF.COM","DG1 MRZ","DG11 Lični","DG12 Dok","DG2 Foto","EF.SOD","DG15" };
        for (int i = 0; i < fids.length; i++) {
            System.out.println("\n--- " + names[i] + " ---");
            byte[] data = readEF(ch, fids[i], variant);
            if (data != null && data.length > 0) {
                System.out.printf("  ✓ %d bajta%n", data.length);
                saveFile(data, String.format("ef_%04X.bin", fids[i]));
                switch (fids[i]) {
                    case 0x011E: parseTLV(data,"  "); break;
                    case 0x0101: parseDG1(data); break;
                    case 0x010B: case 0x010C: parseTLV(data,"  "); break;
                    case 0x0102: savePhoto(data,"face"); break;
                }
            }
        }
    }

    static byte[] readEF(CardChannel ch, int fid, int variant) throws Exception {
        byte hi=(byte)(fid>>8), lo=(byte)(fid&0xFF);
        int sw = testSelectVariant(ch, hi, lo, variant);
        System.out.printf("  SELECT %04X SW=%04X%n", fid, sw);
        if (sw != 0x9000) return null;
        List<Byte> all=new ArrayList<>();
        int off=0;
        while(true) {
            ResponseAPDU rb = smRB_var(ch,(byte)((off>>8)&0x7F),(byte)(off&0xFF),variant);
            int rsw=rb.getSW();
            if(rsw==0x9000){byte[] d=rb.getData();if(d.length==0)break;for(byte b:d)all.add(b);off+=d.length;if(d.length<0xDF)break;}
            else break;
        }
        byte[] res=new byte[all.size()];for(int k=0;k<res.length;k++)res[k]=all.get(k);
        return res.length>0?res:null;
    }

    // ================================================================
    // SM RESPONSE DEKRIPTOVANJE
    // ================================================================
    static ResponseAPDU smDecrypt(byte[] resp, int variant) throws Exception {
        incSSC();
        byte[] IV=(variant<=1)?tdes_ecb(KS_ENC,SSC):new byte[8];
        byte[] v87=null,v99=null,v8E=null;
        int i=0;
        while(i<resp.length){
            int tag=resp[i++]&0xFF; if(tag==0||tag==0xFF) continue;
            if((tag&0x1F)==0x1F&&i<resp.length) tag=(tag<<8)|(resp[i++]&0xFF);
            if(i>=resp.length) break;
            int len=resp[i++]&0xFF;
            if(len==0x81&&i<resp.length)len=resp[i++]&0xFF;
            else if(len==0x82&&i+1<resp.length){len=((resp[i]&0xFF)<<8)|(resp[i+1]&0xFF);i+=2;}
            if(i+len>resp.length) break;
            byte[] val=Arrays.copyOfRange(resp,i,i+len);i+=len;
            int t=tag&0xFF;
            if(t==0x87)v87=val; else if(t==0x99)v99=val; else if(t==0x8E)v8E=val;
        }
        byte[] sscM=(variant==1||variant==3)?isopad(SSC):SSC;
        byte[] macIn=sscM;
        if(v87!=null) macIn=cat(macIn,tlv(0x87,v87));
        if(v99!=null) macIn=cat(macIn,tlv(0x99,v99));
        if(!Arrays.equals(mac3(KS_MAC,macIn),v8E))
            System.out.println("  WARN: response MAC mismatch");
        byte[] plain=new byte[0];
        if(v87!=null){byte[] c=Arrays.copyOfRange(v87,1,v87.length);plain=isounpad(tdes_cbc_dec(KS_ENC,IV,c));}
        int sw=v99!=null?((v99[0]&0xFF)<<8)|(v99[1]&0xFF):0x9000;
        byte[] full=new byte[plain.length+2];System.arraycopy(plain,0,full,0,plain.length);
        full[plain.length]=(byte)(sw>>8);full[plain.length+1]=(byte)(sw&0xFF);
        return new ResponseAPDU(full);
    }

    // ================================================================
    // BAC
    // ================================================================
    static void doBAC(CardChannel ch, String mrzInfo) throws Exception {
        System.out.println("--- BAC ---");
        byte[] kseed=Arrays.copyOf(sha1(mrzInfo.getBytes(StandardCharsets.UTF_8)),16);
        byte[] kenc=kdf(kseed,1), kmac=kdf(kseed,2);
        ResponseAPDU gc=ch.transmit(new CommandAPDU(x("0084000008")));
        if(gc.getSW()!=0x9000) throw new Exception("GET CHALLENGE: "+sw(gc));
        byte[] RND_IC=gc.getData();
        byte[] RND_IFD=new byte[8];new SecureRandom().nextBytes(RND_IFD);
        byte[] K_IFD=new byte[16];new SecureRandom().nextBytes(K_IFD);
        byte[] EIFD=tdes_cbc(kenc,new byte[8],cat(RND_IFD,RND_IC,K_IFD));
        byte[] MIFD=mac3(kmac,EIFD);
        byte[] body=cat(EIFD,MIFD);
        byte[] ea=cat(new byte[]{0x00,(byte)0x82,0x00,0x00,0x28},body,new byte[]{0x28});
        ResponseAPDU ar=ch.transmit(new CommandAPDU(ea));
        System.out.printf("EXT AUTH SW=%04X%n",ar.getSW());
        if(ar.getSW()!=0x9000) throw new Exception("BAC failed");
        byte[] R=ar.getData();
        byte[] dec=tdes_cbc_dec(kenc,new byte[8],Arrays.copyOf(R,32));
        byte[] K_IC=Arrays.copyOfRange(dec,16,32);
        boolean macOk=Arrays.equals(mac3(kmac,Arrays.copyOf(R,32)),Arrays.copyOfRange(R,32,40));
        System.out.println("MAC OK: "+macOk);
        byte[] seed=xor(K_IFD,K_IC);
        KS_ENC=kdf(seed,1); KS_MAC=kdf(seed,2);
        SSC=cat(Arrays.copyOfRange(RND_IC,4,8),Arrays.copyOfRange(RND_IFD,4,8));
        System.out.println("KS_ENC: "+h(KS_ENC));
        System.out.println("KS_MAC: "+h(KS_MAC));
        System.out.println("SSC:    "+h(SSC));
        System.out.println("BAC OK!");
    }

    // ================================================================
    // PARSIRANJE
    // ================================================================
    static void parseDG1(byte[] d){System.out.println("DG1 MRZ:");parseTLV(d,"  ");}
    static void parseTLV(byte[] d,String ind){doTLV(d,0,d.length,ind,0);}
    static void doTLV(byte[] d,int s,int e,String ind,int depth){
        if(depth>8)return;int i=s;
        while(i<e){
            if((d[i]&0xFF)==0||(d[i]&0xFF)==0xFF){i++;continue;}
            int tag=d[i++]&0xFF;boolean con=(tag&0x20)!=0;
            if((tag&0x1F)==0x1F&&i<e) tag=(tag<<8)|(d[i++]&0xFF);
            if(i>=e) break;int len=d[i++]&0xFF;
            if(len==0x81&&i<e)len=d[i++]&0xFF;
            else if(len==0x82&&i+1<e){len=((d[i]&0xFF)<<8)|(d[i+1]&0xFF);i+=2;}
            if(i+len>e||len<0) break;byte[] val=Arrays.copyOfRange(d,i,i+len);i+=len;
            System.out.printf("%s%04X [%s] len=%d%n",ind,tag,tn(tag),len);
            if(tag==0x5F1F){String mrz=new String(val,StandardCharsets.UTF_8);System.out.println(ind+"  ["+mrz.replace("\n","↵")+"]");mrzBox(mrz,ind+"  ");}
            else if(tag==0x5C){System.out.print(ind+"  DG:");for(byte b:val)System.out.printf(" %d",dgN(b&0xFF));System.out.println();}
            else if(con) doTLV(d,i-len,i,ind+"  ",depth+1);
            else{boolean pr=val.length>0;for(byte b:val){int c=b&0xFF;if(c<0x20||c>0x7E){pr=false;break;}}
                System.out.println(ind+"  = "+(pr?"\""+new String(val,StandardCharsets.UTF_8)+"\"":h(val)));}
        }
    }
    static void mrzBox(String mrz,String ind){
        mrz=mrz.replace("\n","").replace("\r","");
        if(mrz.length()<60) return;
        System.out.println(ind+"╔══════════════════════════════╗");
        String l1=mrz.substring(0,30);
        System.out.println(ind+"║ Br.dok  : "+p(l1.substring(5,14).replace("<",""),21)+"║");
        String l2=mrz.substring(30,60);
        System.out.println(ind+"║ Dat.rod : "+p(fD(l2.substring(0,6)),21)+"║");
        System.out.println(ind+"║ Pol     : "+p(l2.substring(7,8).equals("M")?"Muški":"Ženski",21)+"║");
        System.out.println(ind+"║ Dat.ist : "+p(fD(l2.substring(8,14)),21)+"║");
        if(mrz.length()>=90){String l3=mrz.substring(60,90);String[]ps=l3.split("<<",2);
            System.out.println(ind+"║ Prezime : "+p(ps[0].replace("<",""),21)+"║");
            if(ps.length>1) System.out.println(ind+"║ Ime     : "+p(ps[1].replace("<"," ").trim(),21)+"║");}
        System.out.println(ind+"╚══════════════════════════════╝");
    }
    static void savePhoto(byte[] d,String pfx){
        int off=findB(d,new byte[]{(byte)0xFF,(byte)0xD8});
        if(off>=0){saveFile(Arrays.copyOfRange(d,off,d.length),pfx+".jpg");System.out.println("  "+pfx+".jpg saved");}
    }
    static String getSWMeaning(int sw){
        switch(sw){
            case 0x9000:return"OK";case 0x6988:return"SM crypto wrong";
            case 0x6987:return"SM missing";case 0x6985:return"Conditions not met";
            case 0x6982:return"Security status not satisfied";case 0x6A82:return"File not found";
            default:return String.format("SW=%04X",sw);
        }
    }
    static String fD(String s){if(s.length()!=6)return s;int y=Integer.parseInt(s.substring(0,2));return s.substring(4)+"."+s.substring(2,4)+"."+(y>30?"19":"20")+s.substring(0,2);}
    static String p(String s,int n){while(s.length()<n)s+=" ";return s;}
    static int dgN(int b){if(b==0x60)return 0;if(b>=0x61&&b<=0x6F)return b-0x60;return b;}
    static String tn(int t){switch(t){case 0x60:return"EF.COM";case 0x5F01:return"LDS ver";case 0x5F36:return"Unicode ver";case 0x5C:return"DG lista";case 0x5F1F:return"MRZ";case 0x5F0E:return"Ime";case 0x5F1D:return"JMBG";case 0x5F42:return"Adresa";case 0x30:return"SEQ";default:return String.format("?%04X",t);}}

    // ================================================================
    // KRIPTO
    // ================================================================
    static byte[] tdes_ecb(byte[] k16,byte[] d8) throws Exception{
        byte[] k24=cat(k16,Arrays.copyOf(k16,8));
        Cipher c=Cipher.getInstance("DESede/ECB/NoPadding");
        c.init(Cipher.ENCRYPT_MODE,SecretKeyFactory.getInstance("DESede").generateSecret(new DESedeKeySpec(k24)));
        return c.doFinal(d8);
    }
    static byte[] tdes_cbc(byte[] k16,byte[] iv,byte[] d) throws Exception{
        byte[] k24=cat(k16,Arrays.copyOf(k16,8));
        Cipher c=Cipher.getInstance("DESede/CBC/NoPadding");
        c.init(Cipher.ENCRYPT_MODE,SecretKeyFactory.getInstance("DESede").generateSecret(new DESedeKeySpec(k24)),new IvParameterSpec(iv));
        return c.doFinal(d);
    }
    static byte[] tdes_cbc_dec(byte[] k16,byte[] iv,byte[] d) throws Exception{
        byte[] k24=cat(k16,Arrays.copyOf(k16,8));
        Cipher c=Cipher.getInstance("DESede/CBC/NoPadding");
        c.init(Cipher.DECRYPT_MODE,SecretKeyFactory.getInstance("DESede").generateSecret(new DESedeKeySpec(k24)),new IvParameterSpec(iv));
        return c.doFinal(d);
    }
    static byte[] mac3(byte[] k16,byte[] d) throws Exception{
        byte[] p=isopad(d),k1=Arrays.copyOf(k16,8),k2=Arrays.copyOfRange(k16,8,16),cv=new byte[8];
        for(int i=0;i<p.length;i+=8) cv=des_e(k1,cv,Arrays.copyOfRange(p,i,i+8));
        return Arrays.copyOf(des_e(k1,new byte[8],des_d(k2,new byte[8],cv)),8);
    }
    static byte[] des_e(byte[] k,byte[] iv,byte[] d) throws Exception{Cipher c=Cipher.getInstance("DES/CBC/NoPadding");c.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(k,"DES"),new IvParameterSpec(iv));return c.doFinal(d);}
    static byte[] des_d(byte[] k,byte[] iv,byte[] d) throws Exception{Cipher c=Cipher.getInstance("DES/CBC/NoPadding");c.init(Cipher.DECRYPT_MODE,new SecretKeySpec(k,"DES"),new IvParameterSpec(iv));return c.doFinal(d);}
    static byte[] kdf(byte[] s,int c) throws Exception{
        byte[] D=Arrays.copyOf(s,s.length+4);D[D.length-1]=(byte)c;
        byte[] k=Arrays.copyOf(sha1(D),16);
        for(int i=0;i<16;i++){int b=k[i]&0xFE;k[i]=(byte)(b|(Integer.bitCount(b)%2==0?1:0));}
        return k;
    }
    static byte[] isopad(byte[] d){byte[] r=new byte[d.length+8-(d.length%8)];System.arraycopy(d,0,r,0,d.length);r[d.length]=(byte)0x80;return r;}
    static byte[] isounpad(byte[] d){int i=d.length-1;while(i>=0&&d[i]==0)i--;return(i>=0&&(d[i]&0xFF)==0x80)?Arrays.copyOf(d,i):d;}
    static void incSSC(){for(int i=SSC.length-1;i>=0;i--){if(++SSC[i]!=0)break;}}
    static byte[] sha1(byte[] d) throws Exception{return MessageDigest.getInstance("SHA-1").digest(d);}
    static byte[] xor(byte[] a,byte[] b){byte[] r=new byte[a.length];for(int i=0;i<a.length;i++)r[i]=(byte)(a[i]^b[i]);return r;}
    static byte[] tlv(int tag,byte[] val){byte[] t=tag>0xFF?new byte[]{(byte)(tag>>8),(byte)(tag&0xFF)}:new byte[]{(byte)(tag&0xFF)};byte[] l=val.length<0x80?new byte[]{(byte)val.length}:val.length<0x100?new byte[]{(byte)0x81,(byte)val.length}:new byte[]{(byte)0x82,(byte)(val.length>>8),(byte)(val.length&0xFF)};return cat(t,l,val);}
    static int cd(String s){int[]w={7,3,1};int sum=0;for(int i=0;i<s.length();i++){char c=s.charAt(i);int v=(c=='<')?0:(c>='A'&&c<='Z')?c-'A'+10:c-'0';sum+=v*w[i%3];}return sum%10;}
    static ResponseAPDU send(CardChannel ch,String hex,String l) throws CardException{ResponseAPDU r=ch.transmit(new CommandAPDU(x(hex)));System.out.printf("%s SW=%04X%s%n",l,r.getSW(),r.getData().length>0?" data="+h(r.getData()):"");return r;}
    static int findB(byte[] h,byte[] n){outer:for(int i=0;i<=h.length-n.length;i++){for(int j=0;j<n.length;j++)if(h[i+j]!=n[j])continue outer;return i;}return -1;}
    static void saveFile(byte[] d,String n){try(FileOutputStream f=new FileOutputStream(n)){f.write(d);}catch(Exception e){System.out.println("Save: "+e);}}
    static byte[] cat(byte[]...a){int n=0;for(byte[]x:a)if(x!=null)n+=x.length;byte[]r=new byte[n];int o=0;for(byte[]x:a)if(x!=null){System.arraycopy(x,0,r,o,x.length);o+=x.length;}return r;}
    static String h(byte[] b){if(b==null||b.length==0)return"(empty)";StringBuilder s=new StringBuilder();for(byte x:b)s.append(String.format("%02X",x));return s.toString();}
    static String sw(ResponseAPDU r){return String.format("%04X",r.getSW());}
    static byte[] x(String s){s=s.replace(" ","");byte[]d=new byte[s.length()/2];for(int i=0;i<d.length;i++)d[i]=(byte)((Character.digit(s.charAt(i*2),16)<<4)+Character.digit(s.charAt(i*2+1),16));return d;}
}




===========================================
  BiH eID Reader v10 |  ICAO eMRTD + BAC
===========================================

Broj dokumenta (9 znakova): 1E181TKT6
Datum rodjenja (YYMMDD): 931113
Datum isteka   (YYMMDD): 340917
MRZ: 1E181TKT6193111363409176
ATR: 3B8880014241454944322E306E
SELECT AID SW=9000
--- BAC ---
EXT AUTH SW=9000
MAC OK: true
KS_ENC: 68B046CB38E36B80736BCD8379AE5BE6
KS_MAC: 46DA583B5237F2C8A73E3DE3C4233834
SSC:    45119DCFC1EA4D88
BAC OK!

========================================
  ČITANJE SVIH DOSTUPNIH PODATAKA
========================================

--- EF.COM  – Lista DG-ova (EF 011E) ---
  >> 0CA4020C15870901882641E53AB589A48E08876B9398B22BDABE00
  << SW=6988  data=(empty)
  SELECT 011E → SW=6988
  – nije dostupno

--- EF.SOD  – Digitalni potpis / certifikat (EF 011D) ---
  >> 0CA4020C15870901068E5C32E9193B028E0873B4C171EBC1FCF400
  << SW=6985  data=(empty)
  SELECT 011D → SW=6985
  – nije dostupno

--- DG1     – MRZ podaci (EF 0101) ---
  >> 0CA4020C15870901FB9B1CCBA6E117058E08A4558A37EEDB32CF00
  << SW=6985  data=(empty)
  SELECT 0101 → SW=6985
  – nije dostupno

--- DG2     – Fotografija lica (EF 0102) ---
  >> 0CA4020C15870901FCA3E823DF3CF69E8E088C489BBC482D63FD00
  << SW=6985  data=(empty)
  SELECT 0102 → SW=6985
  – nije dostupno

--- DG3     – Otisci prstiju (EF 0103) ---
  >> 0CA4020C158709018216938D3E385E808E08F0F0F1428E3EAA8800
  << SW=6985  data=(empty)
  SELECT 0103 → SW=6985
  – nije dostupno

--- DG5     – Prikazna fotografija (EF 0105) ---
  >> 0CA4020C158709012D4DD00E172F9DC18E08A2A6A3556F3ACE3700
  << SW=6985  data=(empty)
  SELECT 0105 → SW=6985
  – nije dostupno

--- DG7     – Slika potpisa (EF 0107) ---
  >> 0CA4020C15870901032EB52B0CB049C58E086C51ACE30855661200
  << SW=6985  data=(empty)
  SELECT 0107 → SW=6985
  – nije dostupno

--- DG11    – Lični podaci (ime, adresa…) (EF 010B) ---
  >> 0CA4020C158709014CD9E299FD7378198E08D49C6FE1B8D4540100
  << SW=6985  data=(empty)
  SELECT 010B → SW=6985
  – nije dostupno

--- DG12    – Podaci o dokumentu (EF 010C) ---
  >> 0CA4020C15870901DE2D9A7D20E8D9F88E0871EC3B7A33BEE30800
  << SW=6985  data=(empty)
  SELECT 010C → SW=6985
  – nije dostupno

--- DG13    – Vendor podaci (EF 010D) ---
  >> 0CA4020C158709011801B2226DF510A98E0845F1C1622938166C00
  << SW=6985  data=(empty)
  SELECT 010D → SW=6985
  – nije dostupno

--- DG14    – EAC Security Options (EF 010E) ---
  >> 0CA4020C1587090125AE2E7DA3CF36618E08BF2994D76004E0F100
  << SW=6985  data=(empty)
  SELECT 010E → SW=6985
  – nije dostupno

--- DG15    – Active Auth Public Key (EF 010F) ---
  >> 0CA4020C158709017028AE1C253E06068E08696818FA8A70109C00
  << SW=6985  data=(empty)
  SELECT 010F → SW=6985
  – nije dostupno

--- DG16    – Kontakt osobe (EF 0110) ---
  >> 0CA4020C15870901B7350F00775D73608E082F0BC0B6E994077100
  << SW=6985  data=(empty)
  SELECT 0110 → SW=6985
  – nije dostupno

========================================
  SAŽETAK
========================================
  Nijedan fajl nije pročitan.

=== Završeno ===

Process finished with exit code 0



import javax.smartcardio.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.util.*;
import java.io.*;
import java.nio.charset.StandardCharsets;

/**
 * BiH eID Reader v10
 *
 * ISPRAVKA: MAC input = isopad(SSC) || isopad(hdr) || do87 || do97
 *           SSC mora biti ISO-padovan (8→16 bajta)!
 *
 * Ref: ICAO 9303-11 Appendix D.4 primjer:
 *   M = [SSC 8B][pad 8B] || [hdr 4B][pad 4B] || DO'97...
 *
 * Kompajliranje: javac BihEidReader.java
 * Pokretanje:    java BihEidReader
 */
public class BihEidReader {

    static byte[] KS_ENC, KS_MAC, SSC = new byte[8];

    public static void main(String[] args) throws Exception {
        System.out.println("===========================================");
        System.out.println("  BiH eID Reader v10 |  ICAO eMRTD + BAC");
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
        String mrzInfo = docNum + cd(docNum) + dob + cd(dob) + expiry + cd(expiry);
        System.out.println("MRZ: " + mrzInfo);

        // --- Spajanje ---
        TerminalFactory fac = TerminalFactory.getDefault();
        List<CardTerminal> terms = fac.terminals().list();
        CardTerminal term = null;
        for (CardTerminal t : terms) if (t.isCardPresent()) { term = t; break; }
        if (term == null) { terms.get(0).waitForCardPresent(15000); term = terms.get(0); }
        Card card = term.connect("*");
        CardChannel ch = card.getBasicChannel();
        System.out.println("ATR: " + h(card.getATR().getBytes()));

        // SELECT eMRTD AID
        send(ch, "00A4040C07A0000002471001", "SELECT AID");

        // BAC
        doBAC(ch, mrzInfo);

        // Čitaj sve
        readAll(ch);

        card.disconnect(false);
        System.out.println("\n=== Završeno ===");
    }

    // ================================================================
    // ČITANJE SVIH DOSTUPNIH PODATAKA
    // ================================================================
    static void readAll(CardChannel ch) throws Exception {
        System.out.println("\n========================================");
        System.out.println("  ČITANJE SVIH DOSTUPNIH PODATAKA");
        System.out.println("========================================");

        int[] fids   = { 0x011E, 0x011D, 0x0101, 0x0102, 0x0103, 0x0105,
                         0x0107, 0x010B, 0x010C, 0x010D, 0x010E, 0x010F, 0x0110 };
        String[] names = {
            "EF.COM  – Lista DG-ova",
            "EF.SOD  – Digitalni potpis / certifikat",
            "DG1     – MRZ podaci",
            "DG2     – Fotografija lica",
            "DG3     – Otisci prstiju",
            "DG5     – Prikazna fotografija",
            "DG7     – Slika potpisa",
            "DG11    – Lični podaci (ime, adresa…)",
            "DG12    – Podaci o dokumentu",
            "DG13    – Vendor podaci",
            "DG14    – EAC Security Options",
            "DG15    – Active Auth Public Key",
            "DG16    – Kontakt osobe"
        };

        Map<String, byte[]> found = new LinkedHashMap<>();

        for (int i = 0; i < fids.length; i++) {
            System.out.printf("%n--- %s (EF %04X) ---%n", names[i], fids[i]);
            byte[] data = readEF(ch, fids[i]);
            if (data != null && data.length > 0) {
                found.put(names[i], data);
                System.out.printf("  ✓  %d bajta%n", data.length);
                saveFile(data, String.format("ef_%04X.bin", fids[i]));
                switch (fids[i]) {
                    case 0x011E: parseEFCOM(data);   break;
                    case 0x011D: parseSOD(data);     break;
                    case 0x0101: parseDG1(data);     break;
                    case 0x0102: savePhoto(data,"face");  break;
                    case 0x0107: savePhoto(data,"sign");  break;
                    default:     parseTLV(data, "  "); break;
                }
            } else {
                System.out.println("  – nije dostupno");
            }
        }

        // Sažetak
        System.out.println("\n========================================");
        System.out.println("  SAŽETAK");
        System.out.println("========================================");
        if (found.isEmpty()) {
            System.out.println("  Nijedan fajl nije pročitan.");
        } else {
            for (Map.Entry<String, byte[]> e : found.entrySet())
                System.out.printf("  ✓ %-40s %5d bajta%n", e.getKey(), e.getValue().length);
            System.out.println("\n  Fajlovi snimljeni kao ef_XXXX.bin");
        }
    }

    // ================================================================
    // ČITANJE EF FAJLA
    // ================================================================
    static byte[] readEF(CardChannel ch, int fid) throws Exception {
        byte hi = (byte)(fid >> 8), lo = (byte)(fid & 0xFF);

        // SELECT
        ResponseAPDU sel = smSend(ch, (byte)0xA4, (byte)0x02, (byte)0x0C,
                                   new byte[]{hi, lo}, false);
        System.out.printf("  SELECT %04X → SW=%04X%n", fid, sel.getSW());
        if (sel.getSW() != 0x9000) return null;

        // READ BINARY
        List<Byte> all = new ArrayList<>();
        int offset = 0;
        while (true) {
            ResponseAPDU rb = smSend(ch, (byte)0xB0,
                (byte)((offset >> 8) & 0x7F), (byte)(offset & 0xFF),
                null, true);
            int sw = rb.getSW();
            if (sw == 0x9000) {
                byte[] d = rb.getData();
                if (d.length == 0) break;
                for (byte b : d) all.add(b);
                offset += d.length;
                if (d.length < 0xDF) break;
            } else if ((sw & 0xFF00) == 0x6C00) {
                // kartica kaže točnu veličinu, ali nastavimo samo
            } else {
                System.out.printf("  READ err SW=%04X @ offset=%d%n", sw, offset);
                break;
            }
        }
        byte[] res = new byte[all.size()];
        for (int k = 0; k < res.length; k++) res[k] = all.get(k);
        return res.length > 0 ? res : null;
    }

    // ================================================================
    // SECURE MESSAGING  (ICAO 9303-11, tačan MAC input)
    // ================================================================
    static ResponseAPDU smSend(CardChannel ch, byte ins, byte p1, byte p2,
                                byte[] cmdData, boolean expectResp) throws Exception {
        // 1. Inkrement SSC
        incSSC();

        // 2. IV = E(KS_ENC, SSC)  — ECB enkriptovani SSC
        byte[] IV = tdes_ecb(KS_ENC, SSC);

        // 3. DO'87 — enkriptovani command data (ako postoji)
        byte[] do87 = new byte[0];
        if (cmdData != null && cmdData.length > 0) {
            byte[] enc = tdes_cbc(KS_ENC, IV, isopad(cmdData));
            do87 = tlv(0x87, cat(new byte[]{0x01}, enc));
        }

        // 4. DO'97 — Le (ako se očekuje odgovor)
        byte[] do97 = expectResp ? new byte[]{(byte)0x97, 0x01, 0x00} : new byte[0];

        // 5. Header
        byte[] hdr = {(byte)0x0C, ins, p1, p2};

        // 6. MAC input = isopad(SSC) || isopad(hdr) || do87 || do97
        //    KRITIČNO: SSC se ISO-paduje (8 → 16 bajta)!
        byte[] M = cat(isopad(SSC), isopad(hdr), do87, do97);

        // 7. Retail MAC, DO'8E
        byte[] CC  = mac3(KS_MAC, M);
        byte[] do8E = tlv(0x8E, CC);

        // 8. Finalni APDU
        byte[] body = cat(do87, do97, do8E);
        byte[] apdu = cat(
            new byte[]{(byte)0x0C, ins, p1, p2, (byte)body.length},
            body,
            new byte[]{0x00}   // Le
        );

        System.out.println("  >> " + h(apdu));
        ResponseAPDU resp = ch.transmit(new CommandAPDU(apdu));
        System.out.printf("  << SW=%04X  data=%s%n", resp.getSW(), h(resp.getData()));

        if (resp.getSW() == 0x9000 && resp.getData().length > 0)
            return smDecrypt(resp.getData());
        return resp;
    }

    static ResponseAPDU smDecrypt(byte[] respData) throws Exception {
        incSSC();
        byte[] IV = tdes_ecb(KS_ENC, SSC);

        byte[] v87=null, v99=null, v8E=null;
        int i = 0;
        while (i < respData.length) {
            int tag = respData[i++] & 0xFF;
            if (tag == 0 || tag == 0xFF) continue;
            if ((tag & 0x1F) == 0x1F && i < respData.length)
                tag = (tag << 8) | (respData[i++] & 0xFF);
            if (i >= respData.length) break;
            int len = respData[i++] & 0xFF;
            if (len == 0x81 && i < respData.length) len = respData[i++] & 0xFF;
            else if (len == 0x82 && i+1 < respData.length) {
                len = ((respData[i]&0xFF)<<8)|(respData[i+1]&0xFF); i+=2;
            }
            if (i+len > respData.length) break;
            byte[] val = Arrays.copyOfRange(respData, i, i+len); i += len;
            int t = tag & 0xFF;
            if      (t == 0x87) v87 = val;
            else if (t == 0x99) v99 = val;
            else if (t == 0x8E) v8E = val;
        }

        // Verifikuj MAC: isopad(SSC) || tlv(87,v87) || tlv(99,v99)
        byte[] macIn = isopad(SSC);
        if (v87 != null) macIn = cat(macIn, tlv(0x87, v87));
        if (v99 != null) macIn = cat(macIn, tlv(0x99, v99));
        byte[] exp = mac3(KS_MAC, macIn);
        if (!Arrays.equals(exp, v8E))
            System.out.println("  WARN: MAC mismatch exp="+h(exp)+" got="+h(v8E));

        // Dekriptuj DO'87
        byte[] plain = new byte[0];
        if (v87 != null) {
            byte[] cipher = Arrays.copyOfRange(v87, 1, v87.length);
            plain = isounpad(tdes_cbc_dec(KS_ENC, IV, cipher));
        }

        int sw = v99 != null ? ((v99[0]&0xFF)<<8)|(v99[1]&0xFF) : 0x9000;
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
        System.out.println("--- BAC ---");
        byte[] kseed = Arrays.copyOf(sha1(mrzInfo.getBytes(StandardCharsets.UTF_8)), 16);
        byte[] kenc  = kdf(kseed, 1);
        byte[] kmac  = kdf(kseed, 2);

        ResponseAPDU gc = ch.transmit(new CommandAPDU(x("0084000008")));
        if (gc.getSW() != 0x9000) throw new Exception("GET CHALLENGE: " + sw(gc));
        byte[] RND_IC  = gc.getData();
        byte[] RND_IFD = new byte[8]; new SecureRandom().nextBytes(RND_IFD);
        byte[] K_IFD   = new byte[16]; new SecureRandom().nextBytes(K_IFD);

        byte[] EIFD = tdes_cbc(kenc, new byte[8], cat(RND_IFD, RND_IC, K_IFD));
        byte[] MIFD = mac3(kmac, EIFD);
        byte[] ea   = cat(new byte[]{0x00,(byte)0x82,0x00,0x00,0x28}, cat(EIFD,MIFD), new byte[]{0x28});
        ResponseAPDU ar = ch.transmit(new CommandAPDU(ea));
        System.out.printf("EXT AUTH SW=%04X%n", ar.getSW());
        if (ar.getSW() != 0x9000) throw new Exception("BAC failed");

        byte[] R    = ar.getData();
        byte[] dec  = tdes_cbc_dec(kenc, new byte[8], Arrays.copyOf(R, 32));
        byte[] K_IC = Arrays.copyOfRange(dec, 16, 32);
        System.out.println("MAC OK: " + Arrays.equals(mac3(kmac, Arrays.copyOf(R,32)), Arrays.copyOfRange(R,32,40)));

        byte[] seed = xor(K_IFD, K_IC);
        KS_ENC = kdf(seed, 1);
        KS_MAC = kdf(seed, 2);
        SSC    = cat(Arrays.copyOfRange(RND_IC,4,8), Arrays.copyOfRange(RND_IFD,4,8));
        System.out.println("KS_ENC: " + h(KS_ENC));
        System.out.println("KS_MAC: " + h(KS_MAC));
        System.out.println("SSC:    " + h(SSC));
        System.out.println("BAC OK!");
    }

    // ================================================================
    // PARSIRANJE
    // ================================================================
    static void parseEFCOM(byte[] d) {
        System.out.println("  === EF.COM – Dostupni Data Groups ===");
        parseTLV(d, "  ");
    }
    static void parseDG1(byte[] d) {
        System.out.println("  === DG1 – MRZ podaci ===");
        parseTLV(d, "  ");
    }
    static void parseSOD(byte[] d) {
        System.out.println("  === EF.SOD – Security Object Document ===");
        System.out.printf("  Veličina: %d bajta (ASN.1/CMS)%n", d.length);
        saveFile(d, "ef_SOD.bin");
        System.out.println("  Sačuvano: ef_SOD.bin");
        // Ispiši OID-ove
        for (int i=0; i<d.length-2; i++) {
            if ((d[i]&0xFF)==0x06) {
                int l=d[i+1]&0xFF;
                if(l>0 && i+2+l<=d.length)
                    System.out.println("  OID: "+oid(Arrays.copyOfRange(d,i+2,i+2+l)));
            }
        }
    }
    static void savePhoto(byte[] d, String pfx) {
        int off=findB(d,new byte[]{(byte)0xFF,(byte)0xD8});
        if(off>=0){saveFile(Arrays.copyOfRange(d,off,d.length),pfx+".jpg");System.out.println("  Sačuvano: "+pfx+".jpg");}
        off=findB(d,new byte[]{(byte)0xFF,(byte)0x4F});
        if(off<0) off=findB(d,new byte[]{0x00,0x00,0x00,0x0C,0x6A,0x50});
        if(off>=0){saveFile(Arrays.copyOfRange(d,off,d.length),pfx+".jp2");System.out.println("  Sačuvano: "+pfx+".jp2");}
    }

    static void parseTLV(byte[] data, String ind) { doTLV(data,0,data.length,ind,0); }
    static void doTLV(byte[] d, int s, int e, String ind, int depth) {
        if (depth>8) return;
        int i=s;
        while(i<e) {
            if((d[i]&0xFF)==0||(d[i]&0xFF)==0xFF){i++;continue;}
            int tag=d[i++]&0xFF;
            boolean con=(tag&0x20)!=0;
            if((tag&0x1F)==0x1F&&i<e) tag=(tag<<8)|(d[i++]&0xFF);
            if(i>=e) break;
            int len=d[i++]&0xFF;
            if(len==0x81&&i<e) len=d[i++]&0xFF;
            else if(len==0x82&&i+1<e){len=((d[i]&0xFF)<<8)|(d[i+1]&0xFF);i+=2;}
            if(i+len>e||len<0) break;
            byte[] val=Arrays.copyOfRange(d,i,i+len); i+=len;
            System.out.printf("%s%04X [%s] len=%d%n",ind,tag,tn(tag),len);
            if(tag==0x5F1F){
                String mrz=new String(val,StandardCharsets.UTF_8);
                System.out.println(ind+"  MRZ: ["+mrz.replace("\n","↵")+"]");
                mrzBox(mrz,ind+"  ");
            } else if(tag==0x5C){
                System.out.print(ind+"  DG-ovi:");
                for(byte b:val) System.out.printf(" DG%d",dgN(b&0xFF));
                System.out.println();
            } else if(con) {
                doTLV(d,i-len,i,ind+"  ",depth+1);
            } else {
                boolean pr=val.length>0;
                for(byte b:val){int c=b&0xFF;if(c<0x20||c>0x7E){pr=false;break;}}
                System.out.println(ind+"  = "+(pr?"\""+new String(val,StandardCharsets.UTF_8)+"\"":h(val)));
            }
        }
    }
    static void mrzBox(String mrz, String ind) {
        mrz=mrz.replace("\n","").replace("\r","");
        System.out.println(ind+"╔══════════════════════════════╗");
        System.out.println(ind+"║   LIČNA KARTA BiH – PODACI   ║");
        System.out.println(ind+"╠══════════════════════════════╣");
        if(mrz.length()>=30){String l=mrz.substring(0,30);
            System.out.println(ind+"║ Tip/Drž : "+pad(l.substring(0,5).replace("<",""),21)+"║");
            System.out.println(ind+"║ Br.dok. : "+pad(l.substring(5,14).replace("<",""),21)+"║");
        }
        if(mrz.length()>=60){String l=mrz.substring(30,60);
            System.out.println(ind+"║ Dat.rod : "+pad(fD(l.substring(0,6)),21)+"║");
            System.out.println(ind+"║ Pol     : "+pad(l.substring(7,8).equals("M")?"Muški":"Ženski",21)+"║");
            System.out.println(ind+"║ Dat.ist : "+pad(fD(l.substring(8,14)),21)+"║");
            System.out.println(ind+"║ Nat.    : "+pad(l.substring(15,18).replace("<",""),21)+"║");
        }
        if(mrz.length()>=90){String l=mrz.substring(60,90);
            String[] p=l.split("<<",2);
            System.out.println(ind+"║ Prezime : "+pad(p[0].replace("<",""),21)+"║");
            if(p.length>1) System.out.println(ind+"║ Ime     : "+pad(p[1].replace("<"," ").trim(),21)+"║");
        }
        System.out.println(ind+"╚══════════════════════════════╝");
    }
    static String fD(String s){if(s.length()!=6)return s;int y=Integer.parseInt(s.substring(0,2));return s.substring(4)+"."+s.substring(2,4)+"."+(y>30?"19":"20")+s.substring(0,2);}
    static String pad(String s,int n){while(s.length()<n)s+=" ";return s;}
    static int dgN(int b){if(b==0x60)return 0;if(b>=0x61&&b<=0x6F)return b-0x60;return b;}
    static String tn(int t){switch(t){case 0x60:return"EF.COM";case 0x61:return"AppTemplate";case 0x5F01:return"LDS ver";case 0x5F36:return"Unicode ver";case 0x5C:return"DG lista";case 0x5F1F:return"MRZ";case 0x5F0E:return"Puno ime";case 0x5F0F:return"Prezime";case 0x5F10:return"Ime";case 0x5F11:return"Djev.prez";case 0x5F2B:return"Dat.rod";case 0x5F1D:return"JMBG";case 0x5F42:return"Adresa";case 0x5F43:return"Telefon";case 0x30:return"SEQUENCE";case 0x31:return"SET";case 0x06:return"OID";case 0x04:return"OctetStr";case 0x02:return"Integer";default:return String.format("?%04X",t);}}
    static String oid(byte[] o){if(o.length==0)return"";StringBuilder sb=new StringBuilder();sb.append(o[0]/40).append('.').append(o[0]%40);long v=0;for(int i=1;i<o.length;i++){v=(v<<7)|(o[i]&0x7F);if((o[i]&0x80)==0){sb.append('.').append(v);v=0;}}return sb.toString();}

    // ================================================================
    // KRIPTOGRAFIJA
    // ================================================================
    // 3DES ECB (za IV = E(KSenc, SSC))
    static byte[] tdes_ecb(byte[] k16, byte[] data8) throws Exception {
        byte[] k24=cat(k16,Arrays.copyOf(k16,8));
        Cipher c=Cipher.getInstance("DESede/ECB/NoPadding");
        c.init(Cipher.ENCRYPT_MODE,SecretKeyFactory.getInstance("DESede").generateSecret(new DESedeKeySpec(k24)));
        return c.doFinal(data8);
    }
    // 3DES CBC encrypt
    static byte[] tdes_cbc(byte[] k16, byte[] iv, byte[] data) throws Exception {
        byte[] k24=cat(k16,Arrays.copyOf(k16,8));
        Cipher c=Cipher.getInstance("DESede/CBC/NoPadding");
        c.init(Cipher.ENCRYPT_MODE,SecretKeyFactory.getInstance("DESede").generateSecret(new DESedeKeySpec(k24)),new IvParameterSpec(iv));
        return c.doFinal(data);
    }
    // 3DES CBC decrypt
    static byte[] tdes_cbc_dec(byte[] k16, byte[] iv, byte[] data) throws Exception {
        byte[] k24=cat(k16,Arrays.copyOf(k16,8));
        Cipher c=Cipher.getInstance("DESede/CBC/NoPadding");
        c.init(Cipher.DECRYPT_MODE,SecretKeyFactory.getInstance("DESede").generateSecret(new DESedeKeySpec(k24)),new IvParameterSpec(iv));
        return c.doFinal(data);
    }
    // ISO 9797-1 Retail MAC
    static byte[] mac3(byte[] k16, byte[] data) throws Exception {
        byte[] p=isopad(data),k1=Arrays.copyOf(k16,8),k2=Arrays.copyOfRange(k16,8,16),cv=new byte[8];
        for(int i=0;i<p.length;i+=8) cv=des_e(k1,cv,Arrays.copyOfRange(p,i,i+8));
        return Arrays.copyOf(des_e(k1,new byte[8],des_d(k2,new byte[8],cv)),8);
    }
    static byte[] des_e(byte[] k,byte[] iv,byte[] d) throws Exception{Cipher c=Cipher.getInstance("DES/CBC/NoPadding");c.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(k,"DES"),new IvParameterSpec(iv));return c.doFinal(d);}
    static byte[] des_d(byte[] k,byte[] iv,byte[] d) throws Exception{Cipher c=Cipher.getInstance("DES/CBC/NoPadding");c.init(Cipher.DECRYPT_MODE,new SecretKeySpec(k,"DES"),new IvParameterSpec(iv));return c.doFinal(d);}
    // KDF: first 16 bytes of SHA-1(seed || 00 00 00 c), DES parity
    static byte[] kdf(byte[] s,int c) throws Exception{
        byte[] D=Arrays.copyOf(s,s.length+4);D[D.length-1]=(byte)c;
        byte[] k=Arrays.copyOf(sha1(D),16);
        for(int i=0;i<16;i++){int b=k[i]&0xFE;k[i]=(byte)(b|(Integer.bitCount(b)%2==0?1:0));}
        return k;
    }
    static byte[] isopad(byte[] d){byte[] r=new byte[d.length+8-(d.length%8)];System.arraycopy(d,0,r,0,d.length);r[d.length]=(byte)0x80;return r;}
    static byte[] isounpad(byte[] d){int i=d.length-1;while(i>=0&&d[i]==0)i--;return(i>=0&&(d[i]&0xFF)==0x80)?Arrays.copyOf(d,i):d;}
    static void incSSC(){for(int i=SSC.length-1;i>=0;i--){if(++SSC[i]!=0)break;}}
    static byte[] sha1(byte[] d) throws Exception{return MessageDigest.getInstance("SHA-1").digest(d);}
    static byte[] xor(byte[] a,byte[] b){byte[] r=new byte[a.length];for(int i=0;i<a.length;i++)r[i]=(byte)(a[i]^b[i]);return r;}
    static byte[] tlv(int tag,byte[] val){byte[] t=tag>0xFF?new byte[]{(byte)(tag>>8),(byte)(tag&0xFF)}:new byte[]{(byte)(tag&0xFF)};byte[] l=val.length<0x80?new byte[]{(byte)val.length}:val.length<0x100?new byte[]{(byte)0x81,(byte)val.length}:new byte[]{(byte)0x82,(byte)(val.length>>8),(byte)(val.length&0xFF)};return cat(t,l,val);}
    static int cd(String s){int[]w={7,3,1};int sum=0;for(int i=0;i<s.length();i++){char c=s.charAt(i);int v=(c=='<')?0:(c>='A'&&c<='Z')?c-'A'+10:c-'0';sum+=v*w[i%3];}return sum%10;}

    // ================================================================
    // POMOĆNE METODE
    // ================================================================
    static ResponseAPDU send(CardChannel ch,String hex,String l) throws CardException{ResponseAPDU r=ch.transmit(new CommandAPDU(x(hex)));System.out.printf("%s SW=%04X%s%n",l,r.getSW(),r.getData().length>0?" data="+h(r.getData()):"");return r;}
    static int findB(byte[] h,byte[] n){outer:for(int i=0;i<=h.length-n.length;i++){for(int j=0;j<n.length;j++)if(h[i+j]!=n[j])continue outer;return i;}return -1;}
    static void saveFile(byte[] d,String n){try(FileOutputStream f=new FileOutputStream(n)){f.write(d);}catch(Exception e){System.out.println("Save: "+e);}}
    static byte[] cat(byte[]...a){int n=0;for(byte[]x:a)if(x!=null)n+=x.length;byte[]r=new byte[n];int o=0;for(byte[]x:a)if(x!=null){System.arraycopy(x,0,r,o,x.length);o+=x.length;}return r;}
    static String h(byte[] b){if(b==null||b.length==0)return"(empty)";StringBuilder s=new StringBuilder();for(byte x:b)s.append(String.format("%02X",x));return s.toString();}
    static String sw(ResponseAPDU r){return String.format("%04X",r.getSW());}
    static byte[] x(String s){s=s.replace(" ","");byte[]d=new byte[s.length()/2];for(int i=0;i<d.length;i++)d[i]=(byte)((Character.digit(s.charAt(i*2),16)<<4)+Character.digit(s.charAt(i*2+1),16));return d;}
}






===========================================
  BiH eID Reader v9  |  ICAO eMRTD + BAC
===========================================

Broj dokumenta (9 znakova): 1E181TKT6
Datum rodjenja (YYMMDD): 931113
Datum isteka   (YYMMDD): 340917
MRZ: 1E181TKT6193111363409176
ATR: 3B8880014241454944322E306E
SELECT AID SW=9000
--- BAC ---
EXT AUTH SW=9000
MAC OK: true
KS_ENC: 13C7E96DF4070870452C13D63894F76E
KS_MAC: A173F82CB0611CA45BA231C1EA0E496B
SSC:    CC5E357BBCDB7F7F
BAC OK!

========================================
  ČITANJE SVIH DOSTUPNIH PODATAKA
========================================

--- EF.COM (Lista DG-ova) (EF 011E) ---
  >> 0CA4020C158709018AABC9938912561D8E082D3E3CC9C002C22400
  << SW=6988 data=(empty)
  SELECT 011E -> SW=6988
  (nije dostupno)

--- EF.SOD (Digitalni potpis) (EF 011D) ---
  >> 0CA4020C158709016A67919AD65A732C8E08FC17AAC71466E6A800
  << SW=6985 data=(empty)
  SELECT 011D -> SW=6985
  (nije dostupno)

--- DG1  - MRZ podaci (EF 0101) ---
  >> 0CA4020C1587090122A2187AD75B56D58E082AC90BC69B95D67200
  << SW=6985 data=(empty)
  SELECT 0101 -> SW=6985
  (nije dostupno)

--- DG2  - Fotografija lica (EF 0102) ---
  >> 0CA4020C15870901582612069219E9FC8E088255C1D332A10A8800
  << SW=6985 data=(empty)
  SELECT 0102 -> SW=6985
  (nije dostupno)

--- DG3  - Otisci prstiju (EF 0103) ---
  >> 0CA4020C158709013B17E28FB6002D388E08B9EBDB0E989CA85400
  << SW=6985 data=(empty)
  SELECT 0103 -> SW=6985
  (nije dostupno)

--- DG4  - Slika šarenice (EF 0104) ---
  >> 0CA4020C15870901DE7140D1027145708E08ED52C4F16ECEC39700
  << SW=6985 data=(empty)
  SELECT 0104 -> SW=6985
  (nije dostupno)

--- DG5  - Prikazna fotografija (EF 0105) ---
  >> 0CA4020C15870901CFBBC4BEB2329E958E08797388DBFA8ADED800
  << SW=6985 data=(empty)
  SELECT 0105 -> SW=6985
  (nije dostupno)

--- DG7  - Slika potpisa (EF 0107) ---
  >> 0CA4020C1587090179BC621413BCBB218E08B0056F05AE37CF1E00
  << SW=6985 data=(empty)
  SELECT 0107 -> SW=6985
  (nije dostupno)

--- DG11 - Lični podaci (EF 010B) ---
  >> 0CA4020C15870901CF8F61A64948F2F58E085BBF7FBB3E61BF9700
  << SW=6985 data=(empty)
  SELECT 010B -> SW=6985
  (nije dostupno)

--- DG12 - Podaci dokumenta (EF 010C) ---
  >> 0CA4020C15870901300EF104C71810ED8E08171EC53920728C7500
  << SW=6985 data=(empty)
  SELECT 010C -> SW=6985
  (nije dostupno)

--- DG13 - Vendor podaci (EF 010D) ---
  >> 0CA4020C15870901C88133D1CA3413508E08724E44C8CDF9BB3700
  << SW=6985 data=(empty)
  SELECT 010D -> SW=6985
  (nije dostupno)

--- DG14 - EAC Security Options (EF 010E) ---
  >> 0CA4020C158709019A2C229D705971E38E0827EE13582CD94FCC00
  << SW=6985 data=(empty)
  SELECT 010E -> SW=6985
  (nije dostupno)

--- DG15 - Active Auth Public Key (EF 010F) ---
  >> 0CA4020C15870901845B2D93EB2BF9468E081A60E3531CE1FDCB00
  << SW=6985 data=(empty)
  SELECT 010F -> SW=6985
  (nije dostupno)

--- DG16 - Kontakt osobe (EF 0110) ---
  >> 0CA4020C158709016FF5CE7417CEED0A8E089E944B6579C7410F00
  << SW=6985 data=(empty)
  SELECT 0110 -> SW=6985
  (nije dostupno)

--- EF.CardAccess (PACE) (EF 011C) ---
  >> 0CA4020C1587090116B76BC9D9BD56DC8E0868A56268824998C700
  << SW=6985 data=(empty)
  SELECT 011C -> SW=6985
  (nije dostupno)

--- EF.CardSecurity (EF 011B) ---
  >> 0CA4020C15870901812186CD3104661C8E0895A30E5331FF771F00
  << SW=6985 data=(empty)
  SELECT 011B -> SW=6985
  (nije dostupno)

========================================
  REZULTAT
========================================
  Nijedan fajl nije pročitan.
  Provjeri: možda kartica koristi EAC umjesto BAC.

=== Završeno ===

Process finished with exit code 0




import javax.smartcardio.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.util.*;
import java.io.*;
import java.nio.charset.StandardCharsets;

/**
 * BiH eID Reader v9
 *
 * KRITIČNA ISPRAVKA:
 *   IV za 3DES enkriptovanje = E(KS_ENC, SSC)  ← enkriptovani SSC!
 *   NE direktno SSC kao IV.
 *
 * ICAO 9303-11, Section 9.8.6:
 *   "The SSC is used to derive the IV: IV = E(KSenc, SSC)"
 *
 * Kompajliranje: javac BihEidReader.java
 * Pokretanje:    java BihEidReader
 */
public class BihEidReader {

    static byte[] KS_ENC, KS_MAC, SSC = new byte[8];

    public static void main(String[] args) throws Exception {
        System.out.println("===========================================");
        System.out.println("  BiH eID Reader v9  |  ICAO eMRTD + BAC");
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
        String mrzInfo = docNum + cd(docNum) + dob + cd(dob) + expiry + cd(expiry);
        System.out.println("MRZ: " + mrzInfo);

        // Spajanje
        TerminalFactory fac = TerminalFactory.getDefault();
        List<CardTerminal> terms = fac.terminals().list();
        CardTerminal term = null;
        for (CardTerminal t : terms) if (t.isCardPresent()) { term = t; break; }
        if (term == null) { terms.get(0).waitForCardPresent(15000); term = terms.get(0); }
        Card card = term.connect("*");
        CardChannel ch = card.getBasicChannel();
        System.out.println("ATR: " + h(card.getATR().getBytes()));

        // SELECT eMRTD AID
        send(ch, "00A4040C07A0000002471001", "SELECT AID");

        // BAC
        doBAC(ch, mrzInfo);

        // Čitaj sve
        readAll(ch);

        card.disconnect(false);
        System.out.println("\n=== Završeno ===");
    }

    // ================================================================
    // ČITANJE SVIH DOSTUPNIH PODATAKA
    // ================================================================
    static void readAll(CardChannel ch) throws Exception {
        System.out.println("\n========================================");
        System.out.println("  ČITANJE SVIH DOSTUPNIH PODATAKA");
        System.out.println("========================================");

        int[] fids = {
            0x011E, 0x011D, 0x0101, 0x0102, 0x0103, 0x0104,
            0x0105, 0x0107, 0x010B, 0x010C, 0x010D, 0x010E,
            0x010F, 0x0110, 0x011C, 0x011B
        };
        String[] names = {
            "EF.COM (Lista DG-ova)",
            "EF.SOD (Digitalni potpis)",
            "DG1  - MRZ podaci",
            "DG2  - Fotografija lica",
            "DG3  - Otisci prstiju",
            "DG4  - Slika šarenice",
            "DG5  - Prikazna fotografija",
            "DG7  - Slika potpisa",
            "DG11 - Lični podaci",
            "DG12 - Podaci dokumenta",
            "DG13 - Vendor podaci",
            "DG14 - EAC Security Options",
            "DG15 - Active Auth Public Key",
            "DG16 - Kontakt osobe",
            "EF.CardAccess (PACE)",
            "EF.CardSecurity"
        };

        Map<String, byte[]> ok = new LinkedHashMap<>();

        for (int i = 0; i < fids.length; i++) {
            System.out.printf("%n--- %s (EF %04X) ---%n", names[i], fids[i]);
            byte[] data = readEF(ch, fids[i]);
            if (data != null && data.length > 0) {
                ok.put(names[i], data);
                System.out.println("  Veličina: " + data.length + " bajta");
                saveFile(data, String.format("ef_%04X.bin", fids[i]));

                switch (fids[i]) {
                    case 0x011E: parseEFCOM(data); break;
                    case 0x0101: parseDG1(data); break;
                    case 0x010B: case 0x010C: case 0x010D:
                        parseTLV(data, "  "); break;
                    case 0x0102: savePhoto(data, "face"); break;
                    case 0x0107: savePhoto(data, "signature"); break;
                    case 0x011D: parseSOD(data); break;
                    default:
                        System.out.println("  HEX: " + h(data));
                        System.out.println("  TXT: " + txt(data));
                        parseTLV(data, "  ");
                }
            } else {
                System.out.println("  (nije dostupno)");
            }
        }

        // Sažetak
        System.out.println("\n========================================");
        System.out.println("  REZULTAT");
        System.out.println("========================================");
        if (ok.isEmpty()) {
            System.out.println("  Nijedan fajl nije pročitan.");
            System.out.println("  Provjeri: možda kartica koristi EAC umjesto BAC.");
        } else {
            for (Map.Entry<String, byte[]> e : ok.entrySet())
                System.out.printf("  ✓ %-40s %5d bajta%n", e.getKey(), e.getValue().length);
        }
    }

    // ================================================================
    // ČITANJE EF FAJLA SA ISPRAVNIM SM
    // ================================================================
    static byte[] readEF(CardChannel ch, int fid) throws Exception {
        byte hi = (byte)(fid >> 8), lo = (byte)(fid & 0xFF);

        // SM SELECT
        ResponseAPDU sel = smCmd(ch, (byte)0xA4, (byte)0x02, (byte)0x0C,
                                  new byte[]{hi, lo}, false);
        System.out.printf("  SELECT %04X -> SW=%04X%n", fid, sel.getSW());
        if (sel.getSW() != 0x9000) return null;

        // SM READ BINARY
        List<Byte> all = new ArrayList<>();
        int offset = 0;

        while (true) {
            byte p1 = (byte)((offset >> 8) & 0x7F);
            byte p2 = (byte)(offset & 0xFF);
            ResponseAPDU rb = smCmd(ch, (byte)0xB0, p1, p2, null, true);
            int sw = rb.getSW();

            if (sw == 0x9000) {
                byte[] d = rb.getData();
                if (d.length == 0) break;
                for (byte b : d) all.add(b);
                offset += d.length;
                if (d.length < 0xDF) break;
            } else if ((sw & 0xFF00) == 0x6C00) {
                // ignore, retry handled implicitly
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
    // SECURE MESSAGING — ICAO 9303-11 s ispravnim IV
    // ================================================================
    static ResponseAPDU smCmd(CardChannel ch, byte ins, byte p1, byte p2,
                               byte[] cmdData, boolean expectResp) throws Exception {
        // Inkrement SSC
        incSSC();

        // IV = E(KS_ENC, SSC)  ← KLJUČNA ISPRAVKA
        byte[] IV = tdes_enc_ecb(KS_ENC, SSC);

        byte[] do87 = new byte[0];
        byte[] do97 = new byte[0];

        // DO'87: enkriptovani command data (samo ako postoje)
        if (cmdData != null && cmdData.length > 0) {
            byte[] padded = isopad(cmdData);
            byte[] enc    = tdes_enc_cbc(KS_ENC, IV, padded);
            do87 = buildTLV(0x87, cat(new byte[]{0x01}, enc));
        }

        // DO'97: Le (samo za komande koje vraćaju podatke)
        if (expectResp) {
            do97 = new byte[]{(byte)0x97, 0x01, 0x00};
        }

        // Header sa SM bitom
        byte[] hdr = {(byte)0x0C, ins, p1, p2};

        // M = pad(SSC) || pad(hdr) || do87 || do97
        byte[] M = cat(SSC, isopad(hdr), do87, do97);

        // CC = Retail-MAC(KS_MAC, M)
        byte[] CC  = mac3(KS_MAC, M);
        byte[] do8E = buildTLV(0x8E, CC);

        // Finalni APDU
        byte[] body = cat(do87, do97, do8E);
        byte[] apdu = cat(
            new byte[]{(byte)0x0C, ins, p1, p2, (byte)body.length},
            body,
            new byte[]{0x00}
        );

        System.out.println("  >> " + h(apdu));
        ResponseAPDU resp = ch.transmit(new CommandAPDU(apdu));
        System.out.printf("  << SW=%04X data=%s%n", resp.getSW(), h(resp.getData()));

        if (resp.getSW() == 0x9000 && resp.getData().length > 0) {
            return smDecrypt(resp.getData());
        }
        return resp;
    }

    static ResponseAPDU smDecrypt(byte[] respData) throws Exception {
        // Inkrement SSC za odgovor
        incSSC();

        // IV = E(KS_ENC, SSC)
        byte[] IV = tdes_enc_ecb(KS_ENC, SSC);

        byte[] do87v=null, do99v=null, do8Ev=null;
        int i=0;
        while (i < respData.length) {
            int tag = respData[i++] & 0xFF;
            if (tag == 0 || tag == 0xFF) continue;
            if ((tag & 0x1F) == 0x1F && i < respData.length)
                tag = (tag << 8) | (respData[i++] & 0xFF);
            if (i >= respData.length) break;
            int len = respData[i++] & 0xFF;
            if (len == 0x81 && i < respData.length) len = respData[i++] & 0xFF;
            else if (len == 0x82 && i+1 < respData.length) {
                len = ((respData[i]&0xFF)<<8)|(respData[i+1]&0xFF); i+=2;
            }
            if (i+len > respData.length) break;
            byte[] val = Arrays.copyOfRange(respData, i, i+len); i += len;
            int t = tag & 0xFF;
            if      (t == 0x87) do87v = val;
            else if (t == 0x99) do99v = val;
            else if (t == 0x8E) do8Ev = val;
        }

        // Verifikuj MAC
        byte[] macIn = cat(SSC);
        if (do87v != null) macIn = cat(macIn, buildTLV(0x87, do87v));
        if (do99v != null) macIn = cat(macIn, buildTLV(0x99, do99v));
        byte[] expMAC = mac3(KS_MAC, macIn);
        if (!Arrays.equals(expMAC, do8Ev))
            System.out.println("  WARN: MAC mismatch exp="+h(expMAC)+" got="+h(do8Ev));

        // Dekriptuj DO'87
        byte[] plain = new byte[0];
        if (do87v != null) {
            byte[] cipher = Arrays.copyOfRange(do87v, 1, do87v.length); // preskočimo 0x01
            byte[] dec    = tdes_dec_cbc(KS_ENC, IV, cipher);
            plain         = isounpad(dec);
        }

        int sw = do99v != null ? ((do99v[0]&0xFF)<<8)|(do99v[1]&0xFF) : 0x9000;
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
        System.out.println("--- BAC ---");
        byte[] kseed = Arrays.copyOf(sha1(mrzInfo.getBytes(StandardCharsets.UTF_8)), 16);
        byte[] kenc  = kdf(kseed, 1);
        byte[] kmac  = kdf(kseed, 2);

        ResponseAPDU gc = ch.transmit(new CommandAPDU(x("0084000008")));
        if (gc.getSW() != 0x9000) throw new Exception("GET CHALLENGE: " + String.format("%04X", gc.getSW()));
        byte[] RND_IC  = gc.getData();
        byte[] RND_IFD = new byte[8]; new SecureRandom().nextBytes(RND_IFD);
        byte[] K_IFD   = new byte[16]; new SecureRandom().nextBytes(K_IFD);

        // BAC koristi IV=00 (ne enkriptovani SSC!)
        byte[] EIFD = tdes_enc_cbc(kenc, new byte[8], cat(RND_IFD, RND_IC, K_IFD));
        byte[] MIFD = mac3(kmac, EIFD);
        byte[] body = cat(EIFD, MIFD);
        byte[] ea   = cat(new byte[]{0x00,(byte)0x82,0x00,0x00,(byte)body.length}, body, new byte[]{0x28});
        ResponseAPDU ar = ch.transmit(new CommandAPDU(ea));
        System.out.printf("EXT AUTH SW=%04X%n", ar.getSW());
        if (ar.getSW() != 0x9000) throw new Exception("BAC failed");

        byte[] R    = ar.getData();
        byte[] dec  = tdes_dec_cbc(kenc, new byte[8], Arrays.copyOf(R, 32));
        byte[] K_IC = Arrays.copyOfRange(dec, 16, 32);
        System.out.println("MAC OK: " + Arrays.equals(mac3(kmac, Arrays.copyOf(R,32)), Arrays.copyOfRange(R,32,40)));

        byte[] KSseed = xor(K_IFD, K_IC);
        KS_ENC = kdf(KSseed, 1);
        KS_MAC = kdf(KSseed, 2);
        SSC    = cat(Arrays.copyOfRange(RND_IC,4,8), Arrays.copyOfRange(RND_IFD,4,8));
        System.out.println("KS_ENC: " + h(KS_ENC));
        System.out.println("KS_MAC: " + h(KS_MAC));
        System.out.println("SSC:    " + h(SSC));
        System.out.println("BAC OK!");
    }

    // ================================================================
    // PARSIRANJE
    // ================================================================
    static void parseEFCOM(byte[] data) {
        System.out.println("  === EF.COM - Dostupni Data Groups ===");
        parseTLV(data, "  ");
    }

    static void parseDG1(byte[] data) {
        System.out.println("  === DG1 - MRZ Podaci ===");
        parseTLV(data, "  ");
    }

    static void parseSOD(byte[] data) {
        System.out.println("  === EF.SOD - Security Object Document ===");
        System.out.println("  Veličina: " + data.length + " bajta (ASN.1/CMS format)");
        saveFile(data, "ef_SOD_cert.bin");
        System.out.println("  Sačuvano: ef_SOD_cert.bin");
        // Prikaži OID-ove iz ASN.1 strukture
        extractOIDs(data);
    }

    static void parseTLV(byte[] data, String ind) {
        parseTLVAt(data, 0, data.length, ind, 0);
    }

    static void parseTLVAt(byte[] data, int s, int e, String ind, int depth) {
        if (depth > 8) return;
        int i = s;
        while (i < e) {
            if ((data[i]&0xFF)==0 || (data[i]&0xFF)==0xFF) { i++; continue; }
            int tag = data[i++] & 0xFF;
            boolean constr = (tag & 0x20) != 0;
            if ((tag & 0x1F) == 0x1F && i < e) tag = (tag<<8)|(data[i++]&0xFF);
            if (i >= e) break;
            int len = data[i++] & 0xFF;
            if (len == 0x81 && i < e) len = data[i++] & 0xFF;
            else if (len == 0x82 && i+1 < e) { len=((data[i]&0xFF)<<8)|(data[i+1]&0xFF); i+=2; }
            if (i+len > e || len < 0) break;
            byte[] val = Arrays.copyOfRange(data, i, i+len); i += len;

            System.out.printf("%sTag %04X [%s] len=%d%n", ind, tag, tname(tag), len);

            if (tag == 0x5F1F) {
                // MRZ
                String mrz = new String(val, StandardCharsets.UTF_8);
                System.out.println(ind + "  MRZ: [" + mrz.replace("\n","↵") + "]");
                decodeMRZ(mrz, ind + "  ");
            } else if (tag == 0x5C) {
                // Lista DG tagova
                System.out.print(ind + "  DG-ovi prisutni:");
                for (byte b : val) System.out.printf(" DG%d", dgNum(b&0xFF));
                System.out.println();
            } else if (constr) {
                parseTLVAt(data, i-len, i, ind+"  ", depth+1);
            } else {
                boolean pr = val.length > 0;
                for (byte b : val) { int c=b&0xFF; if(c<0x20||c>0x7E){pr=false;break;} }
                String disp = pr
                    ? "\"" + new String(val, StandardCharsets.UTF_8) + "\""
                    : h(val);
                System.out.println(ind + "  = " + disp);
            }
        }
    }

    static void decodeMRZ(String mrz, String ind) {
        mrz = mrz.replace("\n","").replace("\r","");
        System.out.println(ind + "╔══════════════════════════════╗");
        System.out.println(ind + "║  DEKODIRANA LIČNA KARTA BiH  ║");
        System.out.println(ind + "╠══════════════════════════════╣");
        if (mrz.length() >= 30) {
            String l = mrz.substring(0, 30);
            System.out.println(ind + "║ Tip dok : " + p(l.substring(0,2).replace("<",""), 21) + "║");
            System.out.println(ind + "║ Zemlja  : " + p(l.substring(2,5).replace("<",""), 21) + "║");
            System.out.println(ind + "║ Br.dok  : " + p(l.substring(5,14).replace("<",""), 21) + "║");
        }
        if (mrz.length() >= 60) {
            String l = mrz.substring(30, 60);
            System.out.println(ind + "║ Dat.rod : " + p(fmtD(l.substring(0,6)), 21) + "║");
            System.out.println(ind + "║ Pol     : " + p(l.substring(7,8).equals("M")?"Muški":"Ženski", 21) + "║");
            System.out.println(ind + "║ Dat.ist : " + p(fmtD(l.substring(8,14)), 21) + "║");
            System.out.println(ind + "║ Nat.    : " + p(l.substring(15,18).replace("<",""), 21) + "║");
        }
        if (mrz.length() >= 90) {
            String l = mrz.substring(60, 90);
            String[] parts = l.split("<<", 2);
            System.out.println(ind + "║ Prezime : " + p(parts[0].replace("<",""), 21) + "║");
            if (parts.length > 1)
                System.out.println(ind + "║ Ime     : " + p(parts[1].replace("<"," ").trim(), 21) + "║");
        }
        System.out.println(ind + "╚══════════════════════════════╝");
    }

    static void savePhoto(byte[] data, String prefix) {
        int off = findBytes(data, new byte[]{(byte)0xFF,(byte)0xD8});
        if (off >= 0) {
            saveFile(Arrays.copyOfRange(data, off, data.length), prefix + ".jpg");
            System.out.println("  Sačuvano: " + prefix + ".jpg");
        }
        off = findBytes(data, new byte[]{(byte)0xFF,(byte)0x4F});
        if (off < 0) off = findBytes(data, new byte[]{0x00,0x00,0x00,0x0C,0x6A,0x50});
        if (off >= 0) {
            saveFile(Arrays.copyOfRange(data, off, data.length), prefix + ".jp2");
            System.out.println("  Sačuvano: " + prefix + ".jp2");
        }
    }

    static void extractOIDs(byte[] data) {
        // Traži OID tagove (0x06) u ASN.1 strukturi
        for (int i = 0; i < data.length - 2; i++) {
            if ((data[i]&0xFF) == 0x06) {
                int len = data[i+1] & 0xFF;
                if (len > 0 && i+2+len <= data.length) {
                    byte[] oid = Arrays.copyOfRange(data, i+2, i+2+len);
                    System.out.println("  OID: " + oidToString(oid));
                }
            }
        }
    }

    static String oidToString(byte[] oid) {
        if (oid.length == 0) return "";
        StringBuilder sb = new StringBuilder();
        sb.append(oid[0]/40).append('.').append(oid[0]%40);
        long val = 0;
        for (int i = 1; i < oid.length; i++) {
            val = (val << 7) | (oid[i] & 0x7F);
            if ((oid[i] & 0x80) == 0) { sb.append('.').append(val); val = 0; }
        }
        return sb.toString();
    }

    static int dgNum(int b) {
        if (b == 0x60) return 0;
        if (b >= 0x61 && b <= 0x6F) return b - 0x60;
        if (b >= 0x70 && b <= 0x76) return b - 0x60 + 16;
        return b;
    }

    static String tname(int t) {
        switch(t) {
            case 0x60: return "EF.COM template";
            case 0x61: return "App template";
            case 0x5F01: return "LDS verzija";
            case 0x5F36: return "Unicode verzija";
            case 0x5C: return "Lista DG tagova";
            case 0x5F1F: return "MRZ (Machine Readable Zone)";
            case 0x5F0E: return "Puno ime";
            case 0x5F0F: return "Prezime";
            case 0x5F10: return "Ime";
            case 0x5F11: return "Djevojačko prezime";
            case 0x5F2B: return "Datum rodjenja";
            case 0x5F1D: return "Identifikacijski br. (JMBG)";
            case 0x5F42: return "Adresa stanovanja";
            case 0x5F43: return "Telefon";
            case 0x30:   return "SEQUENCE";
            case 0x31:   return "SET";
            case 0x06:   return "OID";
            case 0x04:   return "OctetString";
            case 0x02:   return "Integer";
            case 0xA0:   return "[0] kontekstualni";
            case 0xA3:   return "[3] kontekstualni";
            default:     return String.format("?%04X", t);
        }
    }

    static String p(String s, int n) { while(s.length()<n) s+=" "; return s; }
    static String fmtD(String s) {
        if(s.length()!=6) return s;
        int y=Integer.parseInt(s.substring(0,2));
        return s.substring(4)+"."+s.substring(2,4)+"."+(y>30?"19":"20")+s.substring(0,2);
    }

    // ================================================================
    // KRIPTOGRAFIJA (ICAO 9303-11 ispravno)
    // ================================================================

    // 3DES ECB (za izračunavanje IV = E(KS_ENC, SSC))
    static byte[] tdes_enc_ecb(byte[] key16, byte[] data8) throws Exception {
        byte[] k24 = cat(key16, Arrays.copyOf(key16, 8));
        Cipher c = Cipher.getInstance("DESede/ECB/NoPadding");
        c.init(Cipher.ENCRYPT_MODE,
            SecretKeyFactory.getInstance("DESede").generateSecret(new DESedeKeySpec(k24)));
        return c.doFinal(data8);
    }

    // 3DES CBC encrypt
    static byte[] tdes_enc_cbc(byte[] key16, byte[] iv, byte[] data) throws Exception {
        byte[] k24 = cat(key16, Arrays.copyOf(key16, 8));
        Cipher c = Cipher.getInstance("DESede/CBC/NoPadding");
        c.init(Cipher.ENCRYPT_MODE,
            SecretKeyFactory.getInstance("DESede").generateSecret(new DESedeKeySpec(k24)),
            new IvParameterSpec(iv));
        return c.doFinal(data);
    }

    // 3DES CBC decrypt
    static byte[] tdes_dec_cbc(byte[] key16, byte[] iv, byte[] data) throws Exception {
        byte[] k24 = cat(key16, Arrays.copyOf(key16, 8));
        Cipher c = Cipher.getInstance("DESede/CBC/NoPadding");
        c.init(Cipher.DECRYPT_MODE,
            SecretKeyFactory.getInstance("DESede").generateSecret(new DESedeKeySpec(k24)),
            new IvParameterSpec(iv));
        return c.doFinal(data);
    }

    // ISO 9797-1 Retail MAC Algorithm 3
    static byte[] mac3(byte[] key16, byte[] data) throws Exception {
        byte[] padded = isopad(data);
        byte[] k1 = Arrays.copyOf(key16, 8);
        byte[] k2 = Arrays.copyOfRange(key16, 8, 16);
        byte[] cv = new byte[8];
        for (int i = 0; i < padded.length; i += 8)
            cv = des_e(k1, cv, Arrays.copyOfRange(padded, i, i+8));
        cv = des_d(k2, new byte[8], cv);
        cv = des_e(k1, new byte[8], cv);
        return Arrays.copyOf(cv, 8);
    }

    static byte[] des_e(byte[] k, byte[] iv, byte[] d) throws Exception {
        Cipher c = Cipher.getInstance("DES/CBC/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k,"DES"), new IvParameterSpec(iv));
        return c.doFinal(d);
    }
    static byte[] des_d(byte[] k, byte[] iv, byte[] d) throws Exception {
        Cipher c = Cipher.getInstance("DES/CBC/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(k,"DES"), new IvParameterSpec(iv));
        return c.doFinal(d);
    }

    static byte[] kdf(byte[] seed, int c) throws Exception {
        byte[] D = Arrays.copyOf(seed, seed.length + 4); D[D.length-1] = (byte)c;
        byte[] key = Arrays.copyOf(sha1(D), 16);
        for (int i = 0; i < 16; i++) {
            int b = key[i] & 0xFE;
            key[i] = (byte)(b | (Integer.bitCount(b)%2==0 ? 1 : 0));
        }
        return key;
    }

    static byte[] isopad(byte[] d) {
        byte[] r = new byte[d.length + 8 - (d.length % 8)];
        System.arraycopy(d, 0, r, 0, d.length);
        r[d.length] = (byte)0x80;
        return r;
    }
    static byte[] isounpad(byte[] d) {
        int i = d.length-1;
        while (i >= 0 && d[i] == 0) i--;
        return (i >= 0 && (d[i]&0xFF)==0x80) ? Arrays.copyOf(d, i) : d;
    }
    static void incSSC() {
        for (int i = SSC.length-1; i >= 0; i--) { if (++SSC[i] != 0) break; }
    }
    static byte[] sha1(byte[] d) throws Exception {
        return MessageDigest.getInstance("SHA-1").digest(d);
    }
    static byte[] xor(byte[] a, byte[] b) {
        byte[] r = new byte[a.length];
        for (int i = 0; i < a.length; i++) r[i] = (byte)(a[i]^b[i]);
        return r;
    }
    static byte[] buildTLV(int tag, byte[] val) {
        byte[] t = tag>0xFF ? new byte[]{(byte)(tag>>8),(byte)(tag&0xFF)} : new byte[]{(byte)(tag&0xFF)};
        byte[] l = val.length<0x80 ? new byte[]{(byte)val.length}
                 : val.length<0x100 ? new byte[]{(byte)0x81,(byte)val.length}
                 : new byte[]{(byte)0x82,(byte)(val.length>>8),(byte)(val.length&0xFF)};
        return cat(t, l, val);
    }
    static int cd(String s) {
        int[] w={7,3,1}; int sum=0;
        for (int i=0; i<s.length(); i++) {
            char c=s.charAt(i);
            int v=(c=='<')?0:(c>='A'&&c<='Z')?c-'A'+10:c-'0';
            sum+=v*w[i%3];
        }
        return sum%10;
    }

    // ================================================================
    // POMOĆNE METODE
    // ================================================================
    static ResponseAPDU send(CardChannel ch, String hex, String label) throws CardException {
        ResponseAPDU r = ch.transmit(new CommandAPDU(x(hex)));
        System.out.printf("%s SW=%04X%s%n", label, r.getSW(),
            r.getData().length>0 ? " data="+h(r.getData()) : "");
        return r;
    }
    static int findBytes(byte[] hay, byte[] needle) {
        outer: for (int i=0; i<=hay.length-needle.length; i++) {
            for (int j=0; j<needle.length; j++) if(hay[i+j]!=needle[j]) continue outer;
            return i;
        }
        return -1;
    }
    static void saveFile(byte[] d, String n) {
        try (FileOutputStream f = new FileOutputStream(n)) { f.write(d); }
        catch (Exception e) { System.out.println("Save err: "+e); }
    }
    static byte[] cat(byte[]... a) {
        int n=0; for(byte[] x:a) if(x!=null) n+=x.length;
        byte[] r=new byte[n]; int o=0;
        for(byte[] x:a) if(x!=null){System.arraycopy(x,0,r,o,x.length);o+=x.length;}
        return r;
    }
    static String h(byte[] b) {
        if(b==null||b.length==0) return "(empty)";
        StringBuilder sb=new StringBuilder();
        for(byte x:b) sb.append(String.format("%02X",x));
        return sb.toString();
    }
    static String txt(byte[] b) {
        StringBuilder sb=new StringBuilder();
        for(byte x:b){int c=x&0xFF;sb.append(c>=32&&c<=126?(char)c:'.');}
        return sb.toString();
    }
    static byte[] x(String s) {
        s=s.replace(" ","");
        byte[] d=new byte[s.length()/2];
        for(int i=0;i<d.length;i++)
            d[i]=(byte)((Character.digit(s.charAt(i*2),16)<<4)+Character.digit(s.charAt(i*2+1),16));
        return d;
    }
}








BiH eID Reader v8  |  SM Debug
===========================================

Broj dokumenta (9 znakova): 1E181TKT6
Datum rodjenja (YYMMDD): 931113
Datum isteka   (YYMMDD): 340917
MRZ: 1E181TKT6193111363409176
ATR: 3B8880014241454944322E306E
SELECT AID SW=9000
--- BAC ---
BAC OK! SSC=CFB7EF6DB5748A09

=== TESTIRANJE SM VARIJANTI ===
(Tražimo koja varijanta daje SW=9000 za SELECT 011E)

--- Varijanta A: DO'87 (enc fileId) + DO'8E ---
  APDU: 0CA4020C158709010746E2324BC3D9FE8E08C10F3ABBD4DDF6E700
  SW=6988

--- Varijanta B: DO'81 (plain fileId) + DO'8E ---
  APDU: 0CA4020C0E8102011E8E08D25DC4F8E8B6DAB600
  SW=6985

--- Varijanta C: Samo DO'8E (MAC over padded header) ---
  Plain SELECT SW=6982

--- Varijanta D: Plain SELECT 011E (bez SM) ---
Plain SELECT SW=6982

--- Varijanta E: SELECT SHORT FILE ID ---
  SELECT 0100 -> SW=6982
  SELECT 0101 -> SW=6982
  SELECT 0102 -> SW=6982
  SELECT 0103 -> SW=6982
  SELECT 0104 -> SW=6982
  SELECT 0105 -> SW=6982
  SELECT 0106 -> SW=6982
  SELECT 0107 -> SW=6982
  SELECT 0108 -> SW=6982
  SELECT 0109 -> SW=6982
  SELECT 010A -> SW=6982
  SELECT 010B -> SW=6982
  SELECT 010C -> SW=6982
  SELECT 010D -> SW=6982
  SELECT 010E -> SW=6982
  SELECT 010F -> SW=6982
  SELECT 0110 -> SW=6982
  SELECT 0111 -> SW=6982
  SELECT 0112 -> SW=6982
  SELECT 0113 -> SW=6982
  SELECT 0114 -> SW=6982
  SELECT 0115 -> SW=6982
  SELECT 0116 -> SW=6982
  SELECT 0117 -> SW=6982
  SELECT 0118 -> SW=6982
  SELECT 0119 -> SW=6982
  SELECT 011A -> SW=6982
  SELECT 011B -> SW=6982
  SELECT 011C -> SW=6982
  SELECT 011D -> SW=6982
  SELECT 011E -> SW=6982
  SELECT 011F -> SW=6982

--- Varijanta F: RESET SSC na nulu, probaj ponovo ---
Re-SELECT AID SW=9000
--- BAC ---
BAC OK! SSC=C06F837395D1BCD5
SSC resetovan na: 0000000000000000
  APDU: 0CA4020C15870901B1485F840EB411F58E08A833E38E581D864A00
  SW=6988

--- Varijanta G: CLA=00 sa SM objektima ---
  APDU: 00A4020C0E8102011E8E08728505C4351A8D8100
  SW=6982

--- Varijanta H: READ BINARY bez SELECT ---
Re-SELECT AID SW=9000
--- BAC ---
BAC OK! SSC=2F2C45B1CCBA903E
  READ BINARY SFI=1 -> SW=6988 data=(empty)
  READ BINARY SFI=2 -> SW=6982 data=(empty)
  READ BINARY SFI=3 -> SW=6982 data=(empty)
  READ BINARY SFI=4 -> SW=6982 data=(empty)
  READ BINARY SFI=5 -> SW=6982 data=(empty)
  READ BINARY SFI=6 -> SW=6982 data=(empty)
  READ BINARY SFI=7 -> SW=6982 data=(empty)
  READ BINARY SFI=8 -> SW=6982 data=(empty)
  READ BINARY SFI=9 -> SW=6982 data=(empty)
  READ BINARY SFI=10 -> SW=6982 data=(empty)
  READ BINARY SFI=11 -> SW=6982 data=(empty)
  READ BINARY SFI=12 -> SW=6982 data=(empty)
  READ BINARY SFI=13 -> SW=6982 data=(empty)
  READ BINARY SFI=14 -> SW=6982 data=(empty)
  READ BINARY SFI=15 -> SW=6982 data=(empty)
  READ BINARY SFI=16 -> SW=6982 data=(empty)

--- Varijanta I: GET DATA za DG tagove ---

=== Ako je neka varijanta dala SW=9000, koristimo nju ===
Pokušaj čitanja sa ISPRAVNOM varijantom...

Re-SELECT AID SW=9000
--- BAC ---
BAC OK! SSC=447783DC77602985
--- EF.COM ---
  SEL >> 0CA4020C15870901B1E27F985FF7FB7E8E0801E8E5223461173500
  SEL << SW=6988
--- DG1 MRZ ---
  SEL >> 0CA4020C15870901011FDC514B1FE0378E08EED7AA0EA068E1E500
  SEL << SW=6985
--- DG11 Lični ---
  SEL >> 0CA4020C15870901461BBD6C38A0A90C8E08DBD3F31FAFC7B82600
  SEL << SW=6985
--- DG12 Dok ---
  SEL >> 0CA4020C15870901706056541793D6D18E087CAC8B602E60521E00
  SEL << SW=6985
--- DG2 Foto ---
  SEL >> 0CA4020C158709017A94FABDEA3FF5D38E089D9AB69227CBF68D00
  SEL << SW=6985
--- EF.SOD ---
  SEL >> 0CA4020C158709013C794983D524CCFC8E08114AD4E6D6A011FD00
  SEL << SW=6985

=== Završeno ===

Process finished with exit code 0



import javax.smartcardio.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.util.*;
import java.io.*;
import java.nio.charset.StandardCharsets;

/**
 * BiH eID Reader v8
 * Testira sve SM varijante za SELECT i READ BINARY
 * da nađe koji format kartica prihvata.
 *
 * Kompajliranje: javac BihEidReader.java
 * Pokretanje:    java BihEidReader
 */
public class BihEidReader {

    static byte[] KS_ENC, KS_MAC, SSC = new byte[8];

    public static void main(String[] args) throws Exception {
        System.out.println("===========================================");
        System.out.println("  BiH eID Reader v8  |  SM Debug");
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
        String mrzInfo = docNum + cd(docNum) + dob + cd(dob) + expiry + cd(expiry);
        System.out.println("MRZ: " + mrzInfo);

        // Spajanje
        TerminalFactory fac = TerminalFactory.getDefault();
        List<CardTerminal> terms = fac.terminals().list();
        CardTerminal term = null;
        for (CardTerminal t : terms) if (t.isCardPresent()) { term = t; break; }
        if (term == null) { terms.get(0).waitForCardPresent(15000); term = terms.get(0); }
        Card card = term.connect("*");
        CardChannel ch = card.getBasicChannel();
        System.out.println("ATR: " + h(card.getATR().getBytes()));

        // SELECT AID
        send(ch, "00A4040C07A0000002471001", "SELECT AID");

        // BAC
        doBAC(ch, mrzInfo);

        // ============================================================
        // PROBAJ SVE SM VARIJANTE ZA SELECT EF.COM (011E)
        // ============================================================
        System.out.println("\n=== TESTIRANJE SM VARIJANTI ===");
        System.out.println("(Tražimo koja varijanta daje SW=9000 za SELECT 011E)\n");

        byte[] fileId = {0x01, 0x1E};

        // --- Varijanta A: DO'87 (encrypted data) + DO'8E ---
        System.out.println("--- Varijanta A: DO'87 (enc fileId) + DO'8E ---");
        testVariantA(ch, fileId);

        // --- Varijanta B: DO'81 (plain data) + DO'8E ---
        System.out.println("\n--- Varijanta B: DO'81 (plain fileId) + DO'8E ---");
        testVariantB(ch, fileId);

        // --- Varijanta C: Bez data DO-a, samo DO'8E (MAC over header only) ---
        System.out.println("\n--- Varijanta C: Samo DO'8E (MAC over padded header) ---");
        testVariantC(ch, fileId);

        // --- Varijanta D: Plain SELECT (bez SM) ---
        System.out.println("\n--- Varijanta D: Plain SELECT 011E (bez SM) ---");
        ResponseAPDU plainSel = ch.transmit(new CommandAPDU(x("00A4020C02011E")));
        System.out.printf("Plain SELECT SW=%04X%n", plainSel.getSW());

        // --- Varijanta E: SELECT po short file ID ---
        System.out.println("\n--- Varijanta E: SELECT SHORT FILE ID ---");
        // Short file ID za DG1 = 0x01, za EF.COM različito
        for (int sfi = 0x00; sfi <= 0x1F; sfi++) {
            ResponseAPDU r = ch.transmit(new CommandAPDU(
                new byte[]{0x00,(byte)0xA4,0x02,0x0C,0x02,0x01,(byte)sfi}));
            if (r.getSW() != 0x6A82) {
                System.out.printf("  SELECT 01%02X -> SW=%04X%n", sfi, r.getSW());
            }
        }

        // --- Varijanta F: READ BINARY direktno sa SSC=0 ---
        System.out.println("\n--- Varijanta F: RESET SSC na nulu, probaj ponovo ---");
        // Ponovi BAC da dobijemo svježe ključeve
        send(ch, "00A4040C07A0000002471001", "Re-SELECT AID");
        doBAC(ch, mrzInfo);

        // Postavi SSC na 0 i probaj
        SSC = new byte[8];
        System.out.println("SSC resetovan na: " + h(SSC));
        testVariantA(ch, fileId);

        // --- Varijanta G: Probaj ISO SM format (CLA=00 umjesto 0C) ---
        System.out.println("\n--- Varijanta G: CLA=00 sa SM objektima ---");
        testVariantG(ch, fileId);

        // --- Varijanta H: READ BINARY bez SELECT (direktno iz MF) ---
        System.out.println("\n--- Varijanta H: READ BINARY bez SELECT ---");
        send(ch, "00A4040C07A0000002471001", "Re-SELECT AID");
        doBAC(ch, mrzInfo);
        // Short file ID read: B0 + bit7 + SFI u P1
        for (int sfi = 1; sfi <= 16; sfi++) {
            byte p1 = (byte)(0x80 | sfi); // bit7=1 → short file ID read
            byte[] rb = {0x00,(byte)0xB0, p1, 0x00, 0x00};
            ResponseAPDU r = ch.transmit(new CommandAPDU(rb));
            if (r.getSW() != 0x6A82 && r.getSW() != 0x6985) {
                System.out.printf("  READ BINARY SFI=%d -> SW=%04X data=%s%n",
                    sfi, r.getSW(), h(r.getData()));
            }
        }

        // --- Varijanta I: Probaj GET DATA umjesto SELECT ---
        System.out.println("\n--- Varijanta I: GET DATA za DG tagove ---");
        int[] getDataTags = {0x6105, 0x6106, 0x6107, 0x6101, 0x6102, 0x6B01};
        for (int tag : getDataTags) {
            byte[] apdu = {0x00,(byte)0xCA,(byte)(tag>>8),(byte)(tag&0xFF),0x00};
            ResponseAPDU r = ch.transmit(new CommandAPDU(apdu));
            if (r.getSW() == 0x9000) {
                System.out.printf("  GET DATA %04X -> SW=9000 data=%s%n", tag, h(r.getData()));
            }
        }

        // --- SAČUVAJ STANJE I POKUŠAJ SA ISPRAVNIM SM KOJI RADI ---
        System.out.println("\n=== Ako je neka varijanta dala SW=9000, koristimo nju ===");
        System.out.println("Pokušaj čitanja sa ISPRAVNOM varijantom...\n");

        // Ponovo inicijalizuj
        send(ch, "00A4040C07A0000002471001", "Re-SELECT AID");
        doBAC(ch, mrzInfo);
        tryReadWithWorkingVariant(ch);

        card.disconnect(false);
        System.out.println("\n=== Završeno ===");
    }

    // ================================================================
    // SM VARIJANTE
    // ================================================================

    // Varijanta A: DO'87 = encrypted(padded(fileId)), DO'8E = MAC
    // MAC input: SSC || padded(header) || DO'87
    static ResponseAPDU testVariantA(CardChannel ch, byte[] fileId) throws Exception {
        byte[] sscBefore = SSC.clone();
        incSSC();
        byte[] padded  = isopad(fileId);
        byte[] enc     = tdes_enc(KS_ENC, SSC, padded);   // IV = current SSC
        byte[] do87    = buildTLV(0x87, cat(new byte[]{0x01}, enc));
        byte[] hdr     = {(byte)0x0C,(byte)0xA4,0x02,(byte)0x0C};
        byte[] macIn   = cat(SSC, isopad(hdr), do87);
        byte[] CC      = mac3(KS_MAC, macIn);
        byte[] do8E    = buildTLV(0x8E, CC);
        byte[] body    = cat(do87, do8E);
        byte[] apdu    = cat(new byte[]{(byte)0x0C,(byte)0xA4,0x02,(byte)0x0C,(byte)body.length}, body, new byte[]{0x00});
        System.out.println("  APDU: " + h(apdu));
        ResponseAPDU r = ch.transmit(new CommandAPDU(apdu));
        System.out.printf("  SW=%04X%n", r.getSW());
        if (r.getSW() == 0x9000) { System.out.println("  *** VARIJANTA A RADI! ***"); }
        return r;
    }

    // Varijanta B: DO'81 = plain fileId, DO'8E = MAC
    // MAC input: SSC || padded(header) || DO'81
    static ResponseAPDU testVariantB(CardChannel ch, byte[] fileId) throws Exception {
        incSSC();
        byte[] do81  = buildTLV(0x81, fileId);
        byte[] hdr   = {(byte)0x0C,(byte)0xA4,0x02,(byte)0x0C};
        byte[] macIn = cat(SSC, isopad(hdr), do81);
        byte[] CC    = mac3(KS_MAC, macIn);
        byte[] do8E  = buildTLV(0x8E, CC);
        byte[] body  = cat(do81, do8E);
        byte[] apdu  = cat(new byte[]{(byte)0x0C,(byte)0xA4,0x02,(byte)0x0C,(byte)body.length}, body, new byte[]{0x00});
        System.out.println("  APDU: " + h(apdu));
        ResponseAPDU r = ch.transmit(new CommandAPDU(apdu));
        System.out.printf("  SW=%04X%n", r.getSW());
        if (r.getSW() == 0x9000) System.out.println("  *** VARIJANTA B RADI! ***");
        return r;
    }

    // Varijanta C: Bez data, samo header MAC (za SELECT bez P2=0C response)
    static ResponseAPDU testVariantC(CardChannel ch, byte[] fileId) throws Exception {
        // Pošalji SELECT plain pa onda SM READ BINARY
        ResponseAPDU plain = ch.transmit(new CommandAPDU(x("00A4020C02") + fileId));
        System.out.printf("  Plain SELECT SW=%04X%n", plain.getSW());
        return plain;
    }

    // Varijanta G: Isti SM ali CLA=00
    static ResponseAPDU testVariantG(CardChannel ch, byte[] fileId) throws Exception {
        incSSC();
        byte[] do81  = buildTLV(0x81, fileId);
        byte[] hdr   = {0x00,(byte)0xA4,0x02,(byte)0x0C};  // CLA=00
        byte[] macIn = cat(SSC, isopad(hdr), do81);
        byte[] CC    = mac3(KS_MAC, macIn);
        byte[] do8E  = buildTLV(0x8E, CC);
        byte[] body  = cat(do81, do8E);
        byte[] apdu  = cat(new byte[]{0x00,(byte)0xA4,0x02,(byte)0x0C,(byte)body.length}, body, new byte[]{0x00});
        System.out.println("  APDU: " + h(apdu));
        ResponseAPDU r = ch.transmit(new CommandAPDU(apdu));
        System.out.printf("  SW=%04X%n", r.getSW());
        if (r.getSW() == 0x9000) System.out.println("  *** VARIJANTA G RADI! ***");
        return r;
    }

    // ================================================================
    // POKUŠAJ ČITANJA SA RADEĆOM VARIJANTOM
    // ================================================================
    static void tryReadWithWorkingVariant(CardChannel ch) throws Exception {
        // Probaj sve DG-ove sa varijantom A (DO'87)
        int[] fids = {0x011E, 0x0101, 0x010B, 0x010C, 0x0102, 0x011D};
        String[] names = {"EF.COM","DG1 MRZ","DG11 Lični","DG12 Dok","DG2 Foto","EF.SOD"};

        for (int k = 0; k < fids.length; k++) {
            System.out.println("--- " + names[k] + " ---");
            byte[] data = readEF_varA(ch, fids[k]);
            if (data != null && data.length > 0) {
                System.out.println("  OK! " + data.length + " bajta");
                System.out.println("  HEX: " + h(data));
                System.out.println("  TXT: " + txt(data));
                parseTLV(data, "  ");
                saveFile(data, String.format("dg_%04X.bin", fids[k]));
                if (fids[k] == 0x0102) savePhoto(data);
            }
        }
    }

    static byte[] readEF_varA(CardChannel ch, int fid) throws Exception {
        byte hi = (byte)(fid >> 8), lo = (byte)(fid & 0xFF);

        // SELECT sa DO'87
        incSSC();
        byte[] padded = isopad(new byte[]{hi, lo});
        byte[] enc    = tdes_enc(KS_ENC, SSC, padded);
        byte[] do87   = buildTLV(0x87, cat(new byte[]{0x01}, enc));
        byte[] hdr    = {(byte)0x0C,(byte)0xA4,0x02,(byte)0x0C};
        byte[] macIn  = cat(SSC, isopad(hdr), do87);
        byte[] CC     = mac3(KS_MAC, macIn);
        byte[] do8E   = buildTLV(0x8E, CC);
        byte[] body   = cat(do87, do8E);
        byte[] selApdu = cat(new byte[]{(byte)0x0C,(byte)0xA4,0x02,(byte)0x0C,(byte)body.length}, body, new byte[]{0x00});

        System.out.println("  SEL >> " + h(selApdu));
        ResponseAPDU sel = ch.transmit(new CommandAPDU(selApdu));
        System.out.printf("  SEL << SW=%04X%n", sel.getSW());
        if (sel.getSW() != 0x9000) return null;

        // READ BINARY
        List<Byte> all = new ArrayList<>();
        int offset = 0;
        while (true) {
            incSSC();
            byte p1 = (byte)((offset >> 8) & 0x7F);
            byte p2 = (byte)(offset & 0xFF);
            byte[] do97  = {(byte)0x97, 0x01, 0x00};
            byte[] hdr2  = {(byte)0x0C,(byte)0xB0, p1, p2};
            byte[] macIn2 = cat(SSC, isopad(hdr2), do97);
            byte[] CC2   = mac3(KS_MAC, macIn2);
            byte[] do8E2 = buildTLV(0x8E, CC2);
            byte[] body2 = cat(do97, do8E2);
            byte[] rbApdu = cat(new byte[]{(byte)0x0C,(byte)0xB0,p1,p2,(byte)body2.length}, body2, new byte[]{0x00});

            System.out.println("  RB  >> " + h(rbApdu));
            ResponseAPDU rb = ch.transmit(new CommandAPDU(rbApdu));
            System.out.printf("  RB  << SW=%04X data=%s%n", rb.getSW(), h(rb.getData()));

            int sw = rb.getSW();
            if (sw == 0x9000 && rb.getData().length > 0) {
                ResponseAPDU dec = smDecryptResp(rb.getData());
                byte[] d = dec.getData();
                System.out.printf("  DEC << SW=%04X data=%s%n", dec.getSW(), h(d));
                if (d.length == 0) break;
                for (byte b : d) all.add(b);
                offset += d.length;
                if (d.length < 0xDF) break;
            } else if ((sw & 0xFF00) == 0x6C00) {
                // Ništa, samo nastavi
            } else break;
        }
        byte[] res = new byte[all.size()];
        for (int i = 0; i < res.length; i++) res[i] = all.get(i);
        return res.length > 0 ? res : null;
    }

    static ResponseAPDU smDecryptResp(byte[] resp) throws Exception {
        incSSC();
        byte[] do87v=null, do99v=null, do8Ev=null;
        int i=0;
        while(i<resp.length){
            int tag=resp[i++]&0xFF;
            if(tag==0||tag==0xFF) continue;
            if((tag&0x1F)==0x1F&&i<resp.length) tag=(tag<<8)|(resp[i++]&0xFF);
            if(i>=resp.length) break;
            int len=resp[i++]&0xFF;
            if(len==0x81&&i<resp.length) len=resp[i++]&0xFF;
            else if(len==0x82&&i+1<resp.length){len=((resp[i]&0xFF)<<8)|(resp[i+1]&0xFF);i+=2;}
            if(i+len>resp.length) break;
            byte[] val=Arrays.copyOfRange(resp,i,i+len); i+=len;
            int t=tag&0xFF;
            if(t==0x87) do87v=val;
            else if(t==0x99) do99v=val;
            else if(t==0x8E) do8Ev=val;
        }
        // MAC check
        byte[] macIn=cat(SSC);
        if(do87v!=null) macIn=cat(macIn,buildTLV(0x87,do87v));
        if(do99v!=null) macIn=cat(macIn,buildTLV(0x99,do99v));
        byte[] exp=mac3(KS_MAC,macIn);
        if(!Arrays.equals(exp,do8Ev)) System.out.println("  WARN MAC mismatch! exp="+h(exp)+" got="+h(do8Ev));

        byte[] plain=new byte[0];
        if(do87v!=null){
            byte[] cipher=Arrays.copyOfRange(do87v,1,do87v.length);
            byte[] dec=tdes_dec(KS_ENC,SSC,cipher);
            plain=isounpad(dec);
        }
        int sw=do99v!=null?((do99v[0]&0xFF)<<8)|(do99v[1]&0xFF):0x9000;
        byte[] full=new byte[plain.length+2];
        System.arraycopy(plain,0,full,0,plain.length);
        full[plain.length]=(byte)(sw>>8); full[plain.length+1]=(byte)(sw&0xFF);
        return new ResponseAPDU(full);
    }

    // ================================================================
    // BAC
    // ================================================================
    static void doBAC(CardChannel ch, String mrzInfo) throws Exception {
        System.out.println("--- BAC ---");
        byte[] kseed = Arrays.copyOf(sha1(mrzInfo.getBytes(StandardCharsets.UTF_8)), 16);
        byte[] kenc  = kdf(kseed, 1);
        byte[] kmac  = kdf(kseed, 2);

        ResponseAPDU gc = ch.transmit(new CommandAPDU(x("0084000008")));
        if (gc.getSW() != 0x9000) throw new Exception("GET CHALLENGE: " + String.format("%04X", gc.getSW()));
        byte[] RND_IC  = gc.getData();
        byte[] RND_IFD = new byte[8]; new SecureRandom().nextBytes(RND_IFD);
        byte[] K_IFD   = new byte[16]; new SecureRandom().nextBytes(K_IFD);

        byte[] EIFD = tdes_enc(kenc, new byte[8], cat(RND_IFD, RND_IC, K_IFD));
        byte[] MIFD = mac3(kmac, EIFD);
        byte[] body = cat(EIFD, MIFD);
        byte[] ea   = cat(new byte[]{0x00,(byte)0x82,0x00,0x00,(byte)body.length}, body, new byte[]{0x28});
        ResponseAPDU ar = ch.transmit(new CommandAPDU(ea));
        if (ar.getSW() != 0x9000) throw new Exception("EXT AUTH failed: " + String.format("%04X", ar.getSW()));

        byte[] R    = ar.getData();
        byte[] dec  = tdes_dec(kenc, new byte[8], Arrays.copyOf(R, 32));
        byte[] K_IC = Arrays.copyOfRange(dec, 16, 32);

        KS_ENC = kdf(xor(K_IFD, K_IC), 1);
        KS_MAC = kdf(xor(K_IFD, K_IC), 2);
        SSC    = cat(Arrays.copyOfRange(RND_IC,4,8), Arrays.copyOfRange(RND_IFD,4,8));
        System.out.println("BAC OK! SSC=" + h(SSC));
    }

    // ================================================================
    // PARSIRANJE
    // ================================================================
    static void parseTLV(byte[] data, String ind) {
        int i=0;
        while(i<data.length){
            if((data[i]&0xFF)==0||(data[i]&0xFF)==0xFF){i++;continue;}
            int tag=data[i++]&0xFF;
            boolean c=(tag&0x20)!=0;
            if((tag&0x1F)==0x1F&&i<data.length) tag=(tag<<8)|(data[i++]&0xFF);
            if(i>=data.length) break;
            int len=data[i++]&0xFF;
            if(len==0x81&&i<data.length) len=data[i++]&0xFF;
            else if(len==0x82&&i+1<data.length){len=((data[i]&0xFF)<<8)|(data[i+1]&0xFF);i+=2;}
            if(i+len>data.length||len<0) break;
            byte[] val=Arrays.copyOfRange(data,i,i+len); i+=len;
            System.out.printf("%sTag %04X [%s] len=%d%n",ind,tag,tname(tag),len);
            if(tag==0x5F1F){
                String mrz=new String(val,StandardCharsets.UTF_8);
                System.out.println(ind+"  MRZ: "+mrz);
                decodeMRZ(mrz,ind+"  ");
            } else if(c) parseTLV(val,ind+"  ");
            else {
                boolean pr=val.length>0;
                for(byte b:val){int cv=b&0xFF;if(cv<0x20||cv>0x7E){pr=false;break;}}
                System.out.println(ind+"  = "+(pr?new String(val,StandardCharsets.UTF_8):h(val)));
            }
        }
    }

    static void decodeMRZ(String mrz, String ind) {
        mrz=mrz.replace("\n","").replace("\r","");
        if(mrz.length()<30) return;
        System.out.println(ind+"╔══════════════════════╗");
        String l1=mrz.substring(0,30);
        System.out.println(ind+"║ Br.dok: "+l1.substring(5,14).replace("<",""));
        if(mrz.length()>=60){
            String l2=mrz.substring(30,60);
            System.out.println(ind+"║ Dat.rod: "+fmtD(l2.substring(0,6)));
            System.out.println(ind+"║ Pol:     "+l2.substring(7,8));
            System.out.println(ind+"║ Dat.ist: "+fmtD(l2.substring(8,14)));
        }
        if(mrz.length()>=90){
            String l3=mrz.substring(60,90);
            String[] p=l3.split("<<",2);
            System.out.println(ind+"║ Prezime: "+p[0].replace("<",""));
            if(p.length>1) System.out.println(ind+"║ Ime:     "+p[1].replace("<"," ").trim());
        }
        System.out.println(ind+"╚══════════════════════╝");
    }

    static String fmtD(String s){if(s.length()!=6)return s;int y=Integer.parseInt(s.substring(0,2));return s.substring(4)+"."+s.substring(2,4)+"."+(y>30?"19":"20")+s.substring(0,2);}

    static void savePhoto(byte[] d) {
        int off=findBytes(d,new byte[]{(byte)0xFF,(byte)0xD8});
        if(off>=0){saveFile(Arrays.copyOfRange(d,off,d.length),"photo.jpg");System.out.println("  photo.jpg sačuvana!");}
        off=findBytes(d,new byte[]{(byte)0xFF,(byte)0x4F});
        if(off>=0){saveFile(Arrays.copyOfRange(d,off,d.length),"photo.jp2");System.out.println("  photo.jp2 sačuvana!");}
    }

    static String tname(int t){
        switch(t){
            case 0x60:return"EF.COM"; case 0x61:return"AppTemplate";
            case 0x5F01:return"LDS ver"; case 0x5F36:return"Unicode ver";
            case 0x5C:return"DG lista"; case 0x5F1F:return"MRZ";
            case 0x5F0E:return"Ime"; case 0x5F0F:return"Prezime";
            case 0x5F2B:return"Dat.rod"; case 0x5F1D:return"JMBG";
            case 0x5F42:return"Adresa"; case 0x30:return"SEQUENCE";
            case 0x31:return"SET"; case 0x06:return"OID";
            default:return String.format("?%04X",t);
        }
    }

    // ================================================================
    // KRIPTO
    // ================================================================
    static byte[] kdf(byte[] s,int c) throws Exception{
        byte[] D=Arrays.copyOf(s,s.length+4); D[D.length-1]=(byte)c;
        byte[] k=Arrays.copyOf(sha1(D),16);
        for(int i=0;i<16;i++){int b=k[i]&0xFE;k[i]=(byte)(b|(Integer.bitCount(b)%2==0?1:0));}
        return k;
    }
    static byte[] tdes_enc(byte[] k,byte[] iv,byte[] d) throws Exception{
        byte[] k24=cat(k,Arrays.copyOf(k,8));
        Cipher c=Cipher.getInstance("DESede/CBC/NoPadding");
        c.init(Cipher.ENCRYPT_MODE,SecretKeyFactory.getInstance("DESede").generateSecret(new DESedeKeySpec(k24)),new IvParameterSpec(iv));
        return c.doFinal(d);
    }
    static byte[] tdes_dec(byte[] k,byte[] iv,byte[] d) throws Exception{
        byte[] k24=cat(k,Arrays.copyOf(k,8));
        Cipher c=Cipher.getInstance("DESede/CBC/NoPadding");
        c.init(Cipher.DECRYPT_MODE,SecretKeyFactory.getInstance("DESede").generateSecret(new DESedeKeySpec(k24)),new IvParameterSpec(iv));
        return c.doFinal(d);
    }
    static byte[] mac3(byte[] k,byte[] d) throws Exception{
        byte[] p=isopad(d),k1=Arrays.copyOf(k,8),k2=Arrays.copyOfRange(k,8,16),cv=new byte[8];
        for(int i=0;i<p.length;i+=8) cv=des_e(k1,cv,Arrays.copyOfRange(p,i,i+8));
        return Arrays.copyOf(des_e(k1,new byte[8],des_d(k2,new byte[8],cv)),8);
    }
    static byte[] des_e(byte[] k,byte[] iv,byte[] d) throws Exception{Cipher c=Cipher.getInstance("DES/CBC/NoPadding");c.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(k,"DES"),new IvParameterSpec(iv));return c.doFinal(d);}
    static byte[] des_d(byte[] k,byte[] iv,byte[] d) throws Exception{Cipher c=Cipher.getInstance("DES/CBC/NoPadding");c.init(Cipher.DECRYPT_MODE,new SecretKeySpec(k,"DES"),new IvParameterSpec(iv));return c.doFinal(d);}
    static byte[] isopad(byte[] d){byte[] r=new byte[d.length+8-(d.length%8)];System.arraycopy(d,0,r,0,d.length);r[d.length]=(byte)0x80;return r;}
    static byte[] isounpad(byte[] d){int i=d.length-1;while(i>=0&&d[i]==0)i--;return(i>=0&&(d[i]&0xFF)==0x80)?Arrays.copyOf(d,i):d;}
    static void incSSC(){for(int i=SSC.length-1;i>=0;i--){if(++SSC[i]!=0)break;}}
    static byte[] sha1(byte[] d) throws Exception{return MessageDigest.getInstance("SHA-1").digest(d);}
    static byte[] xor(byte[] a,byte[] b){byte[] r=new byte[a.length];for(int i=0;i<a.length;i++)r[i]=(byte)(a[i]^b[i]);return r;}
    static byte[] buildTLV(int tag,byte[] val){
        byte[] t=tag>0xFF?new byte[]{(byte)(tag>>8),(byte)(tag&0xFF)}:new byte[]{(byte)(tag&0xFF)};
        byte[] l=val.length<0x80?new byte[]{(byte)val.length}:val.length<0x100?new byte[]{(byte)0x81,(byte)val.length}:new byte[]{(byte)0x82,(byte)(val.length>>8),(byte)(val.length&0xFF)};
        return cat(t,l,val);
    }
    static int cd(String s){int[]w={7,3,1};int sum=0;for(int i=0;i<s.length();i++){char c=s.charAt(i);int v=(c=='<')?0:(c>='A'&&c<='Z')?c-'A'+10:c-'0';sum+=v*w[i%3];}return sum%10;}
    static ResponseAPDU send(CardChannel ch,String hex,String l) throws CardException{ResponseAPDU r=ch.transmit(new CommandAPDU(x(hex)));System.out.printf("%s SW=%04X%s%n",l,r.getSW(),r.getData().length>0?" data="+h(r.getData()):"");return r;}
    static int findBytes(byte[] h,byte[] n){outer:for(int i=0;i<=h.length-n.length;i++){for(int j=0;j<n.length;j++)if(h[i+j]!=n[j])continue outer;return i;}return -1;}
    static void saveFile(byte[] d,String n){try(FileOutputStream f=new FileOutputStream(n)){f.write(d);}catch(Exception e){System.out.println("Err: "+e);}}
    static byte[] cat(byte[]...a){int n=0;for(byte[]x:a)if(x!=null)n+=x.length;byte[]r=new byte[n];int o=0;for(byte[]x:a)if(x!=null){System.arraycopy(x,0,r,o,x.length);o+=x.length;}return r;}
    static String h(byte[] b){if(b==null||b.length==0)return"(empty)";StringBuilder sb=new StringBuilder();for(byte x:b)sb.append(String.format("%02X",x));return sb.toString();}
    static String txt(byte[] b){StringBuilder sb=new StringBuilder();for(byte x:b){int c=x&0xFF;sb.append(c>=32&&c<=126?(char)c:'.');}return sb.toString();}
    static byte[] x(String s){s=s.replace(" ","");byte[]d=new byte[s.length()/2];for(int i=0;i<d.length;i++)d[i]=(byte)((Character.digit(s.charAt(i*2),16)<<4)+Character.digit(s.charAt(i*2+1),16));return d;}
}

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
