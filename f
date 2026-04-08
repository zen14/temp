
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
