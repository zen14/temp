
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
